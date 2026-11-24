"""3C Relationship & Flow Mapper: execution paths and blast radius (graph walks, no AI).

Paths are function-level: "user input enters checkout() and checkout() reaches the orders
write", never variable-level taint. Blast radius is *potential* reach, not proof.
"""
from __future__ import annotations

import hashlib
from collections import deque
from typing import Optional

import networkx as nx

from .graph_builder import in_edges, nodes_of, out_edges, pred, succ, tag
from .schema import BlastRadius, Evidence, ExecutionPath, short_label

MAX_DEPTH = 8
MAX_PATHS_PER_ENTRY = 50
MAX_PATHS = 500
SINK_EDGES = ("WRITES", "READS", "CONTACTS", "READS_ENV", "CALLS_API")
SENSITIVE_SINK_TAGS = ("code_exec", "subprocess", "deserialize")


def _ev(d: dict) -> list[Evidence]:
    return [Evidence(**e) for e in d.get("evidence", []) if isinstance(e, dict)]


def function_sinks(G: nx.MultiDiGraph, fn: str) -> list[dict]:
    """Sinks reached directly by one function: tables, services, env vars, package APIs, sensitive calls."""
    sinks: list[dict] = []
    for _, v, d in out_edges(G, fn, *SINK_EDGES):
        item = {"id": v, "via": d["type"], "function": fn, "evidence": d.get("evidence", [])[:1]}
        if d["type"] == "CALLS_API":
            item["target"] = d.get("target")
        sinks.append(item)
    for s in G.nodes[fn].get("sensitive", []):
        if s.get("category") in SENSITIVE_SINK_TAGS:
            sinks.append({"id": f"call:{s.get('target')}", "via": s["category"], "function": fn,
                          "evidence": [{"file": G.nodes[fn].get("file"), "line": s.get("line")}]})
    return sinks


def sink_label(G: nx.MultiDiGraph, sink: dict) -> str:
    sid = sink["id"]
    if sink["via"] == "CALLS_API":
        return sink.get("target") or short_label(sid)
    if sid.startswith("svc:"):
        return G.nodes[sid].get("name", sid[4:])
    if sid.startswith("env:"):
        return sid[4:]
    if sid.startswith("table:"):
        return f"{sid[6:]} table"
    if sid.startswith("call:"):
        return sid[5:]
    return short_label(sid)


def entry_handlers(G: nx.MultiDiGraph, entry: str) -> list[str]:
    return succ(G, entry, "HANDLES")


def _calls(G: nx.MultiDiGraph, fn: str) -> list[tuple[str, dict]]:
    return sorted(((v, d) for _, v, d in out_edges(G, fn, "CALLS")), key=lambda x: x[0])


# --------------------------------------------------------------------------- 7.1 execution paths

def execution_paths(G: nx.MultiDiGraph) -> list[dict]:
    paths: list[dict] = []
    seen: set[tuple] = set()
    entries = sorted(nodes_of(G, "Route")) + sorted(nodes_of(G, "CLIEntry"))
    for entry in entries:
        count = 0
        for handler in entry_handlers(G, entry):
            stack: list[tuple[list[str], list[dict]]] = [([handler], [])]
            while stack and count < MAX_PATHS_PER_ENTRY and len(paths) < MAX_PATHS:
                steps, call_ev = stack.pop()
                fn = steps[-1]
                children = [(c, d) for c, d in _calls(G, fn) if c not in steps]
                if children and len(steps) < MAX_DEPTH:
                    for c, d in reversed(children):
                        stack.append((steps + [c], call_ev + d.get("evidence", [])[:1]))
                    continue
                # leaf: trim trailing functions that reach no sink, then record
                per_fn = [function_sinks(G, s) for s in steps]
                last = max((i for i, s in enumerate(per_fn) if s), default=-1)
                if last < 0:
                    continue
                steps_t = steps[: last + 1]
                key = (entry, tuple(steps_t))
                if key in seen:
                    continue
                seen.add(key)
                sinks = [s for group in per_fn[: last + 1] for s in group]
                inputs = sorted({i.get("source") for s in steps_t for i in G.nodes[s].get("inputs", []) if i.get("source")})
                if not inputs and G.nodes[entry].get("type") == "CLIEntry":
                    inputs = ["command-line arguments"]
                evidence = _ev(G.nodes[entry])[:1] + [Evidence(**e) for e in call_ev[: last]]
                for s in sinks:
                    evidence += [Evidence(**e) for e in s.get("evidence", []) if e.get("file")]
                sink_ids = list(dict.fromkeys(s["id"] for s in sinks))
                pid = hashlib.sha1(f"{entry}|{'>'.join(steps_t)}".encode()).hexdigest()[:10]
                paths.append(ExecutionPath(
                    id=f"path:{pid}", entry=entry, input=", ".join(inputs) or None, steps=steps_t,
                    sinks=sink_ids,
                    sink_details=[{"id": s["id"], "via": s["via"], "function": s["function"],
                                   "label": sink_label(G, s), "target": s.get("target")} for s in sinks],
                    evidence=_dedupe(evidence),
                ).model_dump())
                count += 1
    G.graph["paths"] = [p["id"] for p in paths]
    return paths


def _dedupe(evs: list[Evidence]) -> list[Evidence]:
    out, seen = [], set()
    for e in evs:
        k = (e.file, e.line, e.lines, e.commit)
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out


def mark_reachability(G: nx.MultiDiGraph) -> dict[str, set[str]]:
    """Forward walk from every entry point; tags functions ``reachable_from_route``."""
    reach: dict[str, set[str]] = {}
    for entry in nodes_of(G, "Route", "CLIEntry"):
        q = deque((h, 0) for h in entry_handlers(G, entry))
        seen: set[str] = set()
        while q:
            fn, depth = q.popleft()
            if fn in seen:
                continue
            seen.add(fn)
            reach.setdefault(fn, set()).add(entry)
            if depth < MAX_DEPTH:
                q.extend((c, depth + 1) for c in succ(G, fn, "CALLS"))
    for fn, entries in reach.items():
        G.nodes[fn]["reachable_from"] = sorted(entries)
        if any(e.startswith("route:") for e in entries):
            tag(G, fn, "reachable_from_route")
    return reach


# --------------------------------------------------------------------------- 7.2 blast radius

def _package_chain(G: nx.MultiDiGraph, pkg: str) -> list[str]:
    """The package plus every package that (transitively) requires it."""
    chain, q = [pkg], deque([pkg])
    while q:
        cur = q.popleft()
        for parent in pred(G, cur, "REQUIRES"):
            if parent not in chain:
                chain.append(parent)
                q.append(parent)
    return chain


def _callers(G: nx.MultiDiGraph, fns: set[str]) -> set[str]:
    seen, q = set(fns), deque((f, 0) for f in fns)
    while q:
        fn, depth = q.popleft()
        if depth >= MAX_DEPTH:
            continue
        for c in pred(G, fn, "CALLS"):
            if c not in seen:
                seen.add(c)
                q.append((c, depth + 1))
    return seen


def blast_radius(G: nx.MultiDiGraph) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for pkg in sorted(nodes_of(G, "Package")):
        pd = G.nodes[pkg]
        chain = _package_chain(G, pkg)
        via_direct = [p for p in chain if G.nodes[p].get("direct")]
        files: set[str] = set()
        api_fns: set[str] = set()
        own_calls: set[str] = set()
        chain_calls: set[str] = set()
        evidence: list[Evidence] = []
        for p in chain:
            for u, _, d in in_edges(G, p, "USES_PACKAGE"):
                files.add(u)
                evidence += _ev(d)[:1]
            for u, _, d in in_edges(G, p, "CALLS_API"):
                api_fns.add(u)
                (own_calls if p == pkg else chain_calls).add(d.get("target"))
                evidence += _ev(d)[:1]
        api_calls = own_calls or chain_calls
        # functions in files that import the package but never call it are users too
        user_fns = set(api_fns)
        for f in files:
            contained = [c for c in succ(G, f, "CONTAINS") if G.nodes[c].get("type") in ("Function", "Class")]
            if not any(c in api_fns for c in contained):
                user_fns.update(contained)
        # nearby = everything defined in the files that use the package
        nearby = set(user_fns)
        for f in files:
            nearby.update(c for c in succ(G, f, "CONTAINS") if G.nodes[c].get("type") == "Function")

        ancestors = _callers(G, user_fns)
        routes = sorted({e for fn in ancestors for e in pred(G, fn, "HANDLES") if e.startswith("route:")})
        clis = sorted({e for fn in ancestors for e in pred(G, fn, "HANDLES") if e.startswith("cli:")})
        secrets = sorted({e for fn in nearby for e in succ(G, fn, "READS_ENV") if G.nodes[e].get("secret_like")})
        writes = sorted({t for fn in nearby for t in succ(G, fn, "WRITES")})
        tables = sorted(set(writes) | {t for fn in nearby for t in succ(G, fn, "READS")})
        services = sorted({s for fn in nearby for s in succ(G, fn, "CONTACTS")})
        modules = sorted({G.nodes[f].get("module") for f in files if G.nodes[f].get("module")})
        file_paths = sorted(G.nodes[f]["path"] for f in files)

        reasons: list[str] = []
        if not files:
            radius = "none"
            reasons.append("no code imports it" + ("" if pd.get("direct") else " or the packages that pull it in"))
        elif not routes:
            radius = "internal"
            reasons.append("used by code that no public route reaches" + (f" (CLI: {', '.join(clis)})" if clis else ""))
        else:
            radius = "public"
            reasons.append(f"reachable from public route{'s' if len(routes) > 1 else ''} {', '.join(r[6:] for r in routes)}")
            if secrets:
                reasons.append(f"code near it reads secret {', '.join(s[4:] for s in secrets)}")
            if writes:
                reasons.append(f"code near it writes {', '.join(t[6:] for t in writes)}")
            if services:
                reasons.append(f"code near it contacts {', '.join(G.nodes[s].get('name', s) for s in services)}")
            if secrets or writes or services:
                radius = "large"
        if not pd.get("direct") and via_direct:
            reasons.append(f"pulled in by {', '.join(G.nodes[p].get('name', p) for p in via_direct)}")

        br = BlastRadius(
            package=pkg, name=pd.get("name", pkg), version=pd.get("version"), direct=bool(pd.get("direct")),
            via_direct=via_direct, files=len(files), file_list=file_paths,
            functions=sorted(f for f in user_fns if not G.nodes[f].get("module_level")),
            modules=modules, routes_reaching=routes, cli_reaching=clis, secrets_nearby=secrets,
            tables_nearby=tables, services_nearby=services, api_calls=sorted(a for a in api_calls if a),
            radius=radius, reasons=reasons, evidence=_dedupe(evidence)[:8],
        ).model_dump()
        out[pkg] = br
        pd["blast_radius"] = {"radius": radius, "reasons": reasons}
        tag(G, pkg, f"radius:{radius}")
    return out


def get_paths(paths: list[dict], entry: Optional[str] = None, sink: Optional[str] = None) -> list[dict]:
    res = paths
    if entry:
        res = [p for p in res if p["entry"] == entry or p["entry"].endswith(entry)]
    if sink:
        res = [p for p in res if sink in p["sinks"] or any(sink in (d.get("label") or "") for d in p.get("sink_details", []))]
    return res
