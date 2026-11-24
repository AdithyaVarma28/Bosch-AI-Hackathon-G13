"""3B Semantic Understanding: evidence-backed cards for the repo, every module and selected files.

Cards are written by the LLM from extracted facts only (no full source), validated against
code_index.json and the graph, and cached. Without an LLM a deterministic card is built from
the same facts (``discovered_by: algorithm``) so the pipeline still runs end to end.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import networkx as nx

from .context import Stage3Context
from .graph_builder import nodes_of, out_edges, pred, succ
from .schema import CARD_JSON_SCHEMA, Card, Evidence, short_label
from .structural import module_graph

PROMPTS = Path(__file__).parent / "prompts"
MAX_FACT_CHARS = 14000            # ~3.5k tokens
LOW_CONFIDENCE = 0.6
EAGER_FILE_TAGS = ("entry_point", "reads_secret_env", "writes_db", "contacts_external", "code_exec",
                   "subprocess", "deserialize")


def prompt(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


def first_sentence(text: Optional[str]) -> str:
    if not text:
        return ""
    t = " ".join(text.strip().split())
    m = re.match(r"(.+?[.!?])(\s|$)", t)
    return (m.group(1) if m else t)[:240]


# --------------------------------------------------------------------------- helpers

def functions_of(G: nx.MultiDiGraph, nid: str) -> list[str]:
    """Function/Class nodes under a module or file (module-level pseudo functions excluded)."""
    t = G.nodes[nid].get("type")
    files = succ(G, nid, "CONTAINS") if t == "Module" else [nid]
    out = []
    for f in files:
        for c in succ(G, f, "CONTAINS"):
            if G.nodes[c].get("type") in ("Function", "Class") and not G.nodes[c].get("module_level"):
                out.append(c)
    return out


def files_of(G: nx.MultiDiGraph, nid: str) -> list[str]:
    t = G.nodes[nid].get("type")
    return succ(G, nid, "CONTAINS") if t == "Module" else [nid]


def module_order(G: nx.MultiDiGraph) -> list[str]:
    """Leaves first: condense dependency cycles, then reverse topological order."""
    D = module_graph(G)
    C = nx.condensation(D)
    order: list[str] = []
    for comp in reversed(list(nx.topological_sort(C))):
        order.extend(sorted(C.nodes[comp]["members"]))
    return order


def sensitivity(G: nx.MultiDiGraph, fns: list[str]) -> tuple[str, list[str], list[str], list[str]]:
    secrets = sorted({e for f in fns for e in succ(G, f, "READS_ENV") if G.nodes[e].get("secret_like")})
    envs = sorted({e for f in fns for e in succ(G, f, "READS_ENV")})
    writes = sorted({t for f in fns for t in succ(G, f, "WRITES")})
    reads = sorted({t for f in fns for t in succ(G, f, "READS")})
    services = sorted({s for f in fns for s in succ(G, f, "CONTACTS")})
    dangerous = sorted({t for f in fns for t in G.nodes[f].get("tags", []) if t in ("code_exec", "subprocess", "deserialize")})
    routes = sorted({e for f in fns for e in G.nodes[f].get("reachable_from", []) if e.startswith("route:")})
    reasons = []
    if secrets:
        reasons.append("reads secret " + ", ".join(s[4:] for s in secrets))
    if writes:
        reasons.append("writes " + ", ".join(t[6:] for t in writes))
    if services:
        reasons.append("contacts " + ", ".join(G.nodes[s].get("name", s) for s in services))
    if dangerous:
        reasons.append("performs " + ", ".join(d.replace("_", " ") for d in dangerous))
    if routes:
        reasons.append("reachable from public route " + ", ".join(r[6:] for r in routes))
    if routes and (secrets or writes or services or dangerous):
        level = "high"
    elif secrets or writes or services or dangerous:
        level = "medium"
    else:
        level = "low"
    return level, reasons, writes + [t for t in reads if t not in writes] + envs, services


def _fn_facts(G: nx.MultiDiGraph, fn: str) -> dict:
    d = G.nodes[fn]
    return {k: v for k, v in {
        "name": d.get("qualname"),
        "kind": d.get("kind"),
        "signature": f"{d.get('qualname')}({', '.join(map(str, d.get('params', [])))})",
        "lines": f"{d.get('line')}-{d.get('end_line')}",
        "docstring": first_sentence(d.get("docstring")),
        "decorators": d.get("decorators") or None,
        "tags": [t for t in d.get("tags", []) if t != "module_level"] or None,
        "handles": [e for e in pred(G, fn, "HANDLES")] or None,
        "inputs": [i.get("source") for i in d.get("inputs", [])] or None,
        "calls": [short_label(c) + f" ({G.nodes[c].get('file')})" for c in succ(G, fn, "CALLS")] or None,
        "api_calls": sorted({e.get("target") for _, _, e in out_edges(G, fn, "CALLS_API")}) or None,
        "reads_env": succ(G, fn, "READS_ENV") or None,
        "writes": succ(G, fn, "WRITES") or None,
        "reads": succ(G, fn, "READS") or None,
        "contacts": succ(G, fn, "CONTACTS") or None,
    }.items() if v not in (None, "", [])}


def _bodies(ctx: Stage3Context, fns: list[str]) -> list[dict]:
    """At most two short bodies (<= 40 lines) of sensitive functions without a docstring."""
    if not ctx.source.available:
        return []
    G = ctx.G
    out = []
    for fn in fns:
        d = G.nodes[fn]
        if d.get("docstring") or not any(t in d.get("tags", []) for t in EAGER_FILE_TAGS[1:]):
            continue
        start, end = d.get("line") or 0, d.get("end_line") or 0
        if not start or end - start > 40:
            continue
        try:
            code = "\n".join(t for _, t in ctx.source.read_lines(d["file"], start, end))
        except Exception:
            continue
        out.append({"function": d.get("qualname"), "file": d["file"], "lines": f"{start}-{end}", "code": code})
        if len(out) == 2:
            break
    return out


def _fit(facts: dict) -> dict:
    """Trim facts until they fit the prompt budget."""
    blob = json.dumps(facts, default=str)
    if len(blob) <= MAX_FACT_CHARS:
        return facts
    facts.pop("function_bodies", None)
    for f in facts.get("files", []):
        for fn in f.get("functions", []):
            for k in ("calls", "decorators", "docstring"):
                fn.pop(k, None)
    while len(json.dumps(facts, default=str)) > MAX_FACT_CHARS:
        biggest = max(facts.get("files", []), key=lambda f: len(f.get("functions", [])), default=None)
        if not biggest or not biggest.get("functions"):
            break
        biggest["functions"] = biggest["functions"][: max(0, len(biggest["functions"]) // 2)]
        biggest["functions_truncated"] = True
    return facts


def node_facts(ctx: Stage3Context, nid: str) -> dict:
    G = ctx.G
    d = G.nodes[nid]
    fns = functions_of(G, nid)
    level, reasons, data_ids, ext_ids = sensitivity(G, fns)
    files = []
    for f in files_of(G, nid):
        fd = G.nodes[f]
        files.append({
            "path": fd.get("path"), "loc": fd.get("loc"), "docstring": first_sentence(fd.get("docstring")),
            "tags": fd.get("tags", []),
            "functions": [_fn_facts(G, fn) for fn in functions_of(G, f)],
        })
    pkgs: dict[str, set] = {}
    for f in files_of(G, nid):
        for p in succ(G, f, "USES_PACKAGE"):
            pkgs.setdefault(G.nodes[p].get("name", p), set())
    for fn in fns:
        for _, p, e in out_edges(G, fn, "CALLS_API"):
            pkgs.setdefault(G.nodes[p].get("name", p), set()).add(e.get("target"))
    facts = {
        "id": nid, "kind": d.get("type", "").lower(), "path": d.get("path"), "name": d.get("name"),
        "tags": d.get("tags", []), "files": files,
        "packages_used": [{"name": k, "api_calls": sorted(v)} for k, v in sorted(pkgs.items())],
        "routes": sorted({r for fn in fns for r in pred(G, fn, "HANDLES")}),
        "reachable_from": sorted({r for fn in fns for r in G.nodes[fn].get("reachable_from", [])}),
        "deterministic_sensitivity": {"level": level, "reasons": reasons},
        "known_ids": {"data": data_ids, "external": ext_ids},
        "function_bodies": _bodies(ctx, fns),
    }
    if d.get("type") == "Module":
        facts["centrality"] = d.get("centrality")
        facts["tightly_coupled_with"] = d.get("tightly_coupled_with")
        facts["depends_on"] = [{"module": m, "purpose": (ctx.cards.get(m) or {}).get("purpose")}
                               for m in succ(G, nid, "DEPENDS_ON")]
        facts["used_by"] = pred(G, nid, "DEPENDS_ON")
    return _fit({k: v for k, v in facts.items() if v not in (None, [], {})})


def repo_facts(ctx: Stage3Context, rid: str) -> dict:
    G = ctx.G
    d = G.nodes[rid]
    readme = d.get("readme_excerpt")
    if not readme and d.get("readme") and ctx.source.available:
        try:
            readme = "\n".join(t for _, t in ctx.source.read_lines(d["readme"], 1, 60))[:2000]
        except Exception:
            readme = None
    mods = [m for m in nodes_of(G, "Module")]
    data_ids = sorted(nodes_of(G, "Table") + nodes_of(G, "EnvVar"))
    ext_ids = sorted(nodes_of(G, "ExternalService"))
    return _fit({
        "id": rid, "kind": "repo", "name": d.get("name"), "readme_excerpt": readme,
        "modules": [{"id": m, "purpose": (ctx.cards.get(m) or {}).get("purpose"),
                     "sensitivity": (ctx.cards.get(m) or {}).get("sensitivity"),
                     "tags": G.nodes[m].get("tags", [])} for m in mods],
        "routes": sorted(nodes_of(G, "Route")), "cli_entries": sorted(nodes_of(G, "CLIEntry")),
        "direct_packages": sorted(G.nodes[p].get("name") for p in nodes_of(G, "Package") if G.nodes[p].get("direct")),
        "files": [{"path": G.nodes[f].get("path"), "loc": G.nodes[f].get("loc")} for f in nodes_of(G, "File")][:60],
        "known_ids": {"data": data_ids, "external": ext_ids},
    })


# --------------------------------------------------------------------------- deterministic card

def heuristic_card(ctx: Stage3Context, nid: str) -> Card:
    G = ctx.G
    d = G.nodes[nid]
    t = d.get("type")
    if t == "Repo":
        return _heuristic_repo_card(ctx, nid)
    fns = functions_of(G, nid)
    level, reasons, data_ids, ext_ids = sensitivity(G, fns)
    file_nodes = files_of(G, nid)
    docs = [first_sentence(G.nodes[f].get("docstring")) for f in sorted(file_nodes, key=lambda f: G.nodes[f]["path"].endswith("__init__.py"))]
    docs = [x for x in docs if x]

    behaviours = []
    routes = sorted({r for fn in fns for r in pred(G, fn, "HANDLES") if r.startswith("route:")})
    if routes:
        behaviours.append("handles " + ", ".join(r[6:] for r in routes))
    writes = sorted({x for fn in fns for x in succ(G, fn, "WRITES")})
    if writes:
        behaviours.append("writes the " + ", ".join(x[6:] for x in writes) + " table" + ("s" if len(writes) > 1 else ""))
    svcs = sorted({x for fn in fns for x in succ(G, fn, "CONTACTS")})
    if svcs:
        behaviours.append("contacts " + ", ".join(G.nodes[s].get("name", s) for s in svcs))
    envs = sorted({x for fn in fns for x in succ(G, fn, "READS_ENV")})
    if envs:
        behaviours.append("reads " + ", ".join(e[4:] for e in envs) + " from the environment")
    mapped = sorted({(G.nodes[fn].get("qualname"), t) for fn in fns for t in succ(G, fn, "MAPS_TO")})
    for cls, t in mapped:
        behaviours.append(f"maps {cls} to the {t[6:]} table")
    danger = sorted({(s.get("category"), s.get("target")) for fn in fns for s in G.nodes[fn].get("sensitive", [])
                     if s.get("category") in ("deserialize", "code_exec", "subprocess")})
    for cat, target in danger:
        behaviours.append(f"calls {target} ({cat.replace('_', ' ')})")

    is_tests = d.get("kind") == "tests" or (t == "File" and d.get("is_test"))
    names = [G.nodes[f].get("qualname") for f in fns][:5]
    if is_tests:
        deps = [G.nodes[m].get("name") for m in succ(G, nid, "DEPENDS_ON")] if t == "Module" else []
        purpose = f"Test suite with {len(fns)} test function{'s' if len(fns) != 1 else ''}" + \
                  (f" exercising {', '.join(deps)}." if deps else ".")
        confidence = 0.7
    elif docs:
        purpose = docs[0].rstrip(".") + "."
        confidence = 0.75
    elif names:
        purpose = f"Defines {', '.join(names)}."
        confidence = 0.65 if behaviours else 0.5   # observed behaviour backs the card; names alone do not
    else:
        purpose = "Package marker without definitions."
        confidence = 0.6
    if behaviours and not is_tests:
        purpose += " Observed: " + "; ".join(behaviours) + "."

    responsibilities = []
    for fn in fns:
        fd = G.nodes[fn]
        if fd.get("docstring"):
            responsibilities.append(f"{fd.get('qualname')}(): {first_sentence(fd['docstring'])}")
    responsibilities = responsibilities[:5] or [f"{n}()" for n in names]

    inputs = []
    for fn in fns:
        for i in G.nodes[fn].get("inputs", []):
            rts = [r[6:] for r in pred(G, fn, "HANDLES") if r.startswith("route:")]
            inputs.append(f"{i.get('source')}" + (f" from {', '.join(rts)}" if rts else ""))
    inputs += [f"{e[4:]} (environment)" for e in envs]
    outputs = [f"row in {x[6:]} table" for x in writes] + [f"call to {G.nodes[s].get('name', s)}" for s in svcs]

    def weight(fn):
        return -(len(out_edges(G, fn, "WRITES", "CONTACTS", "READS_ENV", "CALLS_API")) + len(pred(G, fn, "HANDLES")))
    evidence = [Evidence(file=G.nodes[fn]["file"], lines=f"{G.nodes[fn]['line']}-{G.nodes[fn]['end_line']}")
                for fn in sorted(fns, key=weight)[:3] if G.nodes[fn].get("line")]
    if not evidence and file_nodes:
        p = G.nodes[file_nodes[0]]["path"]
        evidence = [Evidence(file=p, lines=f"1-{max(1, ctx.file_len(p))}")]
    open_q = [] if confidence >= LOW_CONFIDENCE else ["No docstrings: purpose inferred from names only."]
    data_ids = data_ids + [t for _, t in mapped if t not in data_ids]
    return Card(id=nid, purpose=purpose, responsibilities=responsibilities, inputs=inputs, outputs=outputs,
                data_touched=data_ids, external=ext_ids, sensitivity=level, sensitivity_reasons=reasons,
                confidence=confidence, evidence=evidence, open_questions=open_q, discovered_by="algorithm",
                commit=G.graph.get("commit"))


def _heuristic_repo_card(ctx: Stage3Context, rid: str) -> Card:
    G = ctx.G
    routes = sorted(nodes_of(G, "Route"))
    svcs = sorted(nodes_of(G, "ExternalService"))
    tables = sorted({t for _, t, d in G.edges(data=True) if d.get("type") == "WRITES"})
    secrets = sorted(e for e in nodes_of(G, "EnvVar") if G.nodes[e].get("secret_like") and pred(G, e, "READS_ENV"))
    frameworks = sorted({G.nodes[r].get("framework") for r in routes if G.nodes[r].get("framework")})
    mods = [m for m in nodes_of(G, "Module") if G.nodes[m].get("kind") != "tests"]
    root_docs = [first_sentence(G.nodes[f].get("docstring")) for f in nodes_of(G, "File")
                 if G.nodes[f]["path"].count("/") == 1 and G.nodes[f]["path"].endswith("__init__.py")]
    lead = next((x for x in root_docs if x), "")
    kind = f"{'/'.join(f.capitalize() for f in frameworks)} application" if frameworks else "Python project"
    parts = [lead.rstrip(".") + "." if lead else f"A {kind} with {len(mods)} source modules."]
    if routes:
        parts.append("Public entry point" + ("s " if len(routes) > 1 else " ") + ", ".join(r[6:] for r in routes) + ".")
    reach = []
    if svcs:
        reach.append("contacts " + ", ".join(G.nodes[s].get("name", s) for s in svcs))
    if tables:
        reach.append("writes the " + ", ".join(t[6:] for t in tables) + " table" + ("s" if len(tables) > 1 else ""))
    if secrets:
        reach.append("reads secret " + ", ".join(s[4:] for s in secrets))
    if reach:
        parts.append("The code " + "; ".join(reach) + ".")
    high = [m for m in mods if (ctx.cards.get(m) or {}).get("sensitivity") == "high"]
    level = "high" if high else "medium" if any((ctx.cards.get(m) or {}).get("sensitivity") == "medium" for m in mods) else "low"
    ev = [Evidence(**e) for r in routes for e in G.nodes[r].get("evidence", [])][:3]
    return Card(id=rid, purpose=" ".join(parts),
                responsibilities=[(ctx.cards.get(m) or {}).get("purpose", G.nodes[m]["name"]) for m in mods][:5],
                inputs=[r[6:] for r in routes] + [c[4:] for c in nodes_of(G, "CLIEntry")],
                outputs=[f"{t[6:]} table" for t in tables] + [G.nodes[s].get("name", s) for s in svcs],
                data_touched=tables + secrets, external=svcs, sensitivity=level,
                sensitivity_reasons=[f"module {G.nodes[m]['name']} is high sensitivity" for m in high],
                confidence=0.7, evidence=ev, discovered_by="algorithm", commit=G.graph.get("commit"))


# --------------------------------------------------------------------------- LLM card + validation

def validate_card(ctx: Stage3Context, raw: dict) -> tuple[dict, list[str]]:
    problems: list[str] = []
    clean = dict(raw)
    good_ev = []
    for e in raw.get("evidence", []) or []:
        f = (e or {}).get("file")
        rng = Evidence(file=f, lines=str((e or {}).get("lines", ""))).line_range()
        if f not in ctx.files_by_path:
            problems.append(f"evidence file {f!r} is not in code_index.json")
        elif rng is None or rng[0] < 1 or rng[1] > max(1, ctx.file_len(f)):
            problems.append(f"evidence lines {e.get('lines')!r} are outside {f} (1-{ctx.file_len(f)})")
        else:
            good_ev.append({"file": f, "lines": f"{rng[0]}-{rng[1]}" if rng[0] != rng[1] else str(rng[0])})
    clean["evidence"] = good_ev
    for fld in ("data_touched", "external"):
        ok = []
        for x in raw.get(fld, []) or []:
            if x in ctx.G:
                ok.append(x)
            else:
                problems.append(f"{fld} id {x!r} does not exist in the graph")
        clean[fld] = ok
    try:
        clean["confidence"] = min(1.0, max(0.0, float(raw.get("confidence", 0.5))))
    except (TypeError, ValueError):
        clean["confidence"] = 0.5
        problems.append("confidence was not a number")
    if not str(raw.get("purpose", "")).strip():
        problems.append("purpose is empty")
    return clean, problems


def llm_card(ctx: Stage3Context, nid: str, facts: dict) -> Optional[Card]:
    llm = ctx.llm
    if llm.used("card") >= ctx.budgets.card_calls:      # budget counts real calls; cache hits are free
        return None
    facts_json = json.dumps(facts, indent=1, default=str)
    user = prompt("card_user.md").replace("{kind}", facts.get("kind", "node")).replace("{id}", nid).replace("{facts}", facts_json)
    system = prompt("card_system.md")
    raw = llm.complete_json("card", system, user, CARD_JSON_SCHEMA)  # served from cache even offline
    if raw is None:
        return None
    clean, problems = validate_card(ctx, raw)
    dropped: list[str] = []
    if problems and llm.used("card") < ctx.budgets.card_calls:
        retry = prompt("card_retry.md").replace("{id}", nid).replace("{facts}", facts_json) \
            .replace("{problems}", "\n".join(f"- {p}" for p in problems))
        raw2 = llm.complete_json("card", system, retry, CARD_JSON_SCHEMA)
        if raw2 is not None:
            clean, problems = validate_card(ctx, raw2)
    if problems:  # still invalid after one retry: drop the claims, lower confidence
        dropped = problems
        clean["confidence"] = round(clean["confidence"] * 0.8, 2)
    try:
        return Card(id=nid, discovered_by="ai", commit=ctx.G.graph.get("commit"), dropped_claims=dropped,
                    **{k: v for k, v in clean.items() if k in CARD_JSON_SCHEMA["properties"]})
    except Exception as exc:
        llm.errors.append(f"card {nid}: {exc}")
        return None


def make_card(ctx: Stage3Context, nid: str) -> dict:
    facts = repo_facts(ctx, nid) if ctx.G.nodes[nid].get("type") == "Repo" else node_facts(ctx, nid)
    card = llm_card(ctx, nid, facts) or heuristic_card(ctx, nid)
    data = card.model_dump()
    data["needs_investigation"] = data["confidence"] < LOW_CONFIDENCE or bool(data["open_questions"])
    ctx.G.nodes[nid]["card"] = data
    ctx.cards[nid] = data
    return data


def ensure_card(ctx: Stage3Context, nid: str) -> Optional[dict]:
    """Lazy card for any module/file/repo node (used by 3D and the API)."""
    if nid not in ctx.G or ctx.G.nodes[nid].get("type") not in ("Module", "File", "Repo"):
        return None
    return ctx.cards.get(nid) or make_card(ctx, nid)


def eager_files(ctx: Stage3Context) -> list[str]:
    G = ctx.G
    out = []
    for f in sorted(nodes_of(G, "File")):
        d = G.nodes[f]
        if d.get("is_test"):
            continue
        if any(t in d.get("tags", []) for t in EAGER_FILE_TAGS) or d.get("changed_recently"):
            out.append(f)
    return out


def build_cards(ctx: Stage3Context) -> dict[str, dict]:
    G = ctx.G
    for m in module_order(G):
        make_card(ctx, m)
    for f in eager_files(ctx):
        make_card(ctx, f)
    for r in nodes_of(G, "Repo"):
        make_card(ctx, r)
    return ctx.cards
