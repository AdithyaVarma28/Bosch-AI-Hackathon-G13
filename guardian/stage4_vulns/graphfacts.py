"""Deterministic graph questions shared by prioritization, the investigator tools and Stage 5.

Reachability is function-level: "an entry point reaches the function that makes the call", never
variable-level dataflow. Entry kinds:

* ``route`` (public) and CLI commands that parse arguments (``click``/``typer``/``argparse``, public:
  the plan counts "CLI with user input" as public),
* ``main_guard`` scripts and ``startup`` (module-level code of a non-test file) are internal.
"""
from __future__ import annotations

from collections import deque
from typing import Optional

from guardian.stage3_knowledge.graph_builder import in_edges, nodes_of, pred, succ
from guardian.stage3_knowledge.schema import normalize_name
from guardian.stage3_knowledge.structural import FALLBACK_DIST

PUBLIC_CLI = ("click", "typer", "argparse")
MAX_DEPTH = 10


def api_of(edge: dict) -> str:
    """API target of a CALLS_API edge (``api``; ``target`` is overwritten when graph.json is reloaded)."""
    api = edge.get("api") or edge.get("target") or ""
    return "" if str(api).startswith("pkg:") else str(api)


def import_names(ctx_s3, pid: str) -> list[str]:
    G = ctx_s3.G
    d = G.nodes[pid]
    n = normalize_name(d.get("name", ""))
    dist_map = {**FALLBACK_DIST, **(ctx_s3.code_index.get("import_name_to_distribution") or {})}
    names = {k for k, v in dist_map.items() if normalize_name(v) == n}
    for f, _, e in in_edges(G, pid, "USES_PACKAGE"):
        if e.get("import_name"):
            names.add(e["import_name"].split(".")[0])
    if not names:
        names.add((d.get("name") or "").replace("-", "_").lower())
    return sorted(names, key=lambda x: (len(x), x))


def files_using(G, pid: str) -> tuple[list[str], list[str]]:
    users = pred(G, pid, "USES_PACKAGE")
    runtime = sorted(f for f in users if not G.nodes[f].get("is_test"))
    tests = sorted(f for f in users if G.nodes[f].get("is_test"))
    return runtime, tests


def used_requirers(G, pid: str) -> list[str]:
    """Packages that (transitively) require ``pid`` and are imported by non-test code."""
    out, seen, q = [], {pid}, deque([pid])
    while q:
        cur = q.popleft()
        for parent in pred(G, cur, "REQUIRES"):
            if parent in seen:
                continue
            seen.add(parent)
            if files_using(G, parent)[0]:
                out.append(parent)
            q.append(parent)
    return sorted(out)


def entry_kind(G, node: str) -> Optional[dict]:
    """If ``node`` is an entry point (or the handler of one), describe it."""
    d = G.nodes.get(node, {})
    t = d.get("type")
    if t == "Route":
        return {"id": node, "kind": "route", "public": True, "label": node.split(":", 1)[1]}
    if t == "CLIEntry":
        kind = d.get("kind") or "cli"
        f = d.get("file") or node
        label = {"main_guard": f"{f} run as a script", "argparse": f"{f} (argparse CLI)"}.get(
            kind, f"{d.get('name') or f} ({kind} command)")
        return {"id": node, "kind": kind, "public": kind in PUBLIC_CLI, "label": label}
    return None


def is_startup(G, fn: str) -> bool:
    d = G.nodes.get(fn, {})
    if not d.get("module_level"):
        return False
    f = G.nodes.get(f"file:{d.get('file')}", {})
    return not f.get("is_test") and not pred(G, fn, "HANDLES")


def reach(G, fn: str, max_depth: int = MAX_DEPTH) -> dict:
    """Reverse CALLS walk from ``fn`` up to entry points. Returns entries and one path per entry."""
    parent: dict[str, Optional[str]] = {fn: None}
    q = deque([(fn, 0)])
    entries: dict[str, dict] = {}
    callers: list[dict] = []
    while q:
        cur, depth = q.popleft()
        for h in pred(G, cur, "HANDLES"):
            e = entry_kind(G, h)
            if e and h not in entries:
                entries[h] = {**e, "handler": cur, "path": _path(parent, cur, h)}
        if is_startup(G, cur) and f"startup:{cur}" not in entries:
            entries[f"startup:{cur}"] = {"id": cur, "kind": "startup", "public": False,
                                         "label": f"module code of {G.nodes[cur].get('file')}", "handler": cur,
                                         "path": _path(parent, cur, None)}
        if depth >= max_depth:
            continue
        for c in pred(G, cur, "CALLS"):
            if c not in parent:
                parent[c] = cur
                callers.append({"id": c, "depth": depth + 1, "calls": cur})
                q.append((c, depth + 1))
    ents = sorted(entries.values(), key=lambda e: (not e["public"], e["kind"], e["id"]))
    return {"function": fn, "entries": ents, "callers": callers}


def _path(parent: dict[str, Optional[str]], start: str, entry: Optional[str]) -> list[str]:
    path = [entry] if entry else []
    cur: Optional[str] = start
    while cur is not None:
        path.append(cur)
        cur = parent[cur]
    return path


def classify(entries: list[dict]) -> str:
    if any(e["public"] for e in entries):
        return "public_path"
    if entries:
        return "internal_only"
    return "no_path_found"


def inputs_on_paths(G, entries: list[dict]) -> list[dict]:
    """Input sources (Stage 2/3 ``inputs``) on the functions of each entry path, entry first."""
    out = []
    for e in entries:
        for node in e.get("path", []):
            for i in G.nodes.get(node, {}).get("inputs", []) or []:
                out.append({"function": node, "source": i.get("source"), "line": i.get("line"),
                            "file": G.nodes[node].get("file"), "entry": e["id"]})
        if e["kind"] in PUBLIC_CLI:
            out.append({"function": e.get("handler"), "source": "command-line arguments", "line": None,
                        "file": G.nodes.get(e["id"], {}).get("file"), "entry": e["id"]})
    return out


def package_functions(G, pid: str) -> list[str]:
    """Functions that call the package's API, or live in non-test files that import it."""
    fns = {u for u, _, _ in in_edges(G, pid, "CALLS_API")}
    for f in files_using(G, pid)[0]:
        contained = [c for c in succ(G, f, "CONTAINS") if G.nodes[c].get("type") == "Function"]
        if not any(c in fns for c in contained):
            fns.update(contained)
    return sorted(fns)


def dynamic_import_files(G, files: list[str]) -> list[str]:
    """Files (or their module siblings) with dynamic imports: static reachability may miss calls."""
    mods = {G.nodes[f].get("module") for f in files if f in G}
    out = []
    for f in nodes_of(G, "File"):
        d = G.nodes[f]
        if d.get("dynamic_imports") and (f in files or d.get("module") in mods):
            out.append(d.get("path"))
    return sorted(out)


def enclosing_function(G, path: str, line: int) -> Optional[str]:
    best = None
    for fn in succ(G, f"file:{path}", "CONTAINS"):
        d = G.nodes[fn]
        if d.get("type") not in ("Function", "Class"):
            continue
        a, b = d.get("line") or 0, d.get("end_line") or d.get("line") or 0
        if a <= line <= b and (best is None or a >= G.nodes[best].get("line", 0)) and not d.get("module_level"):
            best = fn
    if best and G.nodes[best].get("type") == "Class":
        return best
    if best:
        return best
    mod = f"fn:{path}::<module>"
    return mod if mod in G else None
