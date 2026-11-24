"""3C Time travel: light snapshots per dependency commit, and a baseline -> HEAD diff.

* Light snapshots (packages, CI actions, base images) for up to 10 commits from
  ``facts.dependency_history``; CI/Docker refs come from ``git show`` when the repo is available.
* Code-level diff, best source first:
    1. ``full-graph``  - a baseline Stage 1–2 output was supplied: build both graphs and diff them;
    2. ``git-files``   - the repo is a git checkout: nodes/edges introduced by files added since the
                         baseline (modified files are reported, not diffed line by line);
    3. ``dependencies`` - package changes only.
Each change is linked to its Commit node with a ``CHANGED_IN`` edge.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

import networkx as nx

from .context import Stage3Context
from .graph_builder import add_edge, add_node, ev, nodes_of, pred, strip_spec, succ
from .schema import commit_id, normalize_name

SEM_NODE_TYPES = ("Module", "File", "Function", "Class", "Route", "CLIEntry", "EnvVar", "Table",
                  "ExternalService", "Action", "Image", "Workflow")
SEM_EDGE_TYPES = ("IMPORTS", "DEPENDS_ON", "USES_PACKAGE", "CALLS", "CALLS_API", "HANDLES", "RECEIVES_INPUT",
                  "READS_ENV", "READS", "WRITES", "MAPS_TO", "CONTACTS", "USES_ACTION", "USES_IMAGE")
ITEM_PRIORITY = {"module": 0, "network": 1, "package": 2, "secret": 3, "entry": 4, "data": 5, "file": 6, "ci": 7, "code": 8}


# --------------------------------------------------------------------------- labels

def short(nid: str) -> str:
    kind, _, rest = nid.partition(":")
    if kind == "fn":
        return "fn:" + rest.split("::")[-1]
    if kind == "class":
        return "class:" + rest.split("::")[-1]
    if kind == "file":
        return rest
    if kind == "pkg":
        return rest.split("/", 1)[-1].split("@")[0]
    return nid


def node_label(G: nx.MultiDiGraph, nid: str) -> str:
    d = G.nodes[nid]
    t = d.get("type")
    if t == "Module":
        return f"module {d.get('path')}"
    if t == "File":
        return f"file {d.get('path')}"
    if t in ("Function", "Class"):
        return f"{t.lower()} {d.get('qualname')} ({d.get('file')})"
    if t == "ExternalService":
        return f"service {d.get('name')}"
    if t == "EnvVar":
        return f"env {d.get('name')}"
    if t == "Table":
        return f"table {d.get('name')}"
    if t == "Route":
        return f"route {nid[6:]}"
    return f"{(t or 'node').lower()} {nid.split(':', 1)[-1]}"


def category(t: str, G: Optional[nx.MultiDiGraph] = None, v: Optional[str] = None) -> str:
    if t in ("CONTACTS", "ExternalService"):
        return "network"
    if t == "Module":
        return "module"
    if t in ("Package", "USES_PACKAGE", "CALLS_API"):
        return "package"
    if t == "READS_ENV" or t == "EnvVar":
        return "secret" if (G is not None and v in G and G.nodes[v].get("secret_like")) or t == "EnvVar" else "code"
    if t in ("Route", "HANDLES", "RECEIVES_INPUT", "CLIEntry"):
        return "entry"
    if t in ("WRITES", "READS", "Table", "MAPS_TO"):
        return "data"
    if t == "File":
        return "file"
    if t in ("Action", "Image", "Workflow", "USES_ACTION", "USES_IMAGE"):
        return "ci"
    return "code"


def clean_version(v: Optional[str]) -> Optional[str]:
    """'==5.4.1' -> '5.4.1' (history records pins as specs); ranges stay as they are."""
    return re.sub(r"^\s*===?\s*", "", v) if isinstance(v, str) else v


def fmt_date(s: Optional[str]) -> str:
    if not s:
        return ""
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).strftime("%b %d").replace(" 0", " ")
    except ValueError:
        return str(s)[:10]


# --------------------------------------------------------------------------- light snapshots

def _head_packages(G: nx.MultiDiGraph) -> dict[str, tuple[str, Optional[str]]]:
    out = {}
    for p in nodes_of(G, "Package"):
        d = G.nodes[p]
        if d.get("direct"):
            out[normalize_name(d.get("name", ""))] = (d.get("name"), d.get("version"))
    return out


def _git_ci_refs(ctx: Stage3Context, sha: str) -> tuple[Optional[list], Optional[list]]:
    src = ctx.source
    if not src.is_git:
        return None, None
    actions, images = [], []
    for wf in ctx.facts.get("ci_workflows", []) or []:
        text = src.git("show", f"{sha}:{wf.get('file')}")
        if text:
            actions += re.findall(r"uses:\s*['\"]?([^\s'\"#]+)", text)
    for c in ctx.facts.get("containers", []) or []:
        text = src.git("show", f"{sha}:{c.get('file')}")
        if text:
            images += re.findall(r"(?im)^\s*FROM\s+(?:--\S+\s+)*([^\s]+)", text)
    return sorted(set(actions)), sorted(set(images))


def light_snapshots(ctx: Stage3Context) -> list[dict]:
    G = ctx.G
    history = sorted(ctx.facts.get("dependency_history", []) or [], key=lambda h: str(h.get("date") or ""), reverse=True)
    history = history[: ctx.budgets.history_commits]
    state = _head_packages(G)
    head_actions = sorted({G.nodes[a].get("uses", "") + (f"@{G.nodes[a]['ref']}" if G.nodes[a].get("ref") else "")
                           for a in nodes_of(G, "Action")})
    head_images = sorted({G.nodes[i].get("ref") for i in nodes_of(G, "Image") if G.nodes[i].get("ref")})
    snaps = []
    for h in history:
        sha = h.get("commit", "")
        actions, images = _git_ci_refs(ctx, sha)
        snaps.append({
            "commit": sha, "short": sha[:7], "date": h.get("date"), "author": h.get("author"),
            "message": h.get("message"), "files_changed": h.get("files_changed", []),
            "packages": {v[0]: v[1] for v in sorted(state.values(), key=lambda x: normalize_name(x[0]))},
            "actions": actions if actions is not None else head_actions,
            "images": images if images is not None else head_images,
        })
        for a in h.get("added", []) or []:          # step back to the commit's parent
            state.pop(normalize_name(strip_spec(str(a))), None)
        for r in h.get("removed", []) or []:
            name = strip_spec(str(r))
            state[normalize_name(name)] = (name, None)
        for c in h.get("changed", []) or []:
            n = normalize_name(c.get("name", ""))
            state[n] = ((state.get(n) or (c.get("name"),))[0], clean_version(c.get("from")))
    return snaps


def diff_snapshots(a: dict, b: dict) -> list[dict]:
    """Package/CI diff between two light snapshots (a = older)."""
    items = []
    pa = {normalize_name(k): (k, v) for k, v in a.get("packages", {}).items()}
    pb = {normalize_name(k): (k, v) for k, v in b.get("packages", {}).items()}
    for n in sorted(pb.keys() - pa.keys()):
        items.append({"op": "+", "kind": "node", "type": "Package", "id": n, "category": "package",
                      "label": f"+ {pb[n][0]} {pb[n][1] or ''}".rstrip()})
    for n in sorted(pa.keys() - pb.keys()):
        items.append({"op": "-", "kind": "node", "type": "Package", "id": n, "category": "package",
                      "label": f"- {pa[n][0]} {pa[n][1] or ''}".rstrip()})
    for n in sorted(pa.keys() & pb.keys()):
        if pa[n][1] != pb[n][1]:
            items.append({"op": "~", "kind": "node", "type": "Package", "id": n, "category": "package",
                          "label": f"{pb[n][0]} {pa[n][1]} → {pb[n][1]}", "from": pa[n][1], "to": pb[n][1]})
    for field, t in (("actions", "Action"), ("images", "Image")):
        for x in sorted(set(b.get(field, [])) - set(a.get(field, []))):
            items.append({"op": "+", "kind": "node", "type": t, "id": x, "category": "ci", "label": f"+ {t.lower()} {x}"})
        for x in sorted(set(a.get(field, [])) - set(b.get(field, []))):
            items.append({"op": "-", "kind": "node", "type": t, "id": x, "category": "ci", "label": f"- {t.lower()} {x}"})
    return items


# --------------------------------------------------------------------------- full-graph diff

def _norm(G: nx.MultiDiGraph, n: str) -> str:
    return f"pkg:{normalize_name(G.nodes[n].get('name', n))}" if G.nodes[n].get("type") == "Package" else n


def diff_graphs(Ga: nx.MultiDiGraph, Gb: nx.MultiDiGraph) -> list[dict]:
    """Semantic diff of two full graphs (a = baseline, b = head)."""
    items = []
    na = {n for n, d in Ga.nodes(data=True) if d.get("type") in SEM_NODE_TYPES}
    nb = {n for n, d in Gb.nodes(data=True) if d.get("type") in SEM_NODE_TYPES}
    for n in sorted(nb - na):
        t = Gb.nodes[n]["type"]
        items.append({"op": "+", "kind": "node", "type": t, "id": n, "category": category(t, Gb, n),
                      "label": f"+ {node_label(Gb, n)}", "evidence": Gb.nodes[n].get("evidence", [])[:1]})
    for n in sorted(na - nb):
        t = Ga.nodes[n]["type"]
        items.append({"op": "-", "kind": "node", "type": t, "id": n, "category": category(t, Ga, n),
                      "label": f"- {node_label(Ga, n)}"})

    def edges(G):
        out = {}
        for u, v, d in G.edges(data=True):
            if d.get("type") in SEM_EDGE_TYPES:
                out[(_norm(G, u), _norm(G, v), d["type"])] = (u, v, d)
        return out
    ea, eb = edges(Ga), edges(Gb)
    for k in sorted(eb.keys() - ea.keys()):
        u, v, d = eb[k]
        items.append({"op": "+", "kind": "edge", "type": d["type"], "id": f"{u}|{d['type']}|{v}", "from": u, "to": v,
                      "category": category(d["type"], Gb, v), "label": f"+{d['type']} {short(u)} → {short(v)}",
                      "evidence": d.get("evidence", [])[:1]})
    for k in sorted(ea.keys() - eb.keys()):
        u, v, d = ea[k]
        items.append({"op": "-", "kind": "edge", "type": d["type"], "id": f"{u}|{d['type']}|{v}", "from": u, "to": v,
                      "category": category(d["type"], Ga, v), "label": f"-{d['type']} {short(u)} → {short(v)}"})
    return items


# --------------------------------------------------------------------------- git file-level diff

def git_file_status(ctx: Stage3Context, base: str, head: str = "HEAD") -> Optional[dict[str, str]]:
    out = ctx.source.git("diff", "--name-status", "--no-renames", base, head)
    if out is None:
        return None
    status = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            status[parts[-1]] = parts[0][0]
    return status


def diff_from_git(ctx: Stage3Context, status: dict[str, str]) -> list[dict]:
    G = ctx.G
    added_files = {p for p, s in status.items() if s == "A"}
    new_nodes: set[str] = set()
    for f in nodes_of(G, "File"):
        if G.nodes[f]["path"] in added_files:
            new_nodes.add(f)
            new_nodes.update(c for c in succ(G, f, "CONTAINS"))
    for m in nodes_of(G, "Module"):
        files = succ(G, m, "CONTAINS")
        if files and all(f in new_nodes for f in files):
            new_nodes.add(m)
    # leaf resources only reached from new code are new as well
    for n in nodes_of(G, "ExternalService", "EnvVar", "Table", "Route"):
        users = pred(G, n, "CONTACTS", "READS_ENV", "WRITES", "READS") or succ(G, n, "HANDLES")
        if users and all(u in new_nodes for u in users):
            new_nodes.add(n)

    items = []
    for n in sorted(new_nodes):
        t = G.nodes[n].get("type")
        if t in SEM_NODE_TYPES and not G.nodes[n].get("module_level"):
            items.append({"op": "+", "kind": "node", "type": t, "id": n, "category": category(t, G, n),
                          "label": f"+ {node_label(G, n)}", "evidence": G.nodes[n].get("evidence", [])[:1]})
    for u, v, d in G.edges(data=True):
        if d.get("type") not in SEM_EDGE_TYPES:
            continue
        ev_files = {e.get("file") for e in d.get("evidence", [])}
        if u in new_nodes or v in new_nodes or (ev_files and ev_files <= added_files):
            items.append({"op": "+", "kind": "edge", "type": d["type"], "id": f"{u}|{d['type']}|{v}", "from": u,
                          "to": v, "category": category(d["type"], G, v),
                          "label": f"+{d['type']} {short(u)} → {short(v)}", "evidence": d.get("evidence", [])[:1]})
    for p, s in sorted(status.items()):
        if not p.endswith(".py"):
            continue
        if s == "M":
            items.append({"op": "~", "kind": "node", "type": "File", "id": f"file:{p}", "category": "file",
                          "label": f"~ file {p} (modified)"})
        elif s == "D":
            items.append({"op": "-", "kind": "node", "type": "File", "id": f"file:{p}", "category": "file",
                          "label": f"- file {p}"})
    return items


# --------------------------------------------------------------------------- attribution + driver

def _introducing_commit(ctx: Stage3Context, base: str, path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    out = ctx.source.git("log", "--format=%H", "--reverse", f"{base}..HEAD", "--", path)
    return out.split()[0] if out and out.split() else None


def _ensure_commit(ctx: Stage3Context, sha: str) -> str:
    cid = commit_id(sha)
    if cid not in ctx.G:
        info = ctx.source.git("show", "-s", "--format=%H%x1f%aI%x1f%an%x1f%s", sha) or ""
        parts = info.strip().split("\x1f")
        add_node(ctx.G, cid, "Commit", "git", [ev(commit=sha)], sha=parts[0] if parts[0] else sha,
                 date=parts[1] if len(parts) > 1 else None, author=parts[2] if len(parts) > 2 else None,
                 message=parts[3] if len(parts) > 3 else None)
    return cid


def run_timetravel(ctx: Stage3Context, baseline_graph: Optional[nx.MultiDiGraph] = None,
                   baseline_commit: Optional[str] = None) -> dict:
    G = ctx.G
    snaps = light_snapshots(ctx)
    head_sha = G.graph.get("commit") or (snaps[0]["commit"] if snaps else None)
    base = baseline_commit or (snaps[-1]["commit"] if snaps else None)
    base_snap = next((s for s in snaps if base and s["commit"].startswith(base[:7])), snaps[-1] if snaps else None)
    head_snap = snaps[0] if snaps else None

    items: list[dict] = []
    known_unknowns: list[str] = []
    if baseline_graph is not None:
        mode = "full-graph"
        items = diff_graphs(baseline_graph, G)
    else:
        status = git_file_status(ctx, base) if base and ctx.source.is_git else None
        if status is not None:
            mode = "git-files"
            items = diff_from_git(ctx, status)
            modified = [p for p, s in status.items() if s == "M" and p.endswith(".py")]
            if modified:
                known_unknowns.append(f"{len(modified)} modified file(s) diffed at file level only "
                                      f"(new calls into new code are detected): {', '.join(sorted(modified)[:5])}")
        else:
            mode = "dependencies"
            known_unknowns.append("code-level diff unavailable: no baseline Stage 1–2 output and no git checkout")
    # packages always come from the dependency history (versions are exact there)
    items = [i for i in items if i["type"] != "Package"]
    if base_snap and head_snap and base_snap is not head_snap:
        items += diff_snapshots(base_snap, head_snap)

    # attribute every change to a commit and link it with CHANGED_IN
    history = {h.get("commit"): h for h in reversed(ctx.facts.get("dependency_history", []) or [])}
    pkg_commit: dict[str, tuple[str, dict]] = {}
    for sha, h in history.items():
        for a in h.get("added", []) or []:
            pkg_commit[normalize_name(strip_spec(str(a)))] = (sha, {"change": "added"})
        for c in h.get("changed", []) or []:
            pkg_commit[normalize_name(c.get("name", ""))] = (sha, {"change": "version", "from": c.get("from"), "to": c.get("to")})
    for it in items:
        sha = None
        if it["type"] == "Package":
            sha = (pkg_commit.get(it["id"]) or (None,))[0]
        elif ctx.source.is_git and base:
            path = None
            if it["kind"] == "node" and it["id"] in G:
                path = G.nodes[it["id"]].get("path") or G.nodes[it["id"]].get("file") or \
                       next((e.get("file") for e in G.nodes[it["id"]].get("evidence", []) if e.get("file")), None)
            elif it.get("evidence"):
                path = it["evidence"][0].get("file")
            sha = _introducing_commit(ctx, base, path)
        sha = sha or head_sha
        if sha:
            sha = next((h for h in history if h and (h.startswith(sha[:7]) or sha.startswith(h))), sha)
        it["commit"] = sha
        if not sha:
            continue
        target = it["id"] if it["kind"] == "node" else it.get("from")
        if it["type"] == "Package":
            target = next((p for p in nodes_of(G, "Package") if normalize_name(G.nodes[p].get("name", "")) == it["id"]), None)
        if target and target in G and it["op"] in ("+", "~"):
            cid = _ensure_commit(ctx, sha)
            G.nodes[target]["new_in_diff"] = True if it["op"] == "+" else G.nodes[target].get("new_in_diff", False)
            G.nodes[target]["changed_recently"] = True
            if G.nodes[target].get("type") in ("File", "Package", "Module", "Function", "ExternalService"):
                add_edge(G, target, cid, "CHANGED_IN", "git", [ev(commit=sha)], key=f"CHANGED_IN:{cid}",
                         change={"+": "added", "~": "changed"}[it["op"]], item=it["label"])

    # files touched by the last 5 dependency commits get eager cards
    for s in snaps[:5]:
        listed = ctx.source.git("show", "--name-only", "--format=", s["commit"]) if ctx.source.is_git else None
        for p in (listed.split() if listed else s.get("files_changed", [])):
            if f"file:{p}" in G:
                G.nodes[f"file:{p}"]["changed_recently"] = True

    commits = _commit_entries(G, snaps, items, base)
    summary = {
        "files_added": sum(1 for i in items if i["type"] == "File" and i["op"] == "+"),
        "files_modified": sum(1 for i in items if i["type"] == "File" and i["op"] == "~"),
        "files_removed": sum(1 for i in items if i["type"] == "File" and i["op"] == "-"),
        "modules_added": sum(1 for i in items if i["type"] == "Module" and i["op"] == "+"),
        "packages_added": sum(1 for i in items if i["type"] == "Package" and i["op"] == "+"),
        "packages_removed": sum(1 for i in items if i["type"] == "Package" and i["op"] == "-"),
        "packages_changed": sum(1 for i in items if i["type"] == "Package" and i["op"] == "~"),
        "relationships_added": sum(1 for i in items if i["kind"] == "edge" and i["op"] == "+"),
        "notable_relationships": sum(1 for i in items if i["kind"] == "edge" and i["op"] == "+" and i["category"] in ("network", "secret")),
    }
    items.sort(key=lambda i: (ITEM_PRIORITY.get(i["category"], 9), i["op"] != "+", i["label"]))
    result = {
        "mode": mode,
        "baseline": _commit_ref(base_snap, base),
        "head": _commit_ref(head_snap, head_sha),
        "items": items, "summary": summary, "commits": commits, "snapshots": snaps,
        "known_unknowns": known_unknowns,
    }
    G.graph["timetravel"] = {"mode": mode, "baseline": base, "head": head_sha}
    return result


def _commit_ref(snap: Optional[dict], sha: Optional[str]) -> dict:
    if snap:
        return {"commit": snap["commit"], "short": snap["short"], "date": snap.get("date"), "message": snap.get("message")}
    return {"commit": sha, "short": (sha or "")[:7], "date": None, "message": None}


def _commit_entries(G: nx.MultiDiGraph, snaps: list[dict], items: list[dict], base: Optional[str]) -> list[dict]:
    by_commit: dict[str, list[dict]] = {}
    shas = [s["commit"] for s in snaps]
    for it in items:
        c = it.get("commit")
        if c:
            c = next((s for s in shas if s[:7] == c[:7]), c)
            by_commit.setdefault(c, []).append(it)
    entries = []
    extra = [c for c in by_commit if c not in shas]
    for sha in extra + shas:
        snap = next((s for s in snaps if s["commit"] == sha), None)
        cnode = G.nodes.get(commit_id(sha), {})
        its = sorted(by_commit.get(sha, []), key=lambda i: (ITEM_PRIORITY.get(i["category"], 9), i["label"]))
        is_base = bool(base) and sha.startswith(base[:7]) and sha != shas[0] if shas else False
        cats = {i["category"] for i in its if i["op"] == "+"}
        if is_base:
            ctype = "baseline"
        elif cats & {"network", "module", "secret"}:
            ctype = "notable"
        elif any(i["type"] == "Package" for i in its):
            ctype = "dependency"
        else:
            ctype = "code"
        if is_base:
            h = snap or {}
            labels = [f"+ {k} {v or ''}".rstrip() for k, v in list((h.get("packages") or {}).items())[:6]]
        else:
            labels = [i["label"] for i in its if i["kind"] == "edge" or i["type"] not in ("Function", "Class")][:10]
        message = (snap or {}).get("message") or cnode.get("message") or ""
        entries.append({
            "commit": sha, "short": sha[:7], "date": (snap or {}).get("date") or cnode.get("date"),
            "author": (snap or {}).get("author") or cnode.get("author"), "message": message,
            "title": message.splitlines()[0] if message else f"Commit {sha[:7]}",
            "files_changed": (snap or {}).get("files_changed") or cnode.get("files_changed", []),
            "type": ctype, "items": labels, "item_count": len(its),
        })
    entries.sort(key=lambda e: str(e.get("date") or ""), reverse=True)
    return entries
