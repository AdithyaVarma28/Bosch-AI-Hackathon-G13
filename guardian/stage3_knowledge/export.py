"""Write Stage 3 output files, and the dashboard bundle the UI's **Import scan** accepts."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import networkx as nx

from .context import Stage3Context
from .graph_builder import nodes_of, succ
from .schema import Evidence, short_label
from .timetravel import fmt_date

OUTPUT_FILES = ("graph.json", "cards.json", "paths.json", "blast_radius.json", "changes.json", "findings.json",
                "coverage.json", "ui_bundle.json")
TAG_LABELS = {
    "entry_point": "entry point", "receives_user_input": "user input", "reads_secret_env": "secret access",
    "writes_db": "database write", "reads_db": "database read", "contacts_external": "external service",
    "network": "network", "deserialize": "deserialization", "code_exec": "code execution",
    "subprocess": "subprocess", "core": "core", "in_cycle": "dependency cycle",
    "tightly_coupled": "tightly coupled", "dynamic_import": "dynamic import", "file_write": "file write",
}


def _dump(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def graph_json(G: nx.MultiDiGraph) -> dict:
    return nx.node_link_data(G, edges="edges")


def graph_from_json(data: dict) -> nx.MultiDiGraph:
    return nx.node_link_graph(data, directed=True, multigraph=True, edges="edges")


def export_all(ctx: Stage3Context, coverage: dict) -> dict[str, Path]:
    out = Path(ctx.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "graph.json": graph_json(ctx.G),
        "cards.json": ctx.cards,
        "paths.json": ctx.paths,
        "blast_radius.json": ctx.blast,
        "changes.json": ctx.changes,
        "findings.json": ctx.findings,
        "coverage.json": coverage,
        "ui_bundle.json": ui_bundle(ctx, coverage),
    }
    written = {}
    for name, data in files.items():
        _dump(out / name, data)
        written[name] = out / name
    return written


# --------------------------------------------------------------------------- UI bundle

def _ev_labels(items, limit: int = 4) -> list[str]:
    out = []
    for e in items or []:
        lab = (e if isinstance(e, Evidence) else Evidence(**e)).label() if e else ""
        if lab and lab not in out:
            out.append(lab)
    return out[:limit]


def _module_color(G: nx.MultiDiGraph, m: str) -> str:
    d = G.nodes[m]
    tags = set(d.get("tags", []))
    if d.get("kind") == "tests":
        return "gray"
    if "entry_point" in tags:
        return "blue"
    if "contacts_external" in tags or "network" in tags:
        return "amber"
    has_tables = any(succ(G, f, "CONTAINS") and any(succ(G, c, "MAPS_TO") for c in succ(G, f, "CONTAINS"))
                     for f in succ(G, m, "CONTAINS"))
    if has_tables or tags & {"writes_db", "reads_db"}:
        return "teal"
    return "violet"


def _layout(G: nx.MultiDiGraph, mods: list[str]) -> dict[str, tuple[int, int]]:
    """Layered layout for the 740x330 SVG: callers left, dependencies right."""
    D = nx.DiGraph()
    D.add_nodes_from(mods)
    for u, v, d in G.edges(data=True):
        if d.get("type") == "DEPENDS_ON" and u in D and v in D:
            D.add_edge(u, v)
    C = nx.condensation(D)
    layer_of_comp: dict[int, int] = {}
    for comp in nx.topological_sort(C):
        preds = list(C.predecessors(comp))
        layer_of_comp[comp] = 1 + max(layer_of_comp[p] for p in preds) if preds else 0
    layers: dict[int, list[str]] = {}
    for comp, layer in layer_of_comp.items():
        layers.setdefault(layer, []).extend(sorted(C.nodes[comp]["members"]))
    n_layers = max(layers) + 1 if layers else 1
    step_x = min(200, (740 - 160) / max(1, n_layers - 1)) if n_layers > 1 else 0
    pos = {}
    for layer, members in layers.items():
        members.sort(key=lambda m: (G.nodes[m].get("kind") == "tests", G.nodes[m].get("name")))
        n = len(members)
        step_y = min(80, 255 / max(1, n - 1)) if n > 1 else 0
        top = 165 - (step_y * (n - 1)) / 2 - 30
        for i, m in enumerate(members):
            pos[m] = (int(15 + layer * step_x), int(max(5, top + i * step_y)))
    return pos


def _fmt_scanned(s: str | None) -> str:
    if not s:
        return ""
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).strftime("%b %d, %Y · %H:%M").replace(" 0", " ")
    except ValueError:
        return str(s)


def _finding_title(G: nx.MultiDiGraph, f: dict) -> tuple[str, str]:
    kind, subj = f.get("kind"), f.get("subject", "")
    name = G.nodes[subj].get("name") if subj in G else subj.split(":")[-1]
    if kind in ("outbound_data", "new_contact"):
        svc = next((G.nodes[s].get("name") for s in succ(G, subj, "CONTACTS")), "an external service")
        return f"{short_label(subj)} sends data to {svc}", "Network change" if f.get("notable") else "Outbound data"
    if kind == "declared_unused":
        unused = f["status"] == "resolved" and "No import" in f["answer"]
        return (f"{name} is declared but unused" if unused else f"{name} is referenced outside imports"), "Dependency question"
    if kind == "new_package":
        return f"New dependency {name}", "Dependency question"
    if kind == "new_module":
        return f"New module {G.nodes[subj].get('path', name) if subj in G else name}", "New module"
    if kind == "large_radius":
        return f"How {name} is used on public paths", "Blast radius"
    if kind == "tightly_coupled":
        a, _, b = subj.partition("|")
        return f"Coupling between {G.nodes.get(a, {}).get('name', a)} and {G.nodes.get(b, {}).get('name', b)}", "Structure"
    if kind == "undeclared_import":
        return f"Origin of {name.removeprefix('import:') if isinstance(name, str) else name}", "Dependency question"
    if kind == "dynamic_import":
        return "Dynamic import could not be resolved", "Known unknown"
    if kind == "low_confidence":
        return f"What {G.nodes[subj].get('path') or name if subj in G else name} does", "Low-confidence card"
    return f["question"], "Follow-up"


def ui_bundle(ctx: Stage3Context, coverage: dict) -> dict:
    G = ctx.G
    repo = G.nodes[nodes_of(G, "Repo")[0]] if nodes_of(G, "Repo") else {}
    repo_card = repo.get("card") or {}
    mods = sorted(nodes_of(G, "Module"), key=lambda m: G.nodes[m].get("name", ""))
    pos = _layout(G, mods)
    counts = coverage["counts"]

    modules = []
    for m in mods:
        d = G.nodes[m]
        card = d.get("card") or {}
        tags = [TAG_LABELS[t] for t in d.get("tags", []) if t in TAG_LABELS]
        if d.get("kind") == "tests":
            tags = ["test code"] + tags
        if any(G.nodes[f].get("changed_recently") and G.nodes[f].get("new_in_diff") for f in succ(G, m, "CONTAINS")):
            tags.append("recently changed")
        fns = [c for f in succ(G, m, "CONTAINS") for c in succ(G, f, "CONTAINS")
               if G.nodes[c].get("type") == "Function" and not G.nodes[c].get("module_level")]
        x, y = pos.get(m, (20, 20))
        modules.append({
            "id": m, "name": d.get("name"), "path": d.get("path"), "files": len(d.get("files", [])),
            "functions": len(fns), "purpose": card.get("purpose", ""), "tags": list(dict.fromkeys(tags))[:6],
            "evidence": (_ev_labels(card.get("evidence")) or [d.get("path")])[0],
            "confidence": card.get("confidence", 0), "x": x, "y": y, "color": _module_color(G, m),
            "sensitivity": card.get("sensitivity"), "discovered_by": card.get("discovered_by"),
        })
    name_of = {m: G.nodes[m].get("name") for m in mods}
    edges = [{"from": name_of[u], "to": name_of[v], "weight": d.get("weight", 1)}
             for u, v, d in G.edges(data=True) if d.get("type") == "DEPENDS_ON" and u in name_of and v in name_of]

    paths = []
    for p in ctx.paths:
        labels = list(dict.fromkeys(s["label"] for s in p.get("sink_details", [])))
        kind = "network" if any(s["id"].startswith("svc:") and G.nodes.get(s["id"], {}).get("via") == "url"
                                 for s in p.get("sink_details", [])) else \
            "external" if any(s["id"].startswith("svc:") for s in p.get("sink_details", [])) else \
            "data" if any(s["id"].startswith("table:") for s in p.get("sink_details", [])) else "internal"
        paths.append({
            "entry": p["entry"].split(":", 1)[1], "input": p.get("input") or "—",
            "handler": short_label(p["steps"][0]), "steps": [short_label(s) for s in p["steps"]],
            "sinks": labels, "evidence": _ev_labels(p.get("evidence"), 8), "confidence": p.get("confidence", 1.0),
            "kind": kind, "id": p["id"],
        })

    packages = []
    for pid, br in sorted(ctx.blast.items(), key=lambda kv: (not kv[1]["direct"], kv[1]["name"].lower())):
        if not br["direct"]:
            continue
        d = G.nodes[pid]
        nearby = [s[4:] for s in br["secrets_nearby"]] + [t[6:] + " table" for t in br["tables_nearby"]] + \
                 [G.nodes[s].get("name", s) for s in br["services_nearby"]]
        decl = _ev_labels(d.get("evidence"), 1)
        packages.append({
            "name": br["name"], "version": br.get("version") or "?", "direct": True, "used": br["files"] > 0,
            "radius": br["radius"], "files": br["files"], "functions": [short_label(f) for f in br["functions"]][:6],
            "routes": [r.split(":", 1)[1] for r in br["routes_reaching"]], "nearby": nearby,
            "apiCalls": br["api_calls"][:6], "reasons": br["reasons"],
            "evidence": ", ".join(_ev_labels(br.get("evidence"), 2)) or (decl[0] if decl else ""),
            "confidence": 1.0, "scope": d.get("scope"), "dev": d.get("dev"), "tags": d.get("tags", []),
        })

    changes = []
    for c in ctx.changes.get("commits", []):
        detail = f"{c['item_count']} change(s) since the previous snapshot" if c["type"] != "baseline" else \
            "Baseline snapshot for the comparison."
        changes.append({"date": fmt_date(c.get("date")), "commit": c["short"], "title": c["title"],
                        "detail": detail, "type": c["type"] if c["type"] in ("notable", "dependency", "baseline") else "dependency",
                        "items": c["items"] or ["(no tracked changes)"]})

    findings = []
    for f in ctx.findings:
        title, category = _finding_title(G, f)
        findings.append({
            "title": title, "severity": "notable" if f["notable"] else ("review" if f["status"] == "unresolved" else "info"),
            "status": f["status"], "text": f["answer"], "evidence": _ev_labels(f["evidence"], 6) or ["(no verified evidence)"],
            "confidence": f["confidence"], "category": category, "steps": f["steps_used"], "question": f["question"],
            "notableReason": f.get("notable_reason"), "discoveredBy": f.get("discovered_by"),
        })
    findings.sort(key=lambda x: ({"notable": 0, "review": 1, "info": 2}[x["severity"]], -x["confidence"]))

    q = coverage["questions"]
    frameworks = sorted({G.nodes[r].get("framework") for r in nodes_of(G, "Route") if G.nodes[r].get("framework")})
    summ = ctx.changes.get("summary", {})
    return {
        "repo": {
            "name": repo.get("name"), "language": "Python", "branch": repo.get("branch") or "—",
            "commit": (G.graph.get("commit") or "")[:7], "scannedAt": _fmt_scanned(repo.get("scanned_at")),
            "summary": repo_card.get("purpose", ""), "files": counts["files"], "functions": counts["functions"],
            "routes": len(nodes_of(G, "Route")), "packages": sum(1 for p in nodes_of(G, "Package") if G.nodes[p].get("direct")),
            "modules": len(mods), "commitLabel": (G.graph.get("commit") or "")[:7],
            "tags": [f"{fw.capitalize()} app" for fw in frameworks] +
                    (["External services"] if nodes_of(G, "ExternalService") else []) +
                    (["Database"] if nodes_of(G, "Table") else []),
            "baselineLabel": fmt_date((ctx.changes.get("baseline") or {}).get("date")) or (ctx.changes.get("baseline") or {}).get("short"),
            "changeSummary": {"commits": len(ctx.changes.get("commits", [])), "filesAdded": summ.get("files_added", 0),
                              "packagesChanged": summ.get("packages_added", 0) + summ.get("packages_changed", 0) + summ.get("packages_removed", 0),
                              "notableRelationships": summ.get("notable_relationships", 0)},
        },
        "coverage": {
            "files": {"parsed": counts["parsed"], "total": counts["files"]},
            "calls": {"resolved": counts["calls_resolved"], "total": counts["calls_total"]},
            "modules": {"carded": coverage["modules_carded"], "total": coverage["modules"]},
            "filesCarded": {"carded": counts["files_carded"], "total": counts["file_nodes"]},
            "questions": {"resolved": q["resolved"], "total": q["resolved"] + q["unresolved"]},
            "knownUnknowns": coverage["known_unknowns"],
        },
        "modules": modules, "edges": edges, "paths": paths, "packages": packages, "changes": changes,
        "findings": findings,
    }
