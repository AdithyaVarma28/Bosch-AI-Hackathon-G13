"""FastAPI over one Stage 3 output folder (spec section 9), plus the static dashboard.

    python -m guardian.cli serve output/mini-shop      # then open http://127.0.0.1:8000/
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .context import Stage3Context
from .export import graph_from_json
from .graph_builder import load_json, nodes_of, pred, succ
from .flow import get_paths
from .llm import LLM
from .semantic import ensure_card
from .sources import RepoSource
from .timetravel import diff_snapshots

UI_DIR = Path(__file__).resolve().parents[2] / "ui"
NODE_KEYS_LIGHT = ("id", "type", "name", "path", "qualname", "file", "line", "end_line", "version", "direct", "tags",
                   "centrality", "kind", "method", "framework", "via", "scope", "notable", "new_in_diff")


def load_context(output_dir: str | Path, llm_provider: Optional[str] = "offline") -> Stage3Context:
    out = Path(output_dir)
    data = load_json(out / "graph.json")
    if data is None:
        raise FileNotFoundError(f"{out / 'graph.json'} not found: run Stage 3 first")
    G = graph_from_json(data)
    input_dir = Path(G.graph.get("input_dir") or out)
    ctx = Stage3Context(
        G=G, facts=load_json(input_dir / "facts.json") or {}, code_index=load_json(input_dir / "code_index.json") or {},
        llm=LLM(provider=llm_provider, cache_dir=out / ".llm_cache"), source=RepoSource(G.graph.get("repo_path")),
        output_dir=out,
    )
    ctx.cards = load_json(out / "cards.json") or {}
    ctx.paths = load_json(out / "paths.json") or []
    ctx.blast = load_json(out / "blast_radius.json") or {}
    ctx.changes = load_json(out / "changes.json") or {}
    ctx.findings = load_json(out / "findings.json") or []
    return ctx


def create_app(output_dir: str | Path, llm_provider: Optional[str] = "offline"):
    from fastapi import FastAPI, HTTPException, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import RedirectResponse
    from fastapi.staticfiles import StaticFiles

    out = Path(output_dir)
    ctx = load_context(out, llm_provider)
    G = ctx.G
    app = FastAPI(title="Guardian · Stage 3 knowledge graph", version="1.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"])

    def light(n: str) -> dict:
        d = G.nodes[n]
        res = {k: d[k] for k in NODE_KEYS_LIGHT if d.get(k) not in (None, "", [])}
        res["id"] = n
        if d.get("card"):
            res["purpose"] = d["card"].get("purpose")
            res["sensitivity"] = d["card"].get("sensitivity")
        return res

    def edge_list(nodes: set[str], types: Optional[set[str]] = None) -> list[dict]:
        return [{"source": u, "target": v, "type": d.get("type"), "weight": d.get("weight", 1),
                 "evidence": d.get("evidence", [])[:2], "discovered_by": d.get("discovered_by")}
                for u, v, d in G.edges(data=True) if u in nodes and v in nodes and (not types or d.get("type") in types)]

    @app.get("/graph")
    def graph(level: str = Query("repo", pattern="^(repo|module)$"), id: Optional[str] = None):
        if level == "repo":
            mods = set(nodes_of(G, "Module"))
            return {"level": "repo", "nodes": [light(m) for m in sorted(mods)], "edges": edge_list(mods, {"DEPENDS_ON"})}
        if not id or id not in G or G.nodes[id].get("type") != "Module":
            raise HTTPException(404, f"module {id!r} not found")
        files = succ(G, id, "CONTAINS")
        fns = [c for f in files for c in succ(G, f, "CONTAINS")]
        related: set[str] = set(files) | set(fns)
        for f in files:
            related.update(succ(G, f, "USES_PACKAGE"))
        for fn in fns:
            related.update(succ(G, fn, "READS_ENV", "READS", "WRITES", "CONTACTS", "CALLS_API", "MAPS_TO"))
            related.update(pred(G, fn, "HANDLES"))
        return {"level": "module", "id": id, "module": light(id), "nodes": [light(n) for n in sorted(related)],
                "edges": edge_list(related)}

    @app.get("/node/{node_id:path}")
    def node(node_id: str):
        if node_id not in G:
            raise HTTPException(404, f"node {node_id!r} not found")
        d = dict(G.nodes[node_id])
        card = ensure_card(ctx, node_id)          # lazy card for files that were not carded eagerly
        findings = [f for f in ctx.findings if f["id"] in (d.get("findings") or []) or node_id in f["subject"].split("|")]
        return {"node": {k: v for k, v in d.items() if k != "card"}, "card": card, "findings": findings,
                "out": [{"type": e.get("type"), "target": v, "evidence": e.get("evidence", [])[:2]}
                        for _, v, e in G.out_edges(node_id, data=True)],
                "in": [{"type": e.get("type"), "source": u, "evidence": e.get("evidence", [])[:2]}
                       for u, _, e in G.in_edges(node_id, data=True)],
                "blast_radius": ctx.blast.get(node_id)}

    @app.get("/paths")
    def paths(entry: Optional[str] = None, sink: Optional[str] = None):
        return {"paths": get_paths(ctx.paths, entry, sink)}

    @app.get("/blast-radius/{purl:path}")
    def blast(purl: str):
        br = ctx.blast.get(purl) or next((v for k, v in ctx.blast.items() if v["name"].lower() == purl.lower()
                                          or k.split("@")[0] == purl), None)
        if not br:
            raise HTTPException(404, f"package {purl!r} not found")
        return br

    @app.get("/diff")
    def diff(from_: Optional[str] = Query(None, alias="from"), to: Optional[str] = None):
        ch = ctx.changes
        base, head = (ch.get("baseline") or {}).get("commit") or "", (ch.get("head") or {}).get("commit") or ""
        if (not from_ or base.startswith(from_[:7])) and (not to or head.startswith(to[:7])):
            return {"from": ch.get("baseline"), "to": ch.get("head"), "mode": ch.get("mode"), "items": ch.get("items", []),
                    "summary": ch.get("summary"), "commits": ch.get("commits", [])}
        snaps = {s["commit"][:7]: s for s in ch.get("snapshots", [])}
        a, b = snaps.get((from_ or "")[:7]), snaps.get((to or "")[:7])
        if not a or not b:
            raise HTTPException(404, f"no snapshot for {from_ if not a else to}; known: {sorted(snaps)}")
        return {"from": a["commit"], "to": b["commit"], "mode": "dependencies", "items": diff_snapshots(a, b)}

    @app.get("/coverage")
    def coverage():
        return load_json(out / "coverage.json") or {}

    @app.get("/cards")
    def cards():
        return ctx.cards

    @app.get("/findings")
    def findings(notable: Optional[bool] = None, status: Optional[str] = None):
        res = ctx.findings
        if notable is not None:
            res = [f for f in res if f["notable"] == notable]
        if status:
            res = [f for f in res if f["status"] == status]
        return res

    @app.get("/ui-bundle")
    def ui_bundle():
        from guardian.webapp.dashboard import build_dashboard   # ui_bundle.json + stack, SBOM, security, explorer
        bundle = build_dashboard(out)
        vf = out / "vuln_findings.json"
        if vf.exists():   # live review status (decisions made after the scan)
            from guardian.stage4_vulns.report import bundle_entry
            bundle = {**bundle, "vulnerabilities": [bundle_entry(c) for c in json.loads(vf.read_text(encoding="utf-8"))]}
        return bundle

    @app.get("/source/{path:path}")
    def source(path: str, start: int = 1, end: Optional[int] = None):
        """Lines of a scanned source file (the dashboard shows a function's code)."""
        if not ctx.source.available:
            raise HTTPException(404, "repository source is not available to this scan")
        try:
            return {"path": path, "start": start, "lines": [t for _, t in ctx.source.read_lines(path, start, end)]}
        except (FileNotFoundError, ValueError, OSError) as exc:
            raise HTTPException(404, str(exc))

    try:  # Stage 4 endpoints: /vulns, /vulns/{id}, /review/{id}, /blast-radius with vulnerabilities
        from guardian.stage4_vulns.api import attach as attach_stage4
        attach_stage4(app, out, ctx)
    except ImportError:  # pragma: no cover
        pass

    if UI_DIR.exists():
        app.mount("/ui", StaticFiles(directory=UI_DIR, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        def root():
            return RedirectResponse("/ui/")

    return app
