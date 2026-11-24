"""Stage 6 backend: every stage's data behind one ``/api`` prefix, plus the React app (web/dist).

    guardian web --root output/scans      # then open http://127.0.0.1:8000/
"""
from __future__ import annotations

import asyncio
import json
import queue
import re
from pathlib import Path
from typing import Optional

from guardian.stage3_knowledge.graph_builder import nodes_of, pred, succ
from guardian.stage3_knowledge.schema import short_label

from pydantic import BaseModel

from guardian.stage4_vulns.schema import ReviewDecision

from .store import ScanStore, _read


class ScanRequest(BaseModel):
    path: str
    offline: bool = False
    llm: str = "auto"
    label: Optional[str] = None

WEB_DIST = Path(__file__).resolve().parents[2] / "web" / "dist"
UI_DIR = Path(__file__).resolve().parents[2] / "ui"
RISK_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}
LIGHT_KEYS = ("id", "type", "name", "path", "qualname", "file", "line", "end_line", "version", "direct", "tags", "kind",
              "method", "framework", "scope", "notable", "new_in_diff", "module", "ref", "uses", "sha", "date", "message",
              "project_risk", "suspicion", "cvss", "band")


def unified_row(c: dict) -> dict:
    vuln = c.get("type") == "vulnerability"
    return {
        "finding_id": c["finding_id"], "type": c["type"], "title": c["title"], "component": c["component"],
        "component_name": c.get("component_name"), "project_risk": c["project_risk"],
        "severity": c.get("severity") if vuln else None, "suspicion": None if vuln else c.get("suspicion"),
        "confidence": c["confidence"], "usage": c.get("usage"), "reachability": c.get("reachability"),
        "exposure": c.get("exposure"), "review_status": (c.get("review") or {}).get("status"),
        "scope": c.get("scope") or ("container" if str(c.get("component", "")).startswith("image:") else
                                    "ci" if str(c.get("component", "")).startswith("workflow:") else "runtime"),
        "detectors": c.get("detectors"), "vuln_id": c.get("vuln_id"), "commit": c.get("commit"),
        "new_in_last_diff": bool(c.get("commit")),
    }


class ScanData:
    """Lazy, cached view of one snapshot folder."""

    def __init__(self, d: Path):
        self.d = d
        self._ctx = None
        self._mtime = None

    @property
    def ctx(self):
        gp = self.d / "graph.json"
        mt = gp.stat().st_mtime if gp.exists() else None
        if self._ctx is None or mt != self._mtime:
            from guardian.stage3_knowledge.api import load_context
            self._ctx, self._mtime = load_context(self.d), mt
        return self._ctx

    def cards(self) -> list[dict]:
        cards = (_read(self.d / "vuln_findings.json", []) or []) + (_read(self.d / "anomaly_findings.json", []) or [])
        return sorted(cards, key=lambda c: (-RISK_ORDER.get(c["project_risk"], 0),
                                            -{"high": 2, "medium": 1, "low": 0}.get(c["confidence"], 0), c["finding_id"]))

    def trace(self, fid: str) -> list[dict]:
        f = "vuln_traces.json" if fid.startswith("F-") else "anomaly_traces.json"
        return (_read(self.d / f, {}) or {}).get(fid, [])


def create_web_app(root: str | Path):
    from fastapi import FastAPI, HTTPException, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
    from guardian.stage4_vulns.review import ReviewError, submit_review

    store = ScanStore(Path(root))
    cache: dict[str, ScanData] = {}
    app = FastAPI(title="Guardian API", version="1.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"])

    def data(scan_id: str) -> ScanData:
        try:
            d = store.dir(scan_id)
        except KeyError:
            raise HTTPException(404, f"scan {scan_id!r} not found")
        if scan_id not in cache or cache[scan_id].d != d:
            cache[scan_id] = ScanData(d)
        return cache[scan_id]

    def ready(scan_id: str) -> ScanData:
        sd = data(scan_id)
        if not (sd.d / "graph.json").exists():
            raise HTTPException(409, "scan has no knowledge graph yet")
        return sd

    def light(G, n: str) -> dict:
        d = G.nodes[n]
        res = {k: d[k] for k in LIGHT_KEYS if d.get(k) not in (None, "", [])}
        res["id"], res["label"] = n, entity_label(G, n)
        if d.get("card"):
            res["purpose"], res["sensitivity"] = d["card"].get("purpose"), d["card"].get("sensitivity")
        return res

    # ------------------------------------------------------------------ scans
    @app.get("/api/scans")
    def scans():
        return store.list()

    @app.post("/api/scans")
    def start_scan(req: ScanRequest):
        try:
            sid = store.start(req.path, offline=req.offline, llm=req.llm, label=req.label)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return {"scan_id": sid}

    @app.get("/api/scans/{scan_id}")
    def scan_meta(scan_id: str):
        data(scan_id)
        return store.meta(scan_id)

    @app.get("/api/scans/{scan_id}/progress/events")
    async def progress(scan_id: str):
        data(scan_id)
        q = store.subscribe(scan_id)
        past = store.events(scan_id)

        async def gen():
            try:
                for e in past:
                    yield f"data: {json.dumps(e, default=str)}\n\n"
                if any(e.get("type") == "done" for e in past) or store.meta(scan_id).get("status") in ("done", "failed"):
                    yield "data: {\"type\": \"end\"}\n\n"
                    return
                while True:
                    try:
                        e = await asyncio.to_thread(q.get, True, 15)
                    except queue.Empty:
                        yield ": keep-alive\n\n"
                        continue
                    yield f"data: {json.dumps(e, default=str)}\n\n"
                    if e.get("type") == "done":
                        yield "data: {\"type\": \"end\"}\n\n"
                        return
            finally:
                store.unsubscribe(scan_id, q)

        return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    @app.get("/api/scans/{scan_id}/events")
    def events(scan_id: str, tail: Optional[int] = None, types: Optional[str] = None):
        data(scan_id)
        evs = store.events(scan_id)
        if types:
            evs = [e for e in evs if e.get("type") in types.split(",")]
        return evs[-tail:] if tail else evs

    @app.get("/api/scans/{scan_id}/dashboard")
    def dashboard(scan_id: str):
        """Everything the ui/ dashboard shows for one scan (see guardian/webapp/dashboard.py)."""
        from .dashboard import build_dashboard
        sd = ready(scan_id)
        return build_dashboard(sd.d, store.meta(scan_id))

    # ------------------------------------------------------------------ overview
    @app.get("/api/scans/{scan_id}/overview")
    def overview(scan_id: str):
        sd = ready(scan_id)
        ctx, G = sd.ctx, sd.ctx.G
        cards = sd.cards()
        repo = G.nodes[nodes_of(G, "Repo")[0]] if nodes_of(G, "Repo") else {}
        pk = nodes_of(G, "Package")
        summ = ctx.changes.get("summary", {})
        cov = _read(sd.d / "coverage.json", {}) or {}
        top_components: dict[str, dict] = {}
        for c in cards:
            t = top_components.setdefault(c["component"], {"component": c["component"], "name": c.get("component_name"),
                                                           "risk": "low", "vulns": 0, "anomalies": 0,
                                                           "radius": (ctx.blast.get(c["component"]) or {}).get("radius")})
            t["vulns" if c["type"] == "vulnerability" else "anomalies"] += 1
            if RISK_ORDER[c["project_risk"]] > RISK_ORDER[t["risk"]]:
                t["risk"] = c["project_risk"]
        counts = cov.get("counts", {})
        return {
            "scan": store.meta(scan_id),
            "repo": {"name": repo.get("name"), "branch": repo.get("branch"), "commit": (G.graph.get("commit") or "")[:7],
                     "purpose": (repo.get("card") or {}).get("purpose"), "scanned_at": repo.get("scanned_at")},
            "whats_in_it": {"modules": len(nodes_of(G, "Module")), "files": counts.get("files"),
                            "functions": counts.get("functions"),
                            "packages_direct": sum(1 for p in pk if G.nodes[p].get("direct")),
                            "packages_transitive": sum(1 for p in pk if not G.nodes[p].get("direct")),
                            "routes": [light(G, r) for r in sorted(nodes_of(G, "Route"))],
                            "services": [light(G, s) for s in sorted(nodes_of(G, "ExternalService"))],
                            "tables": [light(G, t) for t in sorted(nodes_of(G, "Table"))]},
            "what_changed": {"baseline": ctx.changes.get("baseline"), "head": ctx.changes.get("head"),
                             "summary": {**summ, "commits": len(ctx.changes.get("commits") or [])},
                             "items": (ctx.changes.get("items") or [])[:12]},
            "what_looks_risky": {"by_risk": {r: sum(1 for c in cards if c["project_risk"] == r) for r in RISK_ORDER},
                                 "pending_reviews": sum(1 for c in cards if (c.get("review") or {}).get("status") == "pending"),
                                 "top": [unified_row(c) for c in cards[:5]]},
            "top_components": sorted(top_components.values(), key=lambda t: (-RISK_ORDER[t["risk"]], -(t["vulns"] + t["anomalies"])))[:8],
            "coverage": {"calls_resolved": counts.get("calls_resolved"), "calls_total": counts.get("calls_total"),
                         "files_parsed": counts.get("parsed"), "files": counts.get("files"),
                         "known_unknowns": len(cov.get("known_unknowns", []) or [])},
        }

    # ------------------------------------------------------------------ graph + entities
    @app.get("/api/scans/{scan_id}/graph")
    def graph(scan_id: str, level: str = Query("repo", pattern="^(repo|module)$"), id: Optional[str] = None):
        sd = ready(scan_id)
        G = sd.ctx.G
        risk_of = {}
        for c in sd.cards():
            for n in [c["component"]] + [s["function"] for s in c.get("usage_sites", [])]:
                if RISK_ORDER[c["project_risk"]] > RISK_ORDER.get(risk_of.get(n, "low"), -1) or n not in risk_of:
                    risk_of[n] = c["project_risk"]

        def module_risk(m):
            best = None
            for f in succ(G, m, "CONTAINS"):
                for n in [f] + succ(G, f, "CONTAINS") + succ(G, f, "USES_PACKAGE"):
                    r = risk_of.get(n)
                    if r and (best is None or RISK_ORDER[r] > RISK_ORDER[best]):
                        best = r
            return best

        if level == "repo":
            mods = sorted(nodes_of(G, "Module"))
            nodes = [{**light(G, m), "files": len(G.nodes[m].get("files", [])), "risk": module_risk(m),
                      "changed": any(G.nodes[f].get("new_in_diff") or G.nodes[f].get("changed_recently") for f in succ(G, m, "CONTAINS"))}
                     for m in mods]
            extra = set()
            for m in mods:
                for f in succ(G, m, "CONTAINS"):
                    for fn in succ(G, f, "CONTAINS"):
                        extra.update(succ(G, fn, "CONTACTS", "WRITES", "READS"))
                        extra.update(pred(G, fn, "HANDLES"))
            side = [{**light(G, n), "risk": risk_of.get(n)} for n in sorted(extra)]
            edges = [{"source": u, "target": v, "type": d.get("type"), "weight": d.get("weight", 1)}
                     for u, v, d in G.edges(data=True) if d.get("type") == "DEPENDS_ON" and u in mods and v in mods]
            mod_of = {}
            for m in mods:
                for f in succ(G, m, "CONTAINS"):
                    for fn in succ(G, f, "CONTAINS"):
                        mod_of[fn] = m
            for u, v, d in G.edges(data=True):
                if d.get("type") in ("CONTACTS", "WRITES", "READS") and u in mod_of and v in extra:
                    edges.append({"source": mod_of[u], "target": v, "type": d["type"], "weight": 1})
                if d.get("type") == "HANDLES" and v in mod_of and u in extra:
                    edges.append({"source": u, "target": mod_of[v], "type": "HANDLES", "weight": 1})
            seen, uniq = set(), []
            for e in edges:
                k = (e["source"], e["target"], e["type"])
                if k not in seen:
                    seen.add(k)
                    uniq.append(e)
            return {"level": "repo", "nodes": nodes + side, "edges": uniq}
        if not id or id not in G:
            raise HTTPException(404, f"module {id!r} not found")
        files = succ(G, id, "CONTAINS")
        fns = [c for f in files for c in succ(G, f, "CONTAINS")]
        rel = set(files) | set(fns)
        for f in files:
            rel.update(succ(G, f, "USES_PACKAGE"))
        for fn in fns:
            rel.update(succ(G, fn, "READS_ENV", "WRITES", "READS", "CONTACTS", "CALLS"))
            rel.update(pred(G, fn, "HANDLES"))
        rel = set(list(rel)[:120])
        return {"level": "module", "id": id, "nodes": [{**light(G, n), "risk": risk_of.get(n), "parent": next(
            (f for f in files if n in succ(G, f, "CONTAINS")), None)} for n in sorted(rel)],
                "edges": [{"source": u, "target": v, "type": d.get("type"), "weight": d.get("weight", 1)}
                          for u, v, d in G.edges(data=True) if u in rel and v in rel and d.get("type") != "CONTAINS"]}

    @app.get("/api/scans/{scan_id}/entity/{entity_id:path}")
    def entity(scan_id: str, entity_id: str):
        sd = ready(scan_id)
        ctx, G = sd.ctx, sd.ctx.G
        if entity_id not in G:
            raise HTTPException(404, f"entity {entity_id!r} not found")
        d = G.nodes[entity_id]
        from guardian.stage3_knowledge.semantic import ensure_card
        card = ensure_card(ctx, entity_id) if d.get("type") in ("Module", "File", "Repo") else d.get("card")
        cards = [unified_row(c) for c in sd.cards() if c["component"] == entity_id or entity_id in
                 [s.get("function") for s in c.get("usage_sites", [])] or entity_id == f"file:{(c.get('component') or '')[5:]}"]
        def edges(direction):
            es = G.out_edges(entity_id, data=True) if direction == "out" else G.in_edges(entity_id, data=True)
            out = []
            for u, v, e in list(es)[:80]:
                other = v if direction == "out" else u
                out.append({"type": e.get("type"), "node": other, "label": entity_label(G, other),
                            "node_type": G.nodes[other].get("type"), "evidence": e.get("evidence", [])[:2]})
            return out
        return {"entity": {**{k: v for k, v in d.items() if k not in ("card",) and not isinstance(v, (dict,)) or k in ("blast_radius",)},
                           "label": entity_label(G, entity_id)},
                "card": card, "out": edges("out"), "in": edges("in"), "findings": cards,
                "stage3_findings": [f for f in ctx.findings if entity_id in f["subject"].split("|")],
                "blast_radius": ctx.blast.get(entity_id),
                "paths": [p for p in ctx.paths if entity_id in p["steps"] or p["entry"] == entity_id][:10]}

    # ------------------------------------------------------------------ findings + review
    @app.get("/api/scans/{scan_id}/findings")
    def findings(scan_id: str, risk: Optional[str] = None, type: Optional[str] = None, review: Optional[str] = None,
                 confidence: Optional[str] = None, scope: Optional[str] = None):
        rows = [unified_row(c) for c in data(scan_id).cards()]
        for key, val in (("project_risk", risk), ("type", type), ("review_status", review), ("confidence", confidence), ("scope", scope)):
            if val:
                rows = [r for r in rows if r.get(key) in val.split(",")]
        return rows

    @app.get("/api/scans/{scan_id}/findings/{finding_id}")
    def finding(scan_id: str, finding_id: str):
        sd = data(scan_id)
        card = next((c for c in sd.cards() if c["finding_id"] == finding_id), None)
        if not card:
            raise HTTPException(404, f"finding {finding_id!r} not found")
        snippets = {}
        src = sd.ctx.source if (sd.d / "graph.json").exists() else None
        for e in card.get("evidence", []):
            f, lines = e.get("file"), e.get("lines")
            if not f or not lines or f.startswith("pkg:") or not src or not src.available:
                continue
            m = re.match(r"(\d+)(?:-(\d+))?", str(lines))
            if m:
                a, b = int(m.group(1)), int(m.group(2) or m.group(1))
                try:
                    snippets[f"{f}:{lines}"] = {"file": f, "start": max(1, a - 3), "highlight": [a, b],
                                                "lines": [t for _, t in src.read_lines(f, max(1, a - 3), b + 3)]}
                except Exception:
                    continue
        for e in card.get("evidence", []):
            f = e.get("file") or ""
            mm = re.match(r"^pkg:([^@]+)@([^/]+)/(.+)$", f)
            if mm and e.get("lines"):
                sb = sd.d / ".sandbox"
                for cand in sb.glob(f"*-{mm.group(2)}-*") if sb.exists() else []:
                    p = cand / mm.group(3)
                    if p.exists():
                        a, b = (int(x) for x in (str(e["lines"]).split("-") + [str(e["lines"])])[:2])
                        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                        snippets[f"{f}:{e['lines']}"] = {"file": f, "start": max(1, a - 3), "highlight": [a, b],
                                                         "lines": lines[max(0, a - 4): b + 3]}
                        break
        return {"card": card, "row": unified_row(card), "trace": sd.trace(finding_id), "snippets": snippets}

    @app.post("/api/scans/{scan_id}/review/{finding_id}")
    def review(scan_id: str, finding_id: str, decision: ReviewDecision):
        sd = data(scan_id)
        f = "vuln_findings.json" if finding_id.startswith("F-") else "anomaly_findings.json"
        try:
            return submit_review(sd.d, f, finding_id, decision)
        except ReviewError as exc:
            raise HTTPException(422, str(exc))
        except KeyError:
            raise HTTPException(404, f"finding {finding_id!r} not found")

    @app.get("/api/scans/{scan_id}/review")
    def review_queue(scan_id: str):
        return [unified_row(c) | {"reasons": (c.get("review") or {}).get("reasons", [])}
                for c in data(scan_id).cards() if (c.get("review") or {}).get("status") == "pending"]

    # ------------------------------------------------------------------ changes, flows, packages, files
    @app.get("/api/scans/{scan_id}/changes")
    def changes(scan_id: str):
        return ready(scan_id).ctx.changes

    @app.get("/api/compare")
    def compare(from_: str = Query(..., alias="from"), to: str = Query(...)):
        a, b = ready(from_), ready(to)
        return compare_snapshots(a, b)

    @app.get("/api/scans/{scan_id}/flows")
    def flows(scan_id: str):
        sd = ready(scan_id)
        G = sd.ctx.G
        cards = sd.cards()
        vuln_fns = {s["function"]: c["finding_id"] for c in cards for s in c.get("usage_sites", [])}
        out = []
        for p in sd.ctx.paths:
            out.append({**p, "entry_label": p["entry"].split(":", 1)[1], "step_labels": [short_label(s) for s in p["steps"]],
                        "vuln_sites": {s: vuln_fns[s] for s in p["steps"] if s in vuln_fns}})
        return out

    @app.get("/api/scans/{scan_id}/packages")
    def packages(scan_id: str):
        sd = ready(scan_id)
        G, blast = sd.ctx.G, sd.ctx.blast
        cards = sd.cards()
        out = []
        for p in sorted(nodes_of(G, "Package")):
            d = G.nodes[p]
            mine = [c for c in cards if c["component"] == p]
            out.append({"purl": p, "name": d.get("name"), "version": d.get("version") or d.get("checked_version"),
                        "direct": bool(d.get("direct")), "scope": "dev" if d.get("dev") else "runtime",
                        "used_by": len(d.get("used_by_files") or []), "radius": (blast.get(p) or {}).get("radius"),
                        "vulns": sum(1 for c in mine if c["type"] == "vulnerability"),
                        "anomalies": sum(1 for c in mine if c["type"] == "anomaly"),
                        "max_cvss": max((c["severity"]["cvss"] or 0 for c in mine if c["type"] == "vulnerability"), default=None),
                        "risk": max((c["project_risk"] for c in mine), key=lambda r: RISK_ORDER[r], default=None),
                        "tags": d.get("tags", []), "declared_at": [e for e in d.get("evidence", []) if e.get("file")][:1],
                        "required_by": sorted(set(pred(G, p, "REQUIRES")))})
        return out

    @app.get("/api/scans/{scan_id}/files/{path:path}")
    def file_view(scan_id: str, path: str):
        sd = ready(scan_id)
        G, src = sd.ctx.G, sd.ctx.source
        fid = f"file:{path}"
        if fid not in G:
            raise HTTPException(404, f"file {path!r} not in the scan")
        try:
            text = [t for _, t in src.read_lines(path)] if src.available else []
        except Exception as exc:
            text, err = [], str(exc)
        markers = []
        for _, v, e in G.out_edges(fid, data=True):
            if e.get("type") == "USES_PACKAGE":
                for ev in e.get("evidence", [])[:1]:
                    markers.append({"line": ev.get("line"), "kind": "import", "target": v, "label": entity_label(G, v)})
        for fn in succ(G, fid, "CONTAINS"):
            for _, v, e in G.out_edges(fn, data=True):
                kind = {"READS_ENV": "env", "WRITES": "db_write", "CONTACTS": "network", "CALLS_API": "api"}.get(e.get("type"))
                if kind:
                    for ev in e.get("evidence", [])[:1]:
                        markers.append({"line": ev.get("line"), "kind": kind, "target": v, "label": entity_label(G, v)})
            for r in pred(G, fn, "HANDLES"):
                markers.append({"line": G.nodes[fn].get("line"), "kind": "route", "target": r, "label": entity_label(G, r)})
        for c in sd.cards():
            for s in c.get("usage_sites", []) or []:
                if s["file"] == path:
                    markers.append({"line": int(str(s["lines"]).split("-")[0]), "kind": "vuln", "target": c["finding_id"],
                                    "label": f"{c['finding_id']} {c['vuln_id']}"})
            for e in c.get("evidence", []) if c["type"] == "anomaly" else []:
                if e.get("file") == path and e.get("lines"):
                    markers.append({"line": int(str(e["lines"]).split("-")[0] or 1), "kind": "anomaly", "target": c["finding_id"],
                                    "label": c["finding_id"]})
        fns = [light(G, f) for f in succ(G, fid, "CONTAINS")]
        return {"path": path, "lines": text, "markers": [m for m in markers if m.get("line")], "functions": fns,
                "card": G.nodes[fid].get("card"), "entity": light(G, fid)}

    @app.get("/api/scans/{scan_id}/supply-chain")
    def supply_chain(scan_id: str):
        sd = ready(scan_id)
        facts, G = sd.ctx.facts, sd.ctx.G
        cards = sd.cards()
        per = lambda subj: [unified_row(c) for c in cards if c["component"] == subj]
        disc = ((_read(sd.d / "vulns.json", {}) or {}).get("coverage") or {}).get("discovery") or {}
        return {
            "indexes": facts.get("package_indexes", []),
            "vcs": [{"name": d.get("name"), "kind": d.get("kind"), "spec": d.get("spec")} for d in facts.get("declared_dependencies", [])
                    if d.get("kind") in ("vcs", "url", "local")],
            "images": [{"id": i, "ref": G.nodes[i].get("ref"), "digest": G.nodes[i].get("digest"),
                        "file": next((e.get("file") for e in G.nodes[i].get("evidence", []) if e.get("file")), None), "findings": per(i)}
                       for i in sorted(nodes_of(G, "Image"))],
            "workflows": [{"file": w.get("file"), "triggers": w.get("triggers", []), "permissions": w.get("permissions"),
                           "secrets": w.get("secrets_used", []), "actions": w.get("actions", []), "findings": per(f"workflow:{w.get('file')}")}
                          for w in facts.get("ci_workflows", [])],
            "container_vulns": sum(1 for c in cards if c.get("scope") == "container_os"),
            "grype_note": "; ".join(f"{k}: {v}" for k, v in (disc.get("grype") or {}).items()),
        }

    @app.get("/api/scans/{scan_id}/coverage")
    def coverage(scan_id: str):
        sd = data(scan_id)
        return {"stage3": _read(sd.d / "coverage.json", {}), "stage4": (_read(sd.d / "vulns.json", {}) or {}).get("coverage"),
                "stage5": (_read(sd.d / "signals.json", {}) or {}).get("coverage")}

    @app.get("/api/scans/{scan_id}/search")
    def search(scan_id: str, q: str = Query(..., min_length=1)):
        sd = ready(scan_id)
        G = sd.ctx.G
        ql = q.lower()
        hits = []
        for n, d in G.nodes(data=True):
            if d.get("type") in ("Function", "File", "Package", "Route", "Module", "Commit", "ExternalService", "Vulnerability",
                                 "EnvVar", "Table", "Image", "Workflow") and (ql in n.lower() or ql in str(d.get("name", "")).lower()):
                hits.append({"id": n, "type": d.get("type"), "label": entity_label(G, n)})
        for c in sd.cards():
            if ql in c["finding_id"].lower() or ql in c["title"].lower() or ql in " ".join(c.get("aliases") or []).lower():
                hits.append({"id": c["finding_id"], "type": "Finding", "label": f"{c['finding_id']} {c['title']}"})
        hits.sort(key=lambda h: (not h["label"].lower().startswith(ql), len(h["label"])))
        return hits[:30]

    @app.get("/api/scans/{scan_id}/report")
    def report(scan_id: str, format: str = Query("json", pattern="^(json|sarif|cyclonedx)$")):
        sd = data(scan_id)
        cards = sd.cards()
        if format == "cyclonedx":
            sbom = _read(sd.d / "sbom.cdx.json")
            if sbom is None:
                sbom = minimal_cyclonedx(sd)
            return JSONResponse(sbom, headers={"Content-Disposition": f"attachment; filename={scan_id}.cdx.json"})
        if format == "sarif":
            return JSONResponse(to_sarif(cards), headers={"Content-Disposition": f"attachment; filename={scan_id}.sarif"})
        return JSONResponse({"scan": store.meta(scan_id), "findings": cards,
                             "triage": _read(sd.d / "triage.json", {})},
                            headers={"Content-Disposition": f"attachment; filename={scan_id}-report.json"})

    # ------------------------------------------------------------------ Day 2: prioritize, remediate, approve
    from guardian.day2.api import attach as attach_day2
    attach_day2(app, lambda sid: data(sid).d)
    from guardian.day2.api import attach_finish
    attach_finish(app, lambda sid: data(sid).d)
    from guardian.day2.api import attach_bulk
    attach_bulk(app, lambda sid: data(sid).d)

    # ------------------------------------------------------------------ dashboard (ui/) + SPA
    if UI_DIR.exists():
        from fastapi.responses import RedirectResponse
        from fastapi.staticfiles import StaticFiles

        app.mount("/ui", StaticFiles(directory=UI_DIR, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        def home():
            return RedirectResponse("/ui/")

    if WEB_DIST.exists():
        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            p = (WEB_DIST / full_path).resolve()
            if full_path and p.is_file() and p.is_relative_to(WEB_DIST.resolve()):
                return FileResponse(p)
            return FileResponse(WEB_DIST / "index.html")

    return app


def entity_label(G, n: str) -> str:
    d = G.nodes.get(n, {})
    t = d.get("type")
    if t == "Package":
        return f"{d.get('name')} {d.get('version') or d.get('checked_version') or ''}".strip()
    if t == "Module":
        return d.get("name") or n
    if t == "File":
        return d.get("path") or n
    if t in ("Route", "CLIEntry"):
        return n.split(":", 1)[1]
    if t == "Commit":
        return f"{(d.get('sha') or n[7:])[:7]} {d.get('message') or ''}".strip()
    if t == "Vulnerability":
        return d.get("name") or n
    return short_label(n)


def compare_snapshots(a: ScanData, b: ScanData) -> dict:
    """Diff two stored snapshots (A = from, B = to): packages, modules, routes, services, findings."""
    Ga, Gb = a.ctx.G, b.ctx.G

    def pkgs(G):
        return {G.nodes[p].get("name", p).lower(): (G.nodes[p].get("version") or G.nodes[p].get("checked_version")) for p in nodes_of(G, "Package")}

    pa, pb = pkgs(Ga), pkgs(Gb)
    items = []
    for n in sorted(set(pa) | set(pb)):
        if n not in pa:
            items.append({"group": "Packages", "change": "added", "label": f"+ {n} {pb[n] or ''}"})
        elif n not in pb:
            items.append({"group": "Packages", "change": "removed", "label": f"- {n} {pa[n] or ''}"})
        elif pa[n] != pb[n]:
            items.append({"group": "Packages", "change": "changed", "label": f"{n} {pa[n]} → {pb[n]}"})
    for typ, group in (("Module", "Modules"), ("Route", "Routes"), ("ExternalService", "Code behaviour"), ("EnvVar", "Code behaviour"),
                       ("Image", "Images"), ("Workflow", "CI"), ("File", "Files")):
        na, nb = set(nodes_of(Ga, typ)), set(nodes_of(Gb, typ))
        for n in sorted(nb - na):
            items.append({"group": group, "change": "added", "label": f"+ {entity_label(Gb, n)}", "id": n})
        for n in sorted(na - nb):
            items.append({"group": group, "change": "removed", "label": f"- {entity_label(Ga, n)}", "id": n})
    fa = {(c["type"], c.get("vuln_id") or c["title"], c["component"]) for c in a.cards()}
    for c in b.cards():
        if (c["type"], c.get("vuln_id") or c["title"], c["component"]) not in fa:
            items.append({"group": "Findings", "change": "added", "label": f"+ {c['finding_id']} {c['title']}", "id": c["finding_id"]})
    mods_a, mods_b = set(nodes_of(Ga, "Module")), set(nodes_of(Gb, "Module"))
    return {"from": {"scan_id": a.d.name, "commit": (Ga.graph.get("commit") or "")[:7]},
            "to": {"scan_id": b.d.name, "commit": (Gb.graph.get("commit") or "")[:7]},
            "items": items,
            "graph": {"nodes": [{"id": m, "label": Gb.nodes[m].get("name") if m in Gb else Ga.nodes[m].get("name"),
                                 "status": "added" if m not in mods_a else "removed" if m not in mods_b else "same"}
                                for m in sorted(mods_a | mods_b)],
                      "edges": [{"source": u, "target": v, "status": "same"} for u, v, d in Gb.edges(data=True)
                                if d.get("type") == "DEPENDS_ON"]}}


def to_sarif(cards: list[dict]) -> dict:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    results = []
    for c in cards:
        loc = next((e for e in c.get("evidence", []) if e.get("file") and not e["file"].startswith("pkg:")), None)
        r = {"ruleId": c.get("vuln_id") or (c.get("signals") or [{}])[0].get("check", "anomaly"), "level": level[c["project_risk"]],
             "message": {"text": f"{c['finding_id']}: {c['title']}. {c.get('explanation', '')}"[:1000]},
             "properties": {"project_risk": c["project_risk"], "confidence": c["confidence"], "type": c["type"]}}
        if loc:
            m = re.match(r"(\d+)(?:-(\d+))?", str(loc.get("lines") or "1"))
            r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": loc["file"]},
                                                    "region": {"startLine": int(m.group(1)) if m else 1}}}]
        results.append(r)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "guardian", "version": "0.1.0"}}, "results": results}]}


def minimal_cyclonedx(sd: ScanData) -> dict:
    G = sd.ctx.G
    comps = [{"type": "library", "name": G.nodes[p].get("name"), "version": G.nodes[p].get("version") or G.nodes[p].get("checked_version"),
              "purl": p, "scope": "optional" if G.nodes[p].get("dev") else "required"} for p in sorted(nodes_of(G, "Package"))]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": comps,
            "metadata": {"tools": [{"name": "guardian"}], "component": {"type": "application", "name": G.graph.get("repo")}}}
