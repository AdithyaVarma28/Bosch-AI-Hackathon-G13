"""Stage 4 endpoints (docs/stage4.md section 11), attached to the Stage 3 FastAPI app.

GET  /vulns?risk=&scope=      finding cards
GET  /vulns/{finding_id}      card + investigation trace (tool calls, for transparency)
GET  /blast-radius/{purl}     Stage 3 blast radius, now with the package's vulnerability findings
POST /review/{finding_id}     human decision -> resumes the paused review thread, persisted in triage.json
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .report import FINDINGS_FILE, TRACES_FILE
from .review import ReviewError, load_cards, submit_review
from .schema import ReviewDecision


def _load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def attach(app, out: Path, ctx) -> None:
    from fastapi import HTTPException, Query

    out = Path(out)

    @app.get("/vulns")
    def vulns(risk: Optional[str] = Query(None), scope: Optional[str] = Query(None),
              review: Optional[str] = Query(None)):
        cards = load_cards(out / FINDINGS_FILE)
        if risk:
            cards = [c for c in cards if c["project_risk"] in risk.split(",")]
        if scope:
            cards = [c for c in cards if c["scope"] in scope.split(",")]
        if review:
            cards = [c for c in cards if (c.get("review") or {}).get("status") in review.split(",")]
        return cards

    @app.get("/vulns/{finding_id}")
    def vuln(finding_id: str):
        card = next((c for c in load_cards(out / FINDINGS_FILE) if c["finding_id"] == finding_id), None)
        if not card:
            raise HTTPException(404, f"finding {finding_id!r} not found")
        return {"card": card, "trace": _load(out / TRACES_FILE, {}).get(finding_id, [])}

    @app.post("/review/{finding_id}")
    def review(finding_id: str, decision: ReviewDecision):
        files = [FINDINGS_FILE, "anomaly_findings.json"]
        for f in files:
            if any(c.get("finding_id") == finding_id for c in load_cards(out / f)):
                try:
                    return submit_review(out, f, finding_id, decision)
                except ReviewError as exc:
                    raise HTTPException(422, str(exc))
        raise HTTPException(404, f"finding {finding_id!r} not found")

    # the Stage 3 route is registered first; this one adds the attached vulnerability findings
    for route in list(app.router.routes):
        if getattr(route, "path", None) == "/blast-radius/{purl:path}":
            app.router.routes.remove(route)

    @app.get("/blast-radius/{purl:path}")
    def blast(purl: str):
        br = ctx.blast.get(purl) or next((v for k, v in ctx.blast.items() if v["name"].lower() == purl.lower()
                                          or k.split("@")[0] == purl), None)
        if not br:
            raise HTTPException(404, f"package {purl!r} not found")
        cards = [c for c in load_cards(out / FINDINGS_FILE) if c["component"] == br["package"]]
        return {**br, "vulnerabilities": [{k: c[k] for k in ("finding_id", "vuln_id", "project_risk", "severity",
                                                              "usage", "reachability", "confidence")} for c in cards]}
