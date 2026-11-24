"""Day 2 endpoints, attached to the Guardian web app (docs/DAY_2_PLAN.md section 8)."""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from pydantic import BaseModel

from .common import REGISTER_FILE, load_remediations, read_json
from .history import read_audit
from .workflow import DecisionError, WorkflowManager, submit

TABS = ("decide", "ready", "auto", "unresolved", "decided")


class Decision(BaseModel):
    stage: str
    action: str
    reason: Optional[str] = None
    feedback: Optional[str] = None
    alternative: Optional[int] = None
    reviewer: Optional[str] = None
    large: bool = False


class Suggestion(BaseModel):
    feedback: str
    reviewer: Optional[str] = None
    large: bool = True


def _row(u: dict) -> dict:
    p = u["proposals"][u["current"]] if u.get("proposals") else {}
    return {"rid": u["rid"], "target": u["target"], "target_label": u["target_label"], "target_kind": u["target_kind"],
            "finding_ids": u["finding_ids"], "rank": min(u["ranks"]), "priority": u["priority"], "decision": u["decision"],
            "stage_risk": u["stage_risk"], "finding_confidence": u["finding_confidence"],
            "fix_confidence": p.get("fix_confidence"), "action": p.get("action"), "kind": p.get("kind"),
            "author": p.get("author"), "effect": (p.get("expected_risk") or {}).get("effect"),
            "status": u.get("status"), "tab": u.get("tab"), "working": u.get("working"),
            "gate_reasons": (u.get("gate") or {}).get("reasons", []), "versions": len(u.get("proposals") or []),
            "validation": (u.get("validation") or {}).get("status"), "branch": (u.get("applied") or {}).get("branch")}


def attach(app, scan_dir: Callable[[str], Path]) -> None:
    from fastapi import HTTPException

    def rems(scan_id: str) -> tuple[Path, list[dict]]:
        d = scan_dir(scan_id)
        units = load_remediations(d)
        return d, units

    @app.get("/api/scans/{scan_id}/register")
    def register(scan_id: str):
        return read_json(scan_dir(scan_id) / REGISTER_FILE, []) or []

    @app.get("/api/scans/{scan_id}/remediations")
    def remediations(scan_id: str, tab: Optional[str] = None):
        d, units = rems(scan_id)
        rows = [_row(u) for u in units]
        counts = {t: sum(1 for r in rows if r["tab"] == t) for t in TABS}
        if tab:
            rows = [r for r in rows if r["tab"] == tab]
        return {"available": (d / "remediations.json").exists(), "counts": counts, "items": rows,
                "engine": WorkflowManager.for_dir(d).engine if units else None}

    @app.get("/api/scans/{scan_id}/remediations/{rid}")
    def remediation(scan_id: str, rid: str):
        d, units = rems(scan_id)
        u = next((x for x in units if x["rid"] == rid), None)
        if not u:
            raise HTTPException(404, f"remediation {rid!r} not found")
        reg = {e["finding_id"]: e for e in read_json(d / REGISTER_FILE, []) or []}
        mgr = WorkflowManager.for_dir(d)
        return {**u, "paused_at": mgr.paused_at(u), "engine": mgr.engine,
                "findings": [reg[f] for f in u["finding_ids"] if f in reg], "audit": read_audit(d, rid)}

    @app.post("/api/scans/{scan_id}/remediations/{rid}/decision")
    def decision(scan_id: str, rid: str, body: Decision):
        d = scan_dir(scan_id)
        try:
            u = submit(d, rid, body.model_dump())
        except KeyError:
            raise HTTPException(404, f"remediation {rid!r} not found")
        except DecisionError as exc:
            raise HTTPException(422, str(exc))
        return _row(u)

    @app.post("/api/scans/{scan_id}/findings/{finding_id}/suggest")
    def suggest(scan_id: str, finding_id: str, body: Suggestion):
        d, units = rems(scan_id)
        u = next((x for x in units if finding_id in x["finding_ids"]), None)
        if not u:
            raise HTTPException(404, f"no remediation covers {finding_id}")
        paused = WorkflowManager.for_dir(d).paused_at(u)
        stage = {"proposal_review": "proposal", "patch_review": "patch"}.get(paused or "", "proposal")
        try:
            u = submit(d, u["rid"], {"stage": stage, "action": "revise", "feedback": body.feedback,
                                     "reviewer": body.reviewer, "large": body.large, "source": f"evidence page ({finding_id})"})
        except DecisionError as exc:
            raise HTTPException(422, str(exc))
        return _row(u)

    @app.get("/api/scans/{scan_id}/audit")
    def audit_log(scan_id: str):
        return read_audit(scan_dir(scan_id))
