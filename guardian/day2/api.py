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


class Bulk(BaseModel):
    reviewer: Optional[str] = None
    build: bool = True


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


def attach_finish(app, scan_dir: Callable[[str], Path]) -> None:
    """Routes of docs/DAY_2_COMPLETION_PLAN.md section 9: auto-validate queue, fixed repository, report."""
    from fastapi import HTTPException
    from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse

    from . import fixed_repo, report
    from .queue import AutoValidator, eligible

    @app.get("/api/scans/{scan_id}/queue")
    def queue_state(scan_id: str):
        d = scan_dir(scan_id)
        q = AutoValidator.for_dir(d)
        if (d / "remediations.json").exists():
            q.ensure()
        st = q.state()
        st["build_health"] = read_json(d / "build_health.json")
        return st

    @app.post("/api/scans/{scan_id}/remediations/validate-all")
    def validate_all(scan_id: str):
        d = scan_dir(scan_id)
        q = AutoValidator.for_dir(d)
        q.started = True
        n = q.enqueue([u["rid"] for u in sorted(load_remediations(d), key=lambda u: min(u.get("ranks") or [0])) if eligible(u, True)])
        return {"queued": n, **q.state()}

    @app.post("/api/scans/{scan_id}/build-health")
    def build_health(scan_id: str):
        from .candidates import add_build_health
        return add_build_health(scan_dir(scan_id), force=True)

    @app.get("/api/scans/{scan_id}/fixed-repo")
    def fixed_get(scan_id: str):
        return fixed_repo.state(scan_dir(scan_id))

    @app.post("/api/scans/{scan_id}/fixed-repo")
    def fixed_build(scan_id: str):
        d = scan_dir(scan_id)
        if not fixed_repo.selection(d)[0]:
            raise HTTPException(422, "no approved fix yet: approve at least one tested patch on the Remediation page")
        fixed_repo.stop_live(d)
        started = fixed_repo.Jobs.start(d)
        return {"started": started, **fixed_repo.state(d)}

    @app.get("/api/scans/{scan_id}/fixed-repo/download")
    def fixed_download(scan_id: str, what: str = "zip"):
        d = fixed_repo.fixed_dir(scan_dir(scan_id))
        f = {"zip": d / "fixed-repo.zip", "patch": d / "fixes.patch"}.get(what)
        if f is None or not f.exists():
            raise HTTPException(404, "not built yet")
        return FileResponse(f, filename=f"{scan_id}-{f.name}",
                            media_type="application/zip" if what == "zip" else "text/x-diff")

    @app.post("/api/scans/{scan_id}/fixed-repo/run")
    def fixed_run(scan_id: str, which: str = "after"):
        try:
            return fixed_repo.run_live(scan_dir(scan_id), "before" if which == "before" else "after")
        except RuntimeError as exc:
            raise HTTPException(422, str(exc))

    @app.delete("/api/scans/{scan_id}/fixed-repo/run")
    def fixed_stop(scan_id: str, which: str = "both"):
        fixed_repo.stop_live(scan_dir(scan_id), which)
        return {"stopped": True}

    @app.get("/api/scans/{scan_id}/remediation-report")
    def report_get(scan_id: str):
        return report.build(scan_dir(scan_id))

    @app.get("/api/scans/{scan_id}/remediation-report/download")
    def report_download(scan_id: str, format: str = "html"):
        rep = report.build(scan_dir(scan_id))
        name = f"{scan_id}-guardian-report"
        if format == "md":
            return PlainTextResponse(report.to_md(rep), media_type="text/markdown",
                                     headers={"Content-Disposition": f"attachment; filename={name}.md"})
        return HTMLResponse(report.to_html(rep), headers={"Content-Disposition": f"attachment; filename={name}.html"})


def bulk_candidates(d: Path) -> list[dict]:
    """Fixes a reviewer can approve in one go: the current proposal was validated in the sandbox, nothing failed
    (no new vulnerability, no regression) and Guardian's security tests behaved as expected."""
    out = []
    for u in sorted(load_remediations(d), key=lambda u: (min(u.get("ranks") or [0]), u["rid"])):
        v = u.get("validation") or {}
        p = (u.get("proposals") or [{}])[u.get("current") or 0] if u.get("proposals") else {}
        if u.get("status") not in ("awaiting_proposal_review", "awaiting_patch_review") or u.get("working"):
            continue
        if not v.get("finished_at") or v.get("proposal_version") != p.get("version") or v.get("status") not in ("passed", "partial"):
            continue
        if (v.get("checks") or {}).get("security_tests", {}).get("status") != "pass":
            continue
        out.append({"rid": u["rid"], "label": u["target_label"], "action": p.get("action"), "validation": v.get("status")})
    return out


def attach_bulk(app, scan_dir: Callable[[str], Path]) -> None:
    import threading

    from . import fixed_repo
    from .workflow import submit as _submit

    @app.get("/api/scans/{scan_id}/bulk-approve")
    def bulk_preview(scan_id: str):
        return {"items": bulk_candidates(scan_dir(scan_id))}

    @app.post("/api/scans/{scan_id}/bulk-approve")
    def bulk_approve(scan_id: str, body: Bulk):
        d = scan_dir(scan_id)
        items = bulk_candidates(d)
        who = body.reviewer or "reviewer"

        def work():
            from .common import get_rem
            for it in items:
                try:
                    u = get_rem(d, it["rid"])
                    if u["status"] == "awaiting_proposal_review":
                        _submit(d, it["rid"], {"stage": "proposal", "action": "approve", "reviewer": who,
                                               "source": "approve all validated"}, background=False)
                    u = get_rem(d, it["rid"])
                    if u["status"] == "awaiting_patch_review":
                        part = (u.get("validation") or {}).get("status") != "passed"
                        _submit(d, it["rid"], {"stage": "patch", "action": "approve", "reviewer": who,
                                               "reason": "approved in bulk: validated in the sandbox; open '?' checks reviewed" if part else None,
                                               "source": "approve all validated"}, background=False)
                except Exception:
                    continue
            if body.build and fixed_repo.selection(d)[0]:
                fixed_repo.stop_live(d)
                fixed_repo.Jobs.start(d)

        threading.Thread(target=work, daemon=True, name=f"guardian-bulk-{scan_id}").start()
        return {"approving": items, "build": body.build}
