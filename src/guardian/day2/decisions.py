"""Reviewer-facing operations shared by the CLI and the API: list plans, decide, export an approved patch."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..runner import ToolFailed, git
from ..store import RunStore
from .approval import approve_pr, decide
from .models import RemediationPlan, VerificationReport
from .patcher import diff_sha
from .store import Day2Store


class PlanNotFound(LookupError):
    pass


def open_d2(run_dir: Path) -> tuple[RunStore, Day2Store]:
    run_dir = Path(run_dir)
    rep = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    st = RunStore(run_dir, rep["run_id"])
    return st, Day2Store(st)


def find_plan(d2: Day2Store, ref: str) -> RemediationPlan:
    plans = d2.plans()
    exact = [p for p in plans if p.plan_key == ref or ref in p.finding_ids]
    if exact:
        return exact[0]
    hits = [p for p in plans if ref.lower() in p.plan_key.lower() or ref.lower() in p.title.lower()]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise PlanNotFound(f"no plan matches '{ref}'")
    raise PlanNotFound(f"'{ref}' matches {len(hits)} plans: " + ", ".join(p.plan_key for p in hits[:6]))


def check_hash(plan: RemediationPlan, shown: str | None) -> str:
    """The reviewer must quote (a >=12-char prefix of) the hash they reviewed."""
    if not shown or len(shown) < 12:
        raise ValueError("pass --hash with at least the first 12 characters of the plan hash you reviewed")
    if not plan.plan_hash.startswith(shown.lower()):
        raise ValueError(f"hash {shown[:16]} does not match the current plan (rev {plan.revision}, {plan.plan_hash[:16]}); "
                         "the plan changed: review it again")
    return plan.plan_hash


def record(run_dir: Path, ref: str, decision: str, reviewer: str, shown_hash: str | None, reason: str = "",
           candidate: list[str] | None = None, expires: str | None = None) -> RemediationPlan:
    st, d2 = open_d2(run_dir)
    try:
        plan = find_plan(d2, ref)
        if plan.status not in ("awaiting_approval", "escalated") and decision != "accept_risk":
            raise ValueError(f"plan is '{plan.status}', not awaiting a decision")
        full = check_hash(plan, shown_hash)
        if decision == "accept_risk" and expires and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires):
            raise ValueError("--expires must be YYYY-MM-DD")
        _, new = decide(d2, plan, decision, reviewer, reason, chosen=candidate, expires=expires, plan_hash=full)
        if decision == "accept_risk":
            rep = VerificationReport(plan_key=new.plan_key, title=new.title, finding_ids=new.finding_ids, verdict="Risk accepted",
                                     deterministic_verdict="Not verified", confidence="low",
                                     confidence_reasons=[f"risk accepted by {reviewer} until {expires}: {reason}"],
                                     plan_hash=new.plan_hash, accepted_risk=[a.model_dump() for a in d2.approvals(new.plan_key)
                                                                             if a.decision == "accept_risk"],
                                     timeline=d2.timeline(new.plan_key))
            d2.put(f"report:{new.plan_key}", rep.model_dump())
        elif decision == "reject":
            rep = VerificationReport(plan_key=new.plan_key, title=new.title, finding_ids=new.finding_ids, verdict="Rejected",
                                     deterministic_verdict="Not verified", confidence="low",
                                     confidence_reasons=[f"rejected by {reviewer}: {reason}"], plan_hash=new.plan_hash,
                                     timeline=d2.timeline(new.plan_key))
            d2.put(f"report:{new.plan_key}", rep.model_dump())
        return new
    finally:
        st.close()


def export_patch(run_dir: Path, ref: str, reviewer: str, reason: str = "") -> Path:
    """Second approval (kind=pr) bound to the verified diff hash, then write a git patch. Nothing is pushed."""
    st, d2 = open_d2(run_dir)
    try:
        plan = find_plan(d2, ref)
        raw = d2.get(f"report:{plan.plan_key}")
        if not raw:
            raise ValueError("plan has no verification report yet")
        rep = VerificationReport.model_validate(raw)
        if rep.verdict not in ("Verified", "Partially verified") or not rep.chosen:
            raise ValueError(f"verdict is '{rep.verdict}': only verified fixes can be exported")
        win = next((v for v in rep.tournament if v.winner), None)
        diff = rep.chosen.diff
        patch = d2.dir / "patches" / (re.sub(r"[^A-Za-z0-9._-]+", "_", plan.plan_key)[:80] + ".patch")
        patch.parent.mkdir(parents=True, exist_ok=True)
        text = diff
        if win and win.commit and Path(win.work_dir).exists():
            try:
                text = git(Path(win.work_dir), "format-patch", "-1", win.commit, "--stdout")
            except ToolFailed:
                text = diff
        approve_pr(d2, plan, diff_sha(diff), reviewer, reason)
        header = (f"# Guardian verified patch\n# plan {plan.plan_key} rev {plan.revision} hash {plan.plan_hash}\n"
                  f"# verdict {rep.verdict} (confidence {rep.confidence}); export approved by {reviewer}\n")
        patch.write_text(header + text, encoding="utf-8")
        return patch
    finally:
        st.close()
