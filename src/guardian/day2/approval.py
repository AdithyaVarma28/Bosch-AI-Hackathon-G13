"""S13 Immutable human approval gate.

* A reviewer approves a PLAN, not a finding. The plan hash is sha256 over the normalized plan: plan key, revision,
  target findings and, for every finalist, its action, versions, typed edits and the sha256 of its diff.
* Approvals are append-only rows (SQLite triggers refuse UPDATE/DELETE).
* Before S14 applies anything it recomputes the hash of what it is about to apply; any difference stops it.
* Any change (reviewer edit, self-correction candidate, a regenerated lockfile with different content) produces a
  new plan revision with a new hash, which needs a fresh approval.
* Exporting a patch / opening a PR is a second approval (kind="pr") bound to the final diff hash.
"""
from __future__ import annotations

import hashlib
import json

from .models import ApprovalRecord, RemediationCandidate, RemediationPlan
from .store import Day2Store


class ApprovalRequired(PermissionError):
    pass


class ApprovalMismatch(PermissionError):
    pass


def candidate_fingerprint(c: RemediationCandidate) -> dict:
    return {"id": c.id, "action": c.action, "package": c.package, "from": c.from_version, "to": c.to_version,
            "edits": [e.model_dump(mode="json") for e in c.edits], "diff_sha256": c.diff_sha256}


def compute_plan_hash(plan: RemediationPlan) -> str:
    body = {"plan_key": plan.plan_key, "revision": plan.revision, "parent": plan.parent_hash,
            "findings": sorted(plan.finding_ids),
            "finalists": [candidate_fingerprint(c) for cid in plan.finalists if (c := plan.candidate(cid))]}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def applied_hash(plan: RemediationPlan, real_diffs: dict[str, str]) -> str:
    """Hash of what is actually about to be applied: the plan with each finalist's diff hash replaced by the hash
    of the diff produced on the sandbox branch. Equal to the approved hash only if every real diff matches."""
    from .patcher import diff_sha
    sub = plan.model_copy(deep=True)
    for c in sub.candidates:
        if c.id in real_diffs:
            c.diff_sha256 = diff_sha(real_diffs[c.id])
    return compute_plan_hash(sub)


def decide(d2: Day2Store, plan: RemediationPlan, decision: str, reviewer: str, reason: str = "", chosen: list[str] | None = None,
           expires: str | None = None, plan_hash: str | None = None) -> tuple[ApprovalRecord, RemediationPlan]:
    """Record a reviewer decision. `plan_hash` (what the reviewer saw) must equal the current plan hash.
    Choosing a subset of candidates or a non-finalist ('edit') creates a new revision that the record approves."""
    if plan_hash and plan_hash != plan.plan_hash:
        raise ApprovalMismatch(f"plan changed since it was shown (shown {plan_hash[:12]}, current {plan.plan_hash[:12]}); "
                               "review the new plan")
    if plan.plan_hash != compute_plan_hash(plan):
        raise ApprovalMismatch("stored plan does not match its own hash (tampered or corrupted)")
    if decision == "approve" and chosen and set(chosen) != set(plan.finalists):
        unknown = [c for c in chosen if not plan.candidate(c)]
        if unknown:
            raise ValueError(f"unknown candidate id(s): {', '.join(unknown)}")
        if any(plan.candidate(c).action == "escalate" or not plan.candidate(c).edits for c in chosen):
            raise ValueError("escalation and manual candidates cannot be applied; reject or accept the risk instead")
        if any(not plan.candidate(c).diff for c in chosen):
            raise ValueError("chosen candidate was not simulated (no diff); it cannot be approved")
        plan = revise(d2, plan, chosen, source_note=f"reviewer {reviewer} chose {', '.join(chosen)}")
    rec = d2.add_approval(ApprovalRecord(plan_key=plan.plan_key, plan_hash=plan.plan_hash, decision=decision,
                                         reviewer=reviewer, reason=reason, chosen=chosen or plan.finalists, expires=expires))
    plan.status = {"approve": "approved", "reject": "rejected", "accept_risk": "risk_accepted"}[decision]
    d2.save_plan(plan)
    d2.audit("S13", f"plan {decision}", f"{plan.title} | hash {plan.plan_hash[:12]} | {reason}", actor=reviewer, plan_key=plan.plan_key)
    return rec, plan


def revise(d2: Day2Store, plan: RemediationPlan, finalists: list[str], source_note: str,
           extra: list[RemediationCandidate] | None = None) -> RemediationPlan:
    """New revision with a different finalist set (and optional new candidates). The old revision is kept."""
    old = plan.model_copy(deep=True)
    old.status = "superseded"
    d2.save_plan(old)
    new = plan.model_copy(deep=True)
    if extra:   # re-proposed candidates replace the old copy (fresh simulation, provenance = self-correction)
        by_id = {c.id: c for c in extra}
        new.candidates = [by_id.pop(c.id, c) for c in new.candidates] + list(by_id.values())
    new.revision = plan.revision + 1
    new.parent_hash = plan.plan_hash
    new.finalists = list(finalists)
    new.recommended = finalists[0] if finalists else new.recommended
    new.status = "awaiting_approval"
    new.plan_hash = compute_plan_hash(new)
    d2.save_plan(new)
    d2.audit("S13", "plan revised", f"rev {new.revision} hash {new.plan_hash[:12]} (parent {plan.plan_hash[:12]}): {source_note}",
             plan_key=plan.plan_key)
    return new


def approval_for(d2: Day2Store, plan: RemediationPlan, kind: str = "plan") -> ApprovalRecord | None:
    """The latest decision bound to this exact plan hash."""
    recs = [a for a in d2.approvals(plan.plan_key) if a.plan_hash == plan.plan_hash and a.kind == kind]
    return recs[-1] if recs else None


def require_approval(d2: Day2Store, plan: RemediationPlan, about_to_apply: str) -> ApprovalRecord:
    """Gate before S14: the hash of what is about to be applied must equal an approved plan hash."""
    rec = approval_for(d2, plan)
    if rec is None or rec.decision != "approve":
        raise ApprovalRequired(f"plan {plan.plan_key} rev {plan.revision} ({plan.plan_hash[:12]}) has no approval")
    if about_to_apply != rec.plan_hash:
        d2.audit("S13", "approval mismatch", f"about to apply {about_to_apply[:12]} but approved {rec.plan_hash[:12]}",
                 plan_key=plan.plan_key)
        raise ApprovalMismatch(f"change set {about_to_apply[:12]} differs from approved plan {rec.plan_hash[:12]}")
    return rec


def approve_pr(d2: Day2Store, plan: RemediationPlan, diff_sha256: str, reviewer: str, reason: str = "") -> ApprovalRecord:
    rec = d2.add_approval(ApprovalRecord(plan_key=plan.plan_key, plan_hash=diff_sha256, kind="pr", decision="approve",
                                         reviewer=reviewer, reason=reason))
    d2.audit("S16", "patch export approved", f"diff {diff_sha256[:12]}", actor=reviewer, plan_key=plan.plan_key)
    return rec
