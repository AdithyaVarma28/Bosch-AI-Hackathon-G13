"""Day 2 data contracts (Pydantic v2). Day 1 contracts live in guardian.models and are unchanged."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from ..models import Claim

Bucket = Literal["fix_now", "schedule", "monitor"]
Compat = Literal["low", "medium", "high", "unknown"]
Verdict = Literal["Verified", "Partially verified", "Not verified", "Escalated", "Risk accepted", "Rejected",
                  "Awaiting approval"]
VERDICT_ORDER = ["Verified", "Partially verified", "Not verified"]


class RiskFactor(BaseModel):
    name: str            # severity | exploitability | reachability | exposure | production_use | criticality | policy
    points: float
    detail: str


class RiskScore(BaseModel):
    """S10: explainable 0-100 risk score next to the Day 1 band. Confidence is about data quality, not risk."""
    finding_id: str
    title: str = ""
    subject: str = ""
    band: str | None = None
    total: int
    factors: list[RiskFactor] = Field(default_factory=list)
    reachability: Literal["function_reachable", "route_reachable", "imported", "not_referenced", "unknown", "n/a"] = "unknown"
    criticality: Literal["critical", "high", "normal", "low", "unknown"] = "unknown"
    confidence: Literal["high", "medium", "low"] = "medium"
    confidence_reasons: list[str] = Field(default_factory=list)
    bucket: Bucket = "monitor"
    bucket_reason: str = ""
    needs_human: bool = False
    policy_violations: list[str] = Field(default_factory=list)

    def breakdown(self) -> str:
        parts = [f"{'+' if f.points >= 0 else ''}{f.points:g} {f.name} ({f.detail})" for f in self.factors if f.points]
        return ", ".join(parts) + f" = {self.total}; confidence {self.confidence}"


class ProvenanceCheck(BaseModel):
    name: str
    status: Literal["pass", "fail", "unknown"]
    strong: bool = False             # a failed strong check counts towards "likely malicious"
    detail: str
    evidence_ids: list[str] = Field(default_factory=list)


class Investigation(BaseModel):
    """S11: deep dive on a non-CVE supply-chain signal. Facts cite raw evidence; inferences are labelled."""
    finding_id: str
    subject: str
    signal: str | None = None
    diffs: list[dict[str, Any]] = Field(default_factory=list)
    checks: list[ProvenanceCheck] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    verdict: Literal["likely_malicious", "suspicious", "benign_change", "inconclusive"] = "inconclusive"
    verdict_reason: str = ""
    generated_by: str = "rule-based"
    # agentic investigation (S11 Threat Investigator agent)
    rule_verdict: str | None = None          # deterministic baseline label
    verdict_by: str = "rules"                # who set the final label: rules | <llm name>
    agent_reason: str = ""
    guardrail_notes: list[str] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)


class Edit(BaseModel):
    """One typed change. The patcher is the only code that turns these into file contents."""
    kind: Literal["npm_set_dep", "npm_remove_dep", "npm_override", "npm_lock_set", "npm_lock_remove", "npm_remove_script",
                  "pip_set_pin", "pip_add_pin", "pip_remove", "docker_from", "gha_pin", "gha_permissions", "policy_block"]
    file: str
    params: dict[str, Any] = Field(default_factory=dict)


class SimulationResult(BaseModel):
    method: str = "patched-tree-reparse"
    target_resolved: bool = False
    resolved_changes: list[dict[str, Any]] = Field(default_factory=list)   # {name, from, to}
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    new_advisories: list[dict[str, Any]] = Field(default_factory=list)     # {purl, ids, severity_band}
    remaining_advisories: list[dict[str, Any]] = Field(default_factory=list)
    api_risk: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class RemediationCandidate(BaseModel):
    id: str
    plan_key: str
    action: Literal["upgrade", "parent_upgrade", "override", "pin", "replace", "remove", "update_base_image", "block",
                    "remove_script", "restore_lock_source", "pin_action", "restrict_permissions", "mitigate", "escalate"]
    package: str | None = None
    ecosystem: str | None = None
    from_version: str | None = None
    to_version: str | None = None
    summary: str
    edits: list[Edit] = Field(default_factory=list)
    closes: list[str] = Field(default_factory=list)         # finding ids expected to be resolved
    simulation: SimulationResult | None = None
    risk_reduction: int = 0
    compatibility: Compat = "unknown"
    compatibility_notes: list[str] = Field(default_factory=list)
    rollback: str = ""
    score: float = 0.0
    rank: int | None = None
    rejected_reason: str | None = None
    policy_violations: list[str] = Field(default_factory=list)
    source: Literal["rule", "self-correction", "self-correction-llm", "reviewer"] = "rule"
    floor_safe: bool | None = None                          # the range floor itself is non-vulnerable
    diff: str = ""                                          # unified diff against the scanned tree
    diff_sha256: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    """S12 output and the unit of approval (S13). The plan hash covers finalists, their edits and their diffs."""
    plan_key: str
    title: str
    finding_ids: list[str]
    target: str
    revision: int = 1
    parent_hash: str | None = None
    candidates: list[RemediationCandidate] = Field(default_factory=list)
    finalists: list[str] = Field(default_factory=list)
    recommended: str | None = None
    rationale: list[Claim] = Field(default_factory=list)
    rationale_by: str = "rule-based"
    plan_hash: str = ""
    created_at: str = ""
    status: Literal["awaiting_approval", "approved", "rejected", "risk_accepted", "validated", "superseded",
                    "escalated", "failed"] = "awaiting_approval"

    def candidate(self, cid: str) -> RemediationCandidate | None:
        return next((c for c in self.candidates if c.id == cid), None)


class ApprovalRecord(BaseModel):
    plan_key: str
    plan_hash: str
    kind: Literal["plan", "pr"] = "plan"
    decision: Literal["approve", "reject", "accept_risk"]
    reviewer: str
    reason: str = ""
    chosen: list[str] = Field(default_factory=list)          # candidate ids (an edit = choosing a subset)
    expires: str | None = None                               # accept_risk only
    timestamp: str = ""

    @model_validator(mode="after")
    def _checks(self) -> "ApprovalRecord":
        if not self.reviewer.strip():
            raise ValueError("reviewer is required")
        if self.decision == "accept_risk" and (not self.reason.strip() or not self.expires):
            raise ValueError("accepting a risk needs a reason and an expiry date")
        return self


class StepResult(BaseModel):
    name: str
    command: list[str] = Field(default_factory=list)
    returncode: int | None = None
    ok: bool = False
    skipped: bool = False
    summary: str = ""
    seconds: float = 0.0
    evidence_id: str | None = None


class TestSummary(BaseModel):
    __test__ = False      # not a pytest test class
    framework: str | None = None
    ran: bool = False
    exit_code: int | None = None
    passed: int = 0
    failed: int = 0
    errors: int = 0
    passed_ids: list[str] = Field(default_factory=list)
    failed_ids: list[str] = Field(default_factory=list)
    smoke_only: bool = False
    evidence_id: str | None = None


class RescanDiff(BaseModel):
    plan_key: str
    candidate_id: str
    rescan_run_dir: str = ""
    sbom_added: list[str] = Field(default_factory=list)
    sbom_removed: list[str] = Field(default_factory=list)
    sbom_changed: list[dict[str, Any]] = Field(default_factory=list)
    findings_resolved: list[dict[str, Any]] = Field(default_factory=list)
    findings_open: list[dict[str, Any]] = Field(default_factory=list)      # target findings still present
    findings_new: list[dict[str, Any]] = Field(default_factory=list)
    bands_before: dict[str, int] = Field(default_factory=dict)
    bands_after: dict[str, int] = Field(default_factory=dict)
    score_before: int = 0
    score_after: int = 0
    target_resolved: bool = False
    vulnerable_versions_left: list[str] = Field(default_factory=list)
    new_high: list[str] = Field(default_factory=list)
    sbom_confidence_before: str | None = None
    sbom_confidence_after: str | None = None
    node_status: dict[str, str] = Field(default_factory=dict)
    evidence_id: str | None = None


class ValidationResult(BaseModel):
    plan_key: str
    candidate_id: str
    branch: str = ""
    sandbox: Literal["docker", "local", "none"] = "none"
    applied_hash: str | None = None
    commit: str | None = None
    steps: list[StepResult] = Field(default_factory=list)
    tests_before: TestSummary = Field(default_factory=TestSummary)
    tests_after: TestSummary = Field(default_factory=TestSummary)
    regressions: list[str] = Field(default_factory=list)
    build_ok: bool | None = None
    status: Literal["passed", "failed", "skipped", "error"] = "skipped"
    reason: str = ""
    seconds: float = 0.0
    work_dir: str = ""
    rescan: RescanDiff | None = None
    tournament_score: float | None = None
    winner: bool = False


class CorrectionAttempt(BaseModel):
    plan_key: str
    round: int
    failure_class: Literal["api_removed", "peer_conflict", "lockfile_conflict", "flaky_or_unrelated", "environment",
                           "still_vulnerable", "new_risk", "unknown"]
    failed_candidate: str
    log_evidence_ids: list[str] = Field(default_factory=list)
    proposed: str | None = None                       # candidate id
    proposed_by: str = "rule-based"
    new_plan_hash: str | None = None
    outcome: Literal["proposed", "escalated", "rejected_by_verifier"] = "proposed"
    detail: str = ""


class PolicyResult(BaseModel):
    policy_sha256: str
    rule_id: str
    severity: Literal["block", "warn"]
    passed: bool
    detail: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    floor: bool = False


class VerifierCheck(BaseModel):
    check: str
    ok: bool | None
    detail: str
    evidence_ids: list[str] = Field(default_factory=list)


class VerifierReview(BaseModel):
    checks: list[VerifierCheck] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    downgrade_to: Verdict | None = None
    reason: str = ""
    generated_by: str = "rule-based"


class TimelineEntry(BaseModel):
    at: str
    stage: str
    event: str
    detail: str = ""
    actor: str = "guardian"
    plan_key: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class VerificationReport(BaseModel):
    plan_key: str
    title: str
    finding_ids: list[str]
    verdict: Verdict
    deterministic_verdict: Verdict
    confidence: Literal["high", "medium", "low"]
    confidence_reasons: list[str] = Field(default_factory=list)
    original: list[dict[str, Any]] = Field(default_factory=list)          # finding summary + evidence ids
    risk: list[RiskScore] = Field(default_factory=list)
    investigation: list[Investigation] = Field(default_factory=list)
    plan_hash: str | None = None
    approved: ApprovalRecord | None = None
    chosen: RemediationCandidate | None = None
    alternatives: list[dict[str, Any]] = Field(default_factory=list)
    tournament: list[ValidationResult] = Field(default_factory=list)
    corrections: list[CorrectionAttempt] = Field(default_factory=list)
    rescan: RescanDiff | None = None
    policy: list[PolicyResult] = Field(default_factory=list)
    verifier: VerifierReview | None = None
    remaining_risk: list[dict[str, Any]] = Field(default_factory=list)
    accepted_risk: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)


class AdvisoryAnswer(BaseModel):
    """One of the six questions, answered with a typed claim (fact cites raw evidence; inference labelled; unknown)."""
    question: str
    value: str                                   # enum value for the question (see ADVISORY_QUESTIONS)
    text: str
    basis: Literal["fact", "inference", "unknown"] = "unknown"
    evidence_ids: list[str] = Field(default_factory=list)
    verifier_status: str = "pending"
    by: str = "rules"


class Mitigation(BaseModel):
    kind: Literal["workaround", "configuration", "disable_feature"]
    text: str
    evidence_ids: list[str] = Field(default_factory=list)
    by: str = "rules"


class AdvisoryAssessment(BaseModel):
    """Advisory Analyst output for one confirmed advisory (Day 2, between S11 and S12)."""
    finding_id: str
    advisory_id: str
    package: str
    version: str | None = None
    relevance: AdvisoryAnswer                    # Q1 relevant to how THIS app uses the package?
    feature_usage: AdvisoryAnswer                # Q2 vulnerable feature enabled / unused?
    mitigations: list[Mitigation] = Field(default_factory=list)   # Q3 workaround / configuration mitigation
    mitigation_answer: AdvisoryAnswer | None = None
    affects_installed: AdvisoryAnswer            # Q4 installed version + usage path affected?
    usage_paths: list[list[str]] = Field(default_factory=list)
    recommended: AdvisoryAnswer                  # Q5 upgrade | pin | disable_feature | config_mitigation | accept_risk_temporarily
    missing_evidence: list[str] = Field(default_factory=list)     # Q6
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    generated_by: str = "rules"
