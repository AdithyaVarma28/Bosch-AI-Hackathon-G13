"""Stage 4 data contracts (docs/stage4.md): VulnMatch, Fingerprint, Investigation, Verification, Verdict.

Three values are never mixed: **severity** (CVSS, from the database), **project risk** (rule table)
and **confidence** (evidence quality). Each has its own field everywhere.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from guardian.stage3_knowledge.schema import Evidence

RISKS = ("low", "medium", "high", "critical")
USAGES = ("symbol_called", "package_used_symbol_not_found", "package_used_symbol_unknown",
          "package_not_imported", "not_applicable")
REACHABILITY = ("public_path", "internal_only", "no_path_found", "unknown")
SCOPES = ("runtime", "dev", "test_only", "build", "container_os")
CONDITION_STATUS = ("met", "not_shown", "unknown")
CONFIDENCE = ("low", "medium", "high")

Risk = Literal["low", "medium", "high", "critical"]
Usage = Literal["symbol_called", "package_used_symbol_not_found", "package_used_symbol_unknown",
                "package_not_imported", "not_applicable"]
Reach = Literal["public_path", "internal_only", "no_path_found", "unknown"]
Scope = Literal["runtime", "dev", "test_only", "build", "container_os"]


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def band_of(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def risk_rank(r: Optional[str]) -> int:
    return RISKS.index(r) if r in RISKS else -1


def band_as_risk(band: str) -> str:
    """CVSS band expressed on the project-risk scale (none/unknown count as low)."""
    return band if band in RISKS else "low"


# --------------------------------------------------------------------------- 1. discovery

class CVSS(BaseModel):
    vector: Optional[str] = None
    score: Optional[float] = None
    band: str = "unknown"            # critical | high | medium | low | none | unknown
    version: Optional[str] = None    # "3.1", "4.0", ...
    source: Optional[str] = None     # which record / feed the value came from


class EPSS(BaseModel):
    score: float
    percentile: float
    date: Optional[str] = None


class AffectedRange(BaseModel):
    introduced: Optional[str] = None
    fixed: Optional[str] = None
    last_affected: Optional[str] = None


class Reference(BaseModel):
    type: str = "WEB"
    url: str


class VulnMatch(BaseModel):
    """One known vulnerability in one package version. Every field comes from OSV / Grype / KEV / EPSS."""
    model_config = ConfigDict(extra="ignore")

    match_id: str                                    # "<vuln_id>|<purl>"
    vuln_id: str
    aliases: list[str] = []
    records: list[str] = []                          # every database record merged into this match
    package: str                                     # purl
    package_name: str
    version: Optional[str] = None
    ecosystem: str = "PyPI"
    artifact_type: str = "python"                    # python | deb | apk | rpm | binary ...
    summary: str = ""
    details: str = ""
    cvss: CVSS = Field(default_factory=CVSS)
    affected_ranges: list[AffectedRange] = []
    fixed_versions: list[str] = []
    references: list[Reference] = []
    kev: bool = False
    epss: Optional[EPSS] = None
    source: list[str] = []                           # osv | osv-dump | grype
    scope: Scope = "runtime"
    scope_reason: str = ""
    dependency_path: list[str] = []                  # ["requirements.txt:5", "pkg:pypi/requests@2.31.0", "pkg:pypi/idna@3.7"]
    dependency_paths: list[list[str]] = []
    direct_dependency: Optional[str] = None          # the purl that must change
    image: Optional[str] = None                      # container_os: image reference
    published: Optional[str] = None
    modified: Optional[str] = None


# --------------------------------------------------------------------------- 3. analyst

class Trigger(BaseModel):
    type: Literal["untrusted_input", "argument", "config", "other"] = "other"
    text: str


class QuoteEvidence(BaseModel):
    advisory: str
    quote_span: str


class Fingerprint(BaseModel):
    vuln_id: str
    vulnerable_symbols: list[str] = []
    safe_alternatives: list[str] = []
    trigger_conditions: list[Trigger] = []
    impact: str = ""
    attack_vector: str = "unknown"
    symbols_source: Literal["advisory_text", "fix_commit", "none"] = "none"
    confidence: float = Field(ge=0.0, le=1.0, default=0.3)
    evidence: list[QuoteEvidence] = []
    dropped_symbols: list[str] = []
    fix_functions: list[str] = []
    discovered_by: Literal["ai", "algorithm"] = "algorithm"


# --------------------------------------------------------------------------- 4. investigator

class UsageSite(BaseModel):
    function: str
    file: str
    lines: str
    code: str = ""
    symbol: Optional[str] = None
    unsafe_argument: Optional[bool] = None
    via: Literal["graph", "search"] = "search"
    in_test: bool = False


class ConditionResult(BaseModel):
    condition: str                                   # trigger type
    text: str = ""
    status: Literal["met", "not_shown", "unknown"] = "unknown"
    note: str = ""
    evidence: list[Evidence] = []


class Claim(BaseModel):
    text: str
    kind: Literal["usage", "reachability", "condition", "other"] = "other"
    evidence: list[Evidence] = []
    graph_backed: bool = False
    verified: Optional[bool] = None
    note: Optional[str] = None


class Investigation(BaseModel):
    vuln_id: str
    package: str
    usage: Usage = "package_used_symbol_unknown"
    usage_sites: list[UsageSite] = []
    reachability: Reach = "unknown"
    paths: list[list[str]] = []
    entries: list[dict[str, Any]] = []               # [{"id", "kind", "public"}]
    conditions: list[ConditionResult] = []
    unknowns: list[str] = []
    claims: list[Claim] = []
    dropped: list[str] = []                          # claims/sites removed by evidence checks
    tool_calls_used: int = 0
    budget_exhausted: bool = False
    dynamic_imports: list[str] = []
    light_pass: bool = False
    discovered_by: Literal["ai", "algorithm"] = "algorithm"
    notes: list[str] = []


# --------------------------------------------------------------------------- 5. verifier

class ClaimCheck(BaseModel):
    text: str
    ok: bool
    reason: str = ""
    lines: list[str] = []


class Verification(BaseModel):
    ran: bool = False
    triggers: list[str] = []
    verified: bool = True
    checks: list[ClaimCheck] = []
    retried: bool = False
    objections: list[str] = []
    dropped_claims: list[str] = []
    discovered_by: Literal["ai", "algorithm"] = "algorithm"


# --------------------------------------------------------------------------- 6. risk

class Fix(BaseModel):
    upgrade_to: Optional[str] = None
    code_change: Optional[str] = None


class Verdict(BaseModel):
    project_risk: Risk
    rule: int
    rule_text: str
    confidence: Literal["low", "medium", "high"]
    confidence_reasons: list[str] = []
    needs_human_review: bool = False
    review_reasons: list[str] = []
    downgrade_guard: bool = False
    explanation: str = ""
    recommendation: str = ""
    explanation_by: Literal["ai", "template"] = "template"
    fix: Fix = Field(default_factory=Fix)


class ReviewDecision(BaseModel):
    action: Literal["confirm", "dismiss", "override"]
    reason: Optional[str] = None                     # dismiss: false_positive | not_used | accepted_risk | mitigated_elsewhere
    note: Optional[str] = None
    new_risk: Optional[Risk] = None                  # override
    by: Optional[str] = None


DISMISS_REASONS = ("false_positive", "not_used", "accepted_risk", "mitigated_elsewhere")


def activity(stage: str, action: str, result: str = "", tool: Optional[str] = None,
             input: Optional[dict] = None, ok: bool = True) -> dict:
    """One investigation-timeline step: actions and results only, never model reasoning."""
    return {"stage": stage, "action": action, "tool": tool, "input": input or {}, "result": result, "ok": ok,
            "at": now_iso()}
