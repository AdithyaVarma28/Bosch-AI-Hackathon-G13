"""Deterministic decision tables (docs/DAY_2_PLAN.md section 3).

* CVE findings: SSVC-inspired decision points following CISA's SSVC guide (Exploitation, Automatable,
  Technical impact, Mission & well-being) -> Track / Track* / Attend / Act. We do not claim CISA compliance.
* Suspicious (non-CVE) findings: a Guardian supply-chain table, suspicion x exposure -> the same outcomes.
* Priority (Critical..Low) is a separate field: base from the decision, then documented modifiers.
"""
from __future__ import annotations

from typing import Optional

from .common import BANDS, band_idx

# (exploitation, automatable, technical_impact) -> outcome for mission low / medium / high
CVE_TREE: dict[tuple[str, str, str], tuple[str, str, str]] = {
    ("none", "no", "partial"): ("Track", "Track", "Track"),
    ("none", "no", "total"): ("Track", "Track", "Track*"),
    ("none", "yes", "partial"): ("Track", "Track", "Attend"),
    ("none", "yes", "total"): ("Track", "Track", "Attend"),
    ("poc", "no", "partial"): ("Track", "Track", "Track*"),
    ("poc", "no", "total"): ("Track", "Track*", "Attend"),
    ("poc", "yes", "partial"): ("Track", "Track", "Attend"),
    ("poc", "yes", "total"): ("Track", "Track*", "Attend"),
    ("active", "no", "partial"): ("Track", "Track", "Attend"),
    ("active", "no", "total"): ("Track", "Attend", "Act"),
    ("active", "yes", "partial"): ("Attend", "Attend", "Act"),
    ("active", "yes", "total"): ("Attend", "Act", "Act"),
}
MISSION = ["low", "medium", "high"]


def cve_decision(exploitation: str, automatable: str, technical_impact: str, mission: str) -> str:
    row = CVE_TREE[(exploitation, automatable, technical_impact)]
    return row[MISSION.index(mission)]


# suspicion level -> outcome per exposure column
SUPPLY_COLUMNS = ["install_or_ci", "runtime_public", "runtime_internal", "not_installed"]
SUPPLY_TABLE: dict[str, tuple[str, str, str, str]] = {
    "verified": ("Act", "Act", "Attend", "Track*"),
    "high": ("Act", "Attend", "Attend", "Track"),
    "medium": ("Attend", "Track*", "Track*", "Track"),
    "low": ("Track*", "Track", "Track", "Track"),
}


def exposure_column(exposure: Optional[str]) -> str:
    e = (exposure or "").lower()
    if e in ("install_path", "build_env", "ci_with_secrets", "ci"):
        return "install_or_ci"
    if e == "runtime_public":
        return "runtime_public"
    if e in ("not_in_install_set", "installed_unused", "not_installed"):
        return "not_installed"
    return "runtime_internal"


def supply_decision(suspicion: str, exposure: Optional[str]) -> str:
    return SUPPLY_TABLE[suspicion if suspicion in SUPPLY_TABLE else "low"][SUPPLY_COLUMNS.index(exposure_column(exposure))]


BASE_PRIORITY = {"Act": "critical", "Attend": "high", "Track*": "medium", "Track": "low"}


def priority(decision: str, *, scope: str, exposure_col: Optional[str], kev: Optional[bool], sensitivity: str,
             inputs_by: str, stage_risk: Optional[str]) -> tuple[str, list[str], bool]:
    """(priority, reasons, downgrade_limited). Modifiers are applied in the documented order."""
    p = BASE_PRIORITY[decision]
    reasons = [f"decision {decision} → base priority {p}"]
    if scope in ("dev", "test", "test_only", "build") and exposure_col != "install_or_ci":
        if band_idx(p) > 0:
            reasons.append(f"{scope}-only dependency → capped at low")
        p = "low"
    if exposure_col == "not_installed":
        if band_idx(p) > 0:
            reasons.append("not installed / never imported → capped at low (remove it cheaply)")
        p = "low"
    if sensitivity == "high" and inputs_by == "rules" and band_idx(p) < band_idx("high") and scope == "runtime":
        p = BANDS[band_idx(p) + 1]
        reasons.append("touches high-sensitivity code (secrets, payments, auth or DB writes) → +1 band")
    if kev and scope == "runtime" and band_idx(p) < band_idx("high"):
        p = "high"
        reasons.append("listed in CISA KEV and runtime → at least high")
    limited = False
    if stage_risk and band_idx(stage_risk) - band_idx(p) >= 2:
        newp = BANDS[band_idx(stage_risk) - 1]
        reasons.append(f"contextual result ({p}) is far below the rule-based risk ({stage_risk}); limited to one band "
                       f"down ({newp}) until a human confirms the downgrade")
        p, limited = newp, True
    return p, reasons, limited
