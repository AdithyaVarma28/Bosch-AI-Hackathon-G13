"""Stage 5 data contracts (docs/stage5.md): Signal, AnomalyInvestigation.

Four values per finding are never mixed: **suspicion**, **exposure**, **project risk**, **confidence**.
Metadata-only signals are at most ``medium``; the word "malicious" is never used.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel

from guardian.stage3_knowledge.schema import Evidence

Strength = Literal["weak", "medium", "strong"]
STRENGTH_RANK = {"weak": 0, "medium": 1, "strong": 2}
EXPOSURES = ("install_path", "runtime_public", "runtime_internal", "build_env", "installed_unused",
             "not_in_install_set", "unknown")


class Signal(BaseModel):
    signal_id: str = ""
    detector: str                       # D1..D6
    check: str
    subject: str                        # graph node id (pkg:..., file:..., image:..., workflow:..., lockfile:...)
    subject_label: str = ""
    data: dict[str, Any] = {}           # what triggered the rule
    context: dict[str, Any] = {}        # metadata shown to the agent/user, not used for strength
    commit: Optional[str] = None
    evidence: list[dict] = []           # {"file","line"/"lines"} | {"package_file","lines"} | {"pypi": name} | {"commit"}
    strength: Strength
    metadata_only: bool = False
    behaviour: bool = False             # the signal is based on code/package behaviour
    text: str = ""


class Behaviour(BaseModel):
    type: str
    file: str                           # repo path or "pkg:<name>@<version>/<path>"
    lines: str
    detail: str = ""


class AnomalyClaim(BaseModel):
    text: str
    evidence: list[Evidence] = []
    verified: Optional[bool] = None


class AnomalyInvestigation(BaseModel):
    subject: str
    signals: list[str] = []
    normal_explanation: Optional[str] = None
    normal_explanation_verified: bool = False
    behaviour: list[Behaviour] = []
    capability: str = ""
    exposure: str = "unknown"
    exposure_note: str = ""
    usage_in_repo: dict[str, Any] = {}
    claims: list[AnomalyClaim] = []
    unknowns: list[str] = []
    dropped: list[str] = []
    tool_calls_used: int = 0
    budget_exhausted: bool = False
    light_pass: bool = False
    discovered_by: Literal["ai", "algorithm"] = "algorithm"
