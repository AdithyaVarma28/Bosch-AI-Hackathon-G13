"""Stage 3 contracts shared by graph, detectors, agent and report."""
from typing import Literal

from pydantic import BaseModel, model_validator

from guardian.purl import finding_id

NodeStatus = Literal["ok", "degraded", "skipped", "failed"]


class Evidence(BaseModel):
    id: str
    kind: Literal["raw", "derived"]
    source: str
    locator: str
    excerpt: str
    sha256: str
    captured_at: str
    run_id: str


class Origin(BaseModel):
    registry: str | None = None
    resolved_url: str | None = None
    integrity: str | None = None
    source_repo: str | None = None
    license: str | None = None
    sdist_only: bool = False


class Component(BaseModel):
    purl: str
    name: str
    version: str
    ecosystem: Literal["pypi"] = "pypi"
    scope: Literal["prod", "dev", "build", "test", "unknown"] = "unknown"
    direct: bool = False
    origin: Origin = Origin()
    evidence_ids: list[str] = []


class DepEdge(BaseModel):
    src: str
    dst: str
    kind: Literal["DECLARES", "HAS_ARTIFACT", "DEPENDS_ON", "IMPORTS"] = "DEPENDS_ON"
    evidence_status: Literal[
        "verified", "declared", "registry_derived", "statically_observed", "unknown"
    ] = "verified"
    evidence_ids: list[str] = []


class Declaration(BaseModel):
    project: str
    package: str
    ecosystem: str = "pypi"
    requested_range: str
    scope: str
    source_file: str
    line: int


class UsageRef(BaseModel):
    project: str
    source_file: str
    line: int
    specifier: str
    package: str | None = None
    mapping_status: Literal["mapped", "relative", "stdlib", "unmapped", "dynamic_unresolved"]
    language: Literal["python"] = "python"
    evidence_ids: list[str] = []


class RepoRef(BaseModel):
    url: str
    owner: str
    name: str
    branch: str | None = None
    commit: str
    scan_id: str
    license: str | None = None
    clone_path: str
    history_available: bool = False


class Finding(BaseModel):
    cls: Literal["vuln", "anomaly", "container", "ci", "secret", "sbom_quality", "discrepancy"]
    attack_class: str | None = None
    subject: str
    title: str
    locator: str
    raw_evidence_ids: list[str] = []
    detector: str
    classification: Literal["C", "S", "W"]
    signals: dict = {}
    status: str = "open"

    @property
    def id(self) -> str:
        return finding_id(self.cls, self.subject, self.locator)


class Claim(BaseModel):
    text: str
    type: Literal["fact", "inference", "unknown"]
    evidence_ids: list[str] = []
    confidence: Literal["low", "medium", "high"]
    verifier_status: Literal["pending", "verified", "downgraded", "rejected"] = "pending"

    @model_validator(mode="after")
    def _fact_needs_evidence(self):
        if self.type == "fact" and not self.evidence_ids:
            raise ValueError("a fact claim must cite at least one evidence id")
        return self


class Explanation(BaseModel):
    finding_id: str
    claims: list[Claim] = []
    counterfactual: str | None = None
    notes: str = ""
    generated_by: str = "rule-based"


class Dossier(BaseModel):
    app_type: str
    exposure: Literal["network_facing", "cli_or_library", "unknown"] = "unknown"
    summary: str = ""
    claims: list[Claim] = []
    limits: list[str] = []
    generated_by: str = "rule-based"
