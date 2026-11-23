"""Pydantic v2 data contracts. These are the only cross-module contracts."""
from __future__ import annotations

import hashlib
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

Ecosystem = Literal["npm", "pypi", "other"]
Scope = Literal["prod", "dev", "optional", "build", "test", "unknown"]
NodeStatus = Literal["ok", "degraded", "skipped", "failed"]
DiscoveredBy = Literal[
    "manifest", "lockfile", "pip-report", "npm-resolve", "syft", "trivy", "pypi", "npm-registry",
    "git", "ast", "regex", "yaml", "dockerfile", "osv", "rule", "ai",
]


class Evidence(BaseModel):
    id: str
    kind: Literal["raw", "derived"]
    source: str
    locator: str
    excerpt: str
    sha256: str
    captured_at: str
    run_id: str


# --------------------------------------------------------------------------- repo
class RepoRef(BaseModel):
    url: str
    owner: str | None = None
    name: str
    branch: str | None = None
    commit: str | None = None
    clone_path: str
    history_available: bool = False
    is_local: bool = False


# --------------------------------------------------------------------------- stage 1: facts
class DeclaredDependency(BaseModel):
    name: str
    ecosystem: Ecosystem
    spec: str | None = None
    kind: Literal["registry", "vcs", "url", "path", "alias"] = "registry"
    scope: Scope = "prod"
    extras: list[str] = Field(default_factory=list)
    markers: str | None = None
    source_file: str
    line: int | None = None
    discovered_by: DiscoveredBy = "manifest"
    evidence_id: str | None = None


class PackageIndex(BaseModel):
    url: str
    type: str  # index-url | extra-index-url | poetry-source | uv-index | pipfile-source | npm-registry
    source_file: str
    line: int | None = None
    discovered_by: DiscoveredBy = "manifest"
    evidence_id: str | None = None


class Manifest(BaseModel):
    path: str
    ecosystem: Ecosystem
    project_name: str | None = None
    dependency_count: int = 0
    entry_points: dict[str, str] = Field(default_factory=dict)


class LifecycleScript(BaseModel):
    path: str
    name: str
    command: str
    line: int | None = None
    ecosystem: Ecosystem = "npm"
    evidence_id: str | None = None


class LockfileHealth(BaseModel):
    manifest: str
    ecosystem: Ecosystem
    lockfile: str | None = None
    present: bool = False
    committed: bool = False
    ignored_by: str | None = None
    version: int | None = None
    has_integrity: bool = False
    in_sync: bool | None = None
    resolution: Literal["committed", "resolved_not_committed", "absent"] = "absent"
    evidence_id: str | None = None


class DockerStage(BaseModel):
    base_image: str
    tag: str | None = None
    digest: str | None = None
    name: str | None = None
    line: int


class DockerInstr(BaseModel):
    line: int
    op: str
    args: str


class DockerfileFacts(BaseModel):
    file: str
    stages: list[DockerStage] = Field(default_factory=list)
    user: str | None = None
    exposed_ports: list[int] = Field(default_factory=list)
    instructions: list[DockerInstr] = Field(default_factory=list)
    package_installs: list[DockerInstr] = Field(default_factory=list)
    remote_fetches: list[DockerInstr] = Field(default_factory=list)
    discovered_by: DiscoveredBy = "dockerfile"
    evidence_id: str | None = None


class UsesRef(BaseModel):
    line: int | None
    uses: str
    action: str
    ref: str | None
    pinned_to_sha: bool
    job: str | None = None


class RunStep(BaseModel):
    line: int | None
    cmd: str
    job: str | None = None


class WorkflowFacts(BaseModel):
    file: str
    name: str | None = None
    triggers: list[str] = Field(default_factory=list)
    permissions: Any = None
    job_permissions: dict[str, Any] = Field(default_factory=dict)
    actions: list[UsesRef] = Field(default_factory=list)
    run_steps: list[RunStep] = Field(default_factory=list)
    secrets_used: list[str] = Field(default_factory=list)
    discovered_by: DiscoveredBy = "yaml"
    evidence_id: str | None = None


class ComposeService(BaseModel):
    file: str
    name: str
    image: str | None = None
    tag: str | None = None
    digest: str | None = None
    build: bool = False
    ports: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    line: int | None = None


class EnvFile(BaseModel):
    file: str
    var_names: list[str]


class ConfigInventory(BaseModel):
    env_files: list[EnvFile] = Field(default_factory=list)
    config_files: list[str] = Field(default_factory=list)
    compose_services: list[ComposeService] = Field(default_factory=list)
    migration_dirs: list[str] = Field(default_factory=list)


class VersionChange(BaseModel):
    name: str
    ecosystem: Ecosystem
    from_version: str | None = Field(default=None, alias="from")
    to_version: str | None = Field(default=None, alias="to")

    model_config = {"populate_by_name": True}


class HistoryEntry(BaseModel):
    commit: str
    date: str
    author: str
    message: str
    files_changed: list[str]
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    changed: list[VersionChange] = Field(default_factory=list)
    baseline: bool = False  # first commit in the available history (no parent to diff against)
    discovered_by: DiscoveredBy = "git"


class DocsInventory(BaseModel):
    readme: str | None = None
    readme_excerpt: str | None = None
    doc_files: list[str] = Field(default_factory=list)


class RepoFacts(BaseModel):
    languages: dict[str, int] = Field(default_factory=dict)
    ecosystems: list[Ecosystem] = Field(default_factory=list)
    manifests: list[Manifest] = Field(default_factory=list)
    declared_dependencies: list[DeclaredDependency] = Field(default_factory=list)
    package_indexes: list[PackageIndex] = Field(default_factory=list)
    lockfiles: list[LockfileHealth] = Field(default_factory=list)
    lifecycle_scripts: list[LifecycleScript] = Field(default_factory=list)
    dockerfiles: list[DockerfileFacts] = Field(default_factory=list)
    ci_workflows: list[WorkflowFacts] = Field(default_factory=list)
    other_ci_files: list[str] = Field(default_factory=list)
    config: ConfigInventory = Field(default_factory=ConfigInventory)
    dependency_history: list[HistoryEntry] = Field(default_factory=list)
    docs: DocsInventory = Field(default_factory=DocsInventory)
    errors: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- stage 2: components
class Origin(BaseModel):
    registry: str | None = None
    resolved_url: str | None = None
    integrity: str | None = None
    source_repo: str | None = None
    license: str | None = None
    has_install_script: bool = False


class Component(BaseModel):
    purl: str
    name: str
    version: str | None
    ecosystem: Ecosystem
    scope: Scope = "unknown"
    direct: bool = False
    origin: Origin = Field(default_factory=Origin)
    hashes: list[str] = Field(default_factory=list)
    source: str = "lockfile"  # lockfile | pip-report | npm-resolve | syft | trivy | manifest
    seen_by: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class DepEdge(BaseModel):
    src: str
    dst: str
    source: str = "lockfile"

    def __hash__(self) -> int:  # allow sets of edges
        return hash((self.src, self.dst))


class PackageMetadata(BaseModel):
    version_uploaded: str | None = None
    first_release: str | None = None
    release_count: int | None = None
    maintainers: list[str] = Field(default_factory=list)
    project_urls: dict[str, str] = Field(default_factory=dict)
    source_repo: str | None = None
    yanked: bool | None = None
    deprecated: bool | None = None
    sdist_only: bool | None = None
    registry_hashes: list[str] = Field(default_factory=list)
    status: Literal["live", "cache", "unavailable"] = "unavailable"


class SbomReport(BaseModel):
    tools: dict[str, str] = Field(default_factory=dict)  # tool -> ok | failed: reason
    jaccard: float | None = None
    only_in: dict[str, list[str]] = Field(default_factory=dict)
    confidence: Literal["high", "medium", "low"] = "low"
    resolution: str = "absent"
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- stage 3: code index
class ImportRef(BaseModel):
    name: str
    alias: str | None = None
    kind: Literal["internal", "external", "stdlib", "unknown"]
    line: int
    resolved_file: str | None = None
    distribution: str | None = None
    in_try_except: bool = False
    conditional: bool = False


class Definition(BaseModel):
    id: str
    type: Literal["function", "async_function", "class", "method"]
    name: str
    line: int
    end_line: int | None = None
    decorators: list[str] = Field(default_factory=list)
    params: list[str] = Field(default_factory=list)
    returns: str | None = None
    docstring: str | None = None
    bases: list[str] = Field(default_factory=list)


class CallRef(BaseModel):
    caller: str
    target: str
    kind: Literal["internal", "external", "stdlib", "builtin", "unknown"]
    line: int
    import_name: str | None = None
    resolved_target: str | None = None


class Route(BaseModel):
    framework: str
    method: str
    path: str
    handler: str
    line: int


class SimpleRef(BaseModel):
    """Generic located reference used for several code-index lists."""
    function: str | None = None
    name: str
    line: int
    how: str | None = None
    detail: str | None = None


class DbModel(BaseModel):
    class_id: str
    table: str | None
    fields: list[str] = Field(default_factory=list)
    framework: str
    line: int


class DbAccess(BaseModel):
    function: str | None
    operation: Literal["read", "write", "raw_sql"]
    target: str
    model: str | None = None
    line: int


class ExternalService(BaseModel):
    name: str
    via: Literal["sdk", "url"]
    import_name: str | None = None
    domain: str | None = None
    line: int


class SensitiveCall(BaseModel):
    function: str | None
    category: Literal["network", "subprocess", "code_exec", "deserialize", "file_write", "crypto"]
    target: str
    line: int


class CodeFile(BaseModel):
    path: str
    language: Literal["python", "javascript"]
    module_path: str | None = None
    package_dir: str | None = None
    sha256: str
    loc: int
    is_test: bool = False
    parse_error: str | None = None
    docstring: str | None = None
    imports: list[ImportRef] = Field(default_factory=list)
    definitions: list[Definition] = Field(default_factory=list)
    calls: list[CallRef] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    cli_entrypoints: list[SimpleRef] = Field(default_factory=list)
    input_sources: list[SimpleRef] = Field(default_factory=list)
    env_reads: list[SimpleRef] = Field(default_factory=list)
    db_models: list[DbModel] = Field(default_factory=list)
    db_access: list[DbAccess] = Field(default_factory=list)
    external_services: list[ExternalService] = Field(default_factory=list)
    sensitive_calls: list[SensitiveCall] = Field(default_factory=list)
    string_urls: list[SimpleRef] = Field(default_factory=list)
    dynamic_imports: list[SimpleRef] = Field(default_factory=list)
    name_refs: list[SimpleRef] = Field(default_factory=list)  # non-call uses of imported names (e.g. stripe.api_key = ...)
    discovered_by: DiscoveredBy = "ast"


class CodeCoverage(BaseModel):
    files_total: int = 0
    files_parsed: int = 0
    files_failed: int = 0
    files_cached: int = 0
    internal_calls_resolved: int = 0
    internal_calls_unresolved: int = 0
    dynamic_imports: int = 0


class CodeIndex(BaseModel):
    source_roots: list[str] = Field(default_factory=list)
    import_name_to_distribution: dict[str, str] = Field(default_factory=dict)
    files: list[CodeFile] = Field(default_factory=list)
    coverage: CodeCoverage = Field(default_factory=CodeCoverage)
    errors: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- findings / AI
class Finding(BaseModel):
    cls: Literal["vuln", "anomaly", "container", "ci", "secret", "sbom_quality", "discrepancy"]
    subject: str
    title: str
    locator: str
    detector: str
    classification: Literal["C", "S", "W"] = "C"  # Confirmed (known vuln) | Strong signal | Weak signal
    raw_evidence_ids: list[str] = Field(default_factory=list)
    signals: dict[str, Any] = Field(default_factory=dict)
    attack_class: str | None = None
    band: str | None = None
    band_reason: str | None = None
    status: str = "open"

    @property
    def id(self) -> str:
        return finding_id(self.cls, self.subject, self.locator)


def finding_id(cls: str, subject: str, locator: str) -> str:
    return hashlib.sha256(f"{cls}|{subject}|{locator}".encode()).hexdigest()[:12]


class Claim(BaseModel):
    text: str
    type: Literal["fact", "inference", "unknown"]
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "medium"
    verifier_status: Literal["pending", "verified", "downgraded", "rejected"] = "pending"
    reason: str | None = None

    @model_validator(mode="after")
    def _fact_needs_evidence(self) -> "Claim":
        if self.type == "fact" and not self.evidence_ids:
            raise ValueError("a fact claim must cite at least one evidence id")
        return self


class Explanation(BaseModel):
    finding_id: str
    claims: list[Claim] = Field(default_factory=list)
    counterfactual: str | None = None
    notes: str = ""
    generated_by: str = "rule-based"
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)


class Dossier(BaseModel):
    app_type: str = "unknown"
    exposure: Literal["network_facing", "cli_or_library", "unknown"] = "unknown"
    summary: str = ""
    claims: list[Claim] = Field(default_factory=list)
    limits: list[str] = Field(default_factory=list)
    generated_by: str = "rule-based"
