from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RepoInfo(BaseModel):
    name: str
    commit: str
    branch: Optional[str] = None
    scanned_at: str


class DeclaredDependency(BaseModel):
    name: str
    spec: str = ""
    kind: str = "registry"  # registry | vcs | url | local
    dev: bool = False
    extras: List[str] = Field(default_factory=list)
    markers: Optional[str] = None
    source_file: str
    line: int
    discovered_by: str = "manifest"


class PackageIndex(BaseModel):
    url: str
    type: str = "index-url"  # index-url | extra-index-url | poetry-source | uv-index
    source_file: str
    line: int
    discovered_by: str = "manifest"


class ResolvedPackage(BaseModel):
    purl: str
    name: str
    version: str
    direct: bool = False
    required_by: List[str] = Field(default_factory=list)
    requires: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    source: str = "pip-report"  # lockfile | pip-report | sbom
    discovered_by: str = "resolver"


class PackageMetadata(BaseModel):
    version_uploaded: Optional[str] = None
    first_release: Optional[str] = None
    release_count: int = 0
    maintainers: List[Any] = Field(default_factory=list)
    project_urls: Dict[str, str] = Field(default_factory=dict)
    yanked: bool = False
    sdist_only: bool = False
    hashes: List[str] = Field(default_factory=list)


class WorkflowAction(BaseModel):
    uses: str
    ref: str
    pinned_to_sha: bool = False
    line: int


class WorkflowRunStep(BaseModel):
    line: int
    cmd: str


class CIWorkflow(BaseModel):
    file: str
    triggers: List[str] = Field(default_factory=list)
    permissions: Optional[Any] = None
    actions: List[WorkflowAction] = Field(default_factory=list)
    run_steps: List[WorkflowRunStep] = Field(default_factory=list)
    secrets_used: List[str] = Field(default_factory=list)
    discovered_by: str = "yaml"


class ContainerBaseImage(BaseModel):
    ref: str
    tag: Optional[str] = None
    digest: Optional[str] = None
    line: int


class ContainerPipInstall(BaseModel):
    line: int
    cmd: str


class ContainerRemoteFetch(BaseModel):
    line: int
    cmd: str


class ContainerFile(BaseModel):
    file: str
    base_images: List[ContainerBaseImage] = Field(default_factory=list)
    pip_installs: List[ContainerPipInstall] = Field(default_factory=list)
    remote_fetches: List[ContainerRemoteFetch] = Field(default_factory=list)
    multi_stage: List[str] = Field(default_factory=list)
    discovered_by: str = "dockerfile"


class DependencyCommitDiff(BaseModel):
    commit: str
    date: str
    author: str
    message: str
    files_changed: List[str] = Field(default_factory=list)
    added: List[str] = Field(default_factory=list)
    removed: List[str] = Field(default_factory=list)
    changed: List[Dict[str, Any]] = Field(default_factory=list)


class DocsInventory(BaseModel):
    readme: Optional[str] = None
    doc_files: List[str] = Field(default_factory=list)
    previews: Dict[str, str] = Field(default_factory=dict)


class EnvFileInventory(BaseModel):
    file: str
    var_names: List[str] = Field(default_factory=list)
    line_count: int = 0


class ComposeService(BaseModel):
    file: str
    name: str
    image: Optional[str] = None
    digest: Optional[str] = None
    ports: List[str] = Field(default_factory=list)
    depends_on: List[str] = Field(default_factory=list)
    line: int


class ConfigInventory(BaseModel):
    env_files: List[EnvFileInventory] = Field(default_factory=list)
    config_files: List[str] = Field(default_factory=list)
    compose_services: List[ComposeService] = Field(default_factory=list)
    migration_dirs: List[str] = Field(default_factory=list)


class ScanFacts(BaseModel):
    repo: RepoInfo
    declared_dependencies: List[DeclaredDependency] = Field(default_factory=list)
    package_indexes: List[PackageIndex] = Field(default_factory=list)
    resolved_packages: List[ResolvedPackage] = Field(default_factory=list)
    sbom_path: Optional[str] = None
    package_metadata: Dict[str, PackageMetadata] = Field(default_factory=dict)
    ci_workflows: List[CIWorkflow] = Field(default_factory=list)
    containers: List[ContainerFile] = Field(default_factory=list)
    dependency_history: List[DependencyCommitDiff] = Field(default_factory=list)
    docs: DocsInventory = Field(default_factory=DocsInventory)
    config: ConfigInventory = Field(default_factory=ConfigInventory)
    file_hashes: Dict[str, str] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)


# The team's Stage 1 contract is ScanFacts; "Facts" is the name the rest of the code base uses.
Facts = ScanFacts
