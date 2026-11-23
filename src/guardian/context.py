"""RunContext: everything a stage/detector needs, passed as one object."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .models import CodeIndex, Component, DepEdge, Dossier, PackageMetadata, RepoFacts, RepoRef, SbomReport
from .runner import Runner, default_runner
from .store import RunStore


@dataclass
class Settings:
    offline: bool = False          # no network calls (OSV, registries, LLM); cache only
    use_llm: bool = True           # LLM agents enabled when a GROQ_API_KEY is present
    use_docker: bool = True        # allow sandboxed resolution / tool images
    history_depth: int = 50
    cache_dir: Path = Path(".guardian_cache")
    max_explanations: int = 10     # Evidence Agent budget per run (top findings by band)
    llm_model: str | None = None


@dataclass
class RunContext:
    repo: RepoRef
    store: RunStore
    settings: Settings = field(default_factory=Settings)
    runner: Runner = default_runner
    facts: RepoFacts | None = None
    components: list[Component] = field(default_factory=list)
    edges: list[DepEdge] = field(default_factory=list)
    sbom_report: SbomReport | None = None
    metadata: dict[str, PackageMetadata] = field(default_factory=dict)
    code_index: CodeIndex | None = None
    graph: Any = None              # guardian.graph.UnifiedGraph
    dossier: Dossier | None = None
    llm: Any = None                # guardian.llm.LLMClient | None
    emit: Callable[[dict], None] = lambda e: None

    @property
    def root(self) -> Path:
        return Path(self.repo.clone_path)
