"""Shared state for one Stage 4 run (and the Stage 5 run that reuses its machinery)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from guardian.stage3_knowledge.context import Stage3Context

from .sources import HttpCache, OSVClient


@dataclass
class Budgets:
    deep: int = 25                 # deep investigations per scan
    tool_calls: int = 10           # per investigation
    read_lines: int = 120          # per read_code call
    verifier_retries: int = 1
    concurrency: int = 4           # parallel investigations (LLM rate limits)


@dataclass
class Stage4Context:
    s3: Stage3Context
    cache: HttpCache
    osv: OSVClient
    output_dir: Path
    budgets: Budgets = field(default_factory=Budgets)
    images: list[str] = field(default_factory=list)          # container images to scan with Grype
    sbom_path: Optional[Path] = None
    kev: set[str] = field(default_factory=set)
    coverage: dict[str, Any] = field(default_factory=dict)
    log: Callable[[str], None] = print
    emit: Callable[[dict], None] = lambda event: None        # live activity feed (Stage 6 SSE)
    scan_id: str = ""
    state: dict = field(default_factory=dict)                  # final workflow state (matches, results, cards)

    @property
    def G(self):
        return self.s3.G

    @property
    def llm(self):
        return self.s3.llm
