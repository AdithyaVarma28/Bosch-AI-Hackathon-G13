"""Shared state for one Stage 3 run. All four parts read and write the same graph."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import networkx as nx

from .llm import LLM
from .sources import RepoSource


@dataclass
class Budgets:
    card_calls: int = 30          # 3B: max LLM calls for cards
    questions: int = 20           # 3D: max questions per scan
    steps_per_question: int = 8   # 3D: max tool calls per question
    history_commits: int = 10     # 3C time travel: light snapshots


@dataclass
class Stage3Context:
    G: nx.MultiDiGraph
    facts: dict
    code_index: dict
    llm: LLM
    source: RepoSource
    output_dir: Path
    sbom: Optional[dict] = None
    budgets: Budgets = field(default_factory=Budgets)
    paths: list[dict] = field(default_factory=list)
    blast: dict[str, dict] = field(default_factory=dict)
    changes: dict[str, Any] = field(default_factory=dict)
    cards: dict[str, dict] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    questions: dict[str, Any] = field(default_factory=dict)
    log: Any = print

    @property
    def files_by_path(self) -> dict[str, dict]:
        cache = getattr(self, "_files_by_path", None)
        if cache is None:
            cache = {f.get("path"): f for f in self.code_index.get("files", []) or [] if f.get("path")}
            self._files_by_path = cache
        return cache

    def file_len(self, path: str) -> int:
        """Best-known line count of a file (loc, or the last definition line)."""
        f = self.files_by_path.get(path) or {}
        ends = [d.get("end_line") or d.get("line") or 0 for d in f.get("definitions", []) or []]
        return max([f.get("loc") or 0, *ends])
