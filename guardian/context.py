from dataclasses import dataclass, field
from typing import Any


@dataclass
class RunContext:
    """Passed to every detector as detect_xxx(ctx) -> list[Finding]."""

    repo: Any = None
    facts: Any = None
    index: Any = None
    components: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    graph: Any = None
    store: Any = None
    runner: Any = None
    dossier: Any = None
