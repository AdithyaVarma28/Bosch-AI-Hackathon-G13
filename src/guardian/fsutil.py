"""Filesystem helpers shared by collectors: repo walking, safe reads, line lookup."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterator

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "env", "site-packages",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".next", "bower_components", ".idea",
    ".vscode", "coverage", ".eggs", ".guardian_cache",
}
MAX_FILE_BYTES = 2_000_000


def walk_files(root: Path) -> Iterator[Path]:
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for f in filenames:
            p = Path(dirpath) / f
            if p.is_symlink():
                continue
            yield p


def rel(root: Path, p: Path) -> str:
    return p.relative_to(root).as_posix()


def read_text(p: Path, limit: int = MAX_FILE_BYTES) -> str | None:
    try:
        if p.stat().st_size > limit:
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    return sha256_bytes(p.read_bytes())


def find_line(text: str, needle: str, start: int = 1) -> int | None:
    """1-based line number of the first line (>= start) containing needle."""
    for i, line in enumerate(text.splitlines(), 1):
        if i >= start and needle in line:
            return i
    return None


def line_excerpt(text: str, line: int | None, context: int = 0) -> str:
    if not line:
        return ""
    lines = text.splitlines()
    lo, hi = max(1, line - context), min(len(lines), line + context)
    return "\n".join(lines[lo - 1:hi])
