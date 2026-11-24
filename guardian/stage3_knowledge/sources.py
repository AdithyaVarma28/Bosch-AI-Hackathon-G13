"""Read-only, sandboxed access to the scanned repo for 3B (short function bodies) and 3D tools.

Never executes repo code. Never reads secret files (.env*, keys, certificates).
"""
from __future__ import annotations

import fnmatch
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Optional

SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "build", "dist",
             "site-packages", ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode"}
SECRET_FILE_PATTERNS = (".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "*.p12", "*.pfx",
                        "*secret*", "credentials*", ".netrc", ".pypirc")
MAX_FILE_BYTES = 1_000_000


def is_secret_file(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if name.endswith(".py") and not name.startswith(".env"):
        return False  # source code (e.g. secrets_manager.py) is readable; values live in config files
    return any(fnmatch.fnmatch(name, p) for p in SECRET_FILE_PATTERNS)


class RepoSource:
    def __init__(self, root: Optional[str | Path]):
        self.root = Path(root).resolve() if root and Path(root).exists() else None

    @property
    def available(self) -> bool:
        return self.root is not None

    def _safe(self, rel: str) -> Path:
        if not self.root:
            raise FileNotFoundError("repository source is not available to this scan")
        rel = str(rel).replace("\\", "/").lstrip("/")
        if is_secret_file(rel):
            raise PermissionError(f"refusing to read secret-like file {rel}")
        p = (self.root / rel).resolve()
        if not p.is_relative_to(self.root):
            raise PermissionError("path escapes the repository root")
        return p

    def read_lines(self, rel: str, start: int = 1, end: Optional[int] = None) -> list[tuple[int, str]]:
        p = self._safe(rel)
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("file too large")
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(start or 1))
        end = min(len(lines), int(end or len(lines)))
        return [(i, lines[i - 1]) for i in range(start, end + 1)]

    def iter_files(self, glob: str = "**/*.py"):
        if not self.root:
            return
        for p in sorted(self.root.rglob("*")):
            if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(self.root).parts):
                continue
            rel = p.relative_to(self.root).as_posix()
            if is_secret_file(rel):
                continue
            if fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(rel, glob.removeprefix("**/")):
                yield rel, p

    def grep(self, pattern: str, glob: str = "**/*.py", max_results: int = 50) -> list[dict]:
        if len(pattern) > 200:
            raise ValueError("pattern too long")
        rx = re.compile(pattern)
        out: list[dict] = []
        for rel, p in self.iter_files(glob):
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if rx.search(line[:2000]):
                    out.append({"file": rel, "line": i, "text": line.strip()[:200]})
                    if len(out) >= max_results:
                        return out
        return out

    # ------------------------------------------------------------------ git
    @property
    def is_git(self) -> bool:
        return bool(self.root and (self.root / ".git").exists())

    def git(self, *args: str, timeout: int = 20) -> Optional[str]:
        if not self.is_git:
            return None
        try:
            res = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, text=True,
                                 timeout=timeout, encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return None
        return res.stdout if res.returncode == 0 else None
