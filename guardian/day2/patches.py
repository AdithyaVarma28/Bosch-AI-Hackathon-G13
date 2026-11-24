"""Patches as exact-snippet edits ({path, old_text, new_text}). Each old_text must occur exactly once in the file
(old_text "" creates a new file). A unified diff is derived for people; the edits are what gets applied."""
from __future__ import annotations

import difflib
from pathlib import Path
from typing import Optional


class PatchError(ValueError):
    pass


def safe_path(root: Path, rel: str) -> Path:
    rel = (rel or "").replace("\\", "/").lstrip("/")
    if not rel or ".." in Path(rel).parts or rel.startswith(".git/"):
        raise PatchError(f"path not allowed: {rel!r}")
    p = (Path(root) / rel).resolve()
    if Path(root).resolve() not in p.parents:
        raise PatchError(f"path escapes the repository: {rel!r}")
    return p


def _read(p: Path) -> Optional[str]:
    try:
        with open(p, "r", encoding="utf-8", newline="") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _nl(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def apply_edits(root: Path, edits: list[dict], write: bool = False) -> dict[str, tuple[Optional[str], str]]:
    """{path: (before, after)}. Raises PatchError when an edit does not apply. Writes files when write=True."""
    files: dict[str, tuple[Optional[str], str]] = {}
    for ed in edits:
        rel = (ed.get("path") or "").replace("\\", "/").lstrip("/")
        p = safe_path(root, rel)
        before, cur = (files[rel][0], files[rel][1]) if rel in files else (_read(p), _read(p))
        old, new = ed.get("old_text") or "", ed.get("new_text") or ""
        if old == "":
            if cur is not None:
                raise PatchError(f"{rel}: file exists; give old_text to change it")
            cur = new
        else:
            if cur is None:
                raise PatchError(f"{rel}: file not found")
            nl = _nl(cur)
            o = old.replace("\r\n", "\n").replace("\n", nl)
            n = new.replace("\r\n", "\n").replace("\n", nl)
            count = cur.count(o)
            if count != 1:
                raise PatchError(f"{rel}: old_text found {count} times (must be exactly once): {old[:60]!r}")
            cur = cur.replace(o, n, 1)
        files[rel] = (before, cur)
    if write:
        for rel, (_, after) in files.items():
            p = safe_path(root, rel)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write(after)
    return files


def unified_diff(files: dict[str, tuple[Optional[str], str]]) -> str:
    out = []
    for rel, (before, after) in files.items():
        a = (before or "").replace("\r\n", "\n").splitlines(keepends=True)
        b = after.replace("\r\n", "\n").splitlines(keepends=True)
        out += difflib.unified_diff(a, b, fromfile="/dev/null" if before is None else f"a/{rel}", tofile=f"b/{rel}", n=2)
    return "".join(l if l.endswith("\n") else l + "\n" for l in out)


def check(root: Optional[Path], edits: list[dict]) -> tuple[bool, str, str]:
    """(applies, detail, diff)."""
    if not edits:
        return False, "no code change in this proposal", ""
    if root is None:
        return False, "repository is not on disk", ""
    try:
        files = apply_edits(root, edits)
    except PatchError as exc:
        return False, str(exc), ""
    return True, f"{len(edits)} edit(s) in {len(files)} file(s) apply cleanly", unified_diff(files)
