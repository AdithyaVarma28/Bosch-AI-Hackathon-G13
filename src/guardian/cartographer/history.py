"""Dependency history (time travel input): commits touching dependency files and package-list diffs.

Uses `git show <commit>:<path>` only; never checks anything out.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath

from ..models import HistoryEntry, VersionChange
from ..runner import Runner, ToolFailed, default_runner, git
from ..sbom.lockfiles import is_lockfile, lock_index, parse_lockfile
from .manifests import is_manifest, parse_manifest

SEP = "\x1e"


def is_tracked_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return (is_manifest(name) or is_lockfile(name) or name.lower().startswith("dockerfile")
            or path.startswith(".github/workflows/") or name.startswith("docker-compose"))


def file_at(repo: Path, commit: str, path: str, runner: Runner = default_runner) -> str | None:
    try:
        return git(repo, "show", f"{commit}:{path}", runner=runner)
    except ToolFailed:
        return None


def parents(repo: Path, commit: str, runner: Runner = default_runner) -> list[str]:
    try:
        out = git(repo, "rev-list", "--parents", "-n", "1", commit, runner=runner).split()
        return out[1:]
    except ToolFailed:
        return []


def package_versions(path: str, text: str | None) -> dict[str, str | None]:
    """'eco:name' -> version (or declared spec) for one dependency file at one point in time."""
    if text is None:
        return {}
    name = PurePosixPath(path).name
    if is_lockfile(name):
        return {k: v["version"] for k, v in lock_index(parse_lockfile(path, text)).items()}
    if is_manifest(name):
        p = parse_manifest(path, text)
        out = {}
        for d in p.deps:
            spec = (d.spec or "").strip()
            out[f"{d.ecosystem}:{d.name}"] = spec.lstrip("=^~ ") if spec else None
        return out
    return {}


def commit_log(repo: Path, n: int, runner: Runner = default_runner) -> list[dict]:
    fmt = SEP + "%H%x1f%aI%x1f%an%x1f%s"
    out = git(repo, "log", f"-n{n}", "--name-only", f"--format={fmt}", runner=runner)
    commits = []
    for chunk in out.split(SEP):
        chunk = chunk.strip("\n")
        if not chunk:
            continue
        head, *files = chunk.split("\n")
        h, date, author, msg = (head.split("\x1f") + ["", "", "", ""])[:4]
        commits.append({"commit": h, "date": date, "author": author, "message": msg,
                        "files": [f for f in files if f.strip()]})
    return commits


def dependency_history(repo: Path, n: int = 50, runner: Runner = default_runner) -> tuple[list[HistoryEntry], list[str]]:
    errors: list[str] = []
    try:
        commits = commit_log(repo, n, runner)
    except ToolFailed as e:
        return [], [f"git history unavailable: {e}"]
    entries = []
    for c in commits:
        files = [f for f in c["files"] if is_tracked_file(f)]
        if not files:
            continue
        par = parents(repo, c["commit"], runner)
        before: dict[str, str | None] = {}
        after: dict[str, str | None] = {}
        dep_files = [f for f in files if is_manifest(PurePosixPath(f).name) or is_lockfile(PurePosixPath(f).name)]
        # Prefer lockfiles for versions when both changed; manifests fill the rest.
        for f in sorted(dep_files, key=lambda p: 0 if is_lockfile(PurePosixPath(p).name) else 1, reverse=True):
            after.update(package_versions(f, file_at(repo, c["commit"], f, runner)))
            if par:
                before.update(package_versions(f, file_at(repo, par[0], f, runner)))
        added = sorted(k.split(":", 1)[1] for k in after.keys() - before.keys()) if par else []
        removed = sorted(k.split(":", 1)[1] for k in before.keys() - after.keys()) if par else []
        changed = []
        for k in sorted(after.keys() & before.keys()):
            if after[k] != before[k]:
                eco, name = k.split(":", 1)
                changed.append(VersionChange(name=name, ecosystem=eco, **{"from": before[k], "to": after[k]}))
        entries.append(HistoryEntry(commit=c["commit"], date=c["date"], author=c["author"], message=c["message"],
                                    files_changed=files, added=added, removed=removed, changed=changed,
                                    baseline=not par))
    if commits and not parents(repo, commits[-1]["commit"], runner) and len(commits) >= n:
        errors.append("history truncated (shallow clone); oldest commit treated as baseline")
    return entries, errors
