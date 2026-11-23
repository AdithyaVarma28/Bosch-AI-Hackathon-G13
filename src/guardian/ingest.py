"""S0 Ingest: validate the repo URL (or local path) and clone at a fixed commit."""
from __future__ import annotations

import re
import shutil
from pathlib import Path

from .models import RepoRef
from .runner import Runner, ToolFailed, default_runner, git


class InvalidRepoUrl(ValueError):
    pass


class RepoTooLarge(RuntimeError):
    pass


class CloneFailed(RuntimeError):
    pass


_GH = re.compile(r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?(?:/tree/([^\s?#]+))?/?$")


def parse_repo_url(url: str) -> tuple[str, str, str | None]:
    url = (url or "").strip()
    if ".." in url:
        raise InvalidRepoUrl(f"path traversal not allowed: {url}")
    m = _GH.match(url)
    if not m:
        raise InvalidRepoUrl(f"only public https://github.com/<owner>/<repo> URLs are supported: {url!r}")
    owner, name, branch = m.groups()
    if name in {"", ".", ".git"}:
        raise InvalidRepoUrl(f"missing repository name: {url}")
    return owner, name, branch.rstrip("/") if branch else None


def _dir_mb(p: Path) -> float:
    total = 0
    for f in p.rglob("*"):
        if ".git" in f.parts:
            continue
        try:
            if f.is_file():
                total += f.stat().st_size
        except OSError:
            pass
    return total / 1_048_576


def _head_info(repo: Path, runner: Runner) -> tuple[str | None, bool]:
    try:
        commit = git(repo, "rev-parse", "HEAD", runner=runner).strip()
        count = int(git(repo, "rev-list", "--count", "HEAD", runner=runner).strip() or 0)
        return commit, count > 1
    except (ToolFailed, ValueError):
        return None, False


def open_local(path: str | Path, runner: Runner = default_runner) -> RepoRef:
    """Scan a local checkout in place (no copy). Used for fixtures and offline demos."""
    p = Path(path).resolve()
    if not p.is_dir():
        raise InvalidRepoUrl(f"not a directory: {path}")
    commit, hist = _head_info(p, runner) if (p / ".git").exists() else (None, False)
    return RepoRef(url=str(p), name=p.name, commit=commit, clone_path=str(p),
                   history_available=hist, is_local=True)


def clone_repo(url: str, dest: Path, runner: Runner = default_runner, *, depth: int = 50,
               max_mb: int = 500) -> RepoRef:
    owner, name, branch = parse_repo_url(url)
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", str(depth), "--no-tags", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [f"https://github.com/{owner}/{name}.git", str(dest)]
    try:
        r = runner(cmd, None, 600)
    except ToolFailed as e:
        raise CloneFailed(str(e)) from e
    if r.returncode != 0:
        raise CloneFailed(r.stderr.strip()[:500])
    if _dir_mb(dest) > max_mb:
        shutil.rmtree(dest, ignore_errors=True)
        raise RepoTooLarge(f"repository exceeds {max_mb} MB")
    commit, hist = _head_info(dest, runner)
    return RepoRef(url=url, owner=owner, name=name, branch=branch, commit=commit,
                   clone_path=str(dest), history_available=hist)


def ingest(target: str, work_dir: Path, runner: Runner = default_runner, depth: int = 50) -> RepoRef:
    """Accept either a GitHub URL or a local directory."""
    if Path(target).exists():
        return open_local(target, runner)
    owner, name, _ = parse_repo_url(target)
    return clone_repo(target, Path(work_dir) / "clones" / f"{owner}__{name}", runner, depth=depth)
