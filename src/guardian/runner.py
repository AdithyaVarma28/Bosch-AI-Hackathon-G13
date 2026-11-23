"""Subprocess runner. Always argument lists, never a shell; injectable for tests."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str


class ToolFailed(RuntimeError):
    pass


Runner = Callable[[list[str], "Path | None", int], RunResult]


def default_runner(cmd: list[str], cwd: Path | None = None, timeout: int = 300) -> RunResult:
    if not shutil.which(cmd[0]):
        raise ToolFailed(f"{cmd[0]} not found on PATH")
    try:
        p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, timeout=timeout,
                           text=True, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        raise ToolFailed(f"{cmd[0]} timed out after {timeout}s") from e
    except OSError as e:
        raise ToolFailed(f"{cmd[0]} failed to start: {e}") from e
    return RunResult(p.returncode, p.stdout or "", p.stderr or "")


def git(repo: Path, *args: str, runner: Runner = default_runner, timeout: int = 120) -> str:
    r = runner(["git", "-c", "core.quotepath=off", *args], repo, timeout)
    if r.returncode != 0:
        raise ToolFailed(f"git {' '.join(args)}: {r.stderr.strip()[:300]}")
    return r.stdout


_docker_ok: bool | None = None


def docker_available(runner: Runner = default_runner) -> bool:
    global _docker_ok
    if _docker_ok is None:
        try:
            _docker_ok = runner(["docker", "info", "--format", "{{.ServerVersion}}"], None, 20).returncode == 0
        except ToolFailed:
            _docker_ok = False
    return _docker_ok
