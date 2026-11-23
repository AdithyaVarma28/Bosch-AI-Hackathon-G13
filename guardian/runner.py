"""Subprocess abstraction so tools (git, docker, syft, trivy) can be faked in tests."""
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


class ToolFailed(Exception):
    pass


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[list[str], Path | None, int], RunResult]


def default_runner(cmd: list[str], cwd: Path | None = None, timeout: int = 120) -> RunResult:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ToolFailed(f"{cmd[0]}: {e}") from e
    return RunResult(p.returncode, p.stdout, p.stderr)
