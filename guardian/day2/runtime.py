"""Dynamic validation helpers for the Phase B sandbox: a throwaway virtual environment with the project's real
dependencies, `pip check`, and the repository's own tests run inside that environment.

Static checks read files; these run the code. A venv is created next to the worktree (never inside it, so the rescan
does not see it) with `uv` when it is installed (fast, can fetch a Python build) or `python -m venv` + pip otherwise.
Old pinned packages often have no wheels for the newest Python, so several Python versions are tried in order:
the project's own pin (Dockerfile / .python-version / runtime.txt), then the running interpreter, then 3.12 and 3.11.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "site-packages", "__pycache__", ".tox", "build", "dist"}
REQ_FILES = ("requirements.txt", "requirements-dev.txt", "dev-requirements.txt", "requirements-test.txt",
             "test-requirements.txt", "requirements/dev.txt", "requirements/test.txt")


def _run(cmd: list[str], cwd: Optional[Path] = None, timeout: int = 180, env: Optional[dict] = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, env=env)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as exc:
        return 127, str(exc)


def _tail(text: str, n: int = 2500) -> str:
    return (text or "")[-n:]


def _last_line(text: str) -> str:
    lines = [l for l in (text or "").strip().splitlines() if l.strip()]
    return lines[-1][:220] if lines else ""


def install_enabled(cfg: dict) -> tuple[bool, str]:
    if os.environ.get("GUARDIAN_SANDBOX_INSTALL", "1") == "0":
        return False, "dependency install turned off (GUARDIAN_SANDBOX_INSTALL=0)"
    if cfg.get("offline"):
        return False, "offline scan: installing dependencies needs the package index"
    return True, ""


def project_python(wt: Path) -> Optional[str]:
    """The Python version the project itself pins, if any."""
    probes = [(wt / ".python-version", r"^\s*(\d+\.\d+)"), (wt / "runtime.txt", r"python-(\d+\.\d+)"),
              (wt / "Dockerfile", r"FROM\s+(?:\S+/)?python:(\d+\.\d+)")]
    for f, rx in probes:
        if f.exists():
            m = re.search(rx, f.read_text(encoding="utf-8", errors="replace"), re.I | re.M)
            if m:
                return m.group(1)
    return None


def python_candidates(wt: Path) -> list[str]:
    env = os.environ.get("GUARDIAN_SANDBOX_PYTHON")
    if env:
        return [x.strip() for x in env.split(",") if x.strip()]
    out: list[str] = []
    for v in (project_python(wt), f"{sys.version_info.major}.{sys.version_info.minor}", "3.12", "3.11"):
        if v and v not in out:
            out.append(v)
    return out


def requirement_files(wt: Path) -> list[str]:
    return [r for r in REQ_FILES if (wt / r).exists()]


class Env:
    """A throwaway virtual environment."""

    def __init__(self, path: Path, version: str, tool: str):
        self.path, self.version, self.tool = path, version, tool
        self.python = path / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
        self.full_version = ""

    def pip(self, *args: str) -> list[str]:
        if self.tool == "uv":
            return ["uv", "pip", *args, "--python", str(self.python)]
        return [str(self.python), "-m", "pip", *args]

    def install(self, args: list[str], cwd: Optional[Path] = None, timeout: int = 600) -> tuple[int, str, str]:
        cmd = self.pip("install", "-q", *args)
        code, out = _run(cmd, cwd=cwd, timeout=timeout)
        return code, out, " ".join(Path(c).name if i == 0 else c for i, c in enumerate(cmd))


def create_env(path: Path, version: str) -> tuple[Optional[Env], str]:
    shutil.rmtree(path, ignore_errors=True)
    if shutil.which("uv"):
        code, out = _run(["uv", "venv", "-q", "--python", version, str(path)], timeout=300)
        if code != 0:
            return None, _last_line(out) or f"uv could not create a Python {version} environment"
        env = Env(path, version, "uv")
    else:
        exe = sys.executable
        if version != f"{sys.version_info.major}.{sys.version_info.minor}":
            if os.name == "nt" and shutil.which("py"):
                code, exe_out = _run(["py", f"-{version}", "-c", "import sys; print(sys.executable)"], timeout=30)
                if code != 0:
                    return None, f"Python {version} is not installed"
                exe = exe_out.strip().splitlines()[-1]
            else:
                found = shutil.which(f"python{version}")
                if not found:
                    return None, f"Python {version} is not installed"
                exe = found
        code, out = _run([exe, "-m", "venv", str(path)], timeout=300)
        if code != 0:
            return None, _last_line(out)
        env = Env(path, version, "pip")
    code, out = _run([str(env.python), "-c", "import platform; print(platform.python_version())"], timeout=30)
    env.full_version = out.strip() if code == 0 else version
    return env, ""


def make_project_env(wt: Path, path: Path, step: Callable[[str], None]) -> tuple[Optional[Env], dict]:
    """Create a venv and install the project's dependencies as they are at HEAD (before the patch).
    Tries several Python versions; returns the first environment where the install succeeds."""
    reqs = requirement_files(wt)
    info: dict = {"requirements": reqs, "attempts": [], "tool": "uv" if shutil.which("uv") else "pip"}
    if not reqs and not (wt / "pyproject.toml").exists() and not (wt / "setup.py").exists():
        info["detail"] = "no requirements file, pyproject.toml or setup.py to install from"
        return None, info
    args = [a for r in reqs for a in ("-r", r)] or ["."]
    for ver in python_candidates(wt):
        step(f"creating a throwaway Python {ver} environment and installing the project's dependencies (before the patch)…")
        env, err = create_env(path, ver)
        if env is None:
            info["attempts"].append({"python": ver, "ok": False, "error": err})
            continue
        code, out, cmd = env.install(args, cwd=wt)
        info["attempts"].append({"python": env.full_version or ver, "ok": code == 0, "command": cmd,
                                 "error": "" if code == 0 else _last_line(out), "log": _tail(out, 1200)})
        if code == 0:
            info.update(python=env.full_version, command=cmd)
            return env, info
    shutil.rmtree(path, ignore_errors=True)
    info["detail"] = "the project's dependencies did not install on any tried Python version"
    return None, info


TOOL_PKGS = {"pytest", "pluggy", "iniconfig", "colorama", "exceptiongroup", "tomli", "pygments"}  # our test runner


def _conflicts(text: str) -> list[str]:
    """Conflict lines of `uv pip check` ("The package `x` requires ...") or `pip check` ("x 1.0 has requirement ...")."""
    return [l.strip() for l in text.splitlines()
            if re.match(r"\s*The package `[^`]+` requires", l) or re.search(r" has requirement ", l)]


def _subject(line: str) -> str:
    m = re.match(r"(?:The package `([^`]+)`|([A-Za-z0-9_.\-]+))", line)
    return ((m.group(1) or m.group(2)) if m else "").lower()


def pip_check(env: Env, baseline: Optional[list[str]] = None) -> dict:
    """`pip check` on the installed set. Only conflicts that are new compared with the baseline (before the patch)
    and that are not caused by Guardian's own test runner count."""
    code, out = _run(env.pip("check"), timeout=120)
    text = "\n".join(l for l in out.splitlines() if not l.startswith("Using Python"))
    lines = _conflicts(text)
    n = re.search(r"Checked (\d+) packages", text)
    ours = [l for l in lines if _subject(l) in TOOL_PKGS]
    known = [l for l in lines if l not in ours and l in (baseline or [])]
    new = [l for l in lines if l not in ours and l not in known]
    res = {"conflicts": lines, "ignored_tool": ours, "preexisting": known, "new": new, "output": _tail(text, 1500)}
    if new:
        res.update(status="fail", detail="; ".join(new[:3]))
    else:
        note = [f"{len(known)} conflict(s) already there before the patch" if known else "",
                f"{len(ours)} caused by the test runner ignored" if ours else ""]
        res.update(status="pass", detail=(f"{n.group(1)} installed packages checked, no new conflict" if n else "no new conflict")
                   + "".join(f"; {x}" for x in note if x))
    return res


# ------------------------------------------------------------------ tests
def discover_tests(wt: Path) -> list[str]:
    """Test files the repository ships. pytest's default only collects test_*.py / *_test.py; projects such as
    Flask tutorials keep unittest cases in tests.py, so those names are collected explicitly."""
    found: list[str] = []
    for p in wt.rglob("*.py"):
        rel = p.relative_to(wt)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]) or rel.as_posix().startswith("tests/guardian/"):
            continue                                   # Guardian's own security tests are run separately
        n = p.name
        if n.startswith("test_") or n.endswith("_test.py") or n in ("tests.py", "test.py"):
            found.append(rel.as_posix())
    return sorted(found)[:200]


def run_tests(wt: Path, env: Optional[Env], files: list[str]) -> dict:
    if not files:
        return {"status": "n/a", "summary": "the repository has no test files", "failed": 0, "passed": 0, "ran": 0}
    if env is None:
        return {"status": "n/a", "summary": "tests not run: the project's dependencies could not be installed",
                "failed": 0, "passed": 0, "ran": 0}
    cmd = [str(env.python), "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-header", "-o", "addopts=", *files]
    env_vars = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "VIRTUAL_ENV", "DATABASE_URL")}
    env_vars.update(PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    code, out = _run(cmd, cwd=wt, timeout=300, env=env_vars)
    passed = sum(int(x) for x in re.findall(r"(\d+) passed", out))
    failed = sum(int(x) for x in re.findall(r"(\d+) failed", out))
    errors = sum(int(x) for x in re.findall(r"(\d+) errors?\b", out))
    ran = passed + failed + errors
    status = "ok" if code == 0 and ran else ("empty" if code == 5 or not ran else "failing")
    return {"status": status, "code": code, "passed": passed, "failed": failed + errors, "ran": ran,
            "summary": _last_line(out) or f"pytest exit code {code}", "log": _tail(out, 3000),
            "command": "python -m pytest -q " + " ".join(files[:6]) + (" …" if len(files) > 6 else "")}


def ensure_pytest(env: Env) -> None:
    code, _ = _run([str(env.python), "-c", "import pytest"], timeout=60)
    if code != 0:
        env.install(["pytest"], timeout=300)
