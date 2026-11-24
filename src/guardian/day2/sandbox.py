"""S14 Validate the proposed fix in a controlled branch and sandbox ("test before you trust").

1. copy the scanned tree (with history) to <run_dir>/day2/work/..., create branch guardian/fix-<id>, apply the
   approved edits, commit. The scanned checkout is never touched.
2. build: install dependencies (install scripts disabled), compile/build step
3. tests: the repository's own tests, on the ORIGINAL tree and on the patched tree, so pre-existing failures are
   not blamed on the fix. A regression = a test that passes before and fails after.
4. no tests: smoke check (dependencies install and import) -> `smoke_only`, which caps the verdict
Sandbox modes:
  docker  (default) throwaway containers: install with network, tests with --network none, memory/cpu/pid limits,
          no-new-privileges, no host secrets or env passed in
  local   explicit opt-in: runs the repository's code on this machine in a temp copy with a scrubbed environment
  none    nothing is executed; build/test are recorded as skipped and the verdict is at most Partially verified
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..agent.tools import scrub
from ..context import RunContext
from ..runner import RunResult, ToolFailed, docker_available, git
from .models import RemediationCandidate, RemediationPlan, StepResult, TestSummary, ValidationResult
from .patcher import apply_edits, copy_tree, unified_diff
from .store import Day2Store

IMAGES = {"pypi": "python:3.12-slim", "npm": "node:22-slim", "golang": "golang:1.23", "maven": "maven:3.9-eclipse-temurin-21",
          "cargo": "rust:1-slim"}
DOCKER_LIMITS = ["--memory", "2g", "--cpus", "2", "--pids-limit", "512", "--security-opt", "no-new-privileges",
                 "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
                 "--cap-add", "SETUID", "--cap-add", "SETGID", "-e", "HOME=/tmp", "-e", "CI=true",
                 "-e", "PIP_DISABLE_PIP_VERSION_CHECK=1", "-e", "npm_config_update_notifier=false"]
SECRETISH = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|COOKIE|SESSION)", re.I)
LocalRunner = Callable[[list[str], Path, int, dict], RunResult]


def local_runner(cmd: list[str], cwd: Path, timeout: int, env: dict) -> RunResult:
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, timeout=timeout, text=True, encoding="utf-8",
                           errors="replace", env=env)
    except subprocess.TimeoutExpired:
        return RunResult(124, "", f"timed out after {timeout}s")
    except OSError as e:
        return RunResult(127, "", f"failed to start: {e}")
    return RunResult(p.returncode, p.stdout or "", p.stderr or "")


def scrubbed_env() -> dict:
    keep = ("PATH", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "COMSPEC",
            "PATHEXT", "WINDIR", "LANG", "LC_ALL", "PROGRAMDATA", "PROGRAMFILES", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE")
    env = {k: v for k, v in os.environ.items() if k in keep and not SECRETISH.search(k)}
    env["CI"] = "true"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


@dataclass
class Project:
    ecosystem: str
    dir: str                      # repo-relative
    framework: str | None = None  # pytest | npm | go | maven | None
    steps: list[tuple[str, list[str], bool]] = field(default_factory=list)   # (name, argv, needs_network)
    test: list[str] | None = None
    smoke: list[str] | None = None


def _venv_bin(mode: str, root: Path, exe: str) -> str:
    if mode == "docker":
        return f"/w/.guardian-venv/bin/{exe}"
    sub = "Scripts" if os.name == "nt" else "bin"
    return str(root / ".guardian-venv" / sub / (exe + (".exe" if os.name == "nt" else "")))


def detect_projects(ctx: RunContext, root: Path, mode: str) -> list[Project]:
    out: list[Project] = []
    has_py_tests = any((root / d).is_dir() for d in ("tests", "test")) or any(root.glob("test_*.py"))
    reqs = [p for p in ("requirements.txt", "requirements-dev.txt", "requirements/dev.txt") if (root / p).is_file()]
    if reqs or (root / "pyproject.toml").is_file() or (root / "setup.py").is_file():
        py = sys.executable if mode == "local" else "python"
        pip = [_venv_bin(mode, root, "python"), "-m", "pip", "install", "-q"]
        steps = [("venv", [py, "-m", "venv", "/w/.guardian-venv" if mode == "docker" else str(root / ".guardian-venv")], False)]
        if reqs:
            steps.append(("install", pip + sum((["-r", r] for r in reqs), []), True))
        else:
            steps.append(("install", pip + ["."], True))
        if has_py_tests:
            steps.append(("install-pytest", pip + ["pytest"], True))
        steps.append(("compile", [_venv_bin(mode, root, "python"), "-m", "compileall", "-q", "-x",
                                  r"(\.guardian-venv|node_modules|\.git)", "."], False))
        mods = sorted({i.name.split(".")[0] for cf in (ctx.code_index.files if ctx.code_index else []) for i in cf.imports
                       if cf.language == "python" and i.kind == "external" and not cf.is_test})[:15]
        out.append(Project("pypi", ".", "pytest" if has_py_tests else None, steps,
                           test=[_venv_bin(mode, root, "python"), "-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider"] if has_py_tests else None,
                           smoke=[_venv_bin(mode, root, "python"), "-c",
                                  "import importlib,sys\nfor m in sys.argv[1:]: importlib.import_module(m)\nprint('imports ok')", *mods]))
    pj = root / "package.json"
    if pj.is_file():
        try:
            data = json.loads(pj.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
        scripts = data.get("scripts") or {}
        npm = "npm.cmd" if (mode == "local" and os.name == "nt") else "npm"
        node = "node"
        install = [npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund"] if (root / "package-lock.json").is_file() else \
            [npm, "install", "--ignore-scripts", "--no-audit", "--no-fund"]
        steps = [("install", install, True)]
        if "build" in scripts:
            steps.append(("build", [npm, "run", "build"], False))
        real_test = scripts.get("test") and "no test specified" not in scripts.get("test", "")
        deps = sorted((data.get("dependencies") or {}).keys())[:20]
        out.append(Project("npm", ".", "npm" if real_test else None, steps, test=[npm, "test"] if real_test else None,
                           smoke=[node, "-e", "for (const m of process.argv.slice(1)) require.resolve(m); console.log('resolve ok')", *deps]))
    if (root / "go.mod").is_file():
        out.append(Project("golang", ".", "go", [("build", ["go", "build", "./..."], True)], test=["go", "test", "-v", "./..."]))
    if (root / "pom.xml").is_file():
        out.append(Project("maven", ".", "maven", [("build", ["mvn", "-B", "-q", "-DskipTests", "package"], True)],
                           test=["mvn", "-B", "test"]))
    return out


# ----------------------------------------------------------------------------- execution
class Sandbox:
    def __init__(self, ctx: RunContext, d2: Day2Store, mode: str | None = None, local: LocalRunner = local_runner):
        self.ctx, self.d2 = ctx, d2
        self.mode = mode or ctx.settings.sandbox
        self.local = local
        self.timeout = ctx.settings.sandbox_timeout
        self.unavailable: str | None = None
        if self.mode == "docker" and not docker_available(ctx.runner):
            self.unavailable = "Docker daemon unavailable"
        if self.mode not in ("docker", "local", "none"):
            self.unavailable = f"unknown sandbox mode {self.mode}"

    @property
    def effective(self) -> str:
        return "none" if self.unavailable or self.mode == "none" else self.mode

    def run(self, eco: str, root: Path, name: str, argv: list[str], network: bool) -> StepResult:
        t0 = time.time()
        if self.effective == "docker":
            cmd = ["docker", "run", "--rm", "--network", "bridge" if network else "none", *DOCKER_LIMITS,
                   "-v", f"{root.resolve()}:/w", "-w", "/w", IMAGES.get(eco, "debian:12-slim"), *argv]
            try:
                r = self.ctx.runner(cmd, None, self.timeout)
            except ToolFailed as e:
                r = RunResult(125, "", str(e))
        else:
            cmd = argv
            r = self.local(argv, root, self.timeout, scrubbed_env())
        tail = scrub((r.stdout[-2500:] + "\n--- stderr ---\n" + r.stderr[-1500:]).strip())
        ev = self.ctx.store.add_evidence("raw", f"sandbox:{self.effective}", f"{root.parent.name}:{name}",
                                         f"$ {' '.join(argv)[:300]}\nexit {r.returncode}\n{tail}")
        return StepResult(name=name, command=cmd, returncode=r.returncode, ok=r.returncode == 0, summary=_summ(r),
                          seconds=round(time.time() - t0, 1), evidence_id=ev.id)


def _summ(r: RunResult) -> str:
    text = (r.stdout + "\n" + r.stderr).strip().splitlines()
    tail = [l for l in text if l.strip()][-3:]
    return scrub(" | ".join(tail))[:300]


TEST_LINE = re.compile(r"^(PASSED|FAILED|ERROR)\s+(\S+)", re.M)
PYTEST_COUNTS = re.compile(r"(\d+)\s+(passed|failed|errors?)")
GO_LINE = re.compile(r"^\s*--- (PASS|FAIL): (\S+)", re.M)
MVN = re.compile(r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+)")


def parse_tests(framework: str | None, step: StepResult, output: str) -> TestSummary:
    ts = TestSummary(framework=framework, ran=True, exit_code=step.returncode, evidence_id=step.evidence_id)
    if framework == "pytest":
        for kind, tid in TEST_LINE.findall(output):
            (ts.passed_ids if kind == "PASSED" else ts.failed_ids).append(tid)
        for n, kind in PYTEST_COUNTS.findall(output):
            if kind == "passed":
                ts.passed = int(n)
            elif kind == "failed":
                ts.failed = int(n)
            else:
                ts.errors = int(n)
        if step.returncode not in (0, 1, 5) and not ts.failed_ids:     # collection/usage error: whole suite failed
            ts.failed_ids.append("pytest:session")
    elif framework == "go":
        for kind, tid in GO_LINE.findall(output):
            (ts.passed_ids if kind == "PASS" else ts.failed_ids).append(tid)
        ts.passed, ts.failed = len(ts.passed_ids), len(ts.failed_ids)
    elif framework == "maven":
        m = MVN.findall(output)
        if m:
            run, fail, err = (sum(int(x[i]) for x in m) for i in range(3))
            ts.passed, ts.failed, ts.errors = run - fail - err, fail, err
    if not ts.passed_ids and not ts.failed_ids:
        (ts.passed_ids if step.ok else ts.failed_ids).append(f"{framework or 'suite'}:all")
        if not ts.passed and not ts.failed:
            ts.passed, ts.failed = (1, 0) if step.ok else (0, 1)
    return ts


def run_suite(sb: Sandbox, ctx: RunContext, root: Path) -> tuple[list[StepResult], bool, TestSummary]:
    """Install/build steps then tests (or smoke). Returns (steps, build_ok, tests)."""
    steps: list[StepResult] = []
    projects = detect_projects(ctx, root, sb.effective)
    if not projects:
        return steps, True, TestSummary(ran=False)
    build_ok = True
    merged = TestSummary(ran=False)
    for p in projects:
        ok = True
        for name, argv, net in p.steps:
            s = sb.run(p.ecosystem, root, f"{p.ecosystem}:{name}", argv, net)
            steps.append(s)
            if not s.ok:
                ok = False
                break
        build_ok = build_ok and ok
        if not ok:
            continue
        if p.test:
            s = sb.run(p.ecosystem, root, f"{p.ecosystem}:test", p.test, False)
            steps.append(s)
            out = ""
            if s.evidence_id:
                e = ctx.store.get_evidence(s.evidence_id)
                out = e.excerpt if e else ""
            ts = parse_tests(p.framework, s, out)
        elif p.smoke:
            s = sb.run(p.ecosystem, root, f"{p.ecosystem}:smoke", p.smoke, False)
            steps.append(s)
            ts = TestSummary(framework="smoke", ran=True, exit_code=s.returncode, smoke_only=True, evidence_id=s.evidence_id,
                             passed=int(s.ok), failed=int(not s.ok),
                             passed_ids=[f"{p.ecosystem}:smoke"] if s.ok else [], failed_ids=[] if s.ok else [f"{p.ecosystem}:smoke"])
        else:
            continue
        merged = _merge_tests(merged, ts)
    return steps, build_ok, merged


def _merge_tests(a: TestSummary, b: TestSummary) -> TestSummary:
    if not a.ran:
        return b
    return TestSummary(framework=",".join(x for x in (a.framework, b.framework) if x), ran=True,
                       exit_code=max(a.exit_code or 0, b.exit_code or 0), passed=a.passed + b.passed, failed=a.failed + b.failed,
                       errors=a.errors + b.errors, passed_ids=a.passed_ids + b.passed_ids, failed_ids=a.failed_ids + b.failed_ids,
                       smoke_only=a.smoke_only and b.smoke_only, evidence_id=b.evidence_id or a.evidence_id)


def short_key(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:8]


def work_base(ctx: RunContext) -> Path:
    """Throwaway work trees live under a SHORT temp path: copies of .git exceed Windows MAX_PATH otherwise."""
    import tempfile
    base = Path(tempfile.gettempdir()) / "guardian-work" / short_key(str(ctx.store.run_dir.resolve()))
    base.mkdir(parents=True, exist_ok=True)
    return base


def prepare_branch(ctx: RunContext, d2: Day2Store, plan: RemediationPlan, cand: RemediationCandidate) -> tuple[Path, str, str | None, str]:
    """Copy (with history), branch, apply, commit. Returns (root, real diff, commit sha, branch)."""
    root = work_base(ctx) / short_key(plan.plan_key) / cand.id / ctx.repo.name
    copy_tree(ctx.root, root, with_git=True)
    branch = f"guardian/fix-{cand.id[2:]}"
    has_git = (root / ".git").exists()
    if has_git:
        try:
            git(root, "checkout", "-q", "-B", branch, runner=ctx.runner)
        except ToolFailed:
            has_git = False
    changed = apply_edits(root, cand.edits)
    if cand.simulation and cand.simulation.method == "sandbox-resolution" and docker_available(ctx.runner):
        from .simulate import _regen_npm_lock
        npm_manifest = next((e.file for e in cand.edits if e.kind in ("npm_set_dep", "npm_override", "npm_remove_dep")), None)
        if npm_manifest:
            _regen_npm_lock(ctx, root, npm_manifest)
            import posixpath
            changed.append(posixpath.join(posixpath.dirname(npm_manifest), "package-lock.json"))
    diff = unified_diff(ctx.root, root, changed)
    commit = None
    if has_git:
        try:
            base = ["-c", "user.name=Guardian", "-c", "user.email=guardian@localhost.invalid", "-c", "commit.gpgsign=false",
                    "-c", "core.autocrlf=false"]
            git(root, *base, "add", "-A", "--", *changed, runner=ctx.runner)
            git(root, *base, "commit", "-q", "--no-verify", "-m", f"guardian: {cand.summary[:120]}\n\nplan {plan.plan_key} rev {plan.revision}\n"
                f"plan hash {plan.plan_hash}\ncandidate {cand.id}", runner=ctx.runner)
            commit = git(root, "rev-parse", "HEAD", runner=ctx.runner).strip()
        except ToolFailed as e:
            d2.audit("S14", "commit failed", str(e), plan_key=plan.plan_key)
    return root, diff, commit, branch


def baseline_tests(sb: Sandbox, ctx: RunContext, d2: Day2Store) -> tuple[list[StepResult], bool, TestSummary]:
    cached = d2.get(f"baseline_tests:{sb.effective}")
    if cached:
        return ([StepResult.model_validate(s) for s in cached["steps"]], cached["build_ok"], TestSummary.model_validate(cached["tests"]))
    root = work_base(ctx) / "baseline" / ctx.repo.name
    copy_tree(ctx.root, root, with_git=False)
    steps, ok, ts = run_suite(sb, ctx, root)
    d2.put(f"baseline_tests:{sb.effective}", {"steps": [s.model_dump() for s in steps], "build_ok": ok, "tests": ts.model_dump()})
    return steps, ok, ts


def validate_candidate(sb: Sandbox, ctx: RunContext, d2: Day2Store, plan: RemediationPlan, cand: RemediationCandidate,
                       root: Path, diff: str, commit: str | None, branch: str, applied: str) -> ValidationResult:
    t0 = time.time()
    v = ValidationResult(plan_key=plan.plan_key, candidate_id=cand.id, branch=branch, sandbox=sb.effective,
                         applied_hash=applied, commit=commit, work_dir=str(root))
    if sb.effective == "none":
        v.status, v.reason = "skipped", sb.unavailable or "sandbox disabled (--sandbox none)"
        d2.audit("S14", "build/test skipped", f"{cand.id}: {v.reason}", plan_key=plan.plan_key)
        return v
    _, base_ok, before = baseline_tests(sb, ctx, d2)
    steps, ok, after = run_suite(sb, ctx, root)
    v.steps, v.build_ok, v.tests_before, v.tests_after = steps, ok, before, after
    if not steps:
        v.status, v.reason = "skipped", "no build system detected (nothing to build or test)"
        v.build_ok = None
    else:
        before_pass = set(before.passed_ids)
        v.regressions = sorted(before_pass & set(after.failed_ids))
        if not ok:
            v.status, v.reason = "failed", "build/install failed: " + next((s.summary for s in steps if not s.ok), "")
            if not base_ok:
                v.reason += " (the original tree also fails to build)"
        elif v.regressions:
            v.status, v.reason = "failed", f"{len(v.regressions)} test(s) regressed"
        else:
            v.status = "passed"
            v.reason = "build ok; " + ("smoke check only" if after.smoke_only else f"{after.passed} passed, {after.failed} failed "
                                       f"(before: {before.passed} passed, {before.failed} failed)")
    v.seconds = round(time.time() - t0, 1)
    d2.audit("S14", f"validation {v.status}", f"{cand.id} on {branch}: {v.reason}", plan_key=plan.plan_key,
             evidence_ids=[s.evidence_id for s in steps if s.evidence_id][-3:])
    return v
