"""Phase B: validate a proposal in an isolated git worktree (docs/DAY_2_PLAN.md section 6).

worktree at HEAD -> baseline tests -> apply the edits -> build (byte-compile + manifest/lockfile/workflow parse,
optional pip install) -> tests again -> commit inside the worktree -> full Guardian rescan of the worktree ->
compare findings and SBOM. The user's working copy is never touched; a branch is created only after patch approval."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

from .common import load_config, now, read_json, repo_path
from .patches import PatchError, apply_edits

GIT_ID = ["-c", "user.name=Guardian", "-c", "user.email=guardian@localhost", "-c", "commit.gpgsign=false"]


def _run(cmd: list[str], cwd: Optional[Path] = None, timeout: int = 180, env: Optional[dict] = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, env=env)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as exc:
        return 127, str(exc)


def is_git(repo: Optional[Path]) -> bool:
    return bool(repo) and _run(["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"], timeout=20)[0] == 0


def run_tests(wt: Path) -> dict:
    if not any(wt.glob("test*")) and not any(wt.rglob("test_*.py")):
        return {"status": "n/a", "summary": "no tests in the repository", "failed": 0, "passed": 0}
    code, out = _run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-header"], cwd=wt, timeout=240)
    if "No module named pytest" in out:
        return {"status": "n/a", "summary": "pytest is not installed", "failed": 0, "passed": 0}
    passed = sum(int(x) for x in re.findall(r"(\d+) passed", out))
    failed = sum(int(x) for x in re.findall(r"(\d+) (?:failed|error)", out))
    last = [l for l in out.strip().splitlines() if l.strip()][-1:] or [""]
    return {"status": "ok" if code == 0 else "failing", "code": code, "passed": passed, "failed": failed,
            "summary": last[0][:200], "log": out[-3000:]}


def build(wt: Path, changed: list[str], cfg: dict) -> dict:
    notes, errors = [], []
    py = [f for f in changed if f.endswith(".py")]
    code, out = _run([sys.executable, "-m", "compileall", "-q", str(wt)], timeout=180)
    if code != 0:
        errors.append("byte-compile failed: " + out[-400:])
    else:
        notes.append("all Python files byte-compile")
    from packaging.requirements import InvalidRequirement, Requirement
    for req in sorted(wt.glob("requirements*.txt")):
        for i, line in enumerate(req.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            s = line.split("#", 1)[0].strip()
            if s and not s.startswith("-"):
                try:
                    Requirement(s)
                except InvalidRequirement as exc:
                    errors.append(f"{req.name}:{i} invalid requirement: {exc}")
    notes.append("requirements files parse")
    lock = wt / "poetry.lock"
    if lock.exists():
        try:
            import tomllib
            tomllib.loads(lock.read_text(encoding="utf-8"))
            notes.append("poetry.lock parses")
        except Exception as exc:
            errors.append(f"poetry.lock does not parse: {exc}")
    for wf in [f for f in changed if f.startswith(".github/workflows/")]:
        try:
            import yaml
            yaml.safe_load((wt / wf).read_text(encoding="utf-8"))
            notes.append(f"{wf} is valid YAML")
        except Exception as exc:
            errors.append(f"{wf} is not valid YAML: {exc}")
    install = {"status": "skipped", "detail": "dependency install skipped (set GUARDIAN_SANDBOX_INSTALL=1 to pip-install "
                                             "into a throwaway venv)"}
    if os.environ.get("GUARDIAN_SANDBOX_INSTALL") == "1" and not cfg.get("offline"):
        venv = wt.parent / (wt.name + "-venv")
        c1, o1 = _run([sys.executable, "-m", "venv", str(venv)], timeout=180)
        pip = venv / ("Scripts" if os.name == "nt" else "bin") / "pip"
        reqs = [x for x in ("requirements.txt",) if (wt / x).exists()]
        c2, o2 = (_run([str(pip), "install", "-q", "-r", reqs[0]], cwd=wt, timeout=600) if c1 == 0 and reqs else (c1, o1))
        install = {"status": "pass" if c2 == 0 else "fail", "detail": (o2 or "installed")[-400:]}
        if c2 != 0:
            errors.append("pip install failed")
    return {"status": "fail" if errors else "pass", "detail": "; ".join(errors or notes), "install": install}


def _keys(cards: list[dict]) -> dict[tuple, dict]:
    out = {}
    for c in cards:
        if c.get("type") == "vulnerability":
            k = ("vuln", c.get("vuln_id"), (c.get("component_name") or "").lower())
        else:
            k = ("anomaly", (c.get("component") or "").split("@")[0].lower())
        out[k] = c
    return out


def _sbom(d: Path) -> dict[str, str]:
    g = read_json(d / "graph.json", {}) or {}
    return {n["name"]: n.get("version") for n in g.get("nodes", []) if n.get("type") == "Package" and n.get("name")}


def compare(out: Path, rescan: Path, unit: dict) -> dict:
    before_cards = (read_json(out / "vuln_findings.json", []) or []) + (read_json(out / "anomaly_findings.json", []) or [])
    after_cards = (read_json(rescan / "vuln_findings.json", []) or []) + (read_json(rescan / "anomaly_findings.json", []) or [])
    b, a = _keys(before_cards), _keys(after_cards)
    target = {k for k, c in b.items() if c["finding_id"] in unit["finding_ids"]}
    resolved = [b[k]["finding_id"] for k in target if k not in a]
    remaining = []
    for k in target:
        if k in a:
            bc, ac = b[k], a[k]
            remaining.append({"finding_id": bc["finding_id"], "before": bc.get("project_risk"), "after": ac.get("project_risk"),
                              "usage_before": bc.get("usage") or bc.get("exposure"), "usage_after": ac.get("usage") or ac.get("exposure"),
                              "signals_before": sorted({s.get("check") for s in bc.get("signals") or []}),
                              "signals_after": sorted({s.get("check") for s in ac.get("signals") or []})})
    new = [{"title": a[k].get("title"), "risk": a[k].get("project_risk"), "type": a[k].get("type")}
           for k in a if k not in b]
    sb, sa = _sbom(out), _sbom(rescan)
    sbom = {"added": sorted(f"{n} {v}" for n, v in sa.items() if n not in sb),
            "removed": sorted(f"{n} {v}" for n, v in sb.items() if n not in sa),
            "changed": sorted(f"{n} {sb[n]} → {sa[n]}" for n in sa if n in sb and sa[n] != sb[n])}
    return {"resolved": resolved, "remaining": remaining, "new": new, "sbom_diff": sbom,
            "before_total": len(before_cards), "after_total": len(after_cards)}


def validate(out: Path, unit: dict, proposal: dict, log: Callable[[str], None] = lambda m: None) -> dict:
    out = Path(out)
    cfg = load_config(out)
    repo = repo_path(out)
    v = {"status": "running", "started_at": now(), "checks": {}, "steps": []}

    def step(msg):
        v["steps"].append({"at": now(), "msg": msg})
        log(msg)

    if not is_git(repo):
        v.update(status="unavailable", detail="the scanned repository is not available as a git checkout on this machine")
        return v
    if not proposal.get("edits"):
        v.update(status="unavailable", detail="this proposal has no code change to validate")
        return v
    root = Path(tempfile.gettempdir()) / "guardian-sandbox"
    root.mkdir(parents=True, exist_ok=True)
    wt = root / f"{out.name}-{unit['rid']}-{int(time.time())}"
    code, txt = _run(["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), "HEAD"], timeout=120)
    if code != 0:
        v.update(status="error", detail=f"git worktree failed: {txt[-300:]}")
        return v
    v["worktree"] = str(wt)
    step(f"isolated worktree created at HEAD ({wt.name}); your working copy is untouched")
    base_tests = run_tests(wt)
    step(f"baseline tests: {base_tests['summary']}")
    try:
        files = apply_edits(wt, proposal["edits"], write=True)
    except PatchError as exc:
        v.update(status="failed", detail=f"patch does not apply in the worktree: {exc}")
        v["checks"]["build"] = {"status": "fail", "detail": str(exc)}
        return v
    step(f"patch applied: {', '.join(files)}")
    b = build(wt, list(files), cfg)
    v["checks"]["build"] = {"status": b["status"], "detail": b["detail"]}
    v["install"] = b["install"]
    step(f"build: {b['status']} — {b['detail'][:160]}")
    after_tests = run_tests(wt)
    if after_tests["status"] == "n/a":
        v["checks"]["tests"] = {"status": "n/a", "detail": after_tests["summary"]}
    else:
        regress = after_tests["failed"] > base_tests.get("failed", 0) or (base_tests.get("status") == "ok" and after_tests["status"] != "ok")
        v["checks"]["tests"] = {"status": "fail" if regress else "pass",
                                "detail": f"before: {base_tests['summary']} · after: {after_tests['summary']}"}
    v["tests"] = {"before": base_tests, "after": after_tests}
    step(f"tests: {v['checks']['tests']['status']} ({v['checks']['tests']['detail'][:150]})")
    _run(["git", "-C", str(wt), "add", "-A"], timeout=60)
    msg = f"guardian {unit['rid']}: {proposal['action']}\n\nFindings: {', '.join(unit['finding_ids'])}\nProposal v{proposal.get('version')} by {proposal.get('author')}"
    code, txt = _run(["git", *GIT_ID, "-C", str(wt), "commit", "-q", "-m", msg], timeout=60)
    sha = _run(["git", "-C", str(wt), "rev-parse", "HEAD"], timeout=20)[1].strip()
    v["commit"] = sha if code == 0 else None
    step(f"committed in the sandbox: {sha[:8]}" if code == 0 else f"commit failed: {txt[-200:]}")
    # full Guardian rescan of the patched worktree
    rescan = out / "validation" / unit["rid"] / f"v{proposal.get('version')}"
    if rescan.exists():
        shutil.rmtree(rescan, ignore_errors=True)
    rescan.mkdir(parents=True, exist_ok=True)
    old_env = os.environ.get("GUARDIAN_PYPI_URL")
    try:
        if cfg.get("pypi_url"):
            os.environ["GUARDIAN_PYPI_URL"] = cfg["pypi_url"]
        from guardian.webapp.store import run_pipeline
        step("rescanning the patched code (Stages 1–5)…")
        t0 = time.time()
        run_pipeline(wt, rescan, offline=bool(cfg.get("offline")), llm="offline", osv_dump=cfg.get("osv_dump"), day2=False,
                     log=lambda m: None, scan_id=f"{out.name}-{unit['rid']}-validate")
        cmp = compare(out, rescan, unit)
        step(f"rescan done in {time.time() - t0:.0f}s: {len(cmp['resolved'])} resolved, {len(cmp['new'])} new")
    except Exception as exc:
        cmp = None
        v["checks"]["rescan_resolved"] = {"status": "fail", "detail": f"rescan failed: {type(exc).__name__}: {exc}"}
    finally:
        if old_env is None:
            os.environ.pop("GUARDIAN_PYPI_URL", None)
        else:
            os.environ["GUARDIAN_PYPI_URL"] = old_env
    if cmp is not None:
        v["rescan"] = {**cmp, "dir": str(rescan)}
        eff = (proposal.get("expected_risk") or {}).get("effect", "resolved")
        lowered = [r for r in cmp["remaining"] if r["after"] != r["before"] or r["usage_after"] != r["usage_before"]
                   or len(r["signals_after"]) < len(r["signals_before"])]
        if not cmp["remaining"]:
            v["checks"]["rescan_resolved"] = {"status": "pass", "detail": f"resolved: {', '.join(cmp['resolved'])}"}
        elif eff in ("reduced", "partly resolved") and lowered:
            v["checks"]["rescan_resolved"] = {"status": "pass", "detail": "risk reduced: " + "; ".join(
                f"{r['finding_id']} {r['before']}→{r['after']}"
                + (f" ({r['usage_before']}→{r['usage_after']})" if r['usage_after'] != r['usage_before'] else "")
                + (f"; still flagged: {', '.join(r['signals_after'])}" if r['signals_after'] else "") for r in lowered)}
        elif lowered:
            v["checks"]["rescan_resolved"] = {"status": "unknown", "detail": "reduced but not fully resolved (the proposal "
                f"claimed '{eff}'): " + "; ".join(f"{r['finding_id']} {r['before']}→{r['after']}" for r in lowered)}
        else:
            v["checks"]["rescan_resolved"] = {"status": "fail", "detail": "still present: " + ", ".join(
                f"{r['finding_id']} ({r['after']})" for r in cmp["remaining"])}
        v["checks"]["no_new_vulns"] = ({"status": "fail", "detail": "new: " + "; ".join(f"{n['title']} ({n['risk']})" for n in cmp["new"][:4])}
                                       if cmp["new"] else {"status": "pass", "detail": "no new vulnerability or supply-chain finding"})
    bad = [k for k, c in v["checks"].items() if c["status"] == "fail"]
    partial = [k for k, c in v["checks"].items() if c["status"] == "unknown"]
    v["status"] = "failed" if bad else "partial" if partial else "passed"
    v["finished_at"] = now()
    step(f"validation {v['status']}" + (f" ({', '.join(bad or partial)})" if (bad or partial) else ""))
    return v


def remove_worktree(out: Path, wt: Optional[str]) -> None:
    repo = repo_path(out)
    if wt and repo:
        _run(["git", "-C", str(repo), "worktree", "remove", "--force", wt], timeout=60)
        shutil.rmtree(wt, ignore_errors=True)
        _run(["git", "-C", str(repo), "worktree", "prune"], timeout=60)


def apply_branch(out: Path, unit: dict, validation: dict) -> dict:
    """Create the local branch guardian/fix-<rid> at the validated sandbox commit. Never checks it out, never pushes."""
    repo = repo_path(out)
    sha = validation.get("commit")
    if not repo or not sha:
        return {"ok": False, "detail": "no validated commit to apply"}
    name = f"guardian/fix-{unit['rid'].lower()}"
    i = 2
    while _run(["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"refs/heads/{name}"], timeout=20)[0] == 0:
        name = f"guardian/fix-{unit['rid'].lower()}-{i}"
        i += 1
    code, txt = _run(["git", "-C", str(repo), "branch", name, sha], timeout=30)
    remove_worktree(out, validation.get("worktree"))
    if code != 0:
        return {"ok": False, "detail": txt[-300:]}
    return {"ok": True, "branch": name, "commit": sha,
            "detail": f"branch {name} created at {sha[:8]} (not checked out, not pushed; merge it yourself after review)"}
