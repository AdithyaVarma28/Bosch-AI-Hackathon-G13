"""Phase B: validate a proposal in an isolated git worktree (docs/DAY_2_PLAN.md section 6).

worktree at HEAD -> throwaway venv with the project's real dependencies (before the patch) -> baseline tests ->
apply the edits -> build (byte-compile + manifest/lockfile/workflow parse) -> install the patched dependencies +
pip check -> tests again -> proof-of-fix probes (old vs new version) -> commit inside the worktree -> full Guardian
rescan of the worktree -> compare findings and SBOM. The user's working copy is never touched; a branch is created
only after patch approval."""
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

from . import runtime
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


def build(wt: Path, changed: list[str]) -> dict:
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
    return {"status": "fail" if errors else "pass", "detail": "; ".join(errors or notes)}


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


def card_package(c: dict) -> str:
    m = re.match(r"pkg:pypi/([^@]+)@", c.get("component") or "")
    return re.sub(r"[-_.]+", "-", (m.group(1) if m else (c.get("component_name") or "")).lower())


def is_hard(c: dict, intended: set) -> bool:
    """A new finding that blocks a fix: a CVE, or harmful behaviour that the fix did not ask for. The code diff of
    the very package the fix upgraded on purpose ("new_behaviour_in_update") is expected to change: it is shown
    as "needs a look", not as a failure. Install-time behaviour (install hooks) always blocks."""
    if c.get("type") == "vulnerability":
        return True
    for s in c.get("signals") or []:
        if s.get("behaviour") and s.get("strength") == "strong":
            if s.get("check") == "new_behaviour_in_update" and card_package(c) in intended:
                continue
            return True
    return False


def intended_packages(unit: dict, proposal: Optional[dict] = None) -> set:
    names = set()
    m = re.match(r"pkg:pypi/([^@]+)@", unit.get("target") or "")
    if m:
        names.add(m.group(1))
    for b in (proposal or {}).get("bumps") or []:
        names.add(b["package"])
    return {re.sub(r"[-_.]+", "-", n.lower()) for n in names}


def compare(out: Path, rescan: Path, unit: dict, proposal: Optional[dict] = None) -> dict:
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
    new = []
    for k in a:
        if k in b:
            continue
        c = a[k]
        sig = [{"check": s.get("check"), "strength": s.get("strength"), "behaviour": bool(s.get("behaviour")),
                "text": s.get("text")} for s in c.get("signals") or []]
        # a CVE, or harmful behaviour the fix did not ask for, is a real new problem; metadata-only change signals
        # and the code diff of the package the fix upgraded on purpose need a human look but are not proof of harm
        hard = is_hard(c, intended_packages(unit, proposal))
        expected = not hard and any(s["check"] == "new_behaviour_in_update" for s in sig)
        new.append({"title": c.get("title"), "risk": c.get("project_risk"), "type": c.get("type"),
                    "finding_id": c.get("finding_id"), "signals": sig[:6], "hard": hard, "expected_change": expected})
    sb, sa = _sbom(out), _sbom(rescan)
    sbom = {"added": sorted(f"{n} {v}" for n, v in sa.items() if n not in sb),
            "removed": sorted(f"{n} {v}" for n, v in sb.items() if n not in sa),
            "changed": sorted(f"{n} {sb[n]} → {sa[n]}" for n in sa if n in sb and sa[n] != sb[n])}
    m = re.match(r"pkg:pypi/([^@]+)@", unit.get("target") or "")
    pkg = m.group(1).lower() if m else None
    target_after = sorted({c.get("vuln_id") for c in after_cards if pkg and c.get("type") == "vulnerability"
                           and (c.get("component_name") or "").lower() == pkg})
    # sanity: vulnerabilities in packages the patch did not touch must still be there; if the rescan lost all of
    # them it had no vulnerability data (offline, no dump) and cannot show anything as resolved
    untouched = {(c.get("component_name") or "").lower() for c in before_cards
                 if c.get("type") == "vulnerability" and (c.get("component_name") or "").lower() != pkg}
    vulns_after = [c for c in after_cards if c.get("type") == "vulnerability"]
    return {"resolved": resolved, "remaining": remaining, "new": new, "sbom_diff": sbom,
            "before_total": len(before_cards), "after_total": len(after_cards),
            "vulns_before": sum(1 for c in before_cards if c.get("type") == "vulnerability"), "vulns_after": len(vulns_after),
            "package": pkg, "package_vulns_after": target_after,
            "no_vuln_data": bool(untouched) and not vulns_after}


def effective_offline(out: Path, cfg: dict) -> bool:
    """Validate like the original scan: if that scan used the network (OSV, PyPI), so does the rescan, even when
    the Day 2 plan was regenerated with --offline. Comparing an online scan with an offline rescan makes every
    vulnerability look resolved."""
    meta = read_json(Path(out) / "scan.json", {}) or {}
    if cfg.get("offline") and meta.get("offline") is False and not cfg.get("osv_dump"):
        return False
    return bool(cfg.get("offline"))


def validate(out: Path, unit: dict, proposal: dict, log: Callable[[str], None] = lambda m: None) -> dict:
    out = Path(out)
    cfg = load_config(out)
    cfg["offline"] = effective_offline(out, cfg)
    repo = repo_path(out)
    v = {"status": "running", "started_at": now(), "checks": {}, "steps": [], "offline": bool(cfg.get("offline"))}

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
    work = root / f"{wt.name}-env"            # venvs live next to the worktree, never inside it
    work.mkdir(parents=True, exist_ok=True)
    try:
        return _validate_in(out, unit, proposal, cfg, wt, work, v, step)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _validate_in(out: Path, unit: dict, proposal: dict, cfg: dict, wt: Path, work: Path, v: dict, step) -> dict:
    # 1. the project's real dependencies, as they are before the patch
    can_install, why_not = runtime.install_enabled(cfg)
    env, env_info = None, {"detail": why_not}
    if can_install:
        env, env_info = runtime.make_project_env(wt, work / "venv", step)
        if env is not None:
            env_info["pip_check_before"] = runtime.pip_check(env).get("conflicts", [])
            runtime.ensure_pytest(env)
            step(f"dependencies installed on Python {env.full_version} ({len(env_info.get('requirements') or [])} requirement file(s))")
        else:
            step(f"dependency install failed: {env_info.get('detail')}")
    v["env"] = env_info
    test_files = runtime.discover_tests(wt)
    base_tests = runtime.run_tests(wt, env, test_files)
    step(f"baseline tests (before the patch): {base_tests['summary']}")
    # 2. the patch
    try:
        files = apply_edits(wt, proposal["edits"], write=True)
    except PatchError as exc:
        v.update(status="failed", detail=f"patch does not apply in the worktree: {exc}")
        v["checks"]["build"] = {"status": "fail", "detail": str(exc)}
        return v
    step(f"patch applied: {', '.join(files)}")
    b = build(wt, list(files))
    v["checks"]["build"] = {"status": b["status"], "detail": b["detail"]}
    step(f"build: {b['status']} — {b['detail'][:160]}")
    # 3. install the patched dependency set into a SECOND venv on the same Python (the before venv stays as it was,
    #    so Guardian's security tests can run on both) + pip check
    env_after = None
    if env is not None:
        args = [a for r in env_info.get("requirements") or [] for a in ("-r", r)] or ["."]
        step("installing the patched dependencies in a second environment (the original one is kept for the before run)…")
        env_after, err = runtime.create_env(work / "venv-after", env.version)
        code, o, cmd = env_after.install(args, cwd=wt) if env_after else (1, err, "")
        v["install"] = {"status": "pass" if code == 0 else "fail", "python": env.full_version, "tool": env.tool,
                        "command": cmd, "log": runtime._tail(o, 1500)}
        v["checks"]["install"] = {"status": v["install"]["status"],
                                  "detail": (f"patched requirements install on Python {env.full_version}" if code == 0
                                             else f"install failed: {runtime._last_line(o)}")}
        if code == 0:
            pc = runtime.pip_check(env_after, baseline=env_info.get("pip_check_before"))
            v["deps_check"] = pc
            v["checks"]["deps_compatible"] = {"status": pc["status"], "detail": pc["detail"]}
            runtime.ensure_pytest(env_after)
        else:
            env_after = None
        step(f"install: {v['checks']['install']['status']} — {v['checks']['install']['detail'][:140]}")
    else:
        v["install"] = {"status": "skipped", "detail": env_info.get("detail") or why_not, "attempts": env_info.get("attempts")}
        v["checks"]["install"] = {"status": "skipped", "detail": env_info.get("detail") or why_not}
    # 3b. build-health fixes: the point is the install on the project's target Python
    if proposal.get("kind") == "compat_upgrade" and can_install:
        from . import appboot
        tgt = appboot.target_python(wt)
        step(f"installing the patched dependencies on the target Python {tgt['version']} ({tgt['source']})…")
        ti, tenv = appboot.install_check(wt, tgt["version"], work / "venv-target")
        if ti["ok"]:
            step(f"starting the patched app on Python {ti['python']}…")
            tb = appboot.boot(wt, tenv, work / "boot-target")
            v["target_boot"] = {k: x for k, x in tb.items() if k != "log"}
            v["checks"]["target_boot"] = {"status": {"healthy": "pass", "skipped": "n/a"}.get(tb["status"], "fail"),
                                          "detail": f"Python {ti['python']}: {tb['status']} — {tb.get('detail', '')[:160]}"}
            # the boot writes nothing into the worktree except through the app; drop anything it created
            _run(["git", "-C", str(wt), "clean", "-fdq", "-e", "tests/guardian"], timeout=60)
        v["target_install"] = {**ti, "target": tgt}
        v["checks"]["target_install"] = {"status": "pass" if ti["ok"] else "fail",
                                         "detail": (f"installs on Python {ti['python']} ({tgt['source']})" if ti["ok"]
                                                    else f"still fails on Python {ti['python']}: {ti['error']}")}
        step(f"target install: {v['checks']['target_install']['status']} — {v['checks']['target_install']['detail'][:140]}")
    # 4. the repository's own tests, after the patch
    after_tests = runtime.run_tests(wt, env_after, test_files)
    v["tests"] = {"before": base_tests, "after": after_tests, "files": test_files}
    if after_tests["status"] == "n/a":
        v["checks"]["tests"] = {"status": "skipped" if test_files else "n/a", "detail": after_tests["summary"]}
    elif not after_tests.get("ran"):
        v["checks"]["tests"] = {"status": "unknown", "detail": f"{len(test_files)} test file(s) found but no test ran: {after_tests['summary']}"}
    else:
        regress = after_tests["failed"] > base_tests.get("failed", 0) or (base_tests.get("status") == "ok" and after_tests["status"] != "ok")
        fmt = lambda t: f"{t.get('passed', 0)}/{t.get('ran', 0)} passed" if t.get("ran") else t.get("summary", "")
        v["checks"]["tests"] = {"status": "fail" if regress else "pass",
                                "detail": f"before: {fmt(base_tests)} · after: {fmt(after_tests)}"
                                          + (f" (Python {env.full_version})" if env else "")}
    step(f"tests: {v['checks']['tests']['status']} ({v['checks']['tests']['detail'][:150]})")
    # 5. proof-of-fix: does the new version really stop the vulnerable behaviour?
    if can_install:
        from .agent import make_llm
        from .probe import run_probes
        pv = env.version if env is not None else f"{sys.version_info.major}.{sys.version_info.minor}"
        # code writing: large model first, the default model when its quota is gone
        pr = run_probes(out, unit, proposal, pv, work, [make_llm(out, large=True), make_llm(out, large=False)], step)
    else:
        pr = {"status": "skipped", "detail": why_not}
    if pr.get("status") != "n/a":
        v["probe"] = pr
        v["checks"]["proof_of_fix"] = {"status": pr["status"], "detail": pr["detail"]}
        step(f"proof-of-fix: {pr['status']} — {pr['detail'][:150]}")
    # 6. Guardian's security tests (T1 exploit / T2 guard / T3 feature), run BEFORE and AFTER the fix
    test_paths: list[str] = []
    try:
        from . import testgen
        gen = testgen.generate(out, unit, proposal, wt, v.get("probe"))
        before_wt = None
        if env is not None:
            before_wt = Path(str(wt) + "-before")
            # the worktree's HEAD is still the original commit (nothing is committed yet)
            if _run(["git", "-C", str(wt), "worktree", "add", "--detach", str(before_wt), "HEAD"], timeout=120)[0] != 0:
                before_wt = None
        try:
            st = testgen.run_suite(gen, before_wt, env if before_wt else None, wt, env_after, work, step)
        finally:
            if before_wt is not None:
                _run(["git", "-C", str(wt), "worktree", "remove", "--force", str(before_wt)], timeout=60)
                shutil.rmtree(before_wt, ignore_errors=True)
        v["security_tests"] = st
        test_paths = st.get("files") or []
        v["checks"]["security_tests"] = {"status": st["status"], "detail": st["detail"]}
    except Exception as exc:
        v["checks"]["security_tests"] = {"status": "unknown", "detail": f"test generation failed: {type(exc).__name__}: {exc}"}
    step(f"security tests: {v['checks']['security_tests']['status']} — {v['checks']['security_tests']['detail'][:150]}")
    # commit exactly the patched files and the security tests (nothing the runs left behind)
    _run(["git", "-C", str(wt), "add", "--", *sorted(set(list(files) + test_paths))], timeout=60)
    msg = (f"guardian {unit['rid']}: {proposal['action']}\n\nFindings: {', '.join(unit['finding_ids']) or 'none (build health)'}\n"
           f"Proposal v{proposal.get('version')} by {proposal.get('author')}"
           + (f"\nSecurity tests: {', '.join(test_paths)}" if test_paths else ""))
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
        cmp = compare(out, rescan, unit, proposal)
        step(f"rescan done in {time.time() - t0:.0f}s: {len(cmp['resolved'])} resolved, {len(cmp['new'])} new")
    except Exception as exc:
        cmp = None
        v["checks"]["rescan_resolved"] = {"status": "fail", "detail": f"rescan failed: {type(exc).__name__}: {exc}"}
    finally:
        if old_env is None:
            os.environ.pop("GUARDIAN_PYPI_URL", None)
        else:
            os.environ["GUARDIAN_PYPI_URL"] = old_env
    if cmp is not None and cmp["no_vuln_data"]:
        v["rescan"] = {**cmp, "dir": str(rescan)}
        why = (f"the rescan has no vulnerability data ({cmp['vulns_before']} known vulnerabilities before, 0 after, "
               "including packages the patch did not touch) — it ran without OSV access, so it cannot show the fix")
        v["checks"]["rescan_resolved"] = {"status": "unknown", "detail": why}
        v["checks"]["no_new_vulns"] = {"status": "unknown", "detail": "no vulnerability data in the rescan"}
        cmp = None
    if cmp is not None:
        v["rescan"] = {**cmp, "dir": str(rescan)}
        eff = (proposal.get("expected_risk") or {}).get("effect", "resolved")
        lowered = [r for r in cmp["remaining"] if r["after"] != r["before"] or r["usage_after"] != r["usage_before"]
                   or len(r["signals_after"]) < len(r["signals_before"])]
        if unit.get("target_kind") == "code":
            from .codefix import still_vulnerable
            left = still_vulnerable(wt, unit)
            v["checks"]["rescan_resolved"] = ({"status": "fail", "detail": "still found by the SQL-injection detector at "
                                               + ", ".join(f"{s['file']}:{s['line']}" for s in left)} if left else
                                              {"status": "pass", "detail": f"resolved: {', '.join(unit['finding_ids'])} (the "
                                               "SQL-injection detector no longer finds it in the patched code)"})
        elif not unit["finding_ids"]:
            pass                                  # build health: no finding to resolve, only "nothing new" counts
        elif not cmp["remaining"]:
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
        v["checks"]["no_new_vulns"] = no_new_check(cmp)
    # proof_of_fix is extra evidence: its pass raises confidence, but an inconclusive probe does not block
    core = {k: c for k, c in v["checks"].items() if k != "proof_of_fix"}
    bad = [k for k, c in core.items() if c["status"] == "fail"]
    partial = [k for k, c in core.items() if c["status"] == "unknown"]
    v["status"] = "failed" if bad else "partial" if partial else "passed"
    v["finished_at"] = now()
    step(f"validation {v['status']}" + (f" ({', '.join(bad or partial)})" if (bad or partial) else ""))
    return v


def no_new_check(cmp: dict) -> dict:
    hard = [n for n in cmp["new"] if n["hard"]]
    soft = [n for n in cmp["new"] if not n["hard"]]
    if hard:
        return {"status": "fail", "detail": "new: " + "; ".join(f"{n['title']} ({n['risk']})" for n in hard[:4])}
    if soft:
        return {"status": "unknown", "detail": "no new vulnerability; needs a look: " + "; ".join(
            f"{n['title']} (" + ("code changes in the release the fix upgrades to; review the diff" if n.get("expected_change")
                                 else "metadata change only, no harmful behaviour seen") + ")" for n in soft[:3])}
    return {"status": "pass", "detail": "no new vulnerability or supply-chain finding"}


def overall(v: dict) -> None:
    core = {k: c for k, c in v["checks"].items() if k != "proof_of_fix"}
    bad = [k for k, c in core.items() if c["status"] == "fail"]
    partial = [k for k, c in core.items() if c["status"] == "unknown"]
    v["status"] = "failed" if bad else "partial" if partial else "passed"


def reassess(out: Path, unit: dict, proposal: dict) -> Optional[dict]:
    """Re-apply the comparison rules to a finished validation's stored rescan (no new sandbox run)."""
    v = unit.get("validation") or {}
    d = (v.get("rescan") or {}).get("dir")
    if not d or not Path(d).exists() or (v.get("rescan") or {}).get("no_vuln_data"):
        return None
    cmp = compare(Path(out), Path(d), unit, proposal)
    v["rescan"] = {**cmp, "dir": d}
    v["checks"]["no_new_vulns"] = no_new_check(cmp)
    overall(v)
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
