"""Page 5 "Fixed repository" (docs/DAY_2_COMPLETION_PLAN.md section 7).

Turns the approved fixes into ONE repository that installs, runs and passes the tests, and can be downloaded:

  collect  remediations whose tested patch was approved (status "applied"), in rank order
  compose  fresh worktree at HEAD; cherry-pick each fix's validated sandbox commit (its edits + its security tests),
           one commit per fix with the approvers in the message; a conflicting fix is skipped and reported
  document GUARDIAN_FIXES.md (fixes, findings, tests, approvers, how to run the tests, how to roll back)
  verify   BEFORE (HEAD) and AFTER (fixed): install on the target Python, the full test suite (project tests +
           tests/guardian) as a before/after matrix, the boot check, and a combined rescan compared with the scan
  publish  local branch guardian/fixed-<scan> (never checked out, never pushed), fixed-repo.zip, fixes.patch,
           result.json in output/scans/<scan>/fixed/

The user's checkout is never touched: everything happens in worktrees under the temp folder.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import threading
import time
import traceback
from pathlib import Path
from typing import Callable, Optional

from . import appboot, runtime, testgen
from .common import REGISTER_FILE, band_idx, load_config, load_remediations, now, read_json, repo_path, write_json
from .runtime import Env
from .sandbox import GIT_ID, _keys, _run, _sbom, effective_offline, is_hard

FIXED_DIR = "fixed"


def fixed_dir(out: Path) -> Path:
    return Path(out) / FIXED_DIR


def work_root(out: Path) -> Path:
    return Path(tempfile.gettempdir()) / "guardian-fixed" / Path(out).name


def approvers(unit: dict) -> dict:
    res = {}
    for d in unit.get("decisions") or []:
        if d.get("action") == "approve" and d.get("stage") in ("proposal", "patch"):
            res[d["stage"]] = d.get("reviewer") or "reviewer"
    return res


def selection(out: Path) -> tuple[list[dict], list[dict]]:
    """(included, not_included) remediations."""
    units = sorted(load_remediations(out), key=lambda u: (min(u.get("ranks") or [0]), u["rid"]))
    inc, rest = [], []
    for u in units:
        sha = (u.get("validation") or {}).get("commit")
        if u.get("status") == "applied" and sha:
            inc.append(u)
        else:
            why = {"rejected": "rejected", "awaiting_proposal_review": "proposal not approved yet",
                   "awaiting_patch_review": "tested patch not approved yet"}.get(u.get("status"), u.get("status") or "not decided")
            p = (u.get("proposals") or [{}])[u.get("current") or 0] if u.get("proposals") else {}
            if not p.get("edits") and u.get("status") != "rejected":
                why = "no code change (escalation / accepted risk)"
            rest.append({"rid": u["rid"], "label": u["target_label"], "priority": u["priority"], "why": why,
                         "action": p.get("action"), "findings": u["finding_ids"], "kind": u.get("target_kind")})
    return inc, rest


# ------------------------------------------------------------------ comparison of the whole project
def compare_all(out: Path, rescan: Path, intended: Optional[set] = None) -> dict:
    out, rescan = Path(out), Path(rescan)
    reg = {e["finding_id"]: e for e in read_json(out / REGISTER_FILE, []) or []}
    bc = (read_json(out / "vuln_findings.json", []) or []) + (read_json(out / "anomaly_findings.json", []) or [])
    ac = (read_json(rescan / "vuln_findings.json", []) or []) + (read_json(rescan / "anomaly_findings.json", []) or [])
    b, a = _keys(bc), _keys(ac)
    prio = lambda c: (reg.get(c.get("finding_id")) or {}).get("priority") or c.get("project_risk") or "low"

    def counts(cards, typ):
        res = {k: 0 for k in ("critical", "high", "medium", "low")}
        for c in cards:
            if (c.get("type") == "vulnerability") == (typ == "vuln"):
                res[c["_p"]] = res.get(c["_p"], 0) + 1
        return res

    before = [{**c, "_p": prio(c)} for c in b.values()]
    after = [{**b[k], "_p": prio(b[k])} if k in b else {**c, "_p": c.get("project_risk") or "low"} for k, c in a.items()]
    resolved = [b[k]["finding_id"] for k in b if k not in a]
    remaining = [b[k]["finding_id"] for k in b if k in a]
    new = []
    for k, c in a.items():
        if k in b:
            continue
        sig = c.get("signals") or []
        hard = is_hard(c, intended or set())
        new.append({"title": c.get("title"), "risk": c.get("project_risk"), "type": c.get("type"), "hard": hard,
                    "signals": [s.get("check") for s in sig][:6]})
    vb = sum(1 for c in before if c.get("type") == "vulnerability")
    va = sum(1 for c in after if c.get("type") == "vulnerability")
    sb, sa = _sbom(out), _sbom(rescan)
    return {"vulns_before": vb, "vulns_after": va, "vulns_by_priority_before": counts(before, "vuln"),
            "vulns_by_priority_after": counts(after, "vuln"),
            "supply_before": len(before) - vb, "supply_after": len(after) - va,
            "resolved": resolved, "remaining": remaining, "new": new,
            "sbom_diff": {"added": sorted(f"{n} {v}" for n, v in sa.items() if n not in sb),
                          "removed": sorted(f"{n} {v}" for n, v in sb.items() if n not in sa),
                          "changed": sorted(f"{n} {sb[n]} → {sa[n]}" for n in sa if n in sb and sa[n] != sb[n])},
            # vulnerabilities in packages the fixes did not touch must still be there; if none is, the rescan had no
            # vulnerability data (offline) and cannot show anything as resolved
            "no_vuln_data": va == 0 and any(c.get("type") == "vulnerability" and sb.get(c.get("component_name")) == sa.get(c.get("component_name"))
                                            for c in before)}


# ------------------------------------------------------------------ helpers
def _git(wt: Path, *args: str, timeout: int = 120) -> tuple[int, str]:
    return _run(["git", *GIT_ID, "-C", str(wt), *args], timeout=timeout)


def _rm_worktree(repo: Path, wt: Path) -> None:
    _run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)], timeout=60)
    shutil.rmtree(wt, ignore_errors=True)
    _run(["git", "-C", str(repo), "worktree", "prune"], timeout=60)


def _keyed(run: dict) -> dict[str, str]:
    return run.get("results_full") or {}


def run_all_tests(root: Path, env: Env, files: list[str], junit: Path) -> dict:
    if not files:
        return {"results_full": {}, "summary": "no test files"}
    r = testgen.run_pytest(root, env, files, junit, timeout=600)
    full = {}
    try:
        import xml.etree.ElementTree as ET
        for tc in ET.parse(junit).getroot().iter("testcase"):
            st = "pass"
            for ch in tc:
                if ch.tag in ("failure", "error", "skipped"):
                    st = {"failure": "fail", "error": "error", "skipped": "skip"}[ch.tag]
            cls = (tc.get("classname") or "").split(".")[-1]
            full[f"{cls}::{tc.get('name', '').split('[')[0]}"] = st
    except Exception:
        pass
    r["results_full"] = full
    return r


def fixes_md(repo_name: str, branch: str, rows: list[dict], skipped: list[dict], target: dict) -> str:
    lines = [f"# Guardian fixes for {repo_name}", "",
             f"Branch `{branch}` was built by Guardian from fixes a person approved twice (the approach, then the tested patch).",
             "Each fix is one commit. Its security tests are in `tests/guardian/`.", "",
             "| Fix | What changed | Findings | Security tests | Approved by |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['rid']} | {r['action']} | {', '.join(r['vuln_ids'][:6]) or 'build health'}"
                     f"{' …' if len(r['vuln_ids']) > 6 else ''} | {r['tests_summary']} | "
                     f"{r['approvers'].get('proposal', '?')} / {r['approvers'].get('patch', '?')} |")
    if skipped:
        lines += ["", "Not included because they conflict with an earlier fix (re-validate them on top of this branch):", ""]
        lines += [f"- {s['rid']}: {s['why']}" for s in skipped]
    lines += ["", "## Run the security tests", "", "```", "pip install -r requirements.txt pytest",
              "pytest -m guardian tests/guardian", "```", "",
              "T1 = exploit test (fails on the vulnerable version, passes on the fixed one), "
              "T2 = guard test (the fix is in place; a guard, not a proof), "
              "T3 = feature test (the app's own code still works).", "",
              f"Target Python: {target.get('version')} ({target.get('source')}).", "",
              "## Roll back", "", "Revert one fix: `git revert <commit of that fix>`. Revert all: reset to the commit before the first fix.", ""]
    return "\n".join(lines)


# ------------------------------------------------------------------ the build
def build(out: Path, log: Callable[[str], None] = print) -> dict:
    out = Path(out)
    fd = fixed_dir(out)
    fd.mkdir(parents=True, exist_ok=True)
    res: dict = {"status": "running", "started_at": now(), "steps": []}

    def step(msg: str, key: Optional[str] = None) -> None:
        res["steps"].append({"at": now(), "msg": msg, "key": key})
        write_json(fd / "result.json", res)
        log(msg)

    repo = repo_path(out)
    if repo is None:
        res.update(status="failed", detail="the scanned repository is not on this machine")
        write_json(fd / "result.json", res)
        return res
    inc, rest = selection(out)
    res["not_included"] = rest
    if not inc:
        res.update(status="failed", detail="no approved fix yet: approve at least one tested patch on the Remediation page")
        write_json(fd / "result.json", res)
        return res
    meta = read_json(out / "scan.json", {}) or {}
    sid = meta.get("scan_id") or out.name
    head = _run(["git", "-C", str(repo), "rev-parse", "HEAD"], timeout=20)[1].strip()
    root = work_root(out)
    for old in (root / "repo", root / "before"):
        _rm_worktree(repo, old)
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    wt, wtb = root / "repo", root / "before"
    _run(["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), head], timeout=120)
    _run(["git", "-C", str(repo), "worktree", "add", "--detach", str(wtb), head], timeout=120)
    res.update(repo=str(repo), repo_name=repo.name, head=head, scan_id=sid)
    reg = {e["finding_id"]: e for e in read_json(out / REGISTER_FILE, []) or []}

    # ---- compose
    step(f"composing {len(inc)} approved fix(es) on a fresh worktree at {head[:8]}…", "compose")
    rows, skipped, touched = [], [], {}
    expected: dict[str, str] = {}
    for u in inc:
        v = u["validation"]
        sha = v["commit"]
        files = [f for f in _git(repo, "show", "--name-only", "--format=", sha)[1].split() if f]
        # re-apply the reviewed exact-line edits (two fixes on neighbouring lines do not conflict, the same line does),
        # then take the security tests from the validated sandbox commit
        from .patches import PatchError, apply_edits
        p_edits = (u["proposals"][u["current"]] or {}).get("edits") or []
        code = 0
        try:
            apply_edits(wt, p_edits, write=True)
            for f in files:
                if f.startswith("tests/guardian/"):
                    c2, content = _run(["git", "-C", str(repo), "show", f"{sha}:{f}"], timeout=30)
                    if c2 == 0:
                        (wt / f).parent.mkdir(parents=True, exist_ok=True)
                        with open(wt / f, "w", encoding="utf-8", newline="\n") as fh:
                            fh.write(content)
            _git(wt, "add", "--", *sorted({e["path"] for e in p_edits} | {f for f in files if f.startswith("tests/guardian/")}))
        except PatchError:
            code = 1
        if code != 0:
            _git(wt, "reset", "--hard", "HEAD")
            _git(wt, "clean", "-fdq")
            clash = sorted({touched[f] for f in files if f in touched and not f.startswith("tests/guardian/")})
            skipped.append({"rid": u["rid"], "label": u["target_label"],
                            "why": f"conflicts with {', '.join(clash) or 'an earlier fix'} (re-validate it on top of the fixed branch)"})
            step(f"{u['rid']} skipped: conflicts with {', '.join(clash) or 'an earlier fix'}", "compose")
            continue
        ap = approvers(u)
        msg = _git(repo, "log", "-1", "--format=%B", sha)[1].strip()
        msg += f"\n\nApproved by: {ap.get('proposal', '?')} (proposal), {ap.get('patch', '?')} (tested patch)\nGuardian scan: {sid}"
        mf = root / "msg.txt"
        mf.write_text(msg, encoding="utf-8")
        _git(wt, "commit", "-q", "--allow-empty", "-F", str(mf))
        csha = _git(wt, "rev-parse", "HEAD")[1].strip()
        for f in files:
            touched.setdefault(f, u["rid"])
        st = v.get("security_tests") or {}
        kept = [r for r in st.get("tests") or [] if r.get("kept")]
        stem = Path(st.get("file") or "").stem
        for r in kept:
            expected[f"{stem}::{r['name']}"] = r["expected"]
        p = u["proposals"][u["current"]]
        rows.append({"rid": u["rid"], "label": u["target_label"], "action": p.get("action"), "kind": u.get("target_kind"),
                     "priority": u["priority"], "findings": u["finding_ids"],
                     "vuln_ids": [reg[f]["vuln_id"] for f in u["finding_ids"] if (reg.get(f) or {}).get("vuln_id")],
                     "commit": csha, "sandbox_commit": sha, "approvers": ap, "validation": v.get("status"),
                     "fix_confidence": p.get("fix_confidence"), "test_file": st.get("file"),
                     "tests_summary": (f"{sum(1 for r in kept if r['as_expected'])}/{len(kept)} as expected ("
                                       + ", ".join(sorted({r['kind'] for r in kept})) + ")") if kept else "none"})
        step(f"{u['rid']}: committed {csha[:8]} — {p.get('action')}", "compose")
    if not rows:
        res.update(status="failed", detail="every approved fix conflicted", included=rows, skipped=skipped)
        write_json(fd / "result.json", res)
        return res
    tgt = appboot.target_python(wt)
    from .codefix import find_sites
    res["code_findings"] = {"before": len(find_sites(wtb)), "after": len(find_sites(wt)),
                            "remaining": [f"{s['file']}:{s['line']} {s['function']}()" for s in find_sites(wt)]}
    (wt / "GUARDIAN_FIXES.md").write_text(fixes_md(repo.name, f"guardian/fixed-{sid}", rows, skipped, tgt), encoding="utf-8")
    _git(wt, "add", "GUARDIAN_FIXES.md")
    _git(wt, "commit", "-q", "-m", f"guardian: add GUARDIAN_FIXES.md ({len(rows)} fixes)")
    res.update(included=rows, skipped=skipped, target=tgt)
    step(f"GUARDIAN_FIXES.md added; {len(rows)} fix commit(s), {len(skipped)} skipped", "compose")

    envs = root / "envs"
    try:
        # ---- install + boot on the target Python, before and after
        step(f"installing BEFORE (HEAD) on the target Python {tgt['version']}…", "install")
        bt, benv_t = appboot.install_check(wtb, tgt["version"], envs / "before-target")
        step(f"installing AFTER (fixed) on the target Python {tgt['version']}…", "install")
        at, aenv_t = appboot.install_check(wt, tgt["version"], envs / "after-target")
        res["install"] = {"before": {k: v for k, v in bt.items() if k != "log"}, "after": {k: v for k, v in at.items() if k != "log"},
                          "before_log": bt.get("log"), "after_log": at.get("log")}
        step(f"install on Python {tgt['version']}: before {'✓' if bt['ok'] else '✕ ' + bt['error']} · after {'✓' if at['ok'] else '✕ ' + at['error']}", "install")
        # same-Python environments for the test matrix: the target Python when HEAD installs there, else the first
        # Python where it does (the project's tests and Guardian's tests need a working BEFORE environment)
        if bt["ok"]:
            benv, aenv, mpy = benv_t, aenv_t, tgt["version"]
        else:
            step("HEAD does not install on the target Python: finding a Python where it does, for the before/after tests…", "tests")
            benv, info = runtime.make_project_env(wtb, envs / "before-alt", lambda m: None)
            aenv = None
            if benv is not None:
                aenv, _ = runtime.create_env(envs / "after-alt", benv.version)
                if aenv is not None and aenv.install(appboot.install_args(wt), cwd=wt)[0] != 0:
                    aenv = None
            mpy = benv.full_version if benv else None
        for e in (benv, aenv, aenv_t if at["ok"] else None):
            if e is not None:
                runtime.ensure_pytest(e)
        # ---- tests: before/after matrix
        proj = runtime.discover_tests(wt)
        gfiles = sorted(p.relative_to(wt).as_posix() for p in (wt / "tests" / "guardian").glob("test_*.py"))
        if (wt / "tests" / "guardian").is_dir():
            shutil.copytree(wt / "tests" / "guardian", wtb / "tests" / "guardian", dirs_exist_ok=True)
        step(f"running {len(proj)} project test file(s) + {len(gfiles)} Guardian test file(s) before and after (Python {mpy})…", "tests")
        rb = run_all_tests(wtb, benv, proj + gfiles, root / "junit-before.xml") if benv else {}
        ra = run_all_tests(wt, aenv, proj + gfiles, root / "junit-after.xml") if aenv else {}
        names = sorted(set(_keyed(rb)) | set(_keyed(ra)))
        matrix = []
        for n in names:
            g = n in expected
            exp = expected.get(n) or "pass → pass"
            b_, a_ = _keyed(rb).get(n, "not run"), _keyed(ra).get(n, "not run")
            eb, ea = exp.split(" → ")
            ok = (b_ == eb or (eb == "fail" and b_ in ("error", "not run"))) and a_ == ea
            if not g and b_ != "pass":                 # a project test that already failed before is not a regression
                ok = a_ in ("pass", b_)
            matrix.append({"test": n, "guardian": g, "expected": exp, "before": b_, "after": a_, "as_expected": ok,
                           "kind": (re.match(r".*::test_(t\d)_", n).group(1).upper() if re.match(r".*::test_(t\d)_", n) else "project")})
        ptests = [m for m in matrix if not m["guardian"]]
        gtests = [m for m in matrix if m["guardian"]]
        res["tests"] = {"python": mpy, "matrix": matrix,
                        "project_before": sum(1 for m in ptests if m["before"] == "pass"),
                        "project_after": sum(1 for m in ptests if m["after"] == "pass"), "project_total": len(ptests),
                        "regressions": [m["test"] for m in ptests if m["before"] == "pass" and m["after"] != "pass"],
                        "guardian_total": len(gtests), "guardian_as_expected": sum(1 for m in gtests if m["as_expected"]),
                        "before_summary": rb.get("summary"), "after_summary": ra.get("summary")}
        t = res["tests"]
        step(f"tests: project {t['project_before']}/{t['project_total']} → {t['project_after']}/{t['project_total']}, "
             f"{len(t['regressions'])} regression(s); Guardian tests {t['guardian_as_expected']}/{t['guardian_total']} as expected", "tests")
        if at["ok"] and aenv_t is not None and aenv_t is not aenv:
            rt = run_all_tests(wt, aenv_t, proj + gfiles, root / "junit-target.xml")
            vals = list(_keyed(rt).values())
            res["tests"]["on_target"] = {"python": aenv_t.full_version, "passed": vals.count("pass"), "total": len(vals),
                                         "summary": rt.get("summary")}
            step(f"all tests on the target Python {aenv_t.full_version}: {vals.count('pass')}/{len(vals)} pass", "tests")
        # ---- boot, before and after
        step("boot check BEFORE…", "boot")
        boot_b = appboot.boot(wtb, benv_t if bt["ok"] else None, root / "boot-before")
        if not bt["ok"]:
            boot_b["detail"] = f"cannot start: the dependencies do not install on Python {tgt['version']} ({bt['error']})"
            boot_b["status"] = "not installable"
        if not bt["ok"] and benv is not None:
            step(f"boot check BEFORE on Python {benv.full_version} (where the original installs)…", "boot")
            boot_b["on_other_python"] = appboot.boot(wtb, benv, root / "boot-before-alt")
        # keep the original (vulnerable) version runnable for the side-by-side demo
        b_env, b_dir = (benv_t, envs / "before-target") if bt["ok"] else (benv, envs / "before-alt")
        if b_env is not None:
            res["run_before"] = {"root": str(wtb), "env": str(b_dir), "python": b_env.full_version, "version": b_env.version,
                                 "tool": b_env.tool, "work": str(root / "live-before"),
                                 "note": "" if bt["ok"] else f"runs on Python {b_env.full_version}: it does not install on the target Python {tgt['version']}"}
        step("boot check AFTER…", "boot")
        boot_a = appboot.boot(wt, aenv_t if at["ok"] else None, root / "boot-after")
        res["boot"] = {"before": boot_b, "after": boot_a}
        step(f"boot: before {boot_b['status']} · after {boot_a['status']} ({boot_a.get('detail', '')[:120]})", "boot")
        if at["ok"]:
            res["run"] = {"root": str(wt), "env": str(envs / "after-target"), "python": aenv_t.full_version,
                          "version": tgt["version"], "tool": aenv_t.tool, "work": str(root / "live")}
        # ---- combined rescan
        step("combined rescan of the fixed repository (Stages 1–5)…", "rescan")
        rescan = fd / "rescan"
        shutil.rmtree(rescan, ignore_errors=True)
        rescan.mkdir(parents=True)
        cfg = load_config(out)
        old_env = os.environ.get("GUARDIAN_PYPI_URL")
        try:
            if cfg.get("pypi_url"):
                os.environ["GUARDIAN_PYPI_URL"] = cfg["pypi_url"]
            from guardian.webapp.store import run_pipeline
            run_pipeline(wt, rescan, offline=effective_offline(out, cfg), llm="offline", osv_dump=cfg.get("osv_dump"),
                         day2=False, log=lambda m: None, scan_id=f"{sid}-fixed")
            from .sandbox import intended_packages
            want = set()
            for u in inc:
                if u["rid"] in {r["rid"] for r in rows}:
                    want |= intended_packages(u, u["proposals"][u["current"]])
            cmp = compare_all(out, rescan, want)
            res["rescan"] = cmp
            step(f"rescan: known vulnerabilities {cmp['vulns_before']} → {cmp['vulns_after']}, "
                 f"{len(cmp['resolved'])} resolved, {len([n for n in cmp['new'] if n['hard']])} new", "rescan")
        except Exception as exc:
            res["rescan"] = {"error": f"{type(exc).__name__}: {exc}"}
            step(f"rescan failed: {exc}", "rescan")
        finally:
            if old_env is None:
                os.environ.pop("GUARDIAN_PYPI_URL", None)
            else:
                os.environ["GUARDIAN_PYPI_URL"] = old_env
        # ---- publish
        branch = f"guardian/fixed-{re.sub(r'[^A-Za-z0-9._-]+', '-', sid)}"
        fsha = _git(wt, "rev-parse", "HEAD")[1].strip()
        _run(["git", "-C", str(repo), "branch", "-f", branch, fsha], timeout=30)
        zip_path, patch_path = fd / "fixed-repo.zip", fd / "fixes.patch"
        _run(["git", "-C", str(repo), "archive", "--format=zip", f"--prefix={repo.name}-fixed/", "-o", str(zip_path.resolve()), fsha], timeout=120)
        code, patch = _run(["git", "-C", str(repo), "format-patch", "--stdout", f"{head}..{fsha}"], timeout=120)
        patch_path.write_text(patch, encoding="utf-8")
        res["publish"] = {"branch": branch, "commit": fsha, "zip": zip_path.name, "zip_bytes": zip_path.stat().st_size if zip_path.exists() else 0,
                          "patch": patch_path.name, "commits": len(rows) + 1}
        step(f"published: branch {branch} at {fsha[:8]} (not checked out, not pushed), fixed-repo.zip, fixes.patch", "publish")
        res["summary"] = summary(res, out)
        res.update(status="done", finished_at=now())
    except Exception as exc:
        res.update(status="failed", detail=f"{type(exc).__name__}: {exc}", trace=traceback.format_exc()[-2000:])
    finally:
        keep_b = Path((res.get("run_before") or {}).get("env") or "-").name
        if "run_before" not in res:
            _rm_worktree(repo, wtb)
        for d in ("before-target", "before-alt", "after-alt"):
            if d != keep_b:
                shutil.rmtree(envs / d, ignore_errors=True)
        if "run" not in res:
            shutil.rmtree(envs / "after-target", ignore_errors=True)
    write_json(fd / "result.json", res)
    return res


def summary(res: dict, out: Path) -> dict:
    """The four numbers of the top strip, before → after."""
    rs, t, ins, bt = res.get("rescan") or {}, res.get("tests") or {}, res.get("install") or {}, res.get("boot") or {}
    ch = lambda d: (d or {}).get("critical", 0) + (d or {}).get("high", 0)
    tgt = (res.get("target") or {}).get("version")

    def app_state(i, b):
        if not (i or {}).get("ok"):
            f = (i or {}).get("failing") or {}
            return f"won't install on {tgt}" + (f" ({f.get('package')})" if f.get("package") else "")
        return {"healthy": "running", "unhealthy": "starts, server errors", "failed": "installs, does not start",
                "skipped": "installs (boot not checked)"}.get((b or {}).get("status"), (b or {}).get("status") or "?")
    cf = res.get("code_findings") or {}
    return {"vulns": [rs.get("vulns_before"), rs.get("vulns_after")],
            "code": [cf.get("before"), cf.get("after")] if cf.get("before") else None,
            "critical_high": [ch(rs.get("vulns_by_priority_before")), ch(rs.get("vulns_by_priority_after"))],
            "tests": {"project_before": t.get("project_before"), "project_after": t.get("project_after"),
                      "project_total": t.get("project_total"), "new": t.get("guardian_total"),
                      "new_as_expected": t.get("guardian_as_expected"), "regressions": len(t.get("regressions") or [])},
            "app": [app_state(ins.get("before"), bt.get("before")), app_state(ins.get("after"), bt.get("after"))],
            "app_ok": [bool((ins.get("before") or {}).get("ok")) and (bt.get("before") or {}).get("status") == "healthy",
                       bool((ins.get("after") or {}).get("ok")) and (bt.get("after") or {}).get("status") == "healthy"],
            "python": tgt}


# ------------------------------------------------------------------ background job + live app
class Jobs:
    running: dict[str, threading.Thread] = {}

    @classmethod
    def start(cls, out: Path) -> bool:
        key = str(Path(out).resolve())
        t = cls.running.get(key)
        if t and t.is_alive():
            return False
        write_json(fixed_dir(out) / "result.json", {"status": "running", "started_at": now(), "steps": []})
        t = threading.Thread(target=build, args=(Path(out), lambda m: None), daemon=True, name=f"guardian-fixed-{Path(out).name}")
        cls.running[key] = t
        t.start()
        return True


def state(out: Path) -> dict:
    res = read_json(fixed_dir(out) / "result.json", None)
    inc, rest = selection(out)
    base = {"ready_to_build": [{"rid": u["rid"], "label": u["target_label"]} for u in inc], "not_included": rest}
    if res is None:
        return {"status": "none", **base}
    key = str(Path(out).resolve())
    t = Jobs.running.get(key)
    if res.get("status") == "running" and not (t and t.is_alive()):
        res["status"], res["detail"] = "failed", "the build was interrupted (server restarted); build again"
    res["live"] = {"after": appboot.LiveApps.status(key), "before": appboot.LiveApps.status(key + ":before")}
    built = {r["rid"] for r in res.get("included") or []} | {s["rid"] for s in res.get("skipped") or []}
    res["stale"] = res.get("status") == "done" and bool({u["rid"] for u in inc} - built)
    return {**base, **res}


def run_live(out: Path, which: str = "after") -> dict:
    res = read_json(fixed_dir(out) / "result.json", {}) or {}
    r = res.get("run" if which == "after" else "run_before")
    if not r or not Path(r["root"]).exists() or not Path(r["env"]).exists():
        raise RuntimeError(f"the {'fixed' if which == 'after' else 'original'} app's environment is gone (temp folder cleaned or the build failed): build the fixed repository again")
    env = Env(Path(r["env"]), r["version"], r.get("tool") or "uv")
    env.full_version = r.get("python") or r["version"]
    Path(r["work"]).mkdir(parents=True, exist_ok=True)
    key = str(Path(out).resolve()) + ("" if which == "after" else ":before")
    st = appboot.LiveApps.start(key, Path(r["root"]), env, Path(r["work"]))
    return {**st, "which": which, "note": r.get("note")}


def stop_live(out: Path, which: str = "both") -> None:
    key = str(Path(out).resolve())
    if which in ("after", "both"):
        appboot.LiveApps.stop(key)
    if which in ("before", "both"):
        appboot.LiveApps.stop(key + ":before")
