"""Step C: the critic (docs/DAY_2_PLAN.md section 4.3). Deterministic checks first, then one independent AI review.
Fix confidence is computed from the check results by fixed rules, never from what the proposer claims."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from packaging.version import Version

from . import skills as skillmod
from .common import BANDS, band_idx, now
from .patches import PatchError, apply_edits, check as patch_check

PROMPTS = Path(__file__).parent / "prompts"
CRITIC_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {"verdict": {"type": "string", "enum": ["yes", "no", "unsure"]}, "reason": {"type": "string"},
                   "evidence_ids": {"type": "array", "items": {"type": "string"}}},
    "required": ["verdict", "reason", "evidence_ids"],
}
STATIC = ["patch_applies", "scope_ok", "candidate_clean", "constraints_resolve", "available", "runtime_compatible",
          "lockfile_consistent", "security_check"]
LABELS = {"patch_applies": "Patch applies", "scope_ok": "Only allowed files", "candidate_clean": "New version has no known vulns",
          "constraints_resolve": "Dependency constraints resolve", "available": "Version on the index",
          "runtime_compatible": "Python version compatible", "lockfile_consistent": "Lockfile matches manifest",
          "security_check": "Security check on the patched files", "ai_critic": "Independent AI review",
          "build": "Build", "tests": "Tests (no regressions)", "rescan_resolved": "Rescan: finding resolved",
          "no_new_vulns": "Rescan: nothing new introduced", "install": "Dependencies install",
          "deps_compatible": "Installed set is consistent (pip check)", "proof_of_fix": "Proof-of-fix probe",
          "security_tests": "Guardian security tests (before → after)", "target_install": "Installs on the target Python", "target_boot": "Starts on the target Python"}
SANDBOX_CHECKS = ("build", "install", "deps_compatible", "tests", "proof_of_fix", "security_tests", "target_install", "target_boot",
                  "rescan_resolved", "no_new_vulns")

UNSAFE_CALLS = [re.compile(r"yaml\.load\((?![^)]*SafeLoader)"), re.compile(r"yaml\.unsafe_load\("),
                re.compile(r"shell\s*=\s*True")]


def expected_after(before: str, effect: str) -> str:
    if effect == "resolved":
        return "none"
    if effect in ("reduced", "partly resolved"):
        return BANDS[max(0, band_idx(before) - 1)] if band_idx(before) > 0 else "low"
    return before


def proposal_from_candidate(unit: dict, cand: dict, author: str = "template", feedback: Optional[str] = None) -> dict:
    eff = cand.get("expected_after", "resolved")
    return {"author": author, "candidate_id": cand.get("cid"), "kind": cand["kind"], "skill": cand.get("skill"),
            "action": cand["label"], "edits": cand.get("edits") or [], "target_version": cand.get("target_version"),
            "expected_risk": {"before": unit["priority"], "after": expected_after(unit["priority"], eff), "effect": eff},
            "compatibility": cand.get("compatibility") or [], "notes": cand.get("notes") or [],
            "rollback": cand.get("rollback"), "alternatives_rejected": [], "evidence_ids": [],
            "candidate_checks": cand.get("checks") or {}, "feedback": feedback, "created_at": now(),
            **({"bumps": cand["bumps"]} if cand.get("bumps") else {}),
            "_current_version": (re.match(r"pkg:pypi/[^@]+@(.+)$", unit.get("target") or "") or [None, None])[1]}


def _pkg_name(unit: dict) -> Optional[str]:
    m = re.match(r"pkg:pypi/([^@]+)@", unit.get("target") or "")
    return m.group(1) if m else None


def _security_check(unit: dict, p: dict, files: dict) -> dict:
    after = {k: v[1] for k, v in files.items()}
    kind, name = p.get("kind"), _pkg_name(unit)
    from .candidates import RepoFiles
    name_rx = re.compile(rf"^\s*{RepoFiles.name_re(name)}\s*(==|>=|~=|\[|$)", re.I | re.M) if name else None
    if kind == "parameterize_sql":
        from .codefix import sites_in_source
        fn = (unit.get("target") or "").rpartition("::")[2]
        left = [f"{k}:{s['line']}" for k, t in after.items() if k.endswith(".py")
                for s in sites_in_source(t, k) if str(s["function"]) == fn]
        return {"status": "fail" if left else "pass",
                "detail": f"SQL still built by string formatting at {left}" if left else f"{fn}() now passes values as query parameters"}
    if kind == "compat_upgrade":
        miss = [f"{b['package']} {b['to']}" for b in p.get("bumps") or []
                if not any(re.search(rf"^\s*{RepoFiles.name_re(b['package'])}\s*==\s*{re.escape(b['to'])}\s*$", t, re.I | re.M)
                           for t in after.values())]
        return {"status": "fail" if miss or not p.get("bumps") else "pass",
                "detail": f"not pinned after the patch: {', '.join(miss)}" if miss else
                "manifest now pins " + ", ".join(f"{b['package']}=={b['to']}" for b in p.get("bumps") or [])}
    if kind in ("upgrade", "pin_back") and name:
        tv = p.get("target_version")
        pins = [m.group(1) for t in after.values() for m in re.finditer(rf"^\s*{RepoFiles.name_re(name)}\s*(?:==|>=)\s*([^\s;#]+)", t, re.I | re.M)]
        ok = bool(tv) and bool(pins) and all(x == tv for x in pins)
        return {"status": "pass" if ok else "fail",
                "detail": f"manifest now pins {name} {tv}" if ok else f"manifest pins after the patch: {pins or 'none'} (expected {tv})"}
    if kind == "remove" and name:
        left = [k for k, t in after.items() if k.endswith(".txt") and name_rx.search(t)]
        return {"status": "fail" if left else "pass",
                "detail": f"{name} still declared in {left}" if left else f"{name} is no longer declared"}
    if kind == "replace_api":
        left = [k for k, t in after.items() if k.endswith(".py") and any(r.search(t) for r in UNSAFE_CALLS)]
        return {"status": "fail" if left else "pass",
                "detail": f"unsafe call still present in {left}" if left else "no unsafe call left in the patched files"}
    if kind == "restore_hash":
        bad = [e["old_text"] for e in p.get("edits") or []]
        left = [k for k, t in after.items() if any(b in t for b in bad)]
        return {"status": "fail" if left else "pass", "detail": "tampered hash removed" if not left else "tampered hash still present"}
    if kind == "harden_ci":
        left = [k for k, t in after.items() if "pull_request_target" in t or "pull_request.head.sha" in t]
        return {"status": "fail" if left else "pass",
                "detail": "no pull_request_target / PR-head checkout left" if not left else f"still present in {left}"}
    if kind == "pin_image":
        left = [k for k, t in after.items() if re.search(r"FROM\s+\S+:latest\b", t)]
        return {"status": "fail" if left else "pass", "detail": "no :latest base image left" if not left else "still :latest"}
    return {"status": "unknown", "detail": "no automatic security check for this kind of change"}


def static_checks(unit: dict, p: dict, repo: Optional[Path]) -> dict:
    checks: dict[str, dict] = {}
    edits = p.get("edits") or []
    ok, detail, diff = patch_check(repo, edits)
    p["diff"] = diff
    checks["patch_applies"] = {"status": "pass" if ok else ("n/a" if not edits else "fail"), "detail": detail}
    sk = skillmod.get(p.get("skill"))
    if not edits:
        checks["scope_ok"] = {"status": "n/a", "detail": "no files changed"}
    elif sk:
        bad = [e["path"] for e in edits if not sk.allows(e["path"])]
        checks["scope_ok"] = {"status": "fail" if bad else "pass",
                              "detail": f"skill {sk.name} may not change {bad}" if bad else f"all files allowed by skill {sk.name}"}
    else:
        checks["scope_ok"] = {"status": "pass", "detail": "deterministic template (fixed file set)"}
    for k in ("candidate_clean", "constraints_resolve", "available", "runtime_compatible"):
        c = (p.get("candidate_checks") or {}).get(k)
        checks[k] = c or {"status": "n/a", "detail": "no version change"}
    files = {}
    if ok:
        try:
            files = apply_edits(repo, edits)
        except PatchError:
            files = {}
    name = _pkg_name(unit)
    if ok and name and "poetry.lock" in files:
        from .candidates import RepoFiles
        lock = files["poetry.lock"][1]
        mblock = re.search(rf'name = "{RepoFiles.name_re(name)}"\r?\nversion = "([^"]+)"', lock, re.I)
        pins = [m.group(1) for k, (_, t) in files.items() if k.endswith(".txt")
                for m in re.finditer(rf"^\s*{RepoFiles.name_re(name)}\s*==\s*([^\s;#]+)", t, re.I | re.M)]
        if mblock and pins:
            same = all(x == mblock.group(1) for x in pins)
            checks["lockfile_consistent"] = {"status": "pass" if same else "fail",
                                             "detail": f"manifest {pins[0]} / lock {mblock.group(1)}"}
        else:
            checks["lockfile_consistent"] = {"status": "pass", "detail": "lock entry updated or removed with the manifest"}
    elif ok and name and p.get("kind") in ("upgrade", "pin_back") and repo and (repo / "poetry.lock").exists():
        checks["lockfile_consistent"] = {"status": "fail", "detail": "manifest changed but poetry.lock was not updated"}
    else:
        checks["lockfile_consistent"] = {"status": "n/a", "detail": "no lockfile change needed"}
    checks["security_check"] = _security_check(unit, p, files) if ok else {"status": "n/a" if not edits else "fail",
                                                                            "detail": "patch does not apply" if edits else "no change"}
    return checks


def ai_critic(llm, unit: dict, p: dict, evidence: list[dict]) -> dict:
    if llm is None or not llm.available or not p.get("diff"):
        return {"status": "skipped", "detail": "no LLM available" if (llm is None or not llm.available) else "no patch"}
    known = {e["id"] for e in evidence}
    pack = "\n".join([f"Remediation {unit.get('rid')}: {unit.get('target_label')}",
                      "Evidence:", *[f"- {e['id']} {e['where']} {e['text']}" for e in evidence[:14]],
                      f"Proposed action: {p['action']}",
                      f"Claimed effect: {(p.get('expected_risk') or {}).get('effect')} (resolved = the issue is gone; "
                      "reduced = only the part named in the action is removed)",
                      "Deterministic check results (facts, already verified):",
                      *[f"- {LABELS.get(k, k)}: {v.get('status')} — {v.get('detail')}" for k, v in (p.get("checks") or {}).items()
                        if v.get("status") != "n/a"],
                      "Diff:", p["diff"][:6000]])
    res = llm.complete_json("critic", (PROMPTS / "critic_system.md").read_text(encoding="utf-8"), pack, CRITIC_SCHEMA)
    if not res:
        return {"status": "skipped", "detail": "the critic model did not answer"}
    bad = [i for i in res.get("evidence_ids") or [] if i not in known]
    if bad:
        return {"status": "unsure", "detail": f"critic answer rejected: unknown evidence ids {bad}"}
    status = {"yes": "pass", "no": "fail", "unsure": "unsure"}[res["verdict"]]
    return {"status": status, "detail": res.get("reason", ""), "evidence_ids": res.get("evidence_ids") or []}


def fix_confidence(p: dict, validation: Optional[dict] = None) -> tuple[str, list[str]]:
    c = p.get("checks") or {}
    if not p.get("edits"):
        return "low", ["no code change: the risk stays until someone acts (escalation / accepted)"]
    fails = [LABELS[k] for k in STATIC if c.get(k, {}).get("status") == "fail"]
    if c.get("ai_critic", {}).get("status") == "fail":
        fails.append("independent AI review says the patch does not remove the issue")
    v = validation or {}
    vfail = [LABELS[k] for k in SANDBOX_CHECKS if k != "proof_of_fix" and (v.get("checks") or {}).get(k, {}).get("status") == "fail"]
    if fails or vfail:
        return "low", [f"failed: {x}" for x in fails + vfail]
    unknown = [LABELS[k] for k in STATIC if c.get(k, {}).get("status") == "unknown"]
    critic_yes = c.get("ai_critic", {}).get("status") == "pass"
    validated = v.get("status") == "passed"
    same_major = False
    cur, tv = p.get("_current_version"), p.get("target_version")
    try:
        same_major = bool(cur and tv and Version(cur).major == Version(tv).major)
    except Exception:
        pass
    sec_ok = c.get("security_check", {}).get("status") == "pass"
    reasons = []
    vc = v.get("checks") or {}
    tests_ran = vc.get("tests", {}).get("status") == "pass" and ((v.get("tests") or {}).get("after") or {}).get("passed", 0) > 0
    probe_ok = vc.get("proof_of_fix", {}).get("status") == "pass"
    st_rows = [r for r in (v.get("security_tests") or {}).get("tests") or [] if r.get("kept") and r.get("as_expected")]
    t1_ok = any(r["kind"] == "T1" for r in st_rows)
    t3_ok = any(r["kind"] == "T3" for r in st_rows)
    target_ok = vc.get("target_install", {}).get("status") == "pass" and vc.get("target_boot", {}).get("status") in (None, "pass")
    if sec_ok and validated and c.get("ai_critic", {}).get("status") != "fail":
        executed = [x for x, ok in (("the project's own tests pass after the patch", tests_ran),
                                    ("a proof-of-fix probe showed the vulnerable behaviour gone", probe_ok or t1_ok),
                                    ("Guardian's feature test exercised the app on the new version", t3_ok),
                                    ("the app really installs and starts on the target Python", target_ok)) if ok]
        if executed:
            return "high", ["static checks pass, the security check passes, the sandbox rescan resolved the finding, and "
                            + " and ".join(executed)]
        reasons.append("the sandbox passed, but nothing executed the changed code: no test ran and no proof-of-fix "
                       "probe reproduced the bug, so the rescan's version-range lookup is the only evidence")
    if sec_ok and critic_yes and p.get("kind") in ("upgrade", "pin_back") and same_major and not unknown:
        return "high", ["static checks pass, the AI critic agrees, same-major version change"]
    if unknown:
        reasons.append("not verified yet: " + ", ".join(unknown))
    if not critic_yes:
        reasons.append("no independent AI confirmation" if c.get("ai_critic", {}).get("status") in (None, "skipped")
                       else "AI critic is unsure")
    if not validated:
        part = [f"{LABELS[k]}: {c.get('detail')}" for k, c in (v.get("checks") or {}).items() if c.get("status") == "unknown"]
        reasons.append(f"sandbox validation {v['status']}" + (f" — {'; '.join(part)}" if part else "") if v.get("status")
                       else "sandbox validation (build, tests, rescan) not run yet")
    return "medium", reasons or ["static checks pass"]


def review(unit: dict, p: dict, repo: Optional[Path], llm=None, evidence: Optional[list[dict]] = None) -> dict:
    p["checks"] = static_checks(unit, p, repo)
    if p["checks"]["patch_applies"]["status"] == "pass":
        p["checks"]["ai_critic"] = ai_critic(llm, unit, p, evidence or [])
    p["fix_confidence"], p["fix_confidence_reasons"] = fix_confidence(p)
    return p
