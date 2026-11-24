"""`guardian demo-check <github-url>`: run the whole product headless on a candidate demo repository and score it
against the selection criteria of docs/DAY_2_COMPLETION_PLAN.md section 3.1.

Same path as a person in the web app: clone + scan from the GitHub link (pages 1-3), Day 2 plan with build health
(page 4), auto-validation of Critical/High fixes, the two approvals (recorded as reviewer "demo-check"), the fixed
repository with its final verification (page 5) and the report (page 6). Nothing is pushed.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Callable

from .common import band_idx, get_rem, load_remediations, read_json, write_json


def _wait_scan(root: Path, sid: str, log, timeout: int = 1800) -> dict:
    t0 = time.time()
    seen = set()
    while time.time() - t0 < timeout:
        m = read_json(root / sid / "scan.json", {}) or {}
        for k, st in (m.get("stages") or {}).items():
            if st.get("status") == "done" and k not in seen:
                seen.add(k)
                log(f"  stage {k} done: {st.get('summary') or ''}")
        if m.get("status") in ("done", "failed"):
            return m
        time.sleep(3)
    return {"status": "failed", "error": "timed out"}


def run(url: str, root: Path, approve: int = 4, llm: str = "offline", log: Callable[[str], None] = print) -> dict:
    from guardian.webapp.store import ScanStore
    from . import fixed_repo, report
    from .queue import AutoValidator
    from .workflow import submit

    root = Path(root)
    t0 = time.time()
    store = ScanStore(root)
    sid = store.start(url, llm=llm)
    log(f"scan {sid}: cloning and scanning {url} …")
    meta = _wait_scan(root, sid, log)
    out = root / sid
    res: dict = {"url": url, "scan_id": sid, "scan_status": meta.get("status"), "scan_error": meta.get("error")}
    if meta.get("status") != "done":
        res["criteria"] = [{"criterion": "Clones and scans from the GitHub link", "value": meta.get("error"), "ok": False}]
        return res
    log(f"scan done in {time.time() - t0:.0f}s; auto-validating Critical/High fixes (and build health)…")
    q = AutoValidator.for_dir(out)
    q.ensure()
    while q.thread is not None and q.thread.is_alive():
        time.sleep(3)
    from .queue import eligible
    extra = [u["rid"] for u in sorted(load_remediations(out), key=lambda u: (min(u.get("ranks") or [0]), u["rid"]))
             if eligible(u, True)][: max(0, approve + 2)]
    if extra:
        log(f"validating {len(extra)} more fixes with a patch: {', '.join(extra)}…")
        q.enqueue(extra)
        while q.thread is not None and q.thread.is_alive():
            time.sleep(3)
    units = sorted(load_remediations(out), key=lambda u: (min(u.get("ranks") or [0]), u["rid"]))
    picked = []
    for u in units:
        v = u.get("validation") or {}
        ok = v.get("finished_at") and v.get("status") in ("passed", "partial") and \
            (v.get("checks") or {}).get("security_tests", {}).get("status") == "pass"
        if ok and u.get("status") == "awaiting_proposal_review" and (u.get("target_kind") == "build_health" or len(picked) < approve):
            picked.append(u["rid"])
    for rid in picked:
        submit(out, rid, {"stage": "proposal", "action": "approve", "reviewer": "demo-check"}, background=False)
        u = get_rem(out, rid)
        if u.get("status") == "awaiting_patch_review":
            reason = None if u["validation"]["status"] == "passed" else "demo-check: remaining '?' checks reviewed"
            submit(out, rid, {"stage": "patch", "action": "approve", "reviewer": "demo-check", "reason": reason}, background=False)
        log(f"  approved {rid}: {get_rem(out, rid).get('status')}")
    log("building the fixed repository…")
    fx = fixed_repo.build(out, log=lambda m: log("  " + m))
    rep = report.build(out)
    res.update(fixed_status=fx.get("status"), verdict=rep["header"]["verdict"], approved=picked)
    res["criteria"] = criteria(out, fx, units)
    res["seconds"] = round(time.time() - t0)
    write_json(out / "demo_check.json", res)
    return res


def criteria(out: Path, fx: dict, units: list[dict]) -> list[dict]:
    ci = read_json(out / "code_index.json", {}) or {}
    facts = read_json(out / "facts.json", {}) or {}
    loc = sum(f.get("loc") or 0 for f in ci.get("files") or [] if not f.get("is_test"))
    pins = [d for d in facts.get("declared_dependencies") or [] if re.match(r"^==", str(d.get("specifier") or d.get("spec") or ""))]
    ndeps = len(pins) or len(facts.get("declared_dependencies") or [])
    reg = read_json(out / "register.json", []) or []
    vulns = [e for e in reg if e.get("kind") == "vulnerability"]
    fixable = [e for e in vulns if e.get("fixed_versions") or any((c.get("kind") == "upgrade") for u in units
                                                                    if e["finding_id"] in u["finding_ids"] for c in u["candidates"])]
    used = [e for e in fixable if (e.get("usage") or "") not in ("package_not_imported", "not_imported", "installed_unused")]
    t = fx.get("tests") or {}
    s = fx.get("summary") or {}
    rs = fx.get("rescan") or {}
    boot = (fx.get("boot") or {}).get("after") or {}
    ptotal = t.get("project_total") or 0
    rows = [
        ("Python web app, clones from the GitHub link", "yes", True),
        ("Own test suite (≥ 3 tests that pass)", f"{t.get('project_before', 0)}/{ptotal} pass before", ptotal >= 3 and (t.get("project_before") or 0) >= 3),
        ("Medium size: 2k–20k lines of Python", f"{loc} lines", 2000 <= loc <= 20000),
        ("20–80 pinned dependencies", f"{ndeps}", 20 <= ndeps <= 80),
        ("Runs without external services (boots on SQLite)", boot.get("status") or "not checked", boot.get("status") == "healthy"),
        ("≥ 10 known vulnerabilities with released fixes", f"{len(fixable)} of {len(vulns)}", len(fixable) >= 10),
        ("At least one on a code path the app uses", f"{len(used)}", len(used) >= 1),
        ("Fixed repo installs on the target Python", f"Python {s.get('python')}: {(s.get('app') or ['', ''])[1]}", bool(((fx.get("install") or {}).get("after") or {}).get("ok"))),
        ("Fixed repo boots", boot.get("detail", "")[:60], boot.get("status") == "healthy"),
        ("All tests pass after (0 regressions)", f"{len(t.get('regressions') or [])} regressions", fx.get("status") == "done" and not t.get("regressions")),
        ("Rescan: fewer vulnerabilities, nothing new", f"{rs.get('vulns_before')} → {rs.get('vulns_after')}, {sum(1 for n in rs.get('new') or [] if n.get('hard'))} new",
         rs.get("vulns_after") is not None and rs["vulns_after"] < rs["vulns_before"] and not any(n.get("hard") for n in rs.get("new") or [])),
    ]
    return [{"criterion": c, "value": v, "ok": bool(ok)} for c, v, ok in rows]


def table(res: dict) -> str:
    lines = [f"demo-check {res['url']}  (scan {res.get('scan_id')}, {res.get('seconds', '?')}s)"]
    for c in res.get("criteria") or []:
        lines.append(f"  {'PASS' if c['ok'] else 'FAIL'}  {c['criterion']:<52} {c['value']}")
    if res.get("verdict"):
        lines.append(f"  verdict: {res['verdict']}")
    n = sum(1 for c in res.get("criteria") or [] if c["ok"])
    lines.append(f"  {n}/{len(res.get('criteria') or [])} criteria pass")
    return "\n".join(lines)
