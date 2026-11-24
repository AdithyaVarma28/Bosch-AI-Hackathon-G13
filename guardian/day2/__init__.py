"""Day 2 — Brain & Shield: prioritize risks, recommend safe remediation, human approval, verified fix.
See docs/DAY_2_PLAN.md. Entry point: run_day2(output_dir, ...), called after Stage 5."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Optional

from .common import (CONFIG_FILE, REMEDIATIONS_FILE, WORKFLOW_DB, band_idx, read_json, save_remediations, write_json)


def run_day2(out: str | Path, repo: Optional[str | Path] = None, llm=None, offline: bool = False,
             osv_dump: Optional[str] = None, log: Callable[[str], None] = print, use_agent: Optional[bool] = None) -> dict:
    from .candidates import build_units
    from .prioritize import run_prioritize
    from .workflow import SCAN_LLM, WorkflowManager

    out = Path(out)
    cfg = read_json(out / CONFIG_FILE, {}) or {}
    cfg.update({"repo_path": str(Path(repo).resolve()) if repo else cfg.get("repo_path"), "offline": bool(offline),
                "osv_dump": str(Path(osv_dump).resolve()) if osv_dump else cfg.get("osv_dump"),
                "pypi_url": os.environ.get("GUARDIAN_PYPI_URL") or cfg.get("pypi_url")})
    write_json(out / CONFIG_FILE, cfg)
    if llm is None:
        from guardian.stage3_knowledge.llm import LLM
        llm = LLM(provider="offline" if offline else None, cache_dir=out / ".llm_cache")
    SCAN_LLM[str(out)] = llm

    register = run_prioritize(out, llm, log=log)
    units = build_units(out, register)
    # code-level findings in the application's own code (SQL injection), fixed by changing the code
    try:
        from .codefix import code_units
        from .common import REGISTER_FILE as _RF, repo_path as _rp
        if _rp(out) is not None:
            regs, cunits = code_units(out, _rp(out))
            if cunits:
                register = register + regs
                write_json(out / _RF, register)
                units = sorted(cunits + units, key=lambda u: (-band_idx(u["priority"]), min(u["ranks"])))
                log(f"day2: {len(cunits)} code-level finding(s) (SQL injection) with a code fix")
    except Exception as exc:          # never block the plan on it
        log(f"day2: code-level check failed: {type(exc).__name__}: {exc}")
    meta = read_json(out / "scan.json", {}) or {}
    sid = meta.get("scan_id") or out.name
    import time
    run = int(time.time())
    for u in units:
        u["thread_id"] = f"{sid}:{u['rid']}:{run}"      # a re-run starts fresh threads in the same checkpoint DB
    WorkflowManager._instances.pop(str(out.resolve()), None)
    for f in (WORKFLOW_DB, WORKFLOW_DB + "-wal", WORKFLOW_DB + "-shm"):
        try:
            (out / f).unlink()
        except OSError:      # missing, or held open by a running server (Windows): fresh thread ids make it harmless
            pass
    save_remediations(out, units)
    if use_agent is None:
        use_agent = bool(llm is not None and llm.available and (llm.purposes is None or "remediate" in llm.purposes))
    mgr = WorkflowManager.for_dir(out)
    for u in units:
        mgr.start(u, use_agent=use_agent and band_idx(u["priority"]) >= band_idx("high"))
    if not offline and os.environ.get("GUARDIAN_BUILD_HEALTH", "1") != "0":
        try:                       # does the project install on its target Python? (adds a "build health" fix)
            from .candidates import add_build_health
            bh = add_build_health(out, log=log, force=True)
            log(f"day2: build health on Python {(bh.get('target') or {}).get('version')}: {bh.get('status')} — {bh.get('detail')}")
        except Exception as exc:   # never block the plan on it
            log(f"day2: build health check failed: {type(exc).__name__}: {exc}")
    final = read_json(out / REMEDIATIONS_FILE, []) or []
    tabs = {t: sum(1 for u in final if u.get("tab") == t) for t in ("decide", "ready", "auto", "unresolved")}
    log(f"day2: {len(final)} remediations ({tabs['decide']} need a decision, {tabs['ready']} ready, "
        f"{tabs['auto']} auto-planned, {tabs['unresolved']} unresolved; engine {mgr.engine})")
    return {"register": register, "remediations": final}
