"""Stage 5: Suspicious Change Investigator (6 detectors -> grouped signals -> Stage 4-pattern
investigation -> suspicion x exposure risk -> human review -> report)."""
from __future__ import annotations

from typing import Callable, Optional

from .context import Budgets5, Stage5Context, load_allowlist, load_top
from .pypi import PyPIClient


def run_stage5(s4, offline: bool = False, pypi_url: Optional[str] = None, budgets: Optional[Budgets5] = None,
               log: Callable[[str], None] = print) -> Stage5Context:
    from .workflow import run
    ctx = Stage5Context(s4=s4, pypi=PyPIClient(s4.cache, pypi_url), budgets=budgets or Budgets5(),
                        top=load_top(), allowlist=load_allowlist())
    ctx.coverage["pypi_source"] = ctx.pypi.source
    state = run(ctx, s4.scan_id or "scan")
    cards = state.get("cards", [])
    by = {r: sum(1 for c in cards if c["project_risk"] == r) for r in ("critical", "high", "medium", "low")}
    log(f"stage 5: {len(state.get('signals', []))} signals -> {len(cards)} anomaly findings "
        f"(critical {by['critical']}, high {by['high']}, medium {by['medium']}, low {by['low']}); "
        f"{sum(1 for c in cards if c['review']['status'] == 'pending')} awaiting human review")
    for k in ("detector_errors", "d3_skipped", "d4_skipped"):
        for msg in ctx.coverage.get(k, [])[:5]:
            log(f"stage 5: note: {msg}")
    ctx.state = state
    return ctx


def run_stage5_from_output(output_dir, llm_provider: Optional[str] = None, offline: bool = False, **kw) -> Stage5Context:
    from guardian.stage4_vulns.context import Stage4Context
    from guardian.stage4_vulns.pipeline import vulndb_dir
    from guardian.stage4_vulns.sources import HttpCache, OSVClient
    from guardian.stage3_knowledge.api import load_context
    from guardian.stage3_knowledge.llm import LLM
    from pathlib import Path
    s3 = load_context(output_dir, llm_provider="offline")
    s3.llm = LLM(provider=llm_provider, cache_dir=Path(output_dir) / ".llm_cache")
    cache = HttpCache(vulndb_dir(Path(output_dir)), offline=offline)
    s4 = Stage4Context(s3=s3, cache=cache, osv=OSVClient(cache), output_dir=Path(output_dir),
                       scan_id=(s3.G.graph.get("commit") or "scan")[:12])
    return run_stage5(s4, offline=offline, **kw)


__all__ = ["run_stage5", "run_stage5_from_output"]
