"""Stage 4 driver: Stage 3 knowledge graph -> known vulnerabilities -> investigated finding cards."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Optional

from guardian.stage3_knowledge.context import Stage3Context
from guardian.stage3_knowledge.graph_builder import nodes_of, pred

from .context import Budgets, Stage4Context
from .sources import HttpCache, OSVClient
from .workflow import run


def vulndb_dir(output_dir: Path) -> Path:
    env = os.environ.get("GUARDIAN_VULNDB")
    return Path(env) if env else Path(output_dir).resolve().parent / ".cache" / "vulndb"


def dockerfile_images(G) -> list[str]:
    """Base images of the application's Dockerfile(s) (the container image the plan scans)."""
    out = []
    for img in sorted(nodes_of(G, "Image")):
        # node discovered_by survives a graph.json reload (an edge's "source" attribute does not)
        if G.nodes[img].get("discovered_by") == "dockerfile":
            ref = G.nodes[img].get("ref")
            if ref and ref not in out:
                out.append(ref)
    return out


def run_stage4(s3: Stage3Context, offline: bool = False, osv_dump: Optional[str | Path] = None,
               images: Optional[list[str]] = None, budgets: Optional[Budgets] = None, prefer_dump: bool = False,
               scan_id: Optional[str] = None, log: Callable[[str], None] = print,
               emit: Optional[Callable[[dict], None]] = None) -> Stage4Context:
    out = Path(s3.output_dir)
    cache = HttpCache(vulndb_dir(out), offline=offline)
    osv = OSVClient(cache, Path(osv_dump) if osv_dump else None, prefer_dump=prefer_dump)
    sbom = out / "sbom.cdx.json"
    ctx = Stage4Context(s3=s3, cache=cache, osv=osv, output_dir=out, budgets=budgets or Budgets(),
                        images=dockerfile_images(s3.G) if images is None else images,
                        sbom_path=sbom if sbom.exists() else None, log=log, emit=emit or (lambda e: None),
                        scan_id=scan_id or (s3.G.graph.get("commit") or "scan")[:12])
    state = run(ctx)
    cards = state.get("cards", [])
    by = {r: sum(1 for c in cards if c["project_risk"] == r) for r in ("critical", "high", "medium", "low")}
    pending = sum(1 for c in cards if c["review"]["status"] == "pending")
    d = ctx.coverage.get("discovery", {})
    log(f"stage 4: {d.get('matches', 0)} known vulnerabilities in {d.get('packages', 0)} packages "
        f"({d.get('osv_mode')}; grype: {'; '.join(f'{k}: {v}' for k, v in (d.get('grype') or {}).items())})")
    log(f"stage 4: {len(state.get('deep', []))} investigated, {len(state.get('light', []))} light pass -> "
        f"{len(cards)} findings (critical {by['critical']}, high {by['high']}, medium {by['medium']}, low {by['low']}); "
        f"{pending} awaiting human review (LLM calls: {sum(ctx.llm.calls[p] for p in ('analyst', 'vuln_investigator', 'verifier', 'explain'))})")
    for n in d.get("notes", []):
        log(f"stage 4: note: {n}")
    ctx.state = state
    return ctx


def run_stage4_from_output(output_dir: str | Path, llm_provider: Optional[str] = None, model: Optional[str] = None,
                           **kwargs) -> Stage4Context:
    """Stage 4 on an existing Stage 3 output folder (graph.json is reloaded; nothing is rescanned)."""
    from guardian.stage3_knowledge.api import load_context
    from guardian.stage3_knowledge.llm import LLM
    s3 = load_context(output_dir, llm_provider="offline")
    s3.llm = LLM(provider=llm_provider, model=model, cache_dir=Path(output_dir) / ".llm_cache")
    return run_stage4(s3, **kwargs)
