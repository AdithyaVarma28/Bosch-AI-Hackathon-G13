"""Stage 3 driver: Stage 1–2 JSON -> knowledge graph -> output files.

Order: build graph -> 3A structural -> 3C flow (paths, blast radius, time travel) -> 3B cards
-> 3D investigator -> coverage + export. 3C runs before 3B because it is pure graph walking and
3B uses its reachability and recent-change marks; nothing is rescanned.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from .context import Budgets, Stage3Context
from .coverage import compute_coverage
from .export import export_all
from .flow import blast_radius, execution_paths, mark_reachability
from .graph_builder import GraphBuilder, load_stage12
from .investigator import investigate
from .llm import LLM
from .semantic import build_cards
from .sources import RepoSource
from .structural import run_structural
from .timetravel import run_timetravel


def run_stage3(input_dir: str | Path, output_dir: Optional[str | Path] = None, repo_path: Optional[str | Path] = None,
               baseline_dir: Optional[str | Path] = None, baseline_commit: Optional[str] = None,
               llm: Optional[LLM] = None, llm_provider: Optional[str] = None, model: Optional[str] = None,
               budgets: Optional[Budgets] = None, log: Callable[[str], None] = print) -> Stage3Context:
    input_dir = Path(input_dir)
    out = Path(output_dir or input_dir)
    data = load_stage12(input_dir)
    facts, ci = data["facts"], data["code_index"]
    source = RepoSource(repo_path or (facts.get("repo") or {}).get("path"))
    llm = llm or LLM(provider=llm_provider, model=model, cache_dir=out / ".llm_cache")

    G = GraphBuilder(facts, ci, data["sbom"], source).build()
    G.graph["input_dir"] = str(input_dir.resolve())
    G.graph["repo_path"] = str(source.root) if source.root else None
    ctx = Stage3Context(G=G, facts=facts, code_index=ci, sbom=data["sbom"], llm=llm, source=source,
                        output_dir=out, budgets=budgets or Budgets(), log=log)
    log(f"stage 3: graph built ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges); "
        f"LLM: {llm.provider_name}{'' if llm.available else f' ({llm.disabled_reason})'}")

    s = run_structural(G, ci)
    log(f"stage 3A: {s['modules']} modules, {len(s['cycles'])} cycles")

    mark_reachability(G)
    ctx.paths = execution_paths(G)
    ctx.blast = blast_radius(G)
    baseline_graph = None
    if baseline_dir:
        bd = load_stage12(baseline_dir)
        baseline_graph = GraphBuilder(bd["facts"], bd["code_index"], bd["sbom"], None).build()
        run_structural(baseline_graph, bd["code_index"])
    ctx.changes = run_timetravel(ctx, baseline_graph, baseline_commit)
    log(f"stage 3C: {len(ctx.paths)} execution paths, {len(ctx.blast)} blast radii, "
        f"{len(ctx.changes.get('items', []))} changes ({ctx.changes.get('mode')})")

    build_cards(ctx)
    log(f"stage 3B: {len(ctx.cards)} cards (LLM calls: {llm.used('card')}, cache hits: {llm.cache_hits['card']})")

    investigate(ctx)
    log(f"stage 3D: {len(ctx.findings)} findings, {sum(f['notable'] for f in ctx.findings)} notable "
        f"(LLM calls: {llm.used('investigator')})")

    coverage = compute_coverage(ctx)
    written = export_all(ctx, coverage)
    log(f"stage 3: wrote {', '.join(written)} -> {out}")
    return ctx
