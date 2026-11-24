"""Honest coverage: what Stage 3 understood, and what it could not."""
from __future__ import annotations

from .context import Stage3Context
from .graph_builder import nodes_of


def compute_coverage(ctx: Stage3Context) -> dict:
    G = ctx.G
    files = ctx.code_index.get("files", []) or []
    parsed = sum(1 for f in files if not f.get("parse_error"))
    calls_total = G.graph.get("calls_internal_total", 0)
    calls_ok = G.graph.get("calls_internal_resolved", 0)
    modules = nodes_of(G, "Module")
    modules_carded = sum(1 for m in modules if G.nodes[m].get("card"))
    file_nodes = [f for f in nodes_of(G, "File") if "not_indexed" not in G.nodes[f].get("tags", [])]
    files_carded = sum(1 for f in file_nodes if G.nodes[f].get("card"))
    resolved = sum(1 for f in ctx.findings if f["status"] == "resolved")
    unresolved = len(ctx.findings) - resolved
    skipped = len(ctx.questions.get("skipped", []))

    unknowns: list[str] = []
    for f in files:
        if f.get("parse_error"):
            unknowns.append(f"{f['path']} could not be parsed ({str(f['parse_error'])[:80]})")
        for d in f.get("dynamic_imports", []) or []:
            unknowns.append(f"dynamic import `{d.get('expr', '?')}` in {f['path']}:{d.get('line')}")
    unmapped = sorted({u["import"].split(".")[0] for u in G.graph.get("unresolved_imports", []) if u.get("import")})
    if unmapped:
        unknowns.append(f"{len(unmapped)} external import(s) map to no declared or resolved package: {', '.join(unmapped[:8])}")
    if calls_total - calls_ok:
        sample = ", ".join(sorted({str(c.get('target')) for c in G.graph.get('unresolved_calls', [])})[:5])
        unknowns.append(f"{calls_total - calls_ok} internal call(s) could not be resolved to a definition ({sample})")
    unknowns += G.graph.get("known_unknowns", [])
    if G.graph.get("db_unknown_tables"):
        unknowns.append(f"{len(G.graph['db_unknown_tables'])} database access(es) with an unknown table")
    unknowns += ctx.changes.get("known_unknowns", [])
    if not ctx.source.available:
        unknowns.append("repository source not available to Stage 3: inputs, tables and investigator reads use the index only")
    if ctx.llm.disabled_reason and not sum(ctx.llm.cache_hits.values()):
        unknowns.append(f"LLM not used ({ctx.llm.disabled_reason}): cards and findings are deterministic")
    if ctx.questions.get("needs_llm"):
        unknowns.append(f"{len(ctx.questions['needs_llm'])} module card(s) have no docstrings and need an LLM to explain: "
                        + ", ".join(G.nodes[n].get("name", n) for n in ctx.questions["needs_llm"][:6]))
    if skipped:
        unknowns.append(f"{skipped} investigator question(s) skipped (budget of {ctx.budgets.questions})")
    for e in (ctx.facts.get("errors", []) or [])[:5]:
        unknowns.append(f"stage 1: {str(e).splitlines()[0][:160]}")
    for e in (ctx.code_index.get("errors", []) or [])[:5]:
        unknowns.append(f"stage 2: {str(e)[:160]}")

    return {
        "files_parsed": f"{parsed}/{len(files)}",
        "internal_calls_resolved": f"{calls_ok}/{calls_total}",
        "modules": len(modules),
        "modules_carded": modules_carded,
        "files_carded": f"{files_carded}/{len(file_nodes)}",
        "questions": {"resolved": resolved, "unresolved": unresolved, "skipped": skipped,
                      "queued": ctx.questions.get("queued", 0)},
        "known_unknowns": list(dict.fromkeys(unknowns)),
        "counts": {
            "files": len(files), "parsed": parsed, "calls_total": calls_total, "calls_resolved": calls_ok,
            "file_nodes": len(file_nodes), "files_carded": files_carded,
            "functions": sum(1 for n in nodes_of(G, "Function") if not G.nodes[n].get("module_level")),
            "paths": len(ctx.paths), "packages": len(nodes_of(G, "Package")),
            "nodes": G.number_of_nodes(), "edges": G.number_of_edges(),
        },
        "llm": ctx.llm.stats(),
        "timetravel_mode": ctx.changes.get("mode"),
        "graph_errors": G.graph.get("errors", [])[:20],
    }
