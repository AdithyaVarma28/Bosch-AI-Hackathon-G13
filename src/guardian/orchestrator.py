"""Agentic pipeline as a LangGraph StateGraph.

ingest -> cartographer -> [resolver_sbom || code_index] -> graph -> dossier_agent -> supervisor
       -> [vuln_intel || change_anomaly || package_signals || container_ci || secrets || discrepancies]
       -> correlator -> evidence_agent -> report

* Supervisor routing is a deterministic table with recorded reasons (no LLM needed to decide what runs).
* LLM agents: Dossier agent and Evidence Agent (Groq), both bounded and Verifier-checked, both with rule fallbacks.
* Every node fails soft: exceptions become a `degraded`/`failed` NodeStatus and the run continues.
* Graph state is small and serialisable; heavy objects live in the RunContext registry keyed by run_id.
"""
from __future__ import annotations

import operator
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Callable, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from .agent.dossier import build_dossier, rule_dossier
from .agent.investigate import Budget, investigate
from .cartographer.facts import build_repo_facts
from .codeindex.parser import build_code_index
from .context import RunContext, Settings
from .detectors.changes import detect_changes
from .detectors.infra import detect_ci, detect_container, detect_secrets
from .detectors.packages import (detect_discrepancies, detect_install_scripts, detect_name_confusion,
                                 detect_registry_signals)
from .detectors.vulns import detect_vulns
from .graph import UnifiedGraph
from .ingest import ingest
from .llm import LLMClient
from .models import Finding, RepoRef
from .report import build_report
from .sbom.stage import run_sbom_stage
from .scoring import correlate, score
from .store import RunStore

RUNS: dict[str, RunContext] = {}
DETECTORS = ["vuln_intel", "change_anomaly", "package_signals", "container_ci", "secrets", "discrepancies"]


def _merge(a: dict, b: dict) -> dict:
    return {**a, **b}


class PipelineState(TypedDict, total=False):
    run_id: str
    target: str
    node_status: Annotated[dict[str, str], _merge]
    events: Annotated[list[dict], operator.add]
    plan: dict[str, Any]
    errors: Annotated[list[str], operator.add]
    report_path: str


@dataclass
class PipelineResult:
    run_id: str
    run_dir: Path
    report_path: Path | None
    node_status: dict[str, str]
    events: list[dict] = field(default_factory=list)


def _node(name: str, fn: Callable[[RunContext, PipelineState], dict | None], degrade_only: bool = True):
    """Wrap a stage: timing, events, fail-soft status."""
    def run(state: PipelineState) -> dict:
        ctx = RUNS.get(state["run_id"])
        t0 = time.time()
        if ctx is None and name != "ingest":
            return {"node_status": {name: "skipped"}, "events": [{"node": name, "status": "skipped", "message": "no context"}]}
        try:
            extra = fn(ctx, state) or {}
            status = extra.pop("_status", "ok")
            msg = extra.pop("_message", "")
        except Exception as e:  # fail soft
            status = "degraded" if degrade_only else "failed"
            msg = f"{type(e).__name__}: {str(e)[:300]}"
            extra = {"errors": [f"{name}: {msg}", traceback.format_exc(limit=3)[-800:]]}
        ev = {"node": name, "status": status, "message": msg, "seconds": round(time.time() - t0, 2)}
        if ctx:
            ctx.emit(ev)
        out = {"node_status": {name: status}, "events": [ev]}
        for k, v in extra.items():
            out[k] = v
        return out
    return run


# ----------------------------------------------------------------------------- nodes
def n_ingest(state: PipelineState, settings: Settings, out_dir: Path, emit) -> dict:
    t0 = time.time()
    run_id = state["run_id"]
    try:
        ref: RepoRef = ingest(state["target"], out_dir, depth=settings.history_depth)
    except Exception as e:
        ev = {"node": "ingest", "status": "failed", "message": f"{type(e).__name__}: {e}", "seconds": round(time.time() - t0, 2)}
        emit(ev)
        return {"node_status": {"ingest": "failed"}, "events": [ev], "errors": [f"ingest: {type(e).__name__}: {e}"]}
    run_dir = out_dir / ref.name / run_id
    ctx = RunContext(repo=ref, store=RunStore(run_dir, run_id), settings=settings, emit=emit)
    ctx.llm = LLMClient.from_env(settings.cache_dir, settings.llm_model, settings.offline) if settings.use_llm else None
    RUNS[run_id] = ctx
    ev = {"node": "ingest", "status": "ok", "message": f"{ref.name} @ {(ref.commit or 'no-git')[:12]}",
          "seconds": round(time.time() - t0, 2)}
    emit(ev)
    return {"node_status": {"ingest": "ok"}, "events": [ev]}


def s_cartographer(ctx: RunContext, state) -> dict:
    ctx.facts = build_repo_facts(ctx)
    ctx.store.save_artifact("facts.json", ctx.facts)
    f = ctx.facts
    return {"_message": f"{len(f.declared_dependencies)} declared deps, {len(f.manifests)} manifests, "
                        f"{len(f.dockerfiles)} Dockerfiles, {len(f.ci_workflows)} workflows, {len(f.dependency_history)} history commits",
            "_status": "degraded" if any(not e.startswith("note:") for e in f.errors) else "ok"}


def s_sbom(ctx: RunContext, state) -> dict:
    run_sbom_stage(ctx)
    r = ctx.sbom_report
    ctx.store.save_artifact("sbom_report.json", r)
    ctx.store.save_artifact("package_metadata.json", ctx.metadata)
    degraded = r.confidence == "low" or any(v.startswith("failed") for v in r.tools.values())
    return {"_message": f"{len(ctx.components)} components, {len(ctx.edges)} edges, confidence {r.confidence}",
            "_status": "degraded" if degraded else "ok"}


def s_code(ctx: RunContext, state) -> dict:
    ctx.code_index = build_code_index(ctx)
    ctx.store.save_artifact("code_index.json", ctx.code_index)
    c = ctx.code_index.coverage
    return {"_message": f"{c.files_parsed}/{c.files_total} files parsed, {c.internal_calls_resolved} internal calls resolved",
            "_status": "degraded" if c.files_failed else "ok"}


def s_graph(ctx: RunContext, state) -> dict:
    from .codeindex.parser import link_polyglot_imports
    link_polyglot_imports(ctx)                       # needs SBOM results, so it runs after the parallel join
    ctx.store.save_artifact("code_index.json", ctx.code_index)
    ctx.graph = UnifiedGraph.build(ctx.repo.name, ctx.facts, ctx.components, ctx.edges, ctx.code_index)
    ctx.store.save_artifact("graph.json", ctx.graph.to_json())
    ctx.store.save_artifact("execution_paths.json", ctx.graph.execution_paths())
    ctx.store.save_artifact("discrepancies.json", ctx.graph.discrepancies())
    c = ctx.graph.counts()
    return {"_message": f"{ctx.graph.g.number_of_nodes()} nodes, {ctx.graph.g.number_of_edges()} edges "
                        f"({c.get('edge:DEPENDS_ON', 0)} DEPENDS_ON, {c.get('edge:IMPORTS', 0)} IMPORTS, {c.get('edge:CALLS', 0)} CALLS)"}


def s_dossier(ctx: RunContext, state) -> dict:
    try:
        ctx.dossier = build_dossier(ctx)
    except Exception:
        ctx.dossier = rule_dossier(ctx)
    ctx.store.save_artifact("dossier.json", ctx.dossier)
    return {"_message": f"{ctx.dossier.app_type}; exposure={ctx.dossier.exposure}; by {ctx.dossier.generated_by}"}


def supervisor_plan(ctx: RunContext) -> dict[str, Any]:
    f = ctx.facts
    plan: dict[str, Any] = {"run": {}, "reasons": {}}

    def decide(det: str, run: bool, reason: str) -> None:
        plan["run"][det] = run
        plan["reasons"][det] = reason
    decide("vuln_intel", bool(ctx.components), f"{len(ctx.components)} components to check against OSV"
           if ctx.components else "no resolved components")
    decide("change_anomaly", bool(f and (f.dependency_history or ctx.components)),
           f"{len(f.dependency_history) if f else 0} dependency-file commits in history" if f and f.dependency_history
           else "no git history; only current-state source checks")
    decide("package_signals", bool(ctx.components or (f and f.lifecycle_scripts)),
           "install scripts, name confusion, registry metadata, package indexes")
    has_infra = bool(f and (f.dockerfiles or f.ci_workflows or f.config.compose_services))
    decide("container_ci", has_infra, "Dockerfile/compose/workflow present" if has_infra else "no Dockerfile, compose file or CI workflow found")
    decide("secrets", True, "always scan for hard-coded credentials")
    decide("discrepancies", bool(ctx.graph and ctx.code_index and ctx.code_index.files),
           "declared/resolved/imported layers available" if ctx.code_index and ctx.code_index.files else "no source files indexed")
    return plan


def s_supervisor(ctx: RunContext, state) -> dict:
    plan = supervisor_plan(ctx)
    ctx.store.save_artifact("plan.json", plan)
    on = [k for k, v in plan["run"].items() if v]
    return {"plan": plan, "_message": f"dispatching {', '.join(on)}"}


def _detector(name: str, fn: Callable[[RunContext], list[Finding]]):
    def run(ctx: RunContext, state) -> dict:
        plan = state.get("plan") or {}
        if not plan.get("run", {}).get(name, True):
            return {"_status": "skipped", "_message": plan.get("reasons", {}).get(name, "")}
        fs = fn(ctx)
        for f in fs:
            ctx.store.add_finding(f)
        degraded = any(f.cls == "sbom_quality" for f in fs)
        return {"_message": f"{len(fs)} finding(s)", "_status": "degraded" if degraded else "ok"}
    return run


def _packages(ctx: RunContext) -> list[Finding]:
    return detect_install_scripts(ctx) + detect_name_confusion(ctx) + detect_registry_signals(ctx)


def _container_ci(ctx: RunContext) -> list[Finding]:
    return detect_container(ctx) + detect_ci(ctx)


def s_correlator(ctx: RunContext, state) -> dict:
    raw = ctx.store.list_findings()
    fs = score(correlate(raw), ctx.dossier, ctx.sbom_report.confidence if ctx.sbom_report else "low")
    for f in fs:
        ctx.store.add_finding(f)
    bands: dict[str, int] = {}
    for f in fs:
        bands[f.band or "?"] = bands.get(f.band or "?", 0) + 1
    return {"_message": f"{len(raw)} raw -> {len(fs)} findings; " + ", ".join(f"{k}:{v}" for k, v in sorted(bands.items()))}


def s_evidence_agent(ctx: RunContext, state) -> dict:
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "Unprioritized": 4}
    fs = sorted(ctx.store.list_findings(), key=lambda f: (order.get(f.band or "", 9), f.classification != "S"))
    fs = [f for f in fs if f.cls != "sbom_quality"]
    budget_n = ctx.settings.max_explanations
    agent_targets = {f.id for f in fs[:budget_n]} if ctx.llm else set()
    n_llm = n_rule = 0
    rejected = 0
    from .agent.investigate import rule_explanation
    for f in fs:
        if f.id in agent_targets:
            exp = investigate(f, ctx, budget=Budget())
            n_llm += exp.generated_by != "rule-based"
        else:
            exp = rule_explanation(f, ctx)
        n_rule += exp.generated_by == "rule-based"
        if "unverified claims removed" in exp.notes:
            rejected += int(exp.notes.split("unverified claims removed: ")[1].split(";")[0].split()[0])
        ctx.store.save_explanation(exp)
    mode = f"{n_llm} agent explanation(s) via {ctx.llm.name}" if ctx.llm else "LLM not configured (set GROQ_API_KEY); rule-based explanations"
    return {"_message": f"{mode}; {n_rule} rule-based; {rejected} unverified claim(s) removed"}


def s_report(ctx: RunContext, state) -> dict:
    status = dict(state.get("node_status") or {})
    status["report"] = "ok"
    path = build_report(ctx, status, state.get("plan") or {}, state.get("errors") or [])
    return {"report_path": str(path), "_message": str(path)}


# ----------------------------------------------------------------------------- graph
def build_app(settings: Settings, out_dir: Path, emit: Callable[[dict], None] = lambda e: None):
    g = StateGraph(PipelineState)
    g.add_node("ingest", lambda s: n_ingest(s, settings, out_dir, emit))
    g.add_node("cartographer", _node("cartographer", s_cartographer))
    g.add_node("resolver_sbom", _node("resolver_sbom", s_sbom))
    g.add_node("code_index", _node("code_index", s_code))
    g.add_node("graph", _node("graph", s_graph))
    g.add_node("dossier_agent", _node("dossier_agent", s_dossier))
    g.add_node("supervisor", _node("supervisor", s_supervisor))
    g.add_node("vuln_intel", _node("vuln_intel", _detector("vuln_intel", detect_vulns)))
    g.add_node("change_anomaly", _node("change_anomaly", _detector("change_anomaly", detect_changes)))
    g.add_node("package_signals", _node("package_signals", _detector("package_signals", _packages)))
    g.add_node("container_ci", _node("container_ci", _detector("container_ci", _container_ci)))
    g.add_node("secrets", _node("secrets", _detector("secrets", detect_secrets)))
    g.add_node("discrepancies", _node("discrepancies", _detector("discrepancies", detect_discrepancies)))
    g.add_node("correlator", _node("correlator", s_correlator))
    g.add_node("evidence_agent", _node("evidence_agent", s_evidence_agent))
    g.add_node("report", _node("report", s_report))

    g.add_edge(START, "ingest")
    g.add_conditional_edges("ingest", lambda s: "cartographer" if s["node_status"].get("ingest") == "ok" else END,
                            ["cartographer", END])
    g.add_edge("cartographer", "resolver_sbom")   # SBOM and code index are independent: run in parallel
    g.add_edge("cartographer", "code_index")
    g.add_edge(["resolver_sbom", "code_index"], "graph")
    g.add_edge("graph", "dossier_agent")
    g.add_edge("dossier_agent", "supervisor")
    g.add_conditional_edges("supervisor", lambda s: DETECTORS, DETECTORS)   # parallel fan-out
    g.add_edge(DETECTORS, "correlator")                                    # join
    g.add_edge("correlator", "evidence_agent")
    g.add_edge("evidence_agent", "report")
    g.add_edge("report", END)
    return g.compile(checkpointer=MemorySaver())


def run_pipeline(target: str, out_dir: Path = Path("output"), settings: Settings | None = None,
                 emit: Callable[[dict], None] = lambda e: None, run_id: str | None = None) -> PipelineResult:
    settings = settings or Settings()
    out_dir = Path(out_dir)
    run_id = run_id or time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    app = build_app(settings, out_dir, emit)
    final = app.invoke({"run_id": run_id, "target": target, "node_status": {}, "events": [], "errors": []},
                       config={"configurable": {"thread_id": run_id}, "recursion_limit": 60})
    ctx = RUNS.get(run_id)
    rp = final.get("report_path")
    if ctx is None:  # ingest failed: write a failure report so the caller always gets one
        fail_dir = out_dir / "_failed" / run_id
        fail_dir.mkdir(parents=True, exist_ok=True)
        import json
        rp = fail_dir / "report.json"
        rp.write_text(json.dumps({"schema_version": "1.0", "status": "failed", "target": target,
                                  "node_status": final.get("node_status"), "errors": final.get("errors")}, indent=2), encoding="utf-8")
    return PipelineResult(run_id=run_id, run_dir=ctx.store.run_dir if ctx else Path(rp).parent,
                          report_path=Path(rp) if rp else None, node_status=final.get("node_status", {}),
                          events=final.get("events", []))
