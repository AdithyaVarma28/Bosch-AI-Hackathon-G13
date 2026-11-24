"""Day 2 orchestration (LangGraph), resumable at the human approval gate.

load -> prioritize (S10) -> investigate (S11, re-score) -> plan (S12) -> gate (S13)
     -> [approved plans] validate (S14 tournament + S15 rescan + S14.6 self-correction) -> verify (S16) -> report
     -> [nothing approved] report (status: awaiting approval)

The pause is a persisted state, not an in-memory interrupt: plans, approvals (append-only) and results live in
run.db, so `guardian approve` (or POST /runs/{id}/plans/{key}/decision) can happen in another process and
`guardian remediate` picks up exactly where the gate stopped. Every node fails soft, as on Day 1.
"""
from __future__ import annotations

import json
import operator
import re
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph

from ..context import RunContext, Settings
from ..httpcache import CachedHttp
from ..models import Finding
from ..store import now_iso
from .approval import ApprovalMismatch, ApprovalRequired, applied_hash, approval_for, require_approval, revise
from .candidates import AdvisoryCheck, PlanInput, build_plan, build_queue, evaluate
from .models import CorrectionAttempt, Investigation, RemediationPlan, RiskScore, ValidationResult, VerificationReport
from .policy import VerifyInput, evaluate_verify, load_policy, posture
from .prioritize import prioritize
from .registry import RegistryClient
from .store import Day2Store
from .sandbox import short_key
from .threat import investigate_all
from .verify import build_report, deterministic_verdict, independent_review, worse

D2RUNS: dict[str, "Day2Context"] = {}


@dataclass
class Day2Context:
    ctx: RunContext
    d2: Day2Store
    policy: Any
    reg: RegistryClient
    adv: AdvisoryCheck
    only: list[str] | None = None
    replan: bool = False
    scores: list[RiskScore] = field(default_factory=list)
    investigations: dict[str, Investigation] = field(default_factory=dict)
    queue: list[PlanInput] = field(default_factory=list)
    after_components: dict[str, list] = field(default_factory=dict)
    after_findings: dict[str, list[Finding]] = field(default_factory=dict)
    validated: dict[str, int] = field(default_factory=dict)        # plan key -> revision validated in this run
    emit: Callable[[dict], None] = lambda e: None

    @property
    def findings(self) -> list[Finding]:
        return self.ctx.store.list_findings()


class D2State(TypedDict, total=False):
    d2_key: str
    node_status: Annotated[dict[str, str], lambda a, b: {**a, **b}]
    events: Annotated[list[dict], operator.add]
    approved: list[str]
    d2_status: str


def _node(name: str, fn: Callable[[Day2Context, D2State], dict | None]):
    def run(state: D2State) -> dict:
        dc = D2RUNS.get(state.get("d2_key") or "")
        if dc is None:
            return {"node_status": {name: "skipped"}, "events": [{"node": name, "status": "skipped", "message": "no Day 2 context"}]}
        t0 = time.time()
        try:
            extra = fn(dc, state) or {}
            status, msg = extra.pop("_status", "ok"), extra.pop("_message", "")
        except Exception as e:  # fail soft
            status, msg, extra = "degraded", f"{type(e).__name__}: {str(e)[:300]}", {}
            dc.d2.audit(name, "stage error", msg + "\n" + traceback.format_exc(limit=3)[-600:])
        ev = {"node": name, "status": status, "message": msg, "seconds": round(time.time() - t0, 2)}
        dc.emit(ev)
        return {"node_status": {name: status}, "events": [ev], **extra}
    return run


# ----------------------------------------------------------------------------- nodes
def n_prioritize(dc: Day2Context, state) -> dict:
    dc.scores = prioritize(dc.ctx, dc.findings, dc.policy)
    b = {k: sum(1 for s in dc.scores if s.bucket == k) for k in ("fix_now", "schedule", "monitor")}
    return {"_message": f"{len(dc.scores)} findings scored: {b['fix_now']} fix now, {b['schedule']} schedule, {b['monitor']} monitor"}


def n_investigate(dc: Day2Context, state) -> dict:
    cached = dc.d2.get("investigations")
    if cached and not dc.replan:
        dc.investigations = {k: Investigation.model_validate(v) for k, v in cached.items()}
    else:
        dc.investigations = investigate_all(dc.ctx, dc.findings, dc.reg)
        dc.d2.put("investigations", {k: v.model_dump() for k, v in dc.investigations.items()})
        for inv in dc.investigations.values():
            dc.d2.audit("S11", f"investigated: {inv.verdict}", f"{inv.subject} ({inv.signal}): {inv.verdict_reason}",
                        evidence_ids=sorted({e for c in inv.checks for e in c.evidence_ids})[:5])
    dc.scores = prioritize(dc.ctx, dc.findings, dc.policy, dc.investigations)       # re-score with verdicts
    dc.d2.save_artifact("priority.json", [s.model_dump() for s in dc.scores])
    dc.d2.save_artifact("investigations.json", {k: v.model_dump() for k, v in dc.investigations.items()})
    v = {}
    for inv in dc.investigations.values():
        v[inv.verdict] = v.get(inv.verdict, 0) + 1
    return {"_message": f"{len(dc.investigations)} non-CVE signal(s) investigated: " + ", ".join(f"{k}={n}" for k, n in sorted(v.items()))}


def n_plan(dc: Day2Context, state) -> dict:
    dc.queue = build_queue(dc.ctx, dc.findings, dc.scores, dc.investigations, dc.ctx.settings.max_queue, dc.only)
    made = kept = 0
    baseline = dc.findings
    for pin in dc.queue:
        existing = dc.d2.plan(pin.plan_key)
        if existing and not dc.replan:
            kept += 1
            continue
        work = dc.d2.dir / "sim" / short_key(pin.plan_key)
        plan = build_plan(dc.ctx, pin, dc.reg, dc.adv, dc.policy, baseline, work,
                          revision=(existing.revision + 1) if existing else 1, parent_hash=existing.plan_hash if existing else None)
        if existing:
            old = existing.model_copy(update={"status": "superseded"})
            dc.d2.save_plan(old)
        dc.d2.save_plan(plan)
        made += 1
        rec = plan.candidate(plan.recommended) if plan.recommended else None
        dc.d2.audit("S12", "plan created", f"{plan.title}: {len(plan.candidates)} candidates, finalists {plan.finalists}, "
                    f"recommended {rec.summary if rec else None} | hash {plan.plan_hash[:12]}", plan_key=plan.plan_key,
                    evidence_ids=(rec.evidence_ids if rec else [])[:2])
    dc.d2.save_artifact("remediation_plan.json", [p.model_dump() for p in dc.d2.plans()])
    notes = sorted(set(dc.reg.notes))[:5]
    return {"_message": f"{len(dc.queue)} plan(s) in queue: {made} new, {kept} kept (awaiting their decision)" +
            (f"; notes: {'; '.join(notes)}" if notes else "")}


def n_gate(dc: Day2Context, state) -> dict:
    approved, waiting = [], []
    keys = {p.plan_key for p in dc.queue} | {p.plan_key for p in dc.d2.plans() if p.status == "approved"}
    for key in sorted(keys):
        plan = dc.d2.plan(key)
        if not plan:
            continue
        rec = approval_for(dc.d2, plan)
        if plan.status == "approved" and rec and rec.decision == "approve":
            approved.append(key)
        elif plan.status == "awaiting_approval":
            waiting.append(key)
    msg = f"{len(approved)} approved plan(s) ready for validation; {len(waiting)} awaiting a decision"
    return {"approved": approved, "d2_status": "validated" if approved else "awaiting_approval", "_message": msg}


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:80]


COMPAT_PEN = {"low": 0, "medium": 5, "high": 15, "unknown": 8}


def n_validate(dc: Day2Context, state) -> dict:
    from .rescan import diff_scans, run_rescan
    from .sandbox import Sandbox, prepare_branch, validate_candidate
    from .selfcorrect import propose
    sb = Sandbox(dc.ctx, dc.d2)
    done = []
    for key in state.get("approved") or []:
        plan = dc.d2.plan(key)
        results: list[ValidationResult] = []
        for cid in plan.finalists:
            cand = plan.candidate(cid)
            root, diff, commit, branch = prepare_branch(dc.ctx, dc.d2, plan, cand)
            real = applied_hash(plan, {cid: diff})
            try:
                require_approval(dc.d2, plan, real)
            except (ApprovalRequired, ApprovalMismatch) as e:
                results.append(ValidationResult(plan_key=key, candidate_id=cid, branch=branch, sandbox=sb.effective, applied_hash=real,
                                                status="error", reason=f"approval gate: {e}", work_dir=str(root)))
                continue
            dc.d2.audit("S14", "applied on branch", f"{cid} -> {branch} commit {str(commit)[:12]} (applied hash matches approval)",
                        plan_key=key)
            v = validate_candidate(sb, dc.ctx, dc.d2, plan, cand, root, diff, commit, branch, real)
            if v.status in ("passed", "skipped"):
                rctx, info = run_rescan(dc.ctx, root, dc.d2.dir / "rescans" / short_key(key) / cid)
                if rctx is not None:
                    try:
                        v.rescan = diff_scans(dc.ctx, rctx, key, cid, plan.finding_ids, dc.policy, info)
                        dc.after_components[cid] = list(rctx.components)
                        dc.after_findings[cid] = rctx.store.list_findings()
                    finally:
                        rctx.store.close()
                    dc.d2.audit("S15", "rescanned", f"{cid}: target resolved={v.rescan.target_resolved}, "
                                f"{len(v.rescan.findings_new)} new finding(s), score {v.rescan.score_before} -> {v.rescan.score_after}",
                                plan_key=key, evidence_ids=[v.rescan.evidence_id] if v.rescan.evidence_id else [])
                else:
                    dc.d2.audit("S15", "rescan failed", f"{cid}: the Day 1 pipeline did not produce a context ({info})", plan_key=key)
            r = v.rescan
            v.tournament_score = round(
                (100 if r and r.target_resolved else 0) - 40 * len(r.new_high if r else []) - 20 * len(v.regressions)
                - COMPAT_PEN.get(cand.compatibility, 8) + (10 if v.tests_after.ran and not v.tests_after.smoke_only else 0)
                + (5 if v.status == "passed" else 0) + cand.score / 100, 2)
            results.append(v)
        ok = [v for v in results if v.status in ("passed", "skipped") and v.rescan and v.rescan.target_resolved and not v.rescan.new_high]
        if ok:
            win = max(ok, key=lambda v: v.tournament_score or 0)
            win.winner = True
            dc.d2.audit("S14", "tournament winner", f"{win.candidate_id} (score {win.tournament_score}) of {len(results)} finalist(s)",
                        plan_key=key)
        dc.d2.put(f"validation:{key}:{plan.revision}", [v.model_dump() for v in results])
        dc.validated[key] = plan.revision
        if not ok:
            corrections = [CorrectionAttempt.model_validate(x) for x in dc.d2.get(f"corrections:{key}", [])]
            failed = sorted(results, key=lambda v: -(v.tournament_score or -999))
            if failed and len(corrections) < dc.ctx.settings.max_corrections:
                pin = next((p for p in dc.queue if p.plan_key == key), None) or _plan_input(dc, plan)
                attempt, cand = propose(dc.ctx, plan, pin, failed, dc.reg, dc.adv, len(corrections) + 1)
                if cand is not None:
                    cands, _ = evaluate(dc.ctx, pin, [cand], dc.findings, dc.policy, dc.d2.dir / "sim" / short_key(key), 1)
                    cand = cands[0]
                    if cand.rejected_reason:
                        attempt.outcome, attempt.detail = "rejected_by_verifier", attempt.detail + f"; simulation: {cand.rejected_reason}"
                        plan.status = "failed"
                        dc.d2.save_plan(plan)
                    else:
                        new = revise(dc.d2, plan, [cand.id], f"self-correction round {attempt.round}: {attempt.failure_class}", extra=[cand])
                        attempt.new_plan_hash = new.plan_hash
                else:
                    plan.status = "escalated"
                    dc.d2.save_plan(plan)
                corrections.append(attempt)
                dc.d2.put(f"corrections:{key}", [c.model_dump() for c in corrections])
                dc.d2.audit("S14.6", f"self-correction: {attempt.outcome}", attempt.detail, plan_key=key,
                            evidence_ids=attempt.log_evidence_ids)
            else:
                plan.status = "escalated"
                dc.d2.save_plan(plan)
                dc.d2.audit("S14.6", "escalated", "all finalists failed and the self-correction budget is used up", plan_key=key)
        done.append(key)
    return {"_message": f"{len(done)} plan(s) validated in sandbox mode '{sb.effective}'" +
            (f" ({sb.unavailable})" if sb.unavailable else "")}


def _plan_input(dc: Day2Context, plan: RemediationPlan) -> PlanInput:
    fs = [f for f in dc.findings if f.id in plan.finding_ids]
    sc = {s.finding_id: s for s in dc.scores}
    return PlanInput(plan_key=plan.plan_key, title=plan.title, target=plan.target, findings=fs,
                     scores={f.id: sc[f.id] for f in fs if f.id in sc}, investigations=dc.investigations)


def n_verify(dc: Day2Context, state) -> dict:
    sc = {s.finding_id: s for s in dc.scores}
    out = []
    for key in state.get("approved") or []:
        rev = dc.validated.get(key)
        plan = dc.d2.plan(key, rev) if rev else dc.d2.plan(key)      # the revision that was actually validated
        raw = dc.d2.get(f"validation:{key}:{plan.revision}") or []
        results = [ValidationResult.model_validate(x) for x in raw]
        win = next((v for v in results if v.winner), None)
        corrections = [CorrectionAttempt.model_validate(x) for x in dc.d2.get(f"corrections:{key}", [])]
        approval = approval_for(dc.d2, plan)
        if win is None:
            best = max(results, key=lambda v: v.tournament_score or -999) if results else None
            rescan = best.rescan if best else None
            pol = evaluate_verify(dc.policy, VerifyInput(plan_key=key, plan_hash=plan.plan_hash, applied_hash=best.applied_hash if best else None,
                                                         approvals=dc.d2.approvals(key), target_ids=plan.finding_ids,
                                                         after_findings=dc.after_findings.get(best.candidate_id, []) if best else [],
                                                         new_finding_ids={x["id"] for x in (rescan.findings_new if rescan else [])},
                                                         after_components=dc.after_components.get(best.candidate_id, []) if best else [],
                                                         rescan=rescan, validation=best, investigations=dc.investigations))
            verdict = "Escalated" if plan.status == "escalated" else "Not verified"
            reasons = [best.reason] if best else ["no finalist could be validated"]
            if dc.d2.plan(key).status == "awaiting_approval":
                verdict, reasons = "Awaiting approval", ["self-correction produced a new plan revision; it needs a fresh approval"]
            rep = build_report(dc.ctx, dc.d2, plan, sc, dc.investigations, approval, plan.candidate(best.candidate_id) if best else None,
                               results, corrections, rescan, pol, None, verdict, verdict if verdict != "Awaiting approval" else "Not verified",
                               reasons)
        else:
            cand = plan.candidate(win.candidate_id)
            after_f = dc.after_findings.get(win.candidate_id, [])
            pol = evaluate_verify(dc.policy, VerifyInput(plan_key=key, plan_hash=plan.plan_hash, applied_hash=win.applied_hash,
                                                         approvals=dc.d2.approvals(key), target_ids=plan.finding_ids, after_findings=after_f,
                                                         new_finding_ids={x["id"] for x in win.rescan.findings_new},
                                                         after_components=dc.after_components.get(win.candidate_id, []),
                                                         rescan=win.rescan, validation=win, investigations=dc.investigations))
            det, reasons = deterministic_verdict(pol, win, win.rescan)
            review = independent_review(dc.ctx, plan, cand, win, win.rescan, dc.after_components.get(win.candidate_id, []), pol)
            verdict = worse(det, review.downgrade_to)
            if verdict != det:
                reasons.append(f"downgraded by the independent verifier: {review.reason}")
            rep = build_report(dc.ctx, dc.d2, plan, sc, dc.investigations, approval, cand, results, corrections, win.rescan, pol,
                               review, verdict, det, reasons)
            plan.status = "validated"
            dc.d2.save_plan(plan)
        dc.d2.audit("S16", f"verdict: {rep.verdict}", f"{plan.title}: confidence {rep.confidence}; " + "; ".join(rep.confidence_reasons[:3]),
                    plan_key=key)
        rep.timeline = dc.d2.timeline(key)
        dc.d2.put(f"report:{key}", rep.model_dump())
        dc.d2.save_artifact(f"verification/{_safe(key)}.json", rep)
        out.append(f"{plan.title[:50]}: {rep.verdict}")
    return {"_message": "; ".join(out) or "nothing to verify"}


def n_report(dc: Day2Context, state) -> dict:
    from .report import write_report
    path = write_report(dc)
    status = state.get("d2_status") or "done"
    if status == "validated" and any(p.status == "awaiting_approval" for p in dc.d2.plans()):
        status = "awaiting_approval"      # e.g. a self-correction revision, or other plans still waiting
    return {"_message": str(path), "d2_status": status}


# Day 2 stage nodes. Names are unique so they can live in the same LangGraph as the Day 1 nodes.
D2_NODES = [("prioritize", n_prioritize), ("investigate", n_investigate), ("remediation_plan", n_plan),
            ("approval_gate", n_gate), ("validate", n_validate), ("verify", n_verify), ("remediation_report", n_report)]


def add_day2_nodes(g: StateGraph, entry_from: Any, end: Any = END) -> None:
    """Attach S10-S16 to a graph: `entry_from` -> prioritize -> ... -> remediation_report -> `end`.
    Used by the standalone Day 2 graph (resume after approval) and by the integrated Day 1 + Day 2 pipeline."""
    for name, fn in D2_NODES:
        g.add_node(name, _node(name, fn))
    g.add_edge(entry_from, "prioritize")
    g.add_edge("prioritize", "investigate")
    g.add_edge("investigate", "remediation_plan")
    g.add_edge("remediation_plan", "approval_gate")
    g.add_conditional_edges("approval_gate", lambda s: "validate" if s.get("approved") else "remediation_report",
                            ["validate", "remediation_report"])
    g.add_edge("validate", "verify")
    g.add_edge("verify", "remediation_report")
    g.add_edge("remediation_report", end)


def build_graph():
    g = StateGraph(D2State)
    add_day2_nodes(g, START)
    return g.compile()


def start_day2(ctx: RunContext, only: list[str] | None = None, replan: bool = False,
               emit: Callable[[dict], None] | None = None, key: str | None = None) -> str:
    """Create and register the Day 2 context for a RunContext; returns its key (put it in state['d2_key'])."""
    d2 = Day2Store(ctx.store)
    policy = load_policy(ctx.root, ctx.settings.policy_path)
    d2.put("policy", {"sha256": policy.sha256, "sources": policy.sources, "notes": policy.notes, "rules": policy.rules,
                      "blocked_packages": policy.blocked})
    reg = RegistryClient(CachedHttp(ctx.settings.cache_dir, offline=ctx.settings.offline), ctx.settings.registry_snapshot)
    key = key or f"{ctx.store.run_id}:{time.time_ns()}"
    D2RUNS[key] = Day2Context(ctx=ctx, d2=d2, policy=policy, reg=reg, adv=AdvisoryCheck(ctx), only=only, replan=replan,
                              emit=emit or ctx.emit)
    d2.audit("day2", "run started", f"policy {policy.sha256[:12]} ({', '.join(policy.sources)}); sandbox {ctx.settings.sandbox}; "
             f"advisories {'snapshot' if ctx.settings.advisory_db else 'OSV'}" + (f"; only {only}" if only else ""))
    return key


def day2_result(run_dir: Path, store, status: str, node_status: dict[str, str]) -> "Day2Result":
    d2 = Day2Store(store)
    reports = [VerificationReport.model_validate(d2.get(k)) for k in d2.keys("report:")]
    rp = d2.dir / "report.json"
    return Day2Result(run_dir=Path(run_dir), status=status, report_path=rp if rp.exists() else None,
                      node_status={k: v for k, v in node_status.items() if k in dict(D2_NODES)}, plans=d2.plans(), reports=reports)


# ----------------------------------------------------------------------------- context loading
def load_context(run_dir: Path, settings: Settings) -> RunContext:
    """Rebuild a Day 1 RunContext from a finished run directory (another process, or after a restart)."""
    from ..graph import UnifiedGraph
    from ..llm import LLMClient
    from ..models import CodeIndex, Dossier, RepoFacts, RepoRef
    from ..sbom.stage import run_sbom_stage
    from ..store import RunStore
    run_dir = Path(run_dir)
    rep = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    if rep.get("status") == "failed":
        raise ValueError("the Day 1 run failed; nothing to remediate")
    repo = RepoRef.model_validate(rep["repo"])
    if not Path(repo.clone_path).is_dir():
        raise FileNotFoundError(f"scanned checkout not found: {repo.clone_path}")
    store = RunStore(run_dir, rep["run_id"])
    scratch = RunStore(run_dir / "day2" / "_reload", rep["run_id"])
    tmp = RunContext(repo=repo, store=scratch, settings=settings)
    tmp.facts = RepoFacts.model_validate_json((run_dir / "facts.json").read_text(encoding="utf-8"))
    run_sbom_stage(tmp)   # deterministic from the same tree and cache; evidence ids are content-addressed
    scratch.close()
    ctx = RunContext(repo=repo, store=store, settings=settings, facts=tmp.facts, components=tmp.components, edges=tmp.edges,
                     sbom_report=tmp.sbom_report, metadata=tmp.metadata)
    ci = run_dir / "code_index.json"
    ctx.code_index = CodeIndex.model_validate_json(ci.read_text(encoding="utf-8")) if ci.exists() else None
    ctx.graph = UnifiedGraph.build(repo.name, ctx.facts, ctx.components, ctx.edges, ctx.code_index)
    dp = run_dir / "dossier.json"
    ctx.dossier = Dossier.model_validate_json(dp.read_text(encoding="utf-8")) if dp.exists() else None
    ctx.llm = LLMClient.from_env(settings.cache_dir, settings.llm_model, settings.offline) if settings.use_llm else None
    from ..runner import git, ToolFailed
    try:
        head = git(Path(repo.clone_path), "rev-parse", "HEAD").strip() if (Path(repo.clone_path) / ".git").exists() else None
    except ToolFailed:
        head = None
    if repo.commit and head and head != repo.commit:
        ctx.store.add_evidence("derived", "day2", "checkout", f"checkout moved from {repo.commit} to {head} since the scan")
    return ctx


@dataclass
class Day2Result:
    run_dir: Path
    status: str
    report_path: Path | None
    node_status: dict[str, str]
    plans: list[RemediationPlan]
    reports: list[VerificationReport]


def run_day2(target: Path | RunContext, settings: Settings | None = None, only: list[str] | None = None, replan: bool = False,
             emit: Callable[[dict], None] = lambda e: None) -> Day2Result:
    """Day 2 on its own: resume after an approval, or re-plan. The integrated pipeline (orchestrator) runs the
    same nodes right after Day 1 detection."""
    if isinstance(target, RunContext):
        ctx = target
        if settings is not None:
            ctx.settings = settings
    else:
        ctx = load_context(Path(target), settings or Settings())
    key = start_day2(ctx, only, replan, emit)
    try:
        final = build_graph().invoke({"d2_key": key, "node_status": {}, "events": []}, config={"recursion_limit": 40})
    finally:
        D2RUNS.pop(key, None)
    return day2_result(ctx.store.run_dir, ctx.store, final.get("d2_status", "done"), final.get("node_status", {}))


def posture_summary(dc: Day2Context) -> list[dict]:
    return posture(dc.policy, dc.findings, dc.investigations)


__all__ = ["run_day2", "load_context", "Day2Result", "add_day2_nodes", "start_day2", "day2_result", "D2RUNS", "now_iso"]
