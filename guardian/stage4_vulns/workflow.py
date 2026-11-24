"""LangGraph wiring (docs/stage4.md section 12).

main graph:   discover -> prioritize -> Send("investigate_one", item) per deep item
                                      -> Send("light_one", item) per light item  -> report
per-vuln graph (investigate_one):
              analyst -> investigator -> (needs verifier? verifier : risk)
              verifier -> (claim failed and retry left? investigator : risk) -> END

Deep investigations run in parallel (``max_concurrency`` = budgets.concurrency). Human review is a
separate graph per finding (review.py), opened by the report step, so the report never waits for people.
Without LangGraph installed the same node functions run in order.
"""
from __future__ import annotations

import operator
from typing import Annotated, Any, Optional, TypedDict

from .analyst import analyze
from .context import Stage4Context
from .discovery import discover
from .investigator import investigate, light_investigation
from .prioritize import plan
from .report import write_outputs
from .risk import explain, verdict
from .schema import Fingerprint, Investigation, Verification, VulnMatch, activity
from .verifier import apply_verification, triggers, verify

try:
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import Send
    HAVE_LANGGRAPH = True
except ImportError:  # pragma: no cover
    HAVE_LANGGRAPH = False


class VulnState(TypedDict, total=False):
    match: VulnMatch
    item: dict
    fingerprint: Fingerprint
    investigation: Investigation
    verification: Optional[Verification]
    pending_verification: Optional[Verification]
    objections: list[str]
    retries: int
    verdict: Any
    trace: Annotated[list, operator.add]


class ScanState(TypedDict, total=False):
    matches: list
    deep: list
    light: list
    results: Annotated[list, operator.add]
    cards: list


# --------------------------------------------------------------------------- per-vuln nodes

def make_vuln_nodes(ctx: Stage4Context):
    def emitter(m: VulnMatch):
        def emit(step: dict) -> None:
            ctx.emit({"type": "activity", "stage4_match": m.match_id, "vuln_id": m.vuln_id,
                      "package": m.package_name, **step})
        return emit

    def analyst_node(s: VulnState) -> dict:
        m = s["match"]
        fp = analyze(ctx, m)
        step = activity("analyst", "Advisory parsed",
                        (f"vulnerable symbol(s): {', '.join(fp.vulnerable_symbols)} (from {fp.symbols_source.replace('_', ' ')})"
                         if fp.vulnerable_symbols else "no vulnerable symbol named: package-level check only")
                        + (f"; conditions: {'; '.join(t.text for t in fp.trigger_conditions[:2])}" if fp.trigger_conditions else ""),
                        tool="advisory", input={"vuln_id": m.vuln_id})
        emitter(m)(step)
        return {"fingerprint": fp, "trace": [step], "retries": s.get("retries", 0), "objections": []}

    def investigator_node(s: VulnState) -> dict:
        m, fp = s["match"], s["fingerprint"]
        inv, steps = investigate(ctx, m, fp, s.get("objections") or [], emit=emitter(m))
        decision = activity("investigator", "Investigation submitted",
                            f"usage: {inv.usage}; reachability: {inv.reachability}; {len(inv.claims)} claim(s)"
                            + (f"; {len(inv.dropped)} dropped by evidence checks" if inv.dropped else ""))
        emitter(m)(decision)
        return {"investigation": inv, "trace": steps + [decision]}

    def route_after_investigation(s: VulnState) -> str:
        m, inv, fp = s["match"], s["investigation"], s["fingerprint"]
        if s.get("retries", 0) > 0:
            return "verifier"            # a retried investigation is always re-verified
        prelim = verdict(m, inv, fp, None)
        return "verifier" if triggers(m, inv, prelim) else "risk"

    def verifier_node(s: VulnState) -> dict:
        m, inv, fp = s["match"], s["investigation"], s["fingerprint"]
        prelim = verdict(m, inv, fp, None)
        trig = triggers(m, inv, prelim)
        retries = s.get("retries", 0)
        ver, steps = verify(ctx, m, inv, trig, emit=emitter(m), retried=retries > 0)
        can_retry = (not ver.verified and retries < ctx.budgets.verifier_retries and inv.discovered_by == "ai")
        result = activity("verifier", "Evidence verified",
                          f"{sum(c.ok for c in ver.checks)}/{len(ver.checks)} claim(s) confirmed"
                          + ("; sent back to the investigator once" if can_retry else
                             (f"; {len(ver.objections)} claim(s) dropped" if not ver.verified else "")),
                          ok=ver.verified)
        emitter(m)(result)
        if can_retry:
            return {"pending_verification": ver, "objections": ver.objections, "retries": retries + 1,
                    "trace": steps + [result]}
        inv = apply_verification(inv, ver)
        return {"investigation": inv, "verification": ver, "pending_verification": None, "trace": steps + [result]}

    def route_after_verifier(s: VulnState) -> str:
        return "investigator" if s.get("pending_verification") is not None else "risk"

    def risk_node(s: VulnState) -> dict:
        m, inv, fp, ver = s["match"], s["investigation"], s["fingerprint"], s.get("verification")
        v = verdict(m, inv, fp, ver)
        v = explain(ctx, m, inv, fp, v)
        step = activity("risk", "Risk decided",
                        f"project risk {v.project_risk} (rule {v.rule}: {v.rule_text}); CVSS {m.cvss.score or m.cvss.band}; "
                        f"confidence {v.confidence}" + ("; human review required" if v.needs_human_review else ""))
        emitter(m)(step)
        return {"verdict": v, "trace": [step]}

    return analyst_node, investigator_node, route_after_investigation, verifier_node, route_after_verifier, risk_node


def build_vuln_graph(ctx: Stage4Context):
    a, i, ri, v, rv, r = make_vuln_nodes(ctx)
    b = StateGraph(VulnState)
    b.add_node("analyst", a)
    b.add_node("investigator", i)
    b.add_node("verifier", v)
    b.add_node("risk", r)
    b.add_edge(START, "analyst")
    b.add_edge("analyst", "investigator")
    b.add_conditional_edges("investigator", ri, ["verifier", "risk"])
    b.add_conditional_edges("verifier", rv, ["investigator", "risk"])
    b.add_edge("risk", END)
    return b.compile()


def run_vuln_sequential(ctx: Stage4Context, state: VulnState) -> VulnState:
    a, i, ri, v, rv, r = make_vuln_nodes(ctx)
    s: dict = dict(state)
    trace: list = []

    def merge(update: dict) -> None:
        for k, val in update.items():
            if k == "trace":
                trace.extend(val)
            else:
                s[k] = val
    merge(a(s))
    while True:
        merge(i(s))
        if ri(s) == "risk":
            break
        merge(v(s))
        if rv(s) == "risk":
            break
    merge(r(s))
    s["trace"] = trace
    return s


def _result(state: dict, item: dict) -> dict:
    return {"match": state["match"], "fingerprint": state["fingerprint"], "investigation": state["investigation"],
            "verification": state.get("verification"), "verdict": state["verdict"], "trace": state.get("trace", []),
            "priority": item.get("priority"), "rank": item.get("rank")}


def light_result(ctx: Stage4Context, item: dict) -> dict:
    m: VulnMatch = item["match"]
    fp = Fingerprint(vuln_id=m.vuln_id, symbols_source="none", confidence=0.0)
    if m.scope != "container_os":
        fp = analyze_light(ctx, m)
    inv = light_investigation(ctx, m, item.get("usage"), item["reason"])
    v = explain(ctx, m, inv, fp, verdict(m, inv, fp, None), use_llm=False)
    steps = [activity("prioritize", "Light pass (no agent)", item["reason"]),
             activity("risk", "Risk decided", f"project risk {v.project_risk} (rule {v.rule}: {v.rule_text}); "
                                             f"confidence {v.confidence}")]
    return {"match": m, "fingerprint": fp, "investigation": inv, "verification": None, "verdict": v, "trace": steps,
            "priority": item.get("priority"), "rank": None}


def analyze_light(ctx: Stage4Context, m: VulnMatch) -> Fingerprint:
    """Light items get the deterministic fingerprint only (no LLM call)."""
    from .analyst import extract_offline
    from .graphfacts import import_names
    imports = import_names(ctx.s3, m.package) if m.package in ctx.G else [m.package_name.lower().replace("-", "_")]
    return extract_offline(m, imports, [])


# --------------------------------------------------------------------------- main graph

def run(ctx: Stage4Context) -> dict:
    if not HAVE_LANGGRAPH:
        ctx.coverage["workflow"] = "sequential (LangGraph not installed)"
        matches = discover(ctx)
        deep, light = plan(ctx, matches)
        ctx.emit({"type": "stage", "stage": "4", "status": "investigating", "deep": len(deep), "light": len(light)})
        results = [_result(run_vuln_sequential(ctx, {"match": it["match"], "item": it}), it) for it in deep]
        results += [light_result(ctx, it) for it in light]
        cards = write_outputs(ctx, matches, results)
        return {"matches": matches, "deep": deep, "light": light, "results": results, "cards": cards}

    ctx.coverage["workflow"] = "langgraph"
    vuln_graph = build_vuln_graph(ctx)

    def discover_node(s: ScanState) -> dict:
        matches = discover(ctx)
        ctx.emit({"type": "stage", "stage": "4", "status": "discovered", "matches": len(matches)})
        return {"matches": matches}

    def prioritize_node(s: ScanState) -> dict:
        deep, light = plan(ctx, s["matches"])
        ctx.emit({"type": "stage", "stage": "4", "status": "investigating", "deep": len(deep), "light": len(light)})
        return {"deep": deep, "light": light}

    def fan_out(s: ScanState):
        sends = [Send("investigate_one", {"item": it}) for it in s["deep"]] + \
                [Send("light_one", {"item": it}) for it in s["light"]]
        return sends or "report"

    def investigate_one(payload: dict) -> dict:
        it = payload["item"]
        out = vuln_graph.invoke({"match": it["match"], "item": it})
        return {"results": [_result(out, it)]}

    def light_one(payload: dict) -> dict:
        return {"results": [light_result(ctx, payload["item"])]}

    def report_node(s: ScanState) -> dict:
        cards = write_outputs(ctx, s.get("matches", []), s.get("results", []))
        return {"cards": cards}

    b = StateGraph(ScanState)
    b.add_node("discover", discover_node)
    b.add_node("prioritize", prioritize_node)
    b.add_node("investigate_one", investigate_one)
    b.add_node("light_one", light_one)
    b.add_node("report", report_node)
    b.add_edge(START, "discover")
    b.add_edge("discover", "prioritize")
    b.add_conditional_edges("prioritize", fan_out, ["investigate_one", "light_one", "report"])
    b.add_edge("investigate_one", "report")
    b.add_edge("light_one", "report")
    b.add_edge("report", END)
    g = b.compile()
    return g.invoke({"results": []}, config={"max_concurrency": ctx.budgets.concurrency, "recursion_limit": 100})
