"""Stage 5 LangGraph wiring: detect -> group+prioritize -> Send("investigate_one") per deep subject
(+ light pass) -> report. Each deep subject: investigator -> verifier -> rules (same pattern as Stage 4;
review threads are opened by the report step with the shared Stage 4 review manager)."""
from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from guardian.stage4_vulns.schema import activity

from .context import Stage5Context
from .detectors import run_detectors
from .investigate import investigate, verify
from .report import write_outputs
from .rules import band, confidence, exposure, group, project_risk, review_reasons, sort_key, subject_name, suspicion
from .schema import AnomalyInvestigation

try:
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import Send
    HAVE_LANGGRAPH = True
except ImportError:  # pragma: no cover
    HAVE_LANGGRAPH = False

EXPOSURE_TEXT = {"install_path": "will run when this project is installed", "runtime_public": "is reachable from a public entry point",
                 "runtime_internal": "runs inside the application (no public path found)", "build_env": "is part of the build environment",
                 "installed_unused": "is installed but never imported", "not_in_install_set": "is not in the install set",
                 "unknown": "exposure could not be determined"}


def explain(name: str, sigs, inv: AnomalyInvestigation, susp: str, risk: str) -> tuple[str, str]:
    lead = "; ".join(s.text for s in sorted(sigs, key=lambda s: -{"weak": 0, "medium": 1, "strong": 2}[s.strength])[:3])
    parts = [f"{lead}."]
    if inv.normal_explanation:
        parts.append(f"Normal explanation{' (verified)' if inv.normal_explanation_verified else ''}: {inv.normal_explanation}.")
    elif any(s.behaviour for s in sigs):
        parts.append(f"Suspicious behaviour found ({inv.capability or 'see evidence'}); malicious intent not established.")
    parts.append(f"Exposure: it {EXPOSURE_TEXT.get(inv.exposure, inv.exposure)}" + (f" ({inv.exposure_note.rstrip('.')})." if inv.exposure_note else "."))
    checks = {s.check for s in sigs}
    if "hash_mismatch" in checks:
        rec = "Regenerate the lockfile from the official index and compare hashes before installing."
    elif checks & {"typosquat_edit_distance", "typosquat_separator", "typosquat_affix", "typosquat_lookalike"}:
        rec = f"Remove {name.split()[0]} and depend on {sigs[0].data.get('looks_like', 'the intended package')} instead; rotate any secrets on machines that installed it."
    elif "new_behaviour_in_update" in checks:
        rec = "Pin back to the previous version and review the new release's code before upgrading."
    elif checks & {"pull_request_target_checkout_head", "secrets_in_pr_workflow"}:
        rec = "Do not check out PR code under pull_request_target; use pull_request, or split privileged steps."
    elif checks & {"remote_script", "image_not_digest_pinned", "image_non_official", "image_unknown_registry"}:
        rec = "Pin the base image by digest and replace remote scripts with verified, pinned downloads."
    elif checks & {"new_dependency_unused"}:
        rec = "Remove the unused dependency or document why it is needed."
    elif "new_outbound_domain" in checks:
        rec = "Confirm the destination is approved and limit the data sent to it."
    elif inv.normal_explanation_verified:
        rec = "No action needed beyond normal update review."
    else:
        rec = "Review the evidence and confirm or dismiss."
    return " ".join(parts), rec


def assess(ctx: Stage5Context, subject: str, sigs, inv: AnomalyInvestigation, trace: list, verified: bool, checks: list,
           band_: str, ran: bool) -> dict:
    susp, why = suspicion(sigs, inv)
    risk = project_risk(susp, inv.exposure)
    conf, conf_why = confidence(inv, sigs, verified)
    reasons, guard = review_reasons(sigs, risk, conf, verified, inv.light_pass)
    name = subject_name(ctx, subject)
    text, rec = explain(name, sigs, inv, susp, risk)
    step = activity("risk", "Risk decided", f"suspicion {susp} ({why}); exposure {inv.exposure}; project risk {risk}; confidence {conf}"
                    + ("; human review required" if reasons else ""))
    return {"subject": subject, "name": name, "signals": sigs, "investigation": inv, "suspicion": susp, "suspicion_reason": why,
            "risk": risk, "confidence": conf, "confidence_reasons": conf_why, "review_reasons": reasons, "guard": guard,
            "explanation": text, "recommendation": rec, "verified": verified if ran else None, "verification_ran": ran,
            "checks": checks, "band": band_, "trace": trace + [step]}


def deep_one(ctx: Stage5Context, subject: str, sigs, band_: str) -> dict:
    def emit(step):
        ctx.s4.emit({"type": "activity", "stage5_subject": subject, **step})
    trace = [activity("detectors", "Signals grouped", f"{len(sigs)} signal(s): " + ", ".join(f"{s.detector} {s.check} ({s.strength})" for s in sigs))]
    inv, steps = investigate(ctx, subject, sigs, emit=emit)
    trace += steps + [activity("investigator", "Investigation submitted",
                               f"exposure {inv.exposure}; {len(inv.behaviour)} behaviour item(s); "
                               f"normal explanation: {'yes' if inv.normal_explanation else 'none found'}")]
    verified, checks, vsteps = verify(ctx, inv, sigs, emit=emit)
    trace += vsteps + [activity("verifier", "Evidence verified", f"{sum(c['ok'] for c in checks)}/{len(checks)} claim(s) confirmed", ok=verified)]
    if not verified:
        inv.dropped += [f"verifier dropped: {c['text'][:100]}" for c in checks if not c["ok"]]
        inv.claims = [c for c in inv.claims if c.verified]
    return assess(ctx, subject, sigs, inv, trace, verified, checks, band_, True)


def light_one(ctx: Stage5Context, subject: str, sigs, band_: str) -> dict:
    exp, note = exposure(ctx, subject, sigs)
    inv = AnomalyInvestigation(subject=subject, signals=[s.signal_id for s in sigs], exposure=exp, exposure_note=note,
                               light_pass=True, capability="not investigated (light pass)")
    trace = [activity("prioritize", "Light pass (no agent)", f"band {band_}: weak or metadata-only signals")]
    return assess(ctx, subject, sigs, inv, trace, True, [], band_, False)


def plan(ctx: Stage5Context, signals):
    groups = group(signals)
    items = []
    for subj, sigs in groups.items():
        exp, _ = exposure(ctx, subj, sigs)
        b = band(sigs, exp, (ctx.s3.blast.get(subj) or {}).get("radius"))
        items.append({"subject": subj, "signals": sigs, "band": b})
    items.sort(key=lambda x: (x["band"], sort_key(x["signals"]), x["subject"]))
    deep = [x for x in items if x["band"] in ("P1", "P2")][: ctx.budgets.deep]
    light = [x for x in items if x not in deep]
    return deep, light


def run(ctx: Stage5Context, scan_id: str) -> dict:
    if not HAVE_LANGGRAPH:
        signals = run_detectors(ctx)
        deep, light = plan(ctx, signals)
        results = [deep_one(ctx, x["subject"], x["signals"], x["band"]) for x in deep] + \
                  [light_one(ctx, x["subject"], x["signals"], x["band"]) for x in light]
        return {"signals": signals, "cards": write_outputs(ctx, signals, results, scan_id), "deep": deep, "light": light}

    class S(TypedDict, total=False):
        signals: list
        deep: list
        light: list
        results: Annotated[list, operator.add]
        cards: list

    def detect_node(s):
        sigs = run_detectors(ctx)
        ctx.s4.emit({"type": "stage", "stage": "5", "status": "signals", "signals": len(sigs)})
        return {"signals": sigs}

    def plan_node(s):
        deep, light = plan(ctx, s["signals"])
        ctx.s4.emit({"type": "stage", "stage": "5", "status": "investigating", "deep": len(deep), "light": len(light)})
        return {"deep": deep, "light": light}

    def fan(s):
        sends = [Send("investigate_one", x) for x in s["deep"]] + [Send("light_one", x) for x in s["light"]]
        return sends or "report"

    b = StateGraph(S)
    b.add_node("detect", detect_node)
    b.add_node("group_prioritize", plan_node)
    b.add_node("investigate_one", lambda x: {"results": [deep_one(ctx, x["subject"], x["signals"], x["band"])]})
    b.add_node("light_one", lambda x: {"results": [light_one(ctx, x["subject"], x["signals"], x["band"])]})
    b.add_node("report", lambda s: {"cards": write_outputs(ctx, s.get("signals", []), s.get("results", []), scan_id)})
    b.add_edge(START, "detect")
    b.add_edge("detect", "group_prioritize")
    b.add_conditional_edges("group_prioritize", fan, ["investigate_one", "light_one", "report"])
    b.add_edge("investigate_one", "report")
    b.add_edge("light_one", "report")
    b.add_edge("report", END)
    return b.compile().invoke({"results": []}, config={"max_concurrency": ctx.s4.budgets.concurrency, "recursion_limit": 100})
