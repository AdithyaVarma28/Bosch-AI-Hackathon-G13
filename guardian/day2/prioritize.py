"""Risk prioritization (docs/DAY_2_PLAN.md section 3): the AI answers narrow questions with cited evidence,
fixed tables compute the decision, priority and confidence."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Optional

from .common import BANDS, REGISTER_FILE, band_idx, conf_idx, lower_conf, read_json, write_json
from .history import record_history
from .register import build_register
from .ssvc import cve_decision, exposure_column, priority, supply_decision

PROMPTS = Path(__file__).parent / "prompts"
CLASSIFY_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {"automatable": {"type": "string", "enum": ["yes", "no"]},
                   "technical_impact": {"type": "string", "enum": ["partial", "total"]},
                   "rationale": {"type": "string"},
                   "evidence_ids": {"type": "array", "items": {"type": "string"}}},
    "required": ["automatable", "technical_impact", "rationale", "evidence_ids"],
}


# ------------------------------------------------------------------ rule inputs
def exploitation(e: dict) -> tuple[str, str]:
    if e.get("kev"):
        return "active", "listed in CISA KEV (exploited in the wild)"
    for r in e.get("references") or []:
        t, url = (r.get("type") or "").upper(), (r.get("url") or "").lower()
        if t in ("EXPLOIT", "POC") or re.search(r"exploit|/poc\b|proof-of-concept", url):
            return "poc", f"public exploit / PoC reference: {r.get('url')}"
    pct = (e.get("epss") or {}).get("percentile")
    if pct is not None and pct >= 0.9:
        return "poc", f"EPSS percentile {pct:.2f} ≥ 0.90"
    return "none", "no KEV listing, no exploit reference" + ("" if e.get("epss") else ", no EPSS score")


def automatable_rule(e: dict) -> tuple[str, str]:
    v = ((e.get("cvss") or {}).get("vector") or "")
    ok = all(k in v for k in ("AV:N", "PR:N", "UI:N"))
    return ("yes" if ok else "no"), (f"CVSS vector {'has' if ok else 'lacks'} AV:N/PR:N/UI:N")


def technical_impact_rule(e: dict) -> tuple[str, str]:
    v = ((e.get("cvss") or {}).get("vector") or "")
    text = f"{e.get('summary') or ''} {e.get('title') or ''}".lower()
    if all(k in v for k in ("C:H", "I:H", "A:H")) or all(k in v for k in ("VC:H", "VI:H", "VA:H")):
        return "total", "CVSS impact C/I/A all high"
    if re.search(r"remote code execution|arbitrary code|code execution|\brce\b", text):
        return "total", "advisory describes code execution"
    return "partial", "CVSS impact not total"


def mission(e: dict) -> tuple[str, str]:
    sens = (e.get("sensitivity") or {}).get("level", "low")
    if e.get("scope") != "runtime":
        return "low", f"{e.get('scope')} scope"
    if e.get("usage") == "package_not_imported":
        return "low", "package is never imported by the code"
    public = e.get("reachability") == "public_path"
    if sens == "high":
        return "high", "affected code is high-sensitivity: " + "; ".join((e.get("sensitivity") or {}).get("reasons", [])[:2])
    if public or sens == "medium":
        return "medium", ("reachable from a public route" if public else "affected module is medium-sensitivity")
    return "low", "internal-only, low-sensitivity code"


def suspicion_level(e: dict) -> str:
    s = (e.get("suspicion") or "low").lower()
    verified = any(g.get("behaviour") and g.get("strength") == "strong" for g in e.get("signals") or [])
    if s == "high" and verified and e.get("stage_confidence") == "high":
        return "verified"
    return s if s in ("low", "medium", "high") else "low"


# ------------------------------------------------------------------ AI classifier
def evidence_pack(e: dict) -> str:
    conds = [f"- {c.get('text')}: {c.get('status')} ({c.get('note') or ''})" for c in e.get("conditions") or []]
    sites = [f"- {s.get('file')}:{s.get('lines')} `{s.get('code')}`" for s in e.get("usage_sites") or []]
    ev = [f"- {x['id']} [{x['type']}] {x['where']} {x['text']}" for x in e.get("evidence") or []]
    return "\n".join([
        f"Vulnerability: {e.get('vuln_id')} in {e.get('component')} — {e.get('summary')}",
        f"CVSS: {(e.get('cvss') or {}).get('score')} {(e.get('cvss') or {}).get('vector')}",
        f"Usage in repo: {e.get('usage')}; reachability: {e.get('reachability')}; scope: {e.get('scope')}",
        f"Module sensitivity: {(e.get('sensitivity') or {}).get('level')} {(e.get('sensitivity') or {}).get('reasons')}",
        "Trigger conditions:", *(conds or ["- none extracted"]),
        "Call sites:", *(sites or ["- none"]),
        "Evidence:", *(ev or ["- none"]),
    ])


def classify(llm, e: dict) -> tuple[Optional[dict], bool, list[str]]:
    """(answer or None, agreement, notes). Two samples for self-consistency; invalid citations are rejected."""
    if llm is None or not llm.available:
        return None, True, []
    system = (PROMPTS / "classify_system.md").read_text(encoding="utf-8")
    known = {x["id"] for x in e.get("evidence") or []}
    answers, notes = [], []
    for sample in (1, 2):
        res = llm.complete_json("prioritize", system, evidence_pack(e) + f"\n\n(sample {sample})", CLASSIFY_SCHEMA)
        if not res:
            notes.append(f"sample {sample}: no answer")
            continue
        bad = [i for i in res.get("evidence_ids") or [] if i not in known]
        if bad or not res.get("evidence_ids"):
            notes.append(f"sample {sample} rejected: " + (f"unknown evidence ids {bad}" if bad else "no evidence cited"))
            continue
        answers.append(res)
    if not answers:
        return None, True, notes
    agree = len(answers) < 2 or (answers[0]["automatable"], answers[0]["technical_impact"]) == \
        (answers[1]["automatable"], answers[1]["technical_impact"])
    return answers[0], agree, notes


# ------------------------------------------------------------------ main
def prioritize_entry(e: dict, llm=None) -> dict:
    inputs, why, by = {}, {}, {}
    ai_notes: list[str] = []
    agreement, ai_rejected = True, False
    if e["kind"] == "vulnerability":
        inputs["exploitation"], why["exploitation"] = exploitation(e)
        by["exploitation"] = "rules"
        inputs["automatable"], why["automatable"] = automatable_rule(e)
        inputs["technical_impact"], why["technical_impact"] = technical_impact_rule(e)
        by["automatable"] = by["technical_impact"] = "rules"
        worth_ai = band_idx(e.get("stage_risk")) >= band_idx("high") or ((e.get("cvss") or {}).get("score") or 0) >= 7
        if worth_ai and e.get("usage") != "package_not_imported":
            ans, agreement, ai_notes = classify(llm, e)
            if ans:
                inputs["automatable"], inputs["technical_impact"] = ans["automatable"], ans["technical_impact"]
                why["automatable"] = why["technical_impact"] = ans["rationale"]
                by["automatable"] = by["technical_impact"] = "ai"
                e["ai_evidence_ids"] = ans["evidence_ids"]
            elif ai_notes and any("rejected" in n for n in ai_notes):
                ai_rejected = True
        inputs["mission"], why["mission"] = mission(e)
        by["mission"] = "rules"
        decision = cve_decision(inputs["exploitation"], inputs["automatable"], inputs["technical_impact"], inputs["mission"])
        model, col = "ssvc-cisa-inspired", None
    else:
        inputs["suspicion"] = suspicion_level(e)
        why["suspicion"] = {"verified": "strong signal whose behaviour was verified in the cited lines"}.get(
            inputs["suspicion"], f"Stage 5 suspicion {e.get('suspicion')}")
        inputs["exposure"] = e.get("exposure")
        why["exposure"] = e.get("exposure") or "unknown"
        by["suspicion"] = by["exposure"] = "rules"
        decision = supply_decision(inputs["suspicion"], inputs["exposure"])
        model, col = "guardian-supplychain", exposure_column(e.get("exposure"))
    inputs_by = "ai" if "ai" in by.values() else "rules"
    if e["kind"] == "vulnerability":
        col = "not_installed" if e.get("usage") == "package_not_imported" and e.get("scope") == "runtime" else None
    prio, reasons, limited = priority(decision, scope=e.get("scope") or "runtime", exposure_col=col, kev=e.get("kev"),
                                      sensitivity=(e.get("sensitivity") or {}).get("level", "low"),
                                      inputs_by=inputs_by, stage_risk=e.get("stage_risk"))
    # finding confidence
    conf = e.get("stage_confidence") or "medium"
    creasons = [f"investigation confidence {conf}"]
    if limited:
        conf = lower_conf(conf)
        creasons.append("rule-based risk and contextual decision disagree by 2+ bands → one level lower")
    if not agreement:
        conf = lower_conf(conf)
        creasons.append("the two AI classifier samples disagreed → one level lower")
    if ai_rejected and band_idx(prio) >= band_idx("high") and conf_idx(conf) > conf_idx("medium"):
        conf = "medium"
        creasons.append("AI answer rejected (bad citations); rule fallback used → at most medium")
    e.update({
        "decision_model": model, "decision": decision, "decision_inputs": {**inputs, "stage_risk": e.get("stage_risk"),
                                                                           "cvss": (e.get("cvss") or {}).get("score"),
                                                                           "kev": e.get("kev"),
                                                                           "epss_percentile": (e.get("epss") or {}).get("percentile")},
        "decision_why": why, "decision_by": by, "classifier_agreement": agreement, "classifier_notes": ai_notes,
        "priority": prio, "priority_reasons": reasons, "downgrade_limited": limited,
        "finding_confidence": conf, "confidence_reasons": creasons,
    })
    return e


def order_key(e: dict):
    return (-band_idx(e["priority"]), -["Track", "Track*", "Attend", "Act"].index(e["decision"]), -int(bool(e.get("kev"))),
            -((e.get("epss") or {}).get("probability") or 0), -((e.get("cvss") or {}).get("score") or 0),
            -{"low": 0, "medium": 1, "high": 2}.get((e.get("sensitivity") or {}).get("level"), 0), e["finding_id"])


def run_prioritize(out: Path, llm=None, log: Callable[[str], None] = print) -> list[dict]:
    out = Path(out)
    entries = [prioritize_entry(e, llm) for e in build_register(out)]
    entries.sort(key=order_key)
    for i, e in enumerate(entries, 1):
        e["rank"] = i
    meta = read_json(out / "scan.json", {}) or {}
    repo = meta.get("repo") or ((read_json(out / "facts.json", {}) or {}).get("repo") or {}).get("name") or "repo"
    try:
        hist = record_history(out, repo, meta.get("scan_id") or out.name, entries)
        for e in entries:
            items = hist.get(e["history_key"], [])
            e["history"] = items[-5:]
    except OSError as exc:
        log(f"day2: risk history not written: {exc}")
    write_json(out / REGISTER_FILE, entries)
    by = {b: sum(1 for e in entries if e["priority"] == b) for b in reversed(BANDS)}
    log(f"day2: prioritized {len(entries)} findings (" + ", ".join(f"{k} {v}" for k, v in by.items()) + ")"
        + (f"; AI classifier calls: {llm.used('prioritize')}" if llm is not None and llm.available else "; rules only"))
    return entries
