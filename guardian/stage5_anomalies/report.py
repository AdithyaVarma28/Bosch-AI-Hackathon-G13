"""Stage 5 report: anomaly finding cards (Stage 4 card shape with ``type: anomaly``), graph update
(``Anomaly`` nodes + ``FLAGS`` edges), ``signals.json``, ``anomaly_findings.json``, ``anomaly_traces.json``."""
from __future__ import annotations

import json
from pathlib import Path

from guardian.stage3_knowledge.export import graph_json
from guardian.stage3_knowledge.graph_builder import add_edge, add_node
from guardian.stage4_vulns.review import ReviewManager, files_hash, review_summary, triage_key
from guardian.stage4_vulns.schema import RISKS, activity, risk_rank

from .context import Stage5Context
from .schema import STRENGTH_RANK

FINDINGS_FILE = "anomaly_findings.json"
TRACES_FILE = "anomaly_traces.json"
SIGNALS_FILE = "signals.json"
SUSPICION_RANK = {"low": 0, "medium": 1, "high": 2}


def _dump(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def title_of(r: dict) -> str:
    sigs = r["signals"]
    top = max(sigs, key=lambda s: STRENGTH_RANK[s.strength])
    return f"{r['name']}: {top.text}"[:160]


def build_card(ctx: Stage5Context, r: dict) -> dict:
    inv, sigs = r["investigation"], r["signals"]
    evidence = []
    for b in inv.behaviour:
        evidence.append({"type": "package_code" if b.file.startswith("pkg:") else "code", "file": b.file, "lines": b.lines,
                         "detail": b.detail})
    for s in sigs:
        for e in s.evidence:
            if e.get("pypi"):
                evidence.append({"type": "metadata", "pypi": e["pypi"]})
            elif e.get("commit"):
                evidence.append({"type": "commit", "commit": e["commit"]})
            elif e.get("file") and not any(x.get("file") == e["file"] for x in evidence):
                evidence.append({"type": "code", "file": e["file"], "lines": str(e.get("lines") or e.get("line") or "")})
    seen, ev2 = set(), []
    for e in evidence:
        k = json.dumps(e, sort_keys=True)
        if k not in seen:
            seen.add(k)
            ev2.append(e)
    files = sorted({e.file for c in inv.claims for e in c.evidence if e.file and not e.file.startswith("pkg:")})
    fh = files_hash(ctx.s3.code_index, files)
    subj_ver = r["name"]
    key = triage_key("anomaly", r["subject"], subj_ver, fh + "|" + ",".join(sorted(s.check for s in sigs)))
    return {
        "finding_id": "", "type": "anomaly", "subject_id": r["subject"], "title": title_of(r),
        "component": r["subject"], "component_name": r["name"],
        "detectors": sorted({s.detector for s in sigs}), "signals": [s.model_dump() for s in sigs],
        "suspicion": r["suspicion"], "suspicion_reason": r["suspicion_reason"],
        "exposure": inv.exposure, "exposure_note": inv.exposure_note,
        "capability": inv.capability, "normal_explanation": inv.normal_explanation,
        "normal_explanation_verified": inv.normal_explanation_verified,
        "project_risk": r["risk"], "confidence": r["confidence"], "confidence_reasons": r["confidence_reasons"],
        "priority_band": r["band"], "explanation": r["explanation"], "recommendation": r["recommendation"],
        "explanation_by": "template", "evidence": ev2,
        "claims": [c.model_dump() for c in inv.claims], "unknowns": inv.unknowns,
        "review": {"status": "pending" if r["review_reasons"] else "not_required", "reasons": r["review_reasons"],
                   "downgrade_guard": r["guard"]},
        "verified": r["verified"], "verification": {"ran": r["verification_ran"], "checks": r["checks"]},
        "investigation": {"light_pass": inv.light_pass, "tool_calls_used": inv.tool_calls_used,
                          "budget_exhausted": inv.budget_exhausted, "discovered_by": inv.discovered_by, "dropped": inv.dropped},
        "commit": next((s.commit for s in sigs if s.commit), None),
        "evidence_files": files, "evidence_files_hash": fh, "triage_key": key,
        "discovered_by": ["detector", inv.discovered_by],
    }


def write_outputs(ctx: Stage5Context, signals, results: list[dict], scan_id: str) -> list[dict]:
    out = Path(ctx.output_dir)
    cards = [build_card(ctx, r) for r in results]
    traces_by_subject = {r["subject"]: r["trace"] for r in results}
    cards.sort(key=lambda c: (-risk_rank(c["project_risk"]), -SUSPICION_RANK[c["suspicion"]], c["component"]))
    for i, c in enumerate(cards, 1):
        c["finding_id"] = f"A-{i:03d}"
    mgr = ReviewManager(out)
    try:
        for i, c in enumerate(cards):
            if c["review"]["status"] == "pending":
                cards[i] = mgr.prepare(c, scan_id)
    finally:
        mgr.close()
    G = ctx.G
    for c in cards:
        aid = f"anomaly:{c['finding_id']}"
        add_node(G, aid, "Anomaly", "detector", [], name=c["title"], suspicion=c["suspicion"], exposure=c["exposure"],
                 project_risk=c["project_risk"], detectors=c["detectors"])
        targets = {c["component"]} | {f"commit:{s['commit']}" for s in c["signals"] if s.get("commit")}
        for t in targets:
            if t in G:
                add_edge(G, aid, t, "FLAGS", "detector", [], key=f"FLAGS:{t}")
        if c["component"] in G:
            G.nodes[c["component"]].setdefault("anomalies", [])
            if c["finding_id"] not in G.nodes[c["component"]]["anomalies"]:
                G.nodes[c["component"]]["anomalies"].append(c["finding_id"])
    traces = {}
    for c in cards:
        rv = c["review"]
        traces[c["finding_id"]] = traces_by_subject.get(c["component"], []) + [activity(
            "review", "Human review requested" if rv["status"] == "pending" else
            ("Earlier decision reused" if rv.get("reused") else "No review needed"),
            "; ".join(rv.get("reasons") or []) or "rules did not require a human decision")]
    _dump(out / SIGNALS_FILE, {"signals": [s.model_dump() for s in signals], "coverage": ctx.coverage,
                               "summary": {"findings": len(cards), "by_risk": {r: sum(1 for c in cards if c["project_risk"] == r) for r in RISKS},
                                           "review": review_summary(cards)}})
    _dump(out / FINDINGS_FILE, cards)
    _dump(out / TRACES_FILE, traces)
    _dump(out / "graph.json", graph_json(G))
    return cards
