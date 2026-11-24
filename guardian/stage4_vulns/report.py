"""Step 8 Report + graph update (deterministic): finding cards, Vulnerability nodes, output files.

Files in ``output/<repo>/``: ``vulns.json`` (all matches + discovery coverage), ``vuln_findings.json``
(finding cards), ``vuln_traces.json`` (investigation timeline per finding), ``triage.json`` (human
decisions). ``graph.json`` and ``ui_bundle.json`` are rewritten with the new nodes/cards.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from guardian.stage3_knowledge.export import graph_json
from guardian.stage3_knowledge.graph_builder import add_edge, add_node, ev
from guardian.stage3_knowledge.schema import short_label

from .context import Stage4Context
from .review import ReviewManager, files_hash, review_summary, triage_key
from .schema import RISKS, activity, risk_rank

FINDINGS_FILE = "vuln_findings.json"
TRACES_FILE = "vuln_traces.json"
VULNS_FILE = "vulns.json"


def _dump(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def build_card(ctx: Stage4Context, r: dict) -> dict:
    m, fp, inv, ver, v = r["match"], r["fingerprint"], r["investigation"], r.get("verification"), r["verdict"]
    evidence: list[dict] = []
    for s in inv.usage_sites:
        if not s.in_test:
            evidence.append({"type": "code", "file": s.file, "lines": s.lines, "snippet": s.code,
                             "function": s.function, "symbol": s.symbol, "via": s.via})
    for p in inv.paths[:2]:
        evidence.append({"type": "path", "path": p, "labels": [short_label(x) if not x.startswith(("route:", "cli:")) else x.split(":", 1)[1] for x in p]})
    for c in inv.claims:
        for e in c.evidence:
            if e.file and not any(x.get("file") == e.file and x.get("lines") == (e.lines or str(e.line)) for x in evidence):
                evidence.append({"type": "code", "file": e.file, "lines": e.lines or str(e.line), "snippet": "",
                                 "claim": c.text})
    adv = [ref for ref in m.references if ref.type in ("ADVISORY", "WEB", "REPORT")][:2] or m.references[:1]
    evidence += [{"type": "advisory", "url": ref.url, "ref_type": ref.type} for ref in adv]
    if not adv and m.vuln_id.startswith(("GHSA-", "PYSEC-", "CVE-")):
        evidence.append({"type": "advisory", "url": f"https://osv.dev/vulnerability/{m.vuln_id}"})
    evidence_files = sorted({s.file for s in inv.usage_sites} | {e.file for c in inv.claims for e in c.evidence if e.file})
    fh = files_hash(ctx.s3.code_index, evidence_files)
    key = triage_key("vulnerability", m.vuln_id, m.package, fh)
    sources = list(m.source) + (["ai"] if "ai" in (inv.discovered_by, fp.discovered_by) else ["algorithm"])
    card = {
        "finding_id": "", "type": "vulnerability", "subject_id": m.vuln_id,
        "title": f"{m.package_name} {m.version or ''}: {m.summary or m.vuln_id}".strip(),
        "component": m.package, "component_name": m.package_name, "component_version": m.version,
        "vuln_id": m.vuln_id, "aliases": m.aliases,
        "severity": {"cvss": m.cvss.score, "band": m.cvss.band, "vector": m.cvss.vector, "source": m.cvss.source},
        "kev": m.kev, "epss_percentile": m.epss.percentile if m.epss else None, "epss": m.epss.score if m.epss else None,
        "scope": m.scope, "scope_reason": m.scope_reason, "image": m.image,
        "dependency_path": m.dependency_path, "dependency_paths": m.dependency_paths, "direct_dependency": m.direct_dependency,
        "usage": inv.usage, "usage_sites": [s.model_dump() for s in inv.usage_sites],
        "reachability": inv.reachability, "entries": inv.entries, "paths": inv.paths,
        "conditions": [c.model_dump() for c in inv.conditions], "unknowns": inv.unknowns,
        "project_risk": v.project_risk, "rule": {"id": v.rule, "text": v.rule_text},
        "confidence": v.confidence, "confidence_reasons": v.confidence_reasons,
        "explanation": v.explanation, "explanation_by": v.explanation_by, "recommendation": v.recommendation,
        "evidence": evidence, "claims": [c.model_dump() for c in inv.claims],
        "fix": v.fix.model_dump(),
        "review": {"status": "pending" if v.needs_human_review else "not_required", "reasons": v.review_reasons,
                   "downgrade_guard": v.downgrade_guard},
        "verified": bool(ver.verified) if ver and ver.ran else None,
        "verification": ver.model_dump() if ver else {"ran": False},
        "investigation": {"light_pass": inv.light_pass, "tool_calls_used": inv.tool_calls_used,
                          "budget_exhausted": inv.budget_exhausted, "discovered_by": inv.discovered_by,
                          "notes": inv.notes, "dropped": inv.dropped, "dynamic_imports": inv.dynamic_imports},
        "fingerprint": fp.model_dump(),
        "summary": m.summary, "details": m.details[:4000], "fixed_versions": m.fixed_versions,
        "affected_ranges": [a.model_dump(exclude_none=True) for a in m.affected_ranges],
        "references": [x.model_dump() for x in m.references[:12]], "published": m.published, "modified": m.modified,
        "priority": r.get("priority"), "rank": r.get("rank"),
        "evidence_files": evidence_files, "evidence_files_hash": fh, "triage_key": key,
        "discovered_by": list(dict.fromkeys(sources)), "match_id": m.match_id,
    }
    return card


def card_sort_key(c: dict):
    return (-risk_rank(c["project_risk"]), -(c["severity"]["cvss"] or 0), c["component"], c["vuln_id"])


def update_graph(ctx: Stage4Context, cards: list[dict]) -> None:
    G = ctx.G
    for c in cards:
        vid = f"vuln:{c['vuln_id']}"
        add_node(G, vid, "Vulnerability", "osv" if "osv" in c["discovered_by"] or "osv-dump" in c["discovered_by"] else "grype",
                 [], name=c["vuln_id"], aliases=c["aliases"], cvss=c["severity"]["cvss"], band=c["severity"]["band"],
                 summary=c["summary"], kev=c["kev"])
        G.nodes[vid].setdefault("finding_ids", [])
        if c["finding_id"] not in G.nodes[vid]["finding_ids"]:
            G.nodes[vid]["finding_ids"].append(c["finding_id"])
        prev = G.nodes[vid].get("project_risk")
        if risk_rank(c["project_risk"]) > risk_rank(prev):
            G.nodes[vid]["project_risk"] = c["project_risk"]
        if c["component"] in G:
            add_edge(G, vid, c["component"], "AFFECTS", "osv", [], key=f"AFFECTS:{c['component']}",
                     ranges=c["affected_ranges"], fixed_versions=c["fixed_versions"], finding=c["finding_id"])
            pd = G.nodes[c["component"]]
            pd.setdefault("vulns", [])
            if c["finding_id"] not in pd["vulns"]:
                pd["vulns"].append(c["finding_id"])
        for s in c["usage_sites"]:
            if s["function"] in G and not s.get("in_test"):
                add_edge(G, vid, s["function"], "USED_AT", "ai" if c["investigation"]["discovered_by"] == "ai" else "algorithm",
                         [ev(s["file"], lines=s["lines"])], key=f"USED_AT:{s['function']}", symbol=s.get("symbol"))
        for e in c["entries"]:
            if e["id"] in G:
                add_edge(G, vid, e["id"], "REACHED_VIA", "algorithm", [], key=f"REACHED_VIA:{e['id']}", kind=e.get("kind"))


def bundle_entry(c: dict) -> dict:
    """Compact card for the Stage 3 dashboard bundle."""
    return {"id": c["finding_id"], "title": c["title"], "component": c["component_name"], "version": c["component_version"],
            "vulnId": c["vuln_id"], "cvss": c["severity"]["cvss"], "band": c["severity"]["band"], "risk": c["project_risk"],
            "confidence": c["confidence"], "usage": c["usage"], "reachability": c["reachability"], "scope": c["scope"],
            "review": c["review"]["status"], "explanation": c["explanation"], "recommendation": c["recommendation"]}


def write_outputs(ctx: Stage4Context, matches: list, results: list[dict]) -> list[dict]:
    out = Path(ctx.output_dir)
    cards = [build_card(ctx, r) for r in results]
    traces_by_match = {r["match"].match_id: r.get("trace", []) for r in results}
    cards.sort(key=card_sort_key)
    for i, c in enumerate(cards, 1):
        c["finding_id"] = f"F-{i:03d}"
    mgr = ReviewManager(out)
    try:
        for i, c in enumerate(cards):
            if c["review"]["status"] == "pending":
                cards[i] = mgr.prepare(c, ctx.scan_id or "scan")
        engine = mgr.engine
    finally:
        mgr.close()
    update_graph(ctx, cards)
    traces = {c["finding_id"]: traces_by_match.get(c["match_id"], []) for c in cards}
    for c in cards:
        rv = c["review"]
        action = "Human review requested" if rv["status"] == "pending" else             ("Earlier decision reused" if rv.get("reused") else "No review needed")
        traces[c["finding_id"]].append(activity(
            "review", action, "; ".join(rv.get("reasons") or []) or "rules did not require a human decision"))
    by_risk = {r: sum(1 for c in cards if c["project_risk"] == r) for r in RISKS}
    vulns_doc = {
        "matches": [m.model_dump() for m in matches],
        "coverage": {**ctx.coverage, "deep_investigations": sum(1 for r in results if not r["investigation"].light_pass),
                     "light_pass": sum(1 for r in results if r["investigation"].light_pass),
                     "llm": ctx.llm.stats(), "review_engine": engine,
                     "budgets": {"deep": ctx.budgets.deep, "tool_calls": ctx.budgets.tool_calls,
                                 "verifier_retries": ctx.budgets.verifier_retries}},
        "summary": {"findings": len(cards), "by_risk": by_risk, "review": review_summary(cards)},
    }
    _dump(out / VULNS_FILE, vulns_doc)
    _dump(out / FINDINGS_FILE, cards)
    _dump(out / TRACES_FILE, traces)
    if not (out / "triage.json").exists():
        _dump(out / "triage.json", {"decisions": {}, "history": []})
    _dump(out / "graph.json", graph_json(ctx.G))
    ub = out / "ui_bundle.json"
    if ub.exists():
        bundle = json.loads(ub.read_text(encoding="utf-8"))
        bundle["vulnerabilities"] = [bundle_entry(c) for c in cards]
        _dump(ub, bundle)
    return cards
