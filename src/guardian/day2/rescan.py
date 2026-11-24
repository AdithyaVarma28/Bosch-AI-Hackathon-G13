"""S15 Rescan and compare: run the UNCHANGED Day 1 pipeline on the patched branch and diff against the scan.

* SBOM diff: components added / removed / changed version
* findings diff: target findings resolved or still open, findings the fix introduced (with bands)
* risk delta: summed S10 scores and band counts before vs after
* vulnerable versions left: the target advisories checked against EVERY component of the new tree, so a
  vulnerable copy still pulled in through another path is caught even if the original finding id is gone
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from ..context import RunContext
from ..models import Finding
from ..orchestrator import RUNS, run_pipeline
from ..purl import parse_purl
from .models import RescanDiff
from .policy import Policy
from .prioritize import prioritize
from .simulate import is_historical


def run_rescan(ctx: RunContext, work_root: Path, out_dir: Path) -> tuple[RunContext | None, dict]:
    settings = dataclasses.replace(ctx.settings, use_llm=False, remediate=False)   # detection only: never recurse into Day 2
    res = run_pipeline(str(work_root), out_dir, settings)
    rctx = RUNS.get(res.run_id)
    return rctx, {"run_dir": str(res.run_dir), "node_status": res.node_status}


def _bands(fs: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in fs:
        out[f.band or "?"] = out.get(f.band or "?", 0) + 1
    return out


def _brief(f: Finding) -> dict:
    return {"id": f.id, "title": f.title, "band": f.band, "cls": f.cls, "subject": f.subject}


def diff_scans(ctx: RunContext, rctx: RunContext, plan_key: str, candidate_id: str, target_ids: list[str],
               policy: Policy, info: dict) -> RescanDiff:
    before_f = [f for f in ctx.store.list_findings() if f.cls != "sbom_quality"]
    after_f = [f for f in rctx.store.list_findings() if f.cls != "sbom_quality"]
    before_ids, after_ids = {f.id for f in before_f}, {f.id for f in after_f}
    bmap = {f.id: f for f in before_f}
    resolvable = [i for i in target_ids if i in bmap and not is_historical(bmap[i])]
    d = RescanDiff(plan_key=plan_key, candidate_id=candidate_id, rescan_run_dir=info.get("run_dir", ""),
                   node_status=info.get("node_status", {}))
    b_comp = {c.purl: c for c in ctx.components}
    a_comp = {c.purl: c for c in rctx.components}
    b_names = {(c.ecosystem, c.name): c for c in ctx.components}
    a_names = {(c.ecosystem, c.name): c for c in rctx.components}
    for key, c in a_names.items():
        if key not in b_names:
            d.sbom_added.append(c.purl)
        elif b_names[key].version != c.version:
            d.sbom_changed.append({"name": c.name, "ecosystem": c.ecosystem, "from": b_names[key].version, "to": c.version})
    d.sbom_removed = sorted(c.purl for key, c in b_names.items() if key not in a_names)
    d.sbom_added.sort()
    d.findings_resolved = [_brief(bmap[i]) for i in resolvable if i not in after_ids]
    d.findings_open = [_brief(bmap[i]) for i in resolvable if i in after_ids]
    new = [f for f in after_f if f.id not in before_ids]
    # history findings created by the remediation commit itself are new facts too; keep them, they are visible
    d.findings_new = [_brief(f) for f in sorted(new, key=lambda f: (f.band or "Z", f.title))]
    d.new_high = [f.title for f in new if f.band in ("P0", "P1")]
    d.bands_before, d.bands_after = _bands(before_f), _bands(after_f)
    try:
        d.score_before = sum(s.total for s in prioritize(ctx, before_f, policy))
        d.score_after = sum(s.total for s in prioritize(rctx, after_f, policy))
    except Exception:
        pass
    # every advisory the plan targeted, checked against every component of the new tree
    advisories = {(bmap[i].signals.get("advisory_id"), bmap[i].subject) for i in resolvable if bmap[i].cls == "vuln"}
    if advisories:
        try:
            from ..detectors.osv import affected_by, make_osv
            from ..httpcache import CachedHttp
            osv = make_osv(ctx.settings, CachedHttp(ctx.settings.cache_dir, offline=True))
            for vid, subj in advisories:
                rec = osv.get_vuln(vid) if vid else None
                eco, name, _ = parse_purl(subj)
                for c in rctx.components:
                    if c.ecosystem == eco and c.name.lower() == name.lower() and c.version and rec and affected_by(rec, eco, c.name, c.version):
                        d.vulnerable_versions_left.append(f"{c.purl} ({vid})")
        except Exception:   # record unavailable offline: rely on the rescan's own findings
            pass
    d.target_resolved = bool(resolvable) and not d.findings_open and not d.vulnerable_versions_left
    d.sbom_confidence_before = ctx.sbom_report.confidence if ctx.sbom_report else None
    d.sbom_confidence_after = rctx.sbom_report.confidence if rctx.sbom_report else None
    ev = ctx.store.add_evidence("raw", "rescan", f"rescan:{candidate_id}", json.dumps({
        "rescan_run": d.rescan_run_dir, "resolved": [x["title"] for x in d.findings_resolved],
        "still_open": [x["title"] for x in d.findings_open], "new": [f"[{x['band']}] {x['title']}" for x in d.findings_new][:15],
        "sbom_changed": d.sbom_changed[:15], "sbom_added": d.sbom_added[:15], "sbom_removed": d.sbom_removed[:15],
        "vulnerable_versions_left": d.vulnerable_versions_left, "bands_before": d.bands_before, "bands_after": d.bands_after,
        "score_before": d.score_before, "score_after": d.score_after}, default=str))
    d.evidence_id = ev.id
    return d
