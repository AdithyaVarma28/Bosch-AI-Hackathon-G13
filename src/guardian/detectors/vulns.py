"""Known-vulnerability detector: OSV by PURL, CVSS band, fixes, KEV/EPSS, dependency path, code usage."""
from __future__ import annotations

import json

import httpx

from ..context import RunContext
from ..httpcache import CacheMiss, CachedHttp
from ..models import Finding
from ..purl import ECOSYSTEMS, package_key
from .osv import OsvClient, cve_aliases, fixed_versions, load_epss, load_kev, make_osv, severity_band  # noqa: F401 (OsvClient patched by chaos)


def detect_vulns(ctx: RunContext, http: CachedHttp | None = None) -> list[Finding]:
    http = http or CachedHttp(ctx.settings.cache_dir, offline=ctx.settings.offline)
    osv = make_osv(ctx.settings, http) if getattr(ctx.settings, "advisory_db", None) else OsvClient(http)
    targets = [c for c in ctx.components if c.version and c.ecosystem in ECOSYSTEMS]
    findings: list[Finding] = []
    try:
        hits, source = osv.query_batch([c.purl for c in targets])
    except (CacheMiss, httpx.HTTPError, ValueError) as e:
        ev = ctx.store.add_evidence("derived", "osv", "api.osv.dev", f"OSV unavailable: {type(e).__name__}")
        return [Finding(cls="sbom_quality", subject="osv", title="Vulnerability source unavailable",
                        locator="api.osv.dev", detector="vulns", classification="W", raw_evidence_ids=[ev.id],
                        signals={"source": "unavailable", "reason": "offline cache miss" if isinstance(e, CacheMiss) else str(e)[:200],
                                 "components_not_checked": len(targets)})]
    by_purl = {c.purl: c for c in targets}
    records: dict[str, dict] = {}
    for ids in hits.values():
        for vid in ids:
            if vid not in records:
                try:
                    records[vid] = osv.get_vuln(vid) or {"id": vid}
                except (CacheMiss, httpx.HTTPError, ValueError):
                    records[vid] = {"id": vid}
    all_cves = sorted({cve for r in records.values() for cve in cve_aliases(r)})
    kev, kev_src = load_kev(http)
    epss, epss_src = load_epss(http, all_cves)
    graph = ctx.graph
    for purl, ids in hits.items():
        comp = by_purl[purl]
        seen_groups: list[set[str]] = []
        for vid in ids:
            rec = records[vid]
            group = {vid, *(rec.get("aliases") or [])}
            if any(group & g for g in seen_groups):   # GHSA/CVE/PYSEC aliases of the same advisory
                continue
            seen_groups.append(group)
            score, band, vector = severity_band(rec)
            if not rec.get("summary") and rec.get("details"):
                rec["summary"] = rec["details"].strip().splitlines()[0][:140]
            cves = cve_aliases(rec)
            fixes = fixed_versions(rec, comp.ecosystem, comp.name)
            paths = graph.paths_to(purl) if graph else []
            usage = graph.importers(package_key(comp.ecosystem, comp.name)) if graph else []
            blast = graph.blast_radius(purl) if graph else {}
            excerpt = json.dumps({k: rec.get(k) for k in ("id", "summary", "aliases", "severity", "database_specific")},
                                 default=str)[:3000]
            ev = ctx.store.add_evidence("raw", "osv", f"osv:{vid}", excerpt)
            findings.append(Finding(
                cls="vuln", subject=purl, title=f"{comp.name}@{comp.version}: {rec.get('summary') or vid}",
                locator=vid, detector="vulns", classification="C",
                raw_evidence_ids=[ev.id, *comp.evidence_ids[:2]],
                signals={"advisory_id": vid, "aliases": sorted(group - {vid}), "cves": cves, "cvss": score,
                         "cvss_vector": vector, "severity_band": band, "fixed_versions": fixes,
                         "kev": any(c in kev for c in cves), "kev_source": kev_src,
                         "epss": max((epss.get(c, 0.0) for c in cves), default=None) if cves and epss else None,
                         "epss_source": epss_src, "path": paths[0] if paths else [purl], "all_paths": paths,
                         "direct": comp.direct, "scope": comp.scope, "imported_by": [u["locator"] for u in usage][:10],
                         "statically_referenced": bool(usage), "exposed_routes": blast.get("exposed_routes", []),
                         "reachability": "unknown", "source": source, "published": rec.get("published"),
                         "summary": rec.get("summary")}))
    return findings
