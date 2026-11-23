"""Graph view model for the interactive report: risk per node, blast radius per package, registry groups.

Everything the browser needs for the dependency explorer and the what-if (chaos) simulator is precomputed here,
so the page stays fast and needs no server.
"""
from __future__ import annotations

from typing import Any

from .context import RunContext
from .models import Finding
from .purl import package_key, parse_purl

BAND_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "Unprioritized": 4}
NODE_KEYS = ("type", "label", "ecosystem", "scope", "direct", "version", "depth", "fan_in", "fan_out", "registry",
             "file", "language", "is_test", "category", "framework", "tag", "digest", "pinned_to_sha", "resolved_url",
             "has_install_script", "source_repo", "seen_by", "loc", "triggers", "user")
MAX_BLAST = 2000


def _worst(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if BAND_RANK.get(a, 9) <= BAND_RANK.get(b, 9) else b


def _targets(f: Finding, g, name_index: dict[str, list[str]]) -> list[str]:
    """Graph node ids a finding is about."""
    s, sig = f.subject, f.signals
    out: list[str] = []
    if s in g:
        out.append(s)
    if s.startswith("pkg:"):
        try:
            eco, name, _ = parse_purl(s)
            pk = package_key(eco, name)
            if pk in g:
                out.append(pk)
        except ValueError:
            pass
    else:
        out += name_index.get(s.lower(), [])
    if f.cls == "ci":
        for cand in (f"action:{s}", f"workflow:{s}"):
            if cand in g:
                out.append(cand)
    if f.cls == "container":
        for cand in (f"dockerfile:{s}", f"image:{sig.get('image', '')}", f"image:{s}"):
            if cand in g:
                out.append(cand)
    if f.cls == "secret" and sig.get("path") and f"file:{sig['path']}" in g:
        out.append(f"file:{sig['path']}")
    if f.cls == "discrepancy" and sig.get("package") in g:
        out.append(sig["package"])
    return list(dict.fromkeys(out))


def build_viz(ctx: RunContext, findings: list[Finding]) -> dict[str, Any]:
    ug = ctx.graph
    if ug is None:
        return {"nodes": [], "edges": [], "blast": {}, "registries": {}}
    g = ug.g
    metrics = ug.metrics()
    name_index: dict[str, list[str]] = {}
    for n, d in g.nodes(data=True):
        if d.get("type") in ("artifact", "package"):
            name_index.setdefault(str(d.get("label", "")).split("@")[0].lower(), []).append(n)

    risk: dict[str, str] = {}
    node_findings: dict[str, list[str]] = {}
    vulns: dict[str, int] = {}
    for f in findings:
        for t in _targets(f, g, name_index):
            risk[t] = _worst(risk.get(t), f.band)
            node_findings.setdefault(t, []).append(f.id)
            if f.cls == "vuln":
                vulns[t] = vulns.get(t, 0) + 1
    # a package inherits the worst risk of its artifacts (and vice versa for name-level anomalies)
    for s, t, k in g.edges(keys=True):
        if k == "HAS_ARTIFACT":
            if t in risk:
                risk[s] = _worst(risk.get(s), risk[t])
            if s in risk and t not in risk and g.nodes[t].get("type") == "artifact":
                risk[t] = risk[s]

    nodes = []
    for n, d in g.nodes(data=True):
        item: dict[str, Any] = {"id": n}
        for k in NODE_KEYS:
            v = d.get(k)
            if v not in (None, [], {}, ""):
                item[k] = v
        if n in metrics:
            item.update({k: v for k, v in metrics[n].items() if v is not None})
        if n in risk:
            item["risk"] = risk[n]
        if n in node_findings:
            item["findings"] = node_findings[n][:30]
        if n in vulns:
            item["vulns"] = vulns[n]
        nodes.append(item)
    edges = []
    for s, t, k, d in g.edges(keys=True, data=True):
        e = {"s": s, "t": t, "rel": k}
        if d.get("evidence_status"):
            e["status"] = d["evidence_status"]
        if d.get("locator"):
            e["loc"] = d["locator"]
        edges.append(e)

    # blast radius per artifact: what a compromised / unavailable package reaches
    blast: dict[str, dict] = {}
    for purl in ug.artifacts()[:MAX_BLAST]:
        br = ug.blast_radius(purl)
        if not br:
            continue
        funcs = br.get("reaching_functions", [])
        files = [f"file:{p}" for p in br.get("importing_modules", []) if p and f"file:{p}" in g]
        exposed = set()
        for fn in funcs + files:
            for _, t, k in g.out_edges(fn, keys=True):
                if k in ("READS_ENV", "WRITES_DB", "READS_DB", "RAW_SQL", "CONTACTS"):
                    exposed.add(t)
            if fn.startswith("file:"):
                for _, f2, k in g.out_edges(fn, keys=True):
                    if k == "DEFINES":
                        for _, t, k2 in g.out_edges(f2, keys=True):
                            if k2 in ("READS_ENV", "WRITES_DB", "READS_DB", "RAW_SQL", "CONTACTS"):
                                exposed.add(t)
        pkg = ug._package_of(purl)
        blast[purl] = {"dependents": br.get("dependent_artifacts", []), "introducers": br.get("direct_introducers", []),
                       "package": pkg, "files": files, "functions": funcs, "routes": br.get("exposed_routes", []),
                       "exposed": sorted(exposed)}
    registries: dict[str, list[str]] = {}
    for c in ctx.components:
        reg = c.origin.registry or ("git/url" if c.origin.resolved_url else "unknown")
        registries.setdefault(reg, []).append(c.purl)
    return {"nodes": nodes, "edges": edges, "blast": blast, "registries": registries,
            "ecosystems": sorted({c.ecosystem for c in ctx.components})}
