"""Step 1 Discovery (deterministic): OSV + Grype + KEV + EPSS, scope, transitive paths, dedupe by alias.

Input is the Stage 3 graph: every ``Package`` node (purl + version) plus the SBOM and the Dockerfile
base images. Nothing is rescanned.
"""
from __future__ import annotations

import re
from collections import deque
from typing import Optional

from guardian.stage3_knowledge.graph_builder import nodes_of, pred
from guardian.stage3_knowledge.schema import normalize_name

from .context import Stage4Context
from .schema import CVSS, AffectedRange, Reference, VulnMatch
from .sources import (better_cvss, cvss_from_record, grype_records, load_epss, load_kev, parse_version,
                      preferred_id, ranges_and_fixes, run_grype)

PIN_RE = re.compile(r"^\s*===?\s*([0-9A-Za-z.+!_-]+)\s*$")


# --------------------------------------------------------------------------- inventory

def package_version(d: dict) -> tuple[Optional[str], str]:
    """Version of a Package node: resolved, or an exact ``==`` pin from the manifest."""
    if d.get("version"):
        return d["version"], "resolved"
    for spec in d.get("declared_spec") or []:
        m = PIN_RE.match(spec or "")
        if m:
            return m.group(1), "manifest pin"
    return None, "unpinned"


def manifest_line(d: dict) -> Optional[str]:
    for e in d.get("evidence", []) or []:
        if e.get("file") and e.get("line"):
            return f"{e['file']}:{e['line']}"
        if e.get("file"):
            return e["file"]
    return None


def direct_roots(G, pid: str) -> list[list[str]]:
    """Shortest REQUIRES chains from a direct dependency down to ``pid`` (at most 3), direct first."""
    if G.nodes[pid].get("direct"):
        return [[pid]]
    paths: list[list[str]] = []
    q: deque[list[str]] = deque([[pid]])
    seen = {pid}
    while q and len(paths) < 3:
        chain = q.popleft()
        if len(chain) > 8:
            break
        for parent in sorted(pred(G, chain[0], "REQUIRES")):
            new = [parent] + chain
            if G.nodes[parent].get("direct"):
                paths.append(new)
            elif parent not in seen:
                seen.add(parent)
                q.append(new)
    return paths


def _direct_scope(d: dict) -> tuple[str, str]:
    tags = set(d.get("tags") or [])
    if d.get("dep_kind") == "build":
        return "build", "declared as a build requirement"
    if "dev_used_in_runtime" in tags:
        return "runtime", "declared for development but imported by runtime code"
    if d.get("dev"):
        decl = manifest_line(d)
        return "dev", f"declared only in a development manifest{f' ({decl})' if decl else ''}"
    if "test_only" in tags:
        return "test_only", "only imported by test files"
    return "runtime", "runtime dependency"


def scope_of(G, pid: str) -> tuple[str, str, list[list[str]]]:
    d = G.nodes[pid]
    chains = direct_roots(G, pid)
    if d.get("direct"):
        s, why = _direct_scope(d)
        return s, why, chains
    if not chains:
        if "sbom_only" in (d.get("tags") or []):
            return "runtime", "found only in the SBOM; treated as runtime", chains
        return "runtime", "not traced to a direct dependency; treated as runtime", chains
    scopes = {}
    for ch in chains:
        scopes.setdefault(_direct_scope(G.nodes[ch[0]])[0], []).append(G.nodes[ch[0]].get("name"))
    for s in ("runtime", "build", "test_only", "dev"):
        if s in scopes:
            return s, f"pulled in by {', '.join(sorted(set(scopes[s])))} ({s})", chains
    return "runtime", "transitive dependency", chains


def dependency_path(G, chain: list[str]) -> list[str]:
    head = manifest_line(G.nodes[chain[0]])
    return ([head] if head else []) + chain


# --------------------------------------------------------------------------- merging

def _groups(records: list[dict]) -> list[list[dict]]:
    """Union records that share an id or alias (the same CVE from GHSA and PYSEC counts once)."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for r in records:
        for a in r.get("aliases") or []:
            union(r["id"], a)
        for a in r.get("upstream") or []:
            if a.startswith("CVE-"):
                union(r["id"], a)
    groups: dict[str, list[dict]] = {}
    for r in records:
        groups.setdefault(find(r["id"]), []).append(r)
    return list(groups.values())


def _merge_osv(group: list[dict], name: str, version: str, pid: str, source: str) -> VulnMatch:
    ids = [r["id"] for r in group]
    vid = preferred_id(ids)
    aliases = sorted(({a for r in group for a in (r.get("aliases") or [])} | set(ids)) - {vid})
    main = next((r for r in group if r["id"] == vid), group[0])
    details = main.get("details") or max((r.get("details") or "" for r in group), key=len)
    summary = main.get("summary") or next((r.get("summary") for r in group if r.get("summary")), "") or \
        (details.split(". ")[0][:200] if details else "")
    cvss = CVSS()
    ranges: list[AffectedRange] = []
    fixes: list[str] = []
    refs: dict[str, Reference] = {}
    for r in group:
        cvss = better_cvss(cvss, cvss_from_record(r))
        rg, fx = ranges_and_fixes(r, name)
        for x in rg:
            if x not in ranges:
                ranges.append(x)
        fixes += fx
        for ref in r.get("references") or []:
            if ref.get("url") and ref["url"] not in refs:
                refs[ref["url"]] = Reference(type=ref.get("type", "WEB"), url=ref["url"])
    fixes = sorted(set(fixes), key=lambda v: parse_version(v) or parse_version("0"))
    # only fixes above the installed version are useful recommendations
    pv = parse_version(version)
    if pv:
        fixes = [f for f in fixes if (parse_version(f) or pv) > pv] or fixes
    return VulnMatch(
        match_id=f"{vid}|{pid}", vuln_id=vid, aliases=aliases, records=sorted(ids), package=pid, package_name=name,
        version=version, summary=summary.strip(), details=details.strip(), cvss=cvss, affected_ranges=ranges,
        fixed_versions=fixes, references=list(refs.values()), source=[source],
        published=min((r.get("published") for r in group if r.get("published")), default=None),
        modified=max((r.get("modified") for r in group if r.get("modified")), default=None),
    )


def _merge_into(matches: list[VulnMatch], new: VulnMatch) -> None:
    ids = {new.vuln_id, *new.aliases}
    for m in matches:
        if m.package == new.package and ({m.vuln_id, *m.aliases} & ids):
            for s in new.source:
                if s not in m.source:
                    m.source.append(s)
            m.aliases = sorted(set(m.aliases) | (ids - {m.vuln_id}))
            m.cvss = better_cvss(m.cvss, new.cvss)
            m.fixed_versions = sorted(set(m.fixed_versions) | set(new.fixed_versions),
                                      key=lambda v: parse_version(v) or parse_version("0"))
            return
    matches.append(new)


# --------------------------------------------------------------------------- discover

def discover(ctx: Stage4Context) -> list[VulnMatch]:
    G = ctx.G
    cov = ctx.coverage.setdefault("discovery", {})
    inventory: list[tuple[str, str, str]] = []            # (pid, name, version)
    unversioned: list[str] = []
    for pid in sorted(nodes_of(G, "Package")):
        d = G.nodes[pid]
        version, how = package_version(d)
        if not version:
            unversioned.append(d.get("name", pid))
            continue
        d.setdefault("checked_version", version)
        inventory.append((pid, d.get("name") or pid, version))

    hits = ctx.osv.query([(n, v) for _, n, v in inventory])
    matches: list[VulnMatch] = []
    for pid, name, version in inventory:
        recs = hits.get((name, version), [])
        for group in _groups(recs):
            matches.append(_merge_osv(group, name, version, pid, ctx.osv.mode))
    cov.update({"packages": len(inventory), "unversioned": unversioned, "osv_mode": ctx.osv.mode,
                "notes": list(ctx.osv.notes)})

    # Grype: the SBOM (application packages) and container images (OS packages -> container_os)
    grype_status: dict[str, str] = {}
    by_name = {normalize_name(n): (pid, n, v) for pid, n, v in inventory}
    targets = []
    if ctx.sbom_path and ctx.sbom_path.exists():
        targets.append((f"sbom:{ctx.sbom_path}", "sbom", None))
    targets += [(img, "image", img) for img in ctx.images]
    for target, kind, image in targets:
        doc, err = run_grype(target, ctx.cache)
        if err:
            grype_status[target] = err
            continue
        recs = grype_records(doc)
        grype_status[target] = f"{len(recs)} matches"
        for r in recs:
            art = r["artifact"]
            if kind == "sbom":
                hit = by_name.get(normalize_name(art.get("name") or ""))
                if not hit or hit[2] != art.get("version"):
                    continue
                pid, name, version = hit
                scope_kind = None
            else:
                name, version = art.get("name") or "?", art.get("version") or "?"
                pid = art.get("purl") or f"pkg:{art.get('type') or 'generic'}/{name}@{version}"
                scope_kind = "container_os"
            vid = r["id"] or "?"
            m = VulnMatch(match_id=f"{vid}|{pid}", vuln_id=vid, aliases=r["aliases"], records=[vid], package=pid,
                          package_name=name, version=version, ecosystem=art.get("type") or "?",
                          artifact_type=art.get("type") or "?", summary=r["summary"], details=r["details"],
                          cvss=r["cvss"], fixed_versions=r["fixed_versions"], references=r["references"],
                          source=["grype"], image=image)
            if scope_kind:
                m.scope = "container_os"
                m.scope_reason = f"package in container image {image}"
                m.dependency_path = [f"image:{image}", pid]
            _merge_into(matches, m)
    cov["grype"] = grype_status or {"-": "no SBOM or container image to scan"}

    # scope + transitive paths for application packages
    for m in matches:
        if m.scope == "container_os" or m.package not in G:
            continue
        scope, why, chains = scope_of(G, m.package)
        m.scope, m.scope_reason = scope, why
        m.dependency_paths = [dependency_path(G, ch) for ch in chains] or [[m.package]]
        m.dependency_path = m.dependency_paths[0]
        m.direct_dependency = chains[0][0] if chains else (m.package if G.nodes[m.package].get("direct") else None)

    # KEV + EPSS
    kev, kev_date = load_kev(ctx.cache)
    ctx.kev = kev
    cves = {a for m in matches for a in [m.vuln_id, *m.aliases] if a.startswith("CVE-")}
    epss = load_epss(cves, ctx.cache)
    for m in matches:
        ids = [m.vuln_id, *m.aliases]
        m.kev = any(i in kev for i in ids)
        scores = [epss[i] for i in ids if i in epss]
        if scores:
            m.epss = max(scores, key=lambda e: e.score)
    cov.update({"kev": {"loaded": bool(kev), "date": kev_date, "entries": len(kev)},
                "epss": {"cves": len(cves), "scored": sum(1 for m in matches if m.epss)},
                "matches": len(matches), "network_errors": ctx.cache.errors[-10:]})
    matches.sort(key=lambda m: (m.package, m.vuln_id))
    return matches
