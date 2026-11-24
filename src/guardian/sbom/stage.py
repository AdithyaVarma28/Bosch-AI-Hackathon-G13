"""S2 Resolve + SBOM: lockfile first, sandboxed resolution otherwise, Syft/Trivy cross-check, origin metadata."""
from __future__ import annotations

import re
from pathlib import Path

from ..context import RunContext
from ..fsutil import read_text
from ..httpcache import CachedHttp
from ..models import Component, DepEdge, Origin, SbomReport
from ..purl import make_purl, normalize_name
from ..runner import ToolFailed
from .cyclonedx import validate_cyclonedx, write_cyclonedx
from .lockfiles import ParsedLock
from .lockfiles_poly import parse_lock_in_repo
from .registry import fetch_metadata
from .resolve import resolve_without_lockfile
from .tools import run_syft, run_trivy_fs


def _merge(into: dict[str, Component], comps: list[Component]) -> None:
    for c in comps:
        if c.purl in into:
            prev = into[c.purl]
            prev.seen_by = sorted(set(prev.seen_by) | set(c.seen_by))
            prev.direct = prev.direct or c.direct
            if prev.scope in ("unknown", "dev", "optional") and c.scope == "prod":
                prev.scope = "prod"
            if not prev.hashes and c.hashes:
                prev.hashes = c.hashes
            for f in ("registry", "resolved_url", "integrity", "license", "source_repo"):
                if not getattr(prev.origin, f) and getattr(c.origin, f):
                    setattr(prev.origin, f, getattr(c.origin, f))
            prev.origin.has_install_script = prev.origin.has_install_script or c.origin.has_install_script
        else:
            into[c.purl] = c


DEFAULT_REGISTRY = {"pypi": "pypi.org", "npm": "registry.npmjs.org", "maven": "repo.maven.apache.org",
                    "golang": "proxy.golang.org", "cargo": "crates.io", "gem": "rubygems.org", "composer": "packagist.org",
                    "nuget": "api.nuget.org"}


def _exact_version(ecosystem: str, spec: str | None) -> str | None:
    """A declared spec counts as an exact version only when it pins one (unknown stays unknown)."""
    s = (spec or "").strip()
    if not s:
        return None
    if ecosystem == "pypi":
        m = re.match(r"^===?\s*([0-9A-Za-z][^\s,;]*)$", s)
        return m.group(1) if m and not m.group(1).endswith("*") else None
    if ecosystem == "npm":
        return s if re.fullmatch(r"\d+\.\d+\.\d+(-[\w.]+)?", s) else None
    if ecosystem == "maven":
        return s if re.fullmatch(r"[\w.\-]+", s) and not s.startswith(("[", "(")) and "SNAPSHOT" not in s and "${" not in s else None
    if ecosystem == "nuget":
        return s.strip("[]") if re.fullmatch(r"\[?\d+(\.\d+){1,3}(-[\w.]+)?\]?", s) else None
    if ecosystem == "cargo":
        m = re.fullmatch(r"=\s*(\d+\.\d+\.\d+\S*)", s)
        return m.group(1) if m else None
    if ecosystem in ("gem", "composer"):
        return s if re.fullmatch(r"v?\d+\.\d+(\.\d+)*", s) else None
    if ecosystem == "golang":
        return s.split()[0] if s.startswith("v") else None
    return None


def _name_from_dist_url(url: str) -> tuple[str, str] | None:
    """Name and version from a wheel/sdist URL (`pkg_name-1.2.3-py3-none-any.whl`, `pkg-1.2.3.tar.gz`), else None."""
    tail = url.split("#")[0].split("?")[0].rstrip("/").rsplit("/", 1)[-1]
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._]*)-(\d[^-]*)(?:-[^/]+)?\.whl$", tail) or         re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*?)-(\d[\w.+!]*)\.(?:tar\.gz|tgz|zip)$", tail)
    return (m.group(1), m.group(2)) if m else None


def _jaccard(a: set[str], b: set[str]) -> float | None:
    if not a and not b:
        return None
    return round(len(a & b) / len(a | b), 3)


def run_sbom_stage(ctx: RunContext) -> None:
    facts, store, root = ctx.facts, ctx.store, ctx.root
    assert facts is not None
    comps: dict[str, Component] = {}
    edges: set[tuple[str, str, str]] = set()
    report = SbomReport()
    resolutions: list[str] = []
    native: set[str] = set()
    parsed_locks: set[str] = set()

    def take(parsed: ParsedLock, label: str) -> None:
        report.notes.extend(e for e in parsed.errors if not e.startswith("unpinned:"))
        unpinned = [e for e in parsed.errors if e.startswith("unpinned:")]
        if unpinned:
            report.notes.append(f"{parsed.path}: {len(unpinned)} unpinned requirement(s) not in lock data")
        for c in parsed.components:
            excerpt = f"{c.name}@{c.version} resolved={c.origin.resolved_url} integrity={c.origin.integrity or (c.hashes[0] if c.hashes else None)}"
            c.evidence_ids.append(store.add_evidence("raw", label, parsed.path, excerpt).id)
            native.add(c.purl)
        _merge(comps, parsed.components)
        edges.update((e.src, e.dst, e.source) for e in parsed.edges)

    # 1+2. lockfiles, or sandboxed resolution
    for h in facts.lockfiles:
        if h.present and h.lockfile:
            if h.lockfile in parsed_locks:  # workspace lockfile shared by several manifests
                continue
            parsed_locks.add(h.lockfile)
            parsed = parse_lock_in_repo(root, h.manifest, h.lockfile)
            if parsed.namespaces:
                ctx.import_hints.setdefault(parsed.ecosystem, {}).update(parsed.namespaces)
            if parsed.components:
                take(parsed, "lockfile")
                resolutions.append("committed" if h.committed else "resolved_not_committed")
                no_edges = parsed.ecosystem == "pypi" and not parsed.edges
                if no_edges and ctx.settings.use_docker:
                    try:  # pinned requirements have no transitive data: enrich via sandbox
                        take(resolve_without_lockfile(root, h.manifest, "pypi", ctx.runner), "pip-report")
                    except ToolFailed as e:
                        report.notes.append(f"{h.manifest}: transitive dependencies unknown ({e})")
                elif no_edges:
                    report.notes.append(f"{h.manifest}: transitive dependencies unknown (Docker disabled)")
                continue
            report.notes.append(f"{h.lockfile}: lockfile present but not parseable ({'; '.join(parsed.errors)[:150]})")
        try:
            if not ctx.settings.use_docker:
                raise ToolFailed("Docker disabled by settings")
            parsed = resolve_without_lockfile(root, h.manifest, h.ecosystem, ctx.runner)
            take(parsed, parsed.components[0].source if parsed.components else "resolve")
            resolutions.append("resolved_not_committed")
        except ToolFailed as e:
            report.notes.append(f"{h.manifest}: no usable lockfile and resolution failed ({e}); using declared dependencies only")
            resolutions.append("absent")
            for d in facts.declared_dependencies:
                if d.source_file != h.manifest:
                    continue
                if d.kind == "path":  # local code, not a registry package: naming a component after a path would be wrong
                    report.notes.append(f"{d.source_file}: local path dependency '{d.name}' not included in the SBOM")
                    continue
                if d.kind == "url" and d.ecosystem == "pypi":
                    named = _name_from_dist_url(d.spec or "")
                    if not named:
                        report.notes.append(f"{d.source_file}: URL dependency '{(d.spec or '')[:80]}' has no package name; not included in the SBOM")
                        continue
                    name, d_version = named
                    c = Component(purl=make_purl("pypi", name, d_version), name=name, version=d_version, ecosystem="pypi",
                                  scope=d.scope, direct=True, source="manifest", seen_by=["manifest"],
                                  origin=Origin(resolved_url=d.spec), evidence_ids=[d.evidence_id] if d.evidence_id else [])
                    _merge(comps, [c])
                    continue
                version = _exact_version(d.ecosystem, d.spec)
                c = Component(purl=make_purl(d.ecosystem, d.name, version), name=d.name, version=version,
                              ecosystem=d.ecosystem, scope=d.scope, direct=True, source="manifest", seen_by=["manifest"],
                              origin=Origin(resolved_url=d.spec if d.kind in ("vcs", "url", "path") else None,
                                            registry=DEFAULT_REGISTRY.get(d.ecosystem) if d.kind == "registry" else None),
                              evidence_ids=[d.evidence_id] if d.evidence_id else [])
                _merge(comps, [c])

    # 2b. Maven: versions managed by parent POMs / imported BOMs (no Docker needed; POM XML only)
    unversioned = [c for c in comps.values() if c.ecosystem == "maven" and not c.version]
    if unversioned:
        from .maven_bom import resolve_pom_versions
        managed: dict[str, str] = {}
        for m in facts.manifests:
            if m.path.endswith("pom.xml"):
                got, errs = resolve_pom_versions(read_text(root / m.path) or "", CachedHttp(ctx.settings.cache_dir, offline=ctx.settings.offline))
                managed.update(got)
                report.notes.extend(f"maven BOM: {e}" for e in errs[:5])
        fixed = 0
        for c in unversioned:
            v = managed.get(c.name)
            if v:
                del comps[c.purl]
                c.version, c.purl = v, make_purl("maven", c.name, v)
                c.source, c.seen_by = "manifest", sorted(set(c.seen_by) | {"maven-bom"})
                c.evidence_ids.append(store.add_evidence("raw", "maven-bom", c.name, f"{c.name} version {v} managed by parent POM/BOM").id)
                _merge(comps, [c])
                fixed += 1
        if fixed:
            report.notes.append(f"maven: {fixed}/{len(unversioned)} direct dependency versions taken from parent POM / imported BOMs "
                                "(transitive dependencies still need sandboxed `mvn dependency:tree`)")

    # 3. direct + scope from declarations
    declared = {}
    for d in facts.declared_dependencies:
        if d.markers == "indirect":  # Go `// indirect` requirements are transitive by definition
            continue
        key = (d.ecosystem, normalize_name(d.ecosystem, d.name))
        if key not in declared or d.scope == "prod":
            declared[key] = d.scope
    for c in comps.values():
        key = (c.ecosystem, normalize_name(c.ecosystem, c.name))
        if key in declared:
            c.direct = True
            if c.scope == "unknown" or (declared[key] == "prod" and c.scope != "prod"):
                c.scope = declared[key]  # type: ignore[assignment]
    # transitive scope: inherit "prod" if reachable from a prod direct dependency, else dev
    adj: dict[str, list[str]] = {}
    for s, t, _ in edges:
        adj.setdefault(s, []).append(t)
    prod_reach = _reach([p for p, c in comps.items() if c.direct and c.scope == "prod"], adj)
    any_reach = _reach([p for p, c in comps.items() if c.direct], adj)
    for p, c in comps.items():
        if c.scope == "unknown":
            c.scope = "prod" if p in prod_reach else "dev" if p in any_reach else "unknown"

    # 4. external tools cross-check
    tool_sets: dict[str, set[str]] = {}
    for tool, fn in (("syft", run_syft), ("trivy", run_trivy_fs)):
        try:
            ts = fn(root, store.run_dir, ctx.runner, ctx.settings.use_docker)
            tool_sets[tool] = {c.purl for c in ts.components}
            report.tools[tool] = f"ok ({len(ts.components)} components)"
            for c in ts.components:
                if c.purl in comps:
                    comps[c.purl].seen_by = sorted(set(comps[c.purl].seen_by) | {tool})
                elif not any(x.name == c.name and x.ecosystem == c.ecosystem for x in comps.values()):
                    c.evidence_ids.append(store.add_evidence("raw", tool, str(ts.raw_path.name), f"{c.purl} reported by {tool}").id)
                    _merge(comps, [c])
            edges.update((e.src, e.dst, tool) for e in ts.edges if e.src in comps and e.dst in comps)
        except (ToolFailed, ValueError) as e:
            report.tools[tool] = f"failed: {str(e)[:200]}"
    ok_tools = [t for t, v in report.tools.items() if v.startswith("ok")]
    if len(ok_tools) == 2:
        report.jaccard = _jaccard(tool_sets["syft"], tool_sets["trivy"])
        report.only_in = {"syft": sorted(tool_sets["syft"] - tool_sets["trivy"]), "trivy": sorted(tool_sets["trivy"] - tool_sets["syft"])}
    elif len(ok_tools) == 1 and native:
        t = ok_tools[0]
        report.jaccard = _jaccard(tool_sets[t], native)
        report.only_in = {t: sorted(tool_sets[t] - native), "lockfile": sorted(native - tool_sets[t])}
    committed = bool(resolutions) and all(r == "committed" for r in resolutions)
    report.resolution = "committed" if committed else ("absent" if all(r == "absent" for r in resolutions) else
                                                       "resolved_not_committed") if resolutions else "absent"
    if len(ok_tools) == 2 and committed:
        report.confidence = "high"
    elif ok_tools and (native or comps):
        report.confidence = "medium"  # one tool failed, or no committed lockfile
    else:
        report.confidence = "low"
    if not ok_tools:
        report.notes.append("Syft and Trivy unavailable; SBOM built from native lockfile/manifest parsing only")

    ctx.components = sorted(comps.values(), key=lambda c: c.purl)
    ctx.edges = [DepEdge(src=s, dst=t, source=src) for s, t, src in sorted(edges)]
    ctx.sbom_report = report

    # 5. CycloneDX output
    doc = write_cyclonedx(ctx.components, ctx.edges, store.run_dir / "sbom.cdx.json", ctx.repo.name, ctx.repo.commit)
    problems = validate_cyclonedx(doc)
    report.notes.extend(f"sbom validation: {p}" for p in problems[:20])

    # 6. origin metadata (cache always used; network only when online)
    http = CachedHttp(ctx.settings.cache_dir, offline=ctx.settings.offline)
    targets = [c for c in ctx.components if c.version]
    ctx.metadata, errs = fetch_metadata(targets, http)
    report.notes.extend(errs[:20])
    for c in ctx.components:
        md = ctx.metadata.get(c.purl)
        if md and md.source_repo and not c.origin.source_repo:
            c.origin.source_repo = md.source_repo
    unavailable = sum(1 for m in ctx.metadata.values() if m.status == "unavailable")
    if unavailable:
        report.notes.append(f"registry metadata unavailable for {unavailable}/{len(targets)} packages"
                            + (" (offline mode)" if ctx.settings.offline else ""))


def _reach(starts: list[str], adj: dict[str, list[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(starts)
    while stack:
        p = stack.pop()
        if p not in seen:
            seen.add(p)
            stack.extend(adj.get(p, []))
    return seen
