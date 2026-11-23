"""Package-level supply-chain signals: install scripts, name confusion (typosquats), registry metadata, indexes."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from importlib import resources

from ..context import RunContext
from ..models import Finding, PackageMetadata
from ..purl import normalize_name

PATTERNS = {
    "pipe_to_shell": re.compile(r"(curl|wget)[^|;&]*\|\s*(ba|z|da)?sh\b"),
    "base64_decode": re.compile(r"base64\s+(-d|--decode)|atob\(|Buffer\.from\([^)]*base64"),
    "eval": re.compile(r"\beval\b|node\s+-e\s|python3?\s+-c\s"),
    "remote_download": re.compile(r"(curl|wget|Invoke-WebRequest|iwr)\s+[^|]*https?://"),
}


def _popular(name: str) -> set[str]:
    try:
        text = resources.files("guardian.data").joinpath(name).read_text(encoding="utf-8")
        return {l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")}
    except (FileNotFoundError, ModuleNotFoundError):
        return set()


def levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _age_days(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400
    except ValueError:
        return None


def detect_install_scripts(ctx: RunContext) -> list[Finding]:
    out = []
    for s in (ctx.facts.lifecycle_scripts if ctx.facts else []):
        if s.name == "setup.py":
            continue
        pattern = next((k for k, rx in PATTERNS.items() if rx.search(s.command)), None)
        out.append(Finding(cls="anomaly", subject=f"{s.path}#{s.name}", title=f"'{s.name}' script in {s.path}" +
                           (f" ({pattern.replace('_', ' ')})" if pattern else ""), locator=f"{s.path}:{s.line or 1}",
                           detector="install_scripts", classification="S" if pattern else "W",
                           raw_evidence_ids=[s.evidence_id] if s.evidence_id else [],
                           signals={"signal": "install_script", "pattern": pattern, "command": s.command[:300],
                                    "script": s.name}))
    return out


def detect_name_confusion(ctx: RunContext, popular_npm: set[str] | None = None, popular_pypi: set[str] | None = None) -> list[Finding]:
    pop = {"npm": popular_npm if popular_npm is not None else _popular("popular_npm.txt"),
           "pypi": {normalize_name("pypi", p) for p in (popular_pypi if popular_pypi is not None else _popular("popular_pypi.txt"))}}
    out = []
    for c in ctx.components:
        n = normalize_name(c.ecosystem, c.name)
        base = n.split("/")[-1]
        popular = pop.get(c.ecosystem, set())
        if not popular or n in popular or len(base) <= 3:
            continue
        near = sorted(p for p in popular if p != n and abs(len(p) - len(n)) <= 2 and levenshtein(n, p, 2) <= 2)
        near = [p for p in near if not (n.startswith(p + "-") or n.startswith(p + ".") or n.endswith("-" + p))]
        if not near:
            continue
        md: PackageMetadata | None = ctx.metadata.get(c.purl)
        age = _age_days(md.first_release) if md else None
        # established project: public repo, many releases, more than a year old (maintainer lists are often empty on PyPI)
        benign = bool(md and md.status != "unavailable" and md.source_repo and (md.release_count or 0) > 5
                      and age is not None and age > 365)
        if benign:
            continue
        suspicious = bool(md and md.status != "unavailable" and ((md.release_count or 0) <= 2 or (age is not None and age < 90)
                                                                    or not md.source_repo or md.deprecated))
        ev = ctx.store.add_evidence("derived", "names", c.purl,
                                    f"{c.name} is within edit distance 2 of popular package(s) {', '.join(near[:3])}; "
                                    f"registry: releases={md.release_count if md else None}, first_release={md.first_release if md else None}, "
                                    f"repo={md.source_repo if md else None}, maintainers={len(md.maintainers) if md else None}, status={md.status if md else 'unavailable'}")
        out.append(Finding(cls="anomaly", subject=c.purl, title=f"Possible typosquat: '{c.name}' resembles '{near[0]}'",
                           locator=f"name:{c.name}", detector="names", classification="S" if suspicious else "W",
                           raw_evidence_ids=[ev.id, *c.evidence_ids[:1]],
                           signals={"signal": "name_confusion", "similar_to": near[:3], "direct": c.direct, "scope": c.scope,
                                    "release_count": md.release_count if md else None,
                                    "first_release": md.first_release if md else None,
                                    "source_repo": md.source_repo if md else None,
                                    "has_install_script": c.origin.has_install_script,
                                    "metadata": md.status if md else "unavailable"}))
    return out


def detect_registry_signals(ctx: RunContext) -> list[Finding]:
    out = []
    for c in ctx.components:
        md = ctx.metadata.get(c.purl)
        if not md or md.status == "unavailable":
            continue
        ev = None
        if md.yanked:
            ev = ctx.store.add_evidence("raw", "registry", c.purl, f"{c.purl} is marked yanked in its registry")
            out.append(Finding(cls="anomaly", subject=c.purl, title=f"{c.name}@{c.version} is a yanked release",
                               locator=f"registry:{c.purl}", detector="registry", classification="W", raw_evidence_ids=[ev.id],
                               signals={"signal": "yanked", "scope": c.scope}))
        if md.deprecated:
            ev = ctx.store.add_evidence("raw", "npm-registry", c.purl, f"{c.purl} is deprecated on npm")
            out.append(Finding(cls="anomaly", subject=c.purl, title=f"{c.name}@{c.version} is deprecated",
                               locator=f"registry:{c.purl}", detector="registry", classification="W", raw_evidence_ids=[ev.id],
                               signals={"signal": "deprecated", "scope": c.scope}))
        age = _age_days(md.version_uploaded)
        if age is not None and age < 14:
            ev = ctx.store.add_evidence("raw", "registry", c.purl, f"{c.purl} uploaded {md.version_uploaded}")
            out.append(Finding(cls="anomaly", subject=c.purl, title=f"{c.name}@{c.version} was published {int(age)} day(s) ago",
                               locator=f"registry:{c.purl}", detector="registry", classification="W", raw_evidence_ids=[ev.id],
                               signals={"signal": "recently_published", "uploaded": md.version_uploaded, "scope": c.scope}))
        if c.ecosystem == "pypi" and md.sdist_only:
            ev = ctx.store.add_evidence("raw", "pypi", c.purl, f"{c.purl} has only an sdist: a build script runs on install")
            out.append(Finding(cls="anomaly", subject=c.purl, title=f"{c.name}@{c.version} ships only an sdist (build runs on install)",
                               locator=f"registry:{c.purl}", detector="registry", classification="W", raw_evidence_ids=[ev.id],
                               signals={"signal": "sdist_only", "scope": c.scope}))
        lock_hash = next((h for h in c.hashes if h.startswith("sha256:")), None)
        if lock_hash and md.registry_hashes and c.ecosystem == "pypi" and lock_hash not in md.registry_hashes and \
                not any(h in md.registry_hashes for h in c.hashes):
            ev = ctx.store.add_evidence("raw", "pypi", c.purl, f"lock hashes {c.hashes[:3]} not in PyPI hashes {md.registry_hashes[:3]}")
            out.append(Finding(cls="anomaly", subject=c.purl, title=f"Lockfile hash for {c.name}@{c.version} does not match PyPI",
                               locator=f"registry:{c.purl}", detector="registry", classification="S", raw_evidence_ids=[ev.id],
                               signals={"signal": "hash_mismatch", "scope": c.scope}))
    indexes = ctx.facts.package_indexes if ctx.facts else []
    for ix in indexes:
        official = any(h in ix.url for h in OFFICIAL_INDEX_HOSTS)
        if official and "extra" not in ix.type:
            continue
        # Dependency confusion: a private source *alongside* the public one (pip extra-index, several Bundler
        # sources, Maven/Composer/NuGet repositories added next to the defaults) lets a public name win.
        same_file = [x for x in indexes if x.source_file == ix.source_file]
        mixed = ix.type in ("extra-index-url", "uv-extra-index-url") or (
            ix.type in ("gem-source", "nuget-source") and any(any(h in x.url for h in OFFICIAL_INDEX_HOSTS) for x in same_file)) or \
            ix.type in ("maven-repository",) or ix.type.startswith("composer-")
        out.append(Finding(cls="anomaly", subject=ix.url, title=f"Additional package index configured: {ix.url}",
                           locator=f"{ix.source_file}:{ix.line or 1}", detector="registry",
                           classification="S" if mixed and ix.type in ("extra-index-url", "uv-extra-index-url", "gem-source", "nuget-source") else "W",
                           raw_evidence_ids=[ix.evidence_id] if ix.evidence_id else [],
                           signals={"signal": "extra_index", "type": ix.type, "url": ix.url, "alongside_public_index": mixed}))
    return out


OFFICIAL_INDEX_HOSTS = ("pypi.org", "pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com", "repo.maven.apache.org",
                        "repo1.maven.org", "rubygems.org", "packagist.org", "api.nuget.org", "crates.io", "plugins.gradle.org",
                        "proxy.golang.org")


def detect_discrepancies(ctx: RunContext) -> list[Finding]:
    """Cross-layer: declared but never imported (runtime), imported but not declared."""
    if not ctx.graph or not ctx.code_index:
        return []
    out = []
    from ..purl import LANGUAGE_ECOSYSTEM
    indexed_ecos = {LANGUAGE_ECOSYSTEM.get(cf.language) for cf in ctx.code_index.files}
    for row in ctx.graph.discrepancies():
        eco = row["ecosystem"]
        # Only compare layers where import -> package mapping is reliable. Maven (Java packages != coordinates),
        # NuGet and Composer starter/meta packages are skipped to avoid false "never imported" claims.
        if eco not in indexed_ecos or eco in ("maven", "nuget", "composer"):
            continue
        if eco == "golang" and row["status"] == "declared-not-imported":
            decl = [d for d in ctx.facts.declared_dependencies if d.ecosystem == "golang" and d.name == row["name"]]
            if decl and all(d.markers == "indirect" for d in decl):
                continue
        if row["status"] == "declared-not-imported" and "prod" in row["declared_scopes"]:
            ev = ctx.store.add_evidence("derived", "graph", row["package"],
                                        f"{row['name']} is declared as a runtime dependency but no source file imports it")
            out.append(Finding(cls="discrepancy", subject=row["package"], title=f"'{row['name']}' declared but never imported",
                               locator=f"package:{row['package']}", detector="discrepancies", classification="W",
                               raw_evidence_ids=[ev.id], signals={"signal": "declared_not_imported", **row}))
        elif row["status"] == "imported-not-declared":
            ev = ctx.store.add_evidence("derived", "graph", row["package"],
                                        f"{row['name']} is imported by source code but not declared or resolved")
            out.append(Finding(cls="discrepancy", subject=row["package"], title=f"'{row['name']}' imported but not declared",
                               locator=f"package:{row['package']}", detector="discrepancies", classification="W",
                               raw_evidence_ids=[ev.id], signals={"signal": "imported_not_declared", **row}))
    return out
