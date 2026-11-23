"""Change detectors over dependency history: lockfile tampering, source hijack, new deps, big version jumps."""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import urlparse

from ..cartographer.history import file_at, parents
from ..context import RunContext
from ..models import Finding
from ..sbom.lockfiles import is_lockfile, lock_index, parse_lockfile

TRUSTED_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com", "files.pythonhosted.org", "pypi.org",
                 "codeload.github.com", "api.github.com", "repo.maven.apache.org", "repo1.maven.org", "proxy.golang.org",
                 "static.crates.io", "crates.io", "index.crates.io", "rubygems.org", "index.rubygems.org",
                 "repo.packagist.org", "packagist.org", "api.nuget.org", "plugins.gradle.org"}


def _major(v: str | None) -> int | None:
    m = re.match(r"^\D*(\d+)", v or "")
    return int(m.group(1)) if m else None


def _host(url: str | None) -> str | None:
    if not url:
        return None
    if url.startswith(("git+", "git:", "github:")):
        return "git"
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def detect_changes(ctx: RunContext, last_n: int = 20) -> list[Finding]:
    facts, store, root = ctx.facts, ctx.store, ctx.root
    out: list[Finding] = []
    if not facts:
        return out
    for h in facts.dependency_history[:last_n]:
        if h.baseline:
            continue  # nothing to diff against: never an anomaly
        short = h.commit[:7]
        # new dependency / large jump (manifest + lock level)
        if 0 < len(h.added) <= 3:
            for name in h.added:
                ev = store.add_evidence("raw", "git", f"commit:{h.commit}", f"{short} {h.date} {h.author}: {h.message}\nadded: {name}")
                out.append(Finding(cls="anomaly", subject=name, title=f"New dependency '{name}' added in {short}",
                                   locator=f"commit:{h.commit}", detector="changes", classification="W",
                                   raw_evidence_ids=[ev.id], signals={"signal": "new_dependency", "commit": h.commit,
                                                                     "author": h.author, "date": h.date, "message": h.message}))
        elif h.added:  # bulk change (initial dependency set, framework upgrade): one finding per commit, not N
            ev = store.add_evidence("raw", "git", f"commit:{h.commit}",
                                    f"{short} {h.date} {h.author}: {h.message}\nadded ({len(h.added)}): {', '.join(h.added)}")
            out.append(Finding(cls="anomaly", subject=f"commit:{h.commit}", title=f"{len(h.added)} new dependencies added in {short}",
                               locator=f"commit:{h.commit}", detector="changes", classification="W", raw_evidence_ids=[ev.id],
                               signals={"signal": "new_dependency", "commit": h.commit, "added": h.added, "author": h.author,
                                        "date": h.date, "message": h.message}))
        for ch in h.changed:
            a, b = _major(ch.from_version), _major(ch.to_version)
            if a is not None and b is not None and b - a >= 1:
                ev = store.add_evidence("raw", "git", f"commit:{h.commit}",
                                        f"{short} {h.message}\n{ch.name}: {ch.from_version} -> {ch.to_version}")
                out.append(Finding(cls="anomaly", subject=ch.name, title=f"Major version jump {ch.name} {ch.from_version} -> {ch.to_version}",
                                   locator=f"commit:{h.commit}", detector="changes", classification="W", raw_evidence_ids=[ev.id],
                                   signals={"signal": "large_version_jump", "from": ch.from_version, "to": ch.to_version,
                                            "commit": h.commit, "ecosystem": ch.ecosystem}))
        # lockfile-level diffs (integrity / resolved)
        par = parents(root, h.commit, ctx.runner)
        if not par:
            continue
        for f in h.files_changed:
            if not is_lockfile(PurePosixPath(f).name):
                continue
            after_t = file_at(root, h.commit, f, ctx.runner)
            before_t = file_at(root, par[0], f, ctx.runner)
            if not after_t or not before_t:
                continue
            after, before = lock_index(parse_lockfile(f, after_t)), lock_index(parse_lockfile(f, before_t))
            manifest_changed = any(not is_lockfile(PurePosixPath(x).name) for x in h.files_changed)
            for key in sorted(after.keys() & before.keys()):
                A, B = after[key], before[key]
                name = key.split(":", 1)[1]
                if A["version"] == B["version"] and A["integrity"] and B["integrity"] and A["integrity"] != B["integrity"]:
                    ev = store.add_evidence("raw", "git", f"{f}@{h.commit}",
                                            f"{name}@{A['version']}\nbefore integrity: {B['integrity']}\nafter integrity:  {A['integrity']}\ncommit {short}: {h.message}")
                    out.append(Finding(cls="anomaly", subject=name, title=f"Lockfile integrity of {name}@{A['version']} changed without a version change",
                                       locator=f"{f}@{h.commit}", detector="changes", classification="S", raw_evidence_ids=[ev.id],
                                       signals={"signal": "integrity_changed_same_version", "version": A["version"], "commit": h.commit,
                                                "manifest_changed_in_commit": manifest_changed, "message": h.message}))
                hb, ha = _host(B["resolved"]), _host(A["resolved"])
                if A["resolved"] and B["resolved"] and hb != ha:
                    ev = store.add_evidence("raw", "git", f"{f}@{h.commit}",
                                            f"{name}@{A['version']}\nbefore resolved: {B['resolved']}\nafter resolved:  {A['resolved']}\ncommit {short}: {h.message}")
                    out.append(Finding(cls="anomaly", subject=name, title=f"Resolved source of {name} moved from {hb} to {ha}",
                                       locator=f"{f}@{h.commit}", detector="changes", classification="S", raw_evidence_ids=[ev.id],
                                       signals={"signal": "resolved_host_changed", "from_host": hb, "host": ha, "commit": h.commit,
                                                "message": h.message}))
                if A.get("has_install_script") and not B.get("has_install_script"):
                    ev = store.add_evidence("raw", "git", f"{f}@{h.commit}", f"{name}@{A['version']} gained an install script in {short}")
                    out.append(Finding(cls="anomaly", subject=name, title=f"{name} gained an install script",
                                       locator=f"{f}@{h.commit}", detector="changes", classification="W", raw_evidence_ids=[ev.id],
                                       signals={"signal": "install_script_added", "commit": h.commit}))
    # current state: anything resolved from a non-registry host
    for c in ctx.components:
        url = c.origin.resolved_url
        host = _host(url)
        if url and c.source in ("lockfile", "npm-resolve", "pip-report") and host and host not in TRUSTED_HOSTS:
            insecure = url.startswith("http://")
            ev = store.add_evidence("raw", "lockfile", c.evidence_ids and store.get_evidence(c.evidence_ids[0]).locator or "lockfile",
                                    f"{c.name}@{c.version} resolved={url}")
            out.append(Finding(cls="anomaly", subject=c.purl, title=f"{c.name} is resolved from non-registry source {host}",
                               locator=f"resolved:{url}", detector="changes", classification="S" if insecure or host != "git" else "W",
                               raw_evidence_ids=[ev.id], signals={"signal": "non_registry_source", "host": host, "url": url,
                                                                  "insecure_http": insecure, "scope": c.scope}))
    return out
