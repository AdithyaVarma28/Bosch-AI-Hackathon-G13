"""Lockfile parsers for Cargo, Bundler, Composer, NuGet, Gradle and Go modules (go.mod + go.sum)."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import PurePosixPath

from ..models import Component, DepEdge, Origin
from ..purl import make_purl, normalize_name

POLY_LOCKS = {"Cargo.lock", "Gemfile.lock", "composer.lock", "packages.lock.json", "gradle.lockfile", "go.sum"}


def _comp(eco, name, version, scope="unknown", registry=None, resolved=None, integrity=None, hashes=None,
          install_script=False) -> Component:
    return Component(purl=make_purl(eco, name, version), name=name, version=version, ecosystem=eco, scope=scope,
                     origin=Origin(registry=registry, resolved_url=resolved, integrity=integrity,
                                   has_install_script=install_script),
                     hashes=hashes or ([integrity] if integrity else []), source="lockfile", seen_by=["lockfile"])


def _edges_by_name(out, eco: str, deps: dict[str, list[str]]) -> None:
    by = {}
    for c in out.components:
        by.setdefault(normalize_name(eco, c.name), c.purl)
    for src, names in deps.items():
        s = by.get(normalize_name(eco, src))
        for d in names:
            t = by.get(normalize_name(eco, d))
            if s and t and s != t:
                out.edges.append(DepEdge(src=s, dst=t))


# --------------------------------------------------------------------------- Cargo.lock
def parse_cargo_lock(rel: str, text: str):
    from .lockfiles import ParsedLock
    data = tomllib.loads(text)
    out = ParsedLock(rel, "cargo", version=data.get("version"))
    deps: dict[str, list[str]] = {}
    for p in data.get("package") or []:
        src = p.get("source")
        names = [d.split()[0] for d in p.get("dependencies") or []]
        if not src:  # workspace member (the project itself)
            out.direct_names.update(normalize_name("cargo", n) for n in names)
            continue
        registry = resolved = None
        if src.startswith("registry+"):
            url = src[len("registry+"):]
            registry = "crates.io" if "crates.io-index" in url or "index.crates.io" in url else url
        elif src.startswith("sparse+"):
            url = src[len("sparse+"):]
            registry = "crates.io" if "index.crates.io" in url else url
        else:
            resolved = src  # git+https://...#rev
        checksum = p.get("checksum")
        out.has_integrity = out.has_integrity or bool(checksum)
        out.components.append(_comp("cargo", p["name"], p.get("version"), registry=registry, resolved=resolved,
                                    integrity=f"sha256:{checksum}" if checksum else None))
        deps[p["name"]] = names
    _edges_by_name(out, "cargo", deps)
    return out


# --------------------------------------------------------------------------- Gemfile.lock
def parse_gemfile_lock(rel: str, text: str):
    from .lockfiles import ParsedLock
    out = ParsedLock(rel, "gem")
    section = remote = None
    current = None
    deps: dict[str, list[str]] = {}
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if not raw.startswith(" "):
            section = raw.strip()
            remote = None
            continue
        s = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if s.startswith("remote:"):
            remote = s.split(":", 1)[1].strip()
            continue
        if section in ("GEM", "GIT", "PATH") and indent == 4:
            m = re.match(r"^([^\s(]+) \(([^)]+)\)$", s)
            if m:
                name, ver = m.group(1), m.group(2).split("-")[0] if re.search(r"-(x86|arm|aarch|java|universal|x64|mingw)", m.group(2)) else m.group(2)
                current = name
                registry = re.sub(r"^https?://([^/]+).*$", r"\1", remote) if section == "GEM" and remote else None
                resolved = remote if section in ("GIT", "PATH") else None
                if not any(c.name == name for c in out.components):
                    out.components.append(_comp("gem", name, ver, registry=registry, resolved=resolved))
                deps.setdefault(name, [])
        elif section in ("GEM", "GIT", "PATH") and indent == 6 and current:
            deps[current].append(s.split()[0])
        elif section == "DEPENDENCIES" and indent == 2:
            out.direct_names.add(normalize_name("gem", s.split()[0].rstrip("!")))
    _edges_by_name(out, "gem", deps)
    m = re.search(r"CHECKSUMS\n((?:  .+\n?)+)", text)
    if m:
        out.has_integrity = True
    return out


# --------------------------------------------------------------------------- composer.lock
def parse_composer_lock(rel: str, text: str):
    from .lockfiles import ParsedLock
    data = json.loads(text)
    out = ParsedLock(rel, "composer")
    deps: dict[str, list[str]] = {}
    for key, scope in (("packages", "prod"), ("packages-dev", "dev")):
        for p in data.get(key) or []:
            name, ver = p.get("name"), str(p.get("version", "")).lstrip("v") or None
            dist, src = p.get("dist") or {}, p.get("source") or {}
            shasum = dist.get("shasum") or None
            out.has_integrity = out.has_integrity or bool(shasum or dist.get("reference"))
            resolved = dist.get("url") or src.get("url")
            reg = "packagist.org" if resolved and ("api.github.com" in resolved or "packagist" in resolved or "github.com" in resolved
                                                    or "codeload.github.com" in resolved) else None
            c = _comp("composer", name, ver, scope=scope, registry=reg, resolved=resolved,
                      integrity=f"sha1:{shasum}" if shasum else (f"ref:{dist.get('reference')}" if dist.get("reference") else None),
                      install_script=bool((p.get("scripts") or {})))
            out.components.append(c)
            deps[name] = [d for d in (p.get("require") or {}) if "/" in d]
            for ns in ((p.get("autoload") or {}).get("psr-4") or {}):
                out.namespaces[ns] = name
            for ns in ((p.get("autoload") or {}).get("psr-0") or {}):
                out.namespaces[ns] = name
    _edges_by_name(out, "composer", deps)
    return out


# --------------------------------------------------------------------------- NuGet packages.lock.json
def parse_nuget_lock(rel: str, text: str):
    from .lockfiles import ParsedLock
    data = json.loads(text)
    out = ParsedLock(rel, "nuget", version=data.get("version"))
    deps: dict[str, list[str]] = {}
    for _fw, pkgs in (data.get("dependencies") or {}).items():
        for name, info in (pkgs or {}).items():
            if info.get("type") == "Project":
                continue
            ver = info.get("resolved")
            h = info.get("contentHash")
            out.has_integrity = out.has_integrity or bool(h)
            if not any(c.name.lower() == name.lower() and c.version == ver for c in out.components):
                out.components.append(_comp("nuget", name, ver, registry="api.nuget.org", integrity=f"sha512:{h}" if h else None))
            if info.get("type") in ("Direct", "CentralTransitive") and info.get("type") == "Direct":
                out.direct_names.add(normalize_name("nuget", name))
            deps.setdefault(name, []).extend((info.get("dependencies") or {}).keys())
    _edges_by_name(out, "nuget", deps)
    return out


# --------------------------------------------------------------------------- gradle.lockfile
def parse_gradle_lockfile(rel: str, text: str):
    from .lockfiles import ParsedLock
    out = ParsedLock(rel, "maven")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coord, _, confs = line.partition("=")
        parts = coord.split(":")
        if len(parts) < 3:
            continue
        g, a, v = parts[0], parts[1], parts[2]
        scope = "dev" if confs and all("test" in c.lower() for c in confs.split(",")) else "prod"
        out.components.append(_comp("maven", f"{g}:{a}", v, scope=scope, registry="maven"))
    out.errors.append(f"{rel}: gradle.lockfile has no dependency edges; relationships unknown")
    return out


# --------------------------------------------------------------------------- Go modules
def parse_go_sum(rel: str, text: str):
    """go.sum alone: one component per module version with its h1: hash (used for history diffs)."""
    from .lockfiles import ParsedLock
    out = ParsedLock(rel, "golang")
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[1].endswith("/go.mod"):
            continue
        mod, ver, h = parts
        out.has_integrity = True
        out.components.append(_comp("golang", mod, ver, registry="proxy.golang.org", integrity=h))
    return out


def parse_go_module(gomod_rel: str, gomod_text: str, gosum_text: str | None):
    """Resolved Go build list: go.mod `require` (complete since Go 1.17) + go.sum hashes. No edges in these files."""
    from ..cartographer.manifests_poly import parse_go_mod
    from .lockfiles import ParsedLock
    mp = parse_go_mod(gomod_rel, gomod_text)
    rel = str(PurePosixPath(gomod_rel).parent / "go.sum") if gosum_text is not None else gomod_rel
    out = ParsedLock(rel, "golang")
    hashes: dict[tuple[str, str], str] = {}
    for line in (gosum_text or "").splitlines():
        p = line.split()
        if len(p) == 3 and not p[1].endswith("/go.mod"):
            hashes[(p[0], p[1])] = p[2]
    for d in mp.deps:
        ver = (d.spec or "").split(" =>")[0].strip() or None
        h = hashes.get((d.name, ver or ""))
        out.has_integrity = out.has_integrity or bool(h)
        c = _comp("golang", d.name, ver, registry=None if d.kind in ("path", "vcs") else "proxy.golang.org",
                  resolved=d.spec.split("=>", 1)[1].strip() if d.spec and "=>" in d.spec else None, integrity=h)
        c.direct = d.markers != "indirect"
        out.components.append(c)
        if c.direct:
            out.direct_names.add(d.name)
    out.errors.append(f"{gomod_rel}: Go module files record the build list but not which module requires which; edges unknown")
    return out


def parse_lock_in_repo(root, manifest_rel: str, lock_rel: str):
    """Parse a lockfile in the context of its manifest (Go needs go.mod + go.sum together)."""
    from ..fsutil import read_text
    from .lockfiles import parse_lockfile
    name = PurePosixPath(lock_rel).name
    if name in ("go.sum", "go.mod"):
        gomod = str(PurePosixPath(manifest_rel))
        gosum = str(PurePosixPath(gomod).parent / "go.sum") if PurePosixPath(gomod).parent != PurePosixPath(".") else "go.sum"
        return parse_go_module(gomod, read_text(root / gomod) or "", read_text(root / gosum) if (root / gosum).exists() else None)
    return parse_lockfile(lock_rel, read_text(root / lock_rel) or "")


def parse_poly_lock(rel: str, text: str):
    name = PurePosixPath(rel).name
    return {"Cargo.lock": parse_cargo_lock, "Gemfile.lock": parse_gemfile_lock, "composer.lock": parse_composer_lock,
            "packages.lock.json": parse_nuget_lock, "gradle.lockfile": parse_gradle_lockfile, "go.sum": parse_go_sum}[name](rel, text)
