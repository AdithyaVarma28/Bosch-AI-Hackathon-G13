"""Lockfile parsers -> components + resolved edges. Pure functions over text (reused by git history).

Supported: package-lock.json (v1, v2, v3), npm-shrinkwrap.json, yarn.lock (v1), poetry.lock, uv.lock,
Pipfile.lock, hashed/pinned requirements files.
"""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from ..models import Component, DepEdge, Origin
from ..purl import make_purl, normalize_pypi

NPM_REGISTRY_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com")
LOCKFILE_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
                  "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"}


@dataclass
class ParsedLock:
    path: str
    ecosystem: str
    components: list[Component] = field(default_factory=list)
    edges: list[DepEdge] = field(default_factory=list)
    direct_names: set[str] = field(default_factory=set)   # names the lock itself marks as direct
    errors: list[str] = field(default_factory=list)
    namespaces: dict[str, str] = field(default_factory=dict)  # import/namespace prefix -> package (composer autoload)
    version: int | None = None
    has_integrity: bool = False


def is_lockfile(name: str) -> bool:
    from .lockfiles_poly import POLY_LOCKS
    return name in LOCKFILE_NAMES or name in POLY_LOCKS


def parse_lockfile(rel_path: str, text: str) -> ParsedLock:
    from .lockfiles_poly import POLY_LOCKS, parse_poly_lock
    name = PurePosixPath(rel_path).name
    try:
        if name in POLY_LOCKS:
            return parse_poly_lock(rel_path, text)
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            return parse_package_lock(rel_path, text)
        if name == "yarn.lock":
            return parse_yarn_lock(rel_path, text)
        if name == "poetry.lock":
            return parse_poetry_lock(rel_path, text)
        if name == "uv.lock":
            return parse_uv_lock(rel_path, text)
        if name == "Pipfile.lock":
            return parse_pipfile_lock(rel_path, text)
        if name.endswith(".txt") or name.endswith(".in"):
            return parse_requirements_pins(rel_path, text)
        return ParsedLock(rel_path, "other", errors=[f"{rel_path}: unsupported lockfile format"])
    except Exception as e:
        eco = {"Cargo.lock": "cargo", "Gemfile.lock": "gem", "composer.lock": "composer", "packages.lock.json": "nuget",
               "gradle.lockfile": "maven", "go.sum": "golang"}.get(name, "npm" if name.endswith((".json", "yarn.lock")) else "pypi")
        return ParsedLock(rel_path, eco, errors=[f"{rel_path}: parse_error: {type(e).__name__}: {e}"])


def _registry_of(url: str | None) -> str | None:
    if not url:
        return None
    m = re.match(r"^https?://([^/]+)/", url)
    return m.group(1) if m else None


# ------------------------------------------------------------------------- npm
def _npm_name_from_key(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1]


def _v1_to_packages(deps: dict, prefix: str = "") -> dict:
    out = {}
    for name, info in (deps or {}).items():
        key = f"{prefix}node_modules/{name}"
        entry = {k: info.get(k) for k in ("version", "resolved", "integrity", "dev", "optional")}
        entry["dependencies"] = info.get("requires") or {}
        out[key] = entry
        out.update(_v1_to_packages(info.get("dependencies") or {}, prefix=f"{key}/"))
    return out


def _resolve_npm_dep(packages: dict, from_key: str, dep: str) -> str | None:
    base = from_key
    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in packages:
            return cand
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx >= 0 else ""


def parse_package_lock(rel_path: str, text: str) -> ParsedLock:
    data = json.loads(text)
    ver = int(data.get("lockfileVersion") or 1)
    out = ParsedLock(rel_path, "npm", version=ver)
    if ver >= 2 and isinstance(data.get("packages"), dict):
        packages = {k: v for k, v in data["packages"].items()}
        root = packages.pop("", {}) or {}
    else:
        packages = _v1_to_packages(data.get("dependencies") or {})
        root = {}
    root_direct = {}
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        root_direct.update(root.get(sec) or {})
    # v1 locks hoist everything to the top level, so "direct" is unknown from the lock alone;
    # the SBOM stage marks direct dependencies from the manifest instead.
    out.direct_names = set(root_direct)
    key_to_purl: dict[str, str] = {}
    for key, info in packages.items():
        if not key.startswith("node_modules/") and "/node_modules/" not in key:
            continue  # workspace links ("packages/foo")
        info = info or {}
        name = info.get("name") or _npm_name_from_key(key)
        version = info.get("version")
        if info.get("link"):
            version = None
        purl = make_purl("npm", name, version)
        key_to_purl[key] = purl
        resolved = info.get("resolved")
        integrity = info.get("integrity")
        out.has_integrity = out.has_integrity or bool(integrity)
        scope = "dev" if info.get("dev") else "optional" if info.get("optional") else "prod"
        out.components.append(Component(
            purl=purl, name=name, version=version, ecosystem="npm", scope=scope,
            direct=key.count("node_modules/") == 1 and name in root_direct,
            origin=Origin(registry=_registry_of(resolved) if resolved and resolved.startswith("http") else None,
                          resolved_url=resolved, integrity=integrity, license=info.get("license") if isinstance(info.get("license"), str) else None,
                          has_install_script=bool(info.get("hasInstallScript"))),
            hashes=[integrity] if integrity else [], source="lockfile", seen_by=["lockfile"]))
    for key, info in packages.items():
        if key not in key_to_purl:
            continue
        deps = {}
        for sec in ("dependencies", "optionalDependencies", "requires"):
            d = (info or {}).get(sec)
            if isinstance(d, dict):
                deps.update(d)
        for dep in deps:
            tk = _resolve_npm_dep(packages, key, dep)
            if tk and tk in key_to_purl:
                out.edges.append(DepEdge(src=key_to_purl[key], dst=key_to_purl[tk], source="lockfile"))
    out.components = _dedupe(out.components)
    out.edges = list({(e.src, e.dst): e for e in out.edges}.values())
    return out


def parse_yarn_lock(rel_path: str, text: str) -> ParsedLock:
    out = ParsedLock(rel_path, "npm", version=1)
    if "__metadata:" in text:
        out.errors.append(f"{rel_path}: yarn berry lockfile parsed best-effort")
    blocks: list[tuple[list[str], dict]] = []
    cur: dict | None = None
    in_deps = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            specs = [s.strip().strip('"') for s in raw.rstrip(":").split(",")]
            cur = {"deps": {}}
            blocks.append((specs, cur))
            in_deps = False
            continue
        if cur is None:
            continue
        s = raw.strip()
        if s.rstrip(":") in ("dependencies", "optionalDependencies"):
            in_deps = True
            continue
        if raw.startswith("    ") and in_deps:
            parts = s.split(None, 1)
            cur["deps"][parts[0].strip('"')] = parts[1].strip('"') if len(parts) > 1 else ""
            continue
        in_deps = False
        parts = s.split(None, 1)
        if len(parts) == 2:
            cur[parts[0].rstrip(":")] = parts[1].strip('"')
    spec_to_purl: dict[str, str] = {}
    for specs, info in blocks:
        name = specs[0].rsplit("@", 1)[0] if not specs[0].startswith("@") else "@" + specs[0][1:].rsplit("@", 1)[0]
        purl = make_purl("npm", name, info.get("version"))
        for sp in specs:
            spec_to_purl[sp] = purl
        integ = info.get("integrity") or info.get("checksum")
        out.has_integrity = out.has_integrity or bool(integ)
        out.components.append(Component(purl=purl, name=name, version=info.get("version"), ecosystem="npm",
                                        origin=Origin(resolved_url=info.get("resolved"), integrity=integ,
                                                      registry=_registry_of(info.get("resolved"))),
                                        hashes=[integ] if integ else [], source="lockfile", seen_by=["lockfile"]))
    for specs, info in blocks:
        src = spec_to_purl[specs[0]]
        for dn, dr in info["deps"].items():
            dst = spec_to_purl.get(f"{dn}@{dr}")
            if dst:
                out.edges.append(DepEdge(src=src, dst=dst))
    out.components = _dedupe(out.components)
    return out


# ------------------------------------------------------------------------- python
def _py_edges(out: ParsedLock, deps_by_name: dict[str, list[str]]) -> None:
    by_name = {normalize_pypi(c.name): c.purl for c in out.components}
    for src_name, deps in deps_by_name.items():
        s = by_name.get(normalize_pypi(src_name))
        for d in deps:
            t = by_name.get(normalize_pypi(d))
            if s and t and s != t:
                out.edges.append(DepEdge(src=s, dst=t))


def parse_poetry_lock(rel_path: str, text: str) -> ParsedLock:
    data = tomllib.loads(text)
    out = ParsedLock(rel_path, "pypi")
    deps_by_name: dict[str, list[str]] = {}
    files_meta = (data.get("metadata") or {}).get("files") or {}
    for p in data.get("package") or []:
        name, version = p["name"], p.get("version")
        src = p.get("source") or {}
        hashes = [f.get("hash") for f in (p.get("files") or files_meta.get(name) or []) if f.get("hash")]
        out.has_integrity = out.has_integrity or bool(hashes)
        cat = p.get("category")
        scope = "dev" if cat == "dev" else "optional" if p.get("optional") else "prod" if cat == "main" else "unknown"
        registry, resolved = "pypi.org", None
        if src.get("type") in ("git", "url", "file", "directory"):
            registry, resolved = None, (f"git+{src.get('url')}@{src.get('resolved_reference') or src.get('reference')}"
                                        if src.get("type") == "git" else src.get("url"))
        elif src.get("type") == "legacy":
            registry = _registry_of(src.get("url")) or src.get("url")
        out.components.append(Component(purl=make_purl("pypi", name, version), name=name, version=version,
                                        ecosystem="pypi", scope=scope,
                                        origin=Origin(registry=registry, resolved_url=resolved),
                                        hashes=hashes, source="lockfile", seen_by=["lockfile"]))
        deps_by_name[name] = list((p.get("dependencies") or {}).keys())
    _py_edges(out, deps_by_name)
    return out


def parse_uv_lock(rel_path: str, text: str) -> ParsedLock:
    data = tomllib.loads(text)
    out = ParsedLock(rel_path, "pypi", version=data.get("version"))
    deps_by_name: dict[str, list[str]] = {}
    for p in data.get("package") or []:
        src = p.get("source") or {}
        names = [d["name"] for d in p.get("dependencies") or [] if isinstance(d, dict) and "name" in d]
        for grp in ("optional-dependencies", "dev-dependencies"):
            for lst in (p.get(grp) or {}).values():
                names += [d["name"] for d in lst if isinstance(d, dict) and "name" in d]
        if "virtual" in src or "editable" in src:  # the project itself
            out.direct_names.update(normalize_pypi(n) for n in names)
            continue
        hashes = [w.get("hash") for w in (p.get("wheels") or []) if w.get("hash")]
        if (p.get("sdist") or {}).get("hash"):
            hashes.append(p["sdist"]["hash"])
        out.has_integrity = out.has_integrity or bool(hashes)
        registry = _registry_of(src.get("registry")) if src.get("registry") else None
        resolved = src.get("git") or src.get("url") or src.get("path")
        out.components.append(Component(purl=make_purl("pypi", p["name"], p.get("version")), name=p["name"],
                                        version=p.get("version"), ecosystem="pypi",
                                        origin=Origin(registry=registry, resolved_url=resolved,
                                                      has_install_script=not p.get("wheels") and bool(p.get("sdist"))),
                                        hashes=hashes, source="lockfile", seen_by=["lockfile"]))
        deps_by_name[p["name"]] = names
    _py_edges(out, deps_by_name)
    return out


def parse_pipfile_lock(rel_path: str, text: str) -> ParsedLock:
    data = json.loads(text)
    out = ParsedLock(rel_path, "pypi")
    for section, scope in (("default", "prod"), ("develop", "dev")):
        for name, info in (data.get(section) or {}).items():
            v = (info.get("version") or "").lstrip("=") or None
            hashes = info.get("hashes") or []
            out.has_integrity = out.has_integrity or bool(hashes)
            resolved = info.get("git") or info.get("file") or info.get("path")
            out.components.append(Component(purl=make_purl("pypi", name, v), name=name, version=v, ecosystem="pypi",
                                            scope=scope, origin=Origin(registry=None if resolved else "pypi.org",
                                                                       resolved_url=resolved),
                                            hashes=hashes, source="lockfile", seen_by=["lockfile"]))
    out.errors.append(f"{rel_path}: Pipfile.lock has no dependency edges; relationships unknown")
    return out


_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;\\]+)")


def parse_requirements_pins(rel_path: str, text: str) -> ParsedLock:
    """Only exact `==` pins become components. Others are reported as `unpinned:<line>`."""
    out = ParsedLock(rel_path, "pypi")
    joined = re.sub(r"\\\s*\n", " ", text)
    for i, raw in enumerate(joined.splitlines(), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line or line.startswith("-"):
            continue
        m = _PIN.match(line)
        if not m:
            out.errors.append(f"unpinned:{rel_path}:{i}:{line[:60]}")
            continue
        hashes = re.findall(r"--hash[= ](\S+)", line)
        out.has_integrity = out.has_integrity or bool(hashes)
        name, ver = m.group(1), m.group(3)
        out.components.append(Component(purl=make_purl("pypi", name, ver), name=name, version=ver, ecosystem="pypi",
                                        origin=Origin(registry="pypi.org"), hashes=hashes, source="lockfile",
                                        seen_by=["lockfile"]))
    return out


def _dedupe(components: list[Component]) -> list[Component]:
    seen: dict[str, Component] = {}
    for c in components:
        if c.purl in seen:
            prev = seen[c.purl]
            prev.direct = prev.direct or c.direct
            if prev.scope != "prod" and c.scope == "prod":
                prev.scope = "prod"
        else:
            seen[c.purl] = c
    return list(seen.values())


def lock_index(parsed: ParsedLock) -> dict[str, dict]:
    """name -> {version, integrity, resolved} for diffing lockfiles across commits."""
    out = {}
    for c in parsed.components:
        out[f"{c.ecosystem}:{c.name}"] = {"version": c.version, "integrity": c.origin.integrity or (c.hashes[0] if c.hashes else None),
                                          "resolved": c.origin.resolved_url, "has_install_script": c.origin.has_install_script}
    return out
