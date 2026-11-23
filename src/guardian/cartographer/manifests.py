"""Manifest parsers (npm + Python). Pure functions over text so git history can reuse them.

Records facts only: what is declared, where, how. No judging.
"""
from __future__ import annotations

import configparser
import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement

from ..fsutil import find_line
from ..models import DeclaredDependency, LifecycleScript, Manifest, PackageIndex

NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare")
DEV_HINTS = re.compile(r"(^|[-_.])(dev|test|tests|testing|lint|docs|doc|ci|typing)([-_.]|$)", re.I)

MANIFEST_NAMES = {"package.json", "pyproject.toml", "setup.cfg", "setup.py", "Pipfile"}


def is_manifest(name: str) -> bool:
    return name in MANIFEST_NAMES or bool(re.match(r"^requirements.*\.(txt|in)$", name, re.I)) \
        or (name.endswith(".txt") and "requirements" in name.lower())


@dataclass
class ManifestParse:
    manifest: Manifest | None = None
    deps: list[DeclaredDependency] = field(default_factory=list)
    indexes: list[PackageIndex] = field(default_factory=list)
    scripts: list[LifecycleScript] = field(default_factory=list)
    includes: list[tuple[str, str]] = field(default_factory=list)  # (kind "-r"/"-c", rel path)
    errors: list[str] = field(default_factory=list)


def parse_manifest(rel_path: str, text: str) -> ManifestParse:
    name = PurePosixPath(rel_path).name
    try:
        if name == "package.json":
            return parse_package_json(rel_path, text)
        if name == "pyproject.toml":
            return parse_pyproject(rel_path, text)
        if name == "setup.cfg":
            return parse_setup_cfg(rel_path, text)
        if name == "setup.py":
            return parse_setup_py(rel_path, text)
        if name == "Pipfile":
            return parse_pipfile(rel_path, text)
        return parse_requirements(rel_path, text)
    except Exception as e:  # fail soft: one broken manifest never aborts the scan
        return ManifestParse(errors=[f"{rel_path}: parse_error: {type(e).__name__}: {e}"])


# ------------------------------------------------------------------------- npm
def _npm_kind(spec: str) -> str:
    s = spec.strip()
    if s.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:")) or re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s):
        return "vcs"
    if s.startswith(("http://", "https://")):
        return "url"
    if s.startswith(("file:", "link:", "./", "../", "/")):
        return "path"
    if s.startswith("npm:"):
        return "alias"
    return "registry"


def parse_package_json(rel_path: str, text: str) -> ManifestParse:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package.json is not an object")
    out = ManifestParse()
    groups = (("dependencies", "prod"), ("devDependencies", "dev"), ("optionalDependencies", "optional"),
              ("peerDependencies", "optional"))
    for key, scope in groups:
        section = data.get(key) or {}
        if not isinstance(section, dict):
            continue
        sec_line = find_line(text, f'"{key}"')
        for dep, spec in section.items():
            spec = str(spec)
            out.deps.append(DeclaredDependency(
                name=dep, ecosystem="npm", spec=spec, kind=_npm_kind(spec), scope=scope,
                source_file=rel_path, line=find_line(text, f'"{dep}"', sec_line or 1) or sec_line))
    for sname, cmd in (data.get("scripts") or {}).items():
        if sname in NPM_LIFECYCLE:
            out.scripts.append(LifecycleScript(path=rel_path, name=sname, command=str(cmd),
                                               line=find_line(text, f'"{sname}"'), ecosystem="npm"))
    entry = {}
    if isinstance(data.get("bin"), dict):
        entry.update({k: str(v) for k, v in data["bin"].items()})
    if data.get("main"):
        entry["main"] = str(data["main"])
    out.manifest = Manifest(path=rel_path, ecosystem="npm", project_name=data.get("name"),
                            dependency_count=len(out.deps), entry_points=entry)
    return out


def parse_npmrc(rel_path: str, text: str) -> tuple[list[PackageIndex], str | None]:
    """Returns registries and 'package-lock=false' style ignore marker."""
    idx, ignored = [], None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if k == "registry" or k.endswith(":registry"):
            idx.append(PackageIndex(url=v, type="npm-registry" if k == "registry" else f"npm-scope-registry({k.split(':')[0]})",
                                    source_file=rel_path, line=i))
        if k in ("package-lock", "shrinkwrap") and v.lower() == "false":
            ignored = f".npmrc:{k}=false"
    return idx, ignored


# ------------------------------------------------------------------------- requirements.txt
def _logical_lines(text: str):
    buf, start = "", None
    for i, raw in enumerate(text.splitlines(), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if start is None:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        if buf.strip():
            yield start, buf.strip()
        buf, start = "", None
    if buf.strip():
        yield start or 1, buf.strip()


def _vcs_name(url: str) -> str:
    m = re.search(r"[#&]egg=([A-Za-z0-9_.\-\[\]]+)", url)
    if m:
        return re.sub(r"\[.*\]", "", m.group(1))
    tail = url.split("#")[0].rstrip("/").split("/")[-1]
    return re.sub(r"(\.git|@.*)$", "", tail) or url


def _dep_from_line(rel_path: str, line_no: int, s: str, scope: str) -> DeclaredDependency | None:
    s = re.split(r"\s--hash[= ]", s)[0].strip()
    if s.startswith(("-e ", "--editable ")):
        s = s.split(None, 1)[1].strip()
    if re.match(r"^(git|hg|svn|bzr)\+", s):
        return DeclaredDependency(name=_vcs_name(s), ecosystem="pypi", spec=s, kind="vcs", scope=scope,
                                  source_file=rel_path, line=line_no)
    if s.startswith(("http://", "https://", "file:")):
        return DeclaredDependency(name=_vcs_name(s), ecosystem="pypi", spec=s, kind="url", scope=scope,
                                  source_file=rel_path, line=line_no)
    if s.startswith((".", "/")) or re.match(r"^[A-Za-z]:\\", s):
        return DeclaredDependency(name=s, ecosystem="pypi", spec=s, kind="path", scope=scope,
                                  source_file=rel_path, line=line_no)
    return _pep508(rel_path, line_no, s, scope)


def _pep508(rel_path: str, line_no: int | None, s: str, scope: str) -> DeclaredDependency | None:
    try:
        r = Requirement(s)
    except InvalidRequirement:
        return None
    kind = "registry"
    spec = str(r.specifier) or None
    if r.url:
        kind = "vcs" if re.match(r"^(git|hg|svn|bzr)\+", r.url) else "url"
        spec = r.url
    return DeclaredDependency(name=r.name, ecosystem="pypi", spec=spec, kind=kind, scope=scope,
                              extras=sorted(r.extras), markers=str(r.marker) if r.marker else None,
                              source_file=rel_path, line=line_no)


def parse_requirements(rel_path: str, text: str) -> ManifestParse:
    out = ManifestParse()
    stem = PurePosixPath(rel_path).stem
    scope = "dev" if DEV_HINTS.search(stem) else "prod"
    base = PurePosixPath(rel_path).parent
    for line_no, s in _logical_lines(text):
        if s.startswith(("-r", "--requirement", "-c", "--constraint")):
            parts = s.replace("=", " ").split(None, 1)
            if len(parts) == 2:
                kind = "-c" if parts[0] in ("-c", "--constraint") else "-r"
                out.includes.append((kind, (base / parts[1].strip()).as_posix()))
            continue
        if s.startswith(("-i", "--index-url", "--extra-index-url", "-f", "--find-links")):
            parts = s.replace("=", " ").split(None, 1)
            if len(parts) == 2:
                t = {"-i": "index-url", "--index-url": "index-url", "--extra-index-url": "extra-index-url",
                     "-f": "find-links", "--find-links": "find-links"}[parts[0]]
                out.indexes.append(PackageIndex(url=parts[1].strip(), type=t, source_file=rel_path, line=line_no))
            continue
        if s.startswith("-") and not s.startswith(("-e", "--editable")):
            continue  # other pip options (--trusted-host, --pre, ...)
        dep = _dep_from_line(rel_path, line_no, s, scope)
        if dep:
            out.deps.append(dep)
        else:
            out.errors.append(f"{rel_path}:{line_no}: unparseable requirement: {s[:80]}")
    out.manifest = Manifest(path=rel_path, ecosystem="pypi", dependency_count=len(out.deps))
    return out


# ------------------------------------------------------------------------- pyproject / setup.cfg / Pipfile
def _group_scope(group: str) -> str:
    return "dev" if DEV_HINTS.search(group) else "optional"


def parse_pyproject(rel_path: str, text: str) -> ManifestParse:
    data = tomllib.loads(text)
    out = ManifestParse()
    proj = data.get("project") or {}
    for s in proj.get("dependencies") or []:
        d = _pep508(rel_path, find_line(text, s.split(";")[0].strip()), s, "prod")
        d and out.deps.append(d)
    for group, reqs in (proj.get("optional-dependencies") or {}).items():
        for s in reqs:
            d = _pep508(rel_path, find_line(text, s.split(";")[0].strip()), s, _group_scope(group))
            d and out.deps.append(d)
    for group, reqs in (data.get("dependency-groups") or {}).items():
        for s in reqs:
            if isinstance(s, str):
                d = _pep508(rel_path, find_line(text, s.split(";")[0].strip()), s, "dev")
                d and out.deps.append(d)
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") or {}

    def poetry_deps(section: dict, scope: str):
        for name, spec in (section or {}).items():
            if name.lower() == "python":
                continue
            kind, sp = "registry", spec if isinstance(spec, str) else None
            if isinstance(spec, dict):
                if "git" in spec:
                    kind, sp = "vcs", f"git+{spec['git']}" + (f"@{spec.get('rev') or spec.get('tag') or spec.get('branch')}" if any(k in spec for k in ("rev", "tag", "branch")) else "")
                elif "url" in spec:
                    kind, sp = "url", spec["url"]
                elif "path" in spec:
                    kind, sp = "path", spec["path"]
                else:
                    sp = spec.get("version")
            out.deps.append(DeclaredDependency(name=name, ecosystem="pypi", spec=sp, kind=kind, scope=scope,
                                               source_file=rel_path, line=find_line(text, name)))

    poetry_deps(poetry.get("dependencies"), "prod")
    poetry_deps(poetry.get("dev-dependencies"), "dev")
    for gname, g in (poetry.get("group") or {}).items():
        poetry_deps((g or {}).get("dependencies"), "dev" if gname != "main" else "prod")
    for src in poetry.get("source") or []:
        if src.get("url"):
            out.indexes.append(PackageIndex(url=src["url"], type=f"poetry-source({src.get('priority', 'default')})",
                                            source_file=rel_path, line=find_line(text, src["url"])))
    uv = tool.get("uv") or {}
    for ix in uv.get("index") or []:
        if ix.get("url"):
            out.indexes.append(PackageIndex(url=ix["url"], type="uv-index", source_file=rel_path,
                                            line=find_line(text, ix["url"])))
    for key in ("index-url", "extra-index-url"):
        vals = uv.get(key)
        for v in ([vals] if isinstance(vals, str) else vals or []):
            out.indexes.append(PackageIndex(url=v, type=f"uv-{key}", source_file=rel_path, line=find_line(text, v)))
    entry = {k: str(v) for k, v in (proj.get("scripts") or {}).items()}
    entry.update({k: str(v) for k, v in (poetry.get("scripts") or {}).items()})
    out.manifest = Manifest(path=rel_path, ecosystem="pypi", project_name=proj.get("name") or poetry.get("name"),
                            dependency_count=len(out.deps), entry_points=entry)
    return out


def parse_setup_cfg(rel_path: str, text: str) -> ManifestParse:
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_string(text)
    out = ManifestParse()
    if cp.has_option("options", "install_requires"):
        for s in cp.get("options", "install_requires").splitlines():
            s = s.strip()
            if s:
                d = _pep508(rel_path, find_line(text, s), s, "prod")
                d and out.deps.append(d)
    if cp.has_section("options.extras_require"):
        for group, val in cp.items("options.extras_require"):
            for s in val.splitlines():
                s = s.strip()
                if s:
                    d = _pep508(rel_path, find_line(text, s), s, _group_scope(group))
                    d and out.deps.append(d)
    entry = {}
    if cp.has_option("options.entry_points", "console_scripts"):
        for s in cp.get("options.entry_points", "console_scripts").splitlines():
            if "=" in s:
                k, v = s.split("=", 1)
                entry[k.strip()] = v.strip()
    out.manifest = Manifest(path=rel_path, ecosystem="pypi", project_name=cp.get("metadata", "name", fallback=None),
                            dependency_count=len(out.deps), entry_points=entry)
    return out


def parse_setup_py(rel_path: str, text: str) -> ManifestParse:
    """Static, best-effort: string literals inside install_requires=[...]. Never executed."""
    out = ManifestParse()
    m = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.S)
    if m:
        for s in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
            d = _pep508(rel_path, find_line(text, s), s, "prod")
            d and out.deps.append(d)
    out.scripts.append(LifecycleScript(path=rel_path, name="setup.py", command="setup.py (runs on sdist install)",
                                       line=1, ecosystem="pypi"))
    out.manifest = Manifest(path=rel_path, ecosystem="pypi", dependency_count=len(out.deps))
    return out


def parse_pipfile(rel_path: str, text: str) -> ManifestParse:
    data = tomllib.loads(text)
    out = ManifestParse()
    for section, scope in (("packages", "prod"), ("dev-packages", "dev")):
        for name, spec in (data.get(section) or {}).items():
            kind, sp = "registry", spec if isinstance(spec, str) else None
            if isinstance(spec, dict):
                if "git" in spec:
                    kind, sp = "vcs", spec["git"]
                elif "path" in spec:
                    kind, sp = "path", spec["path"]
                elif "file" in spec:
                    kind, sp = "url", spec["file"]
                else:
                    sp = spec.get("version")
            out.deps.append(DeclaredDependency(name=name, ecosystem="pypi", spec=None if sp == "*" else sp,
                                               kind=kind, scope=scope, source_file=rel_path,
                                               line=find_line(text, name)))
    for src in data.get("source") or []:
        if src.get("url"):
            out.indexes.append(PackageIndex(url=src["url"], type="pipfile-source", source_file=rel_path,
                                            line=find_line(text, src["url"])))
    out.manifest = Manifest(path=rel_path, ecosystem="pypi", dependency_count=len(out.deps))
    return out
