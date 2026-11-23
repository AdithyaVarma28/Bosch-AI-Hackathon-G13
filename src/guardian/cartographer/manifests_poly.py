"""Manifest parsers for Maven, Gradle, Go modules, Cargo, Bundler, Composer and NuGet.

Pure functions over text (reused by git history). Facts only: what is declared, where, how.
"""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath

from ..fsutil import find_line
from ..models import DeclaredDependency, LifecycleScript, Manifest, PackageIndex

POLY_MANIFESTS = {"pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Cargo.toml", "Gemfile", "composer.json",
                  "packages.config", "Directory.Packages.props"}
DOTNET_PROJ = (".csproj", ".fsproj", ".vbproj")


def is_poly_manifest(name: str) -> bool:
    return name in POLY_MANIFESTS or name.endswith(DOTNET_PROJ)


def _dep(eco, name, spec, rel, line, scope="prod", kind="registry", extras=None, markers=None) -> DeclaredDependency:
    return DeclaredDependency(name=name, ecosystem=eco, spec=spec, kind=kind, scope=scope, extras=extras or [],
                              markers=markers, source_file=rel, line=line)


# --------------------------------------------------------------------------- Maven
def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def parse_pom(rel: str, text: str):
    from .manifests import ManifestParse
    root = ET.fromstring(text)
    _strip_ns(root)
    out = ManifestParse()
    props = {}
    for p in root.findall("./properties/*"):
        props[p.tag] = (p.text or "").strip()
    gid = root.findtext("groupId") or root.findtext("parent/groupId") or ""
    aid = root.findtext("artifactId") or ""
    ver = root.findtext("version") or root.findtext("parent/version") or ""
    props.update({"project.groupId": gid, "project.artifactId": aid, "project.version": ver, "pom.version": ver})

    def sub(v: str | None) -> str | None:
        if not v:
            return v
        for _ in range(5):
            nv = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
            if nv == v:
                break
            v = nv
        return v.strip()

    managed = {}
    for d in root.findall("./dependencyManagement/dependencies/dependency"):
        managed[f"{sub(d.findtext('groupId'))}:{sub(d.findtext('artifactId'))}"] = sub(d.findtext("version"))
    parent = root.find("parent")
    if parent is not None:
        out.notes = [f"parent POM {parent.findtext('groupId')}:{parent.findtext('artifactId')}:{parent.findtext('version')} "
                     "may manage versions not visible here"]
    for d in root.findall("./dependencies/dependency") + root.findall("./profiles/profile/dependencies/dependency"):
        g, a = sub(d.findtext("groupId")), sub(d.findtext("artifactId"))
        if not g or not a:
            continue
        name = f"{g}:{a}"
        v = sub(d.findtext("version")) or managed.get(name)
        scope = (d.findtext("scope") or "compile").strip()
        sc = {"test": "dev", "provided": "build", "system": "build", "import": "build"}.get(scope, "prod")
        if (d.findtext("optional") or "").strip() == "true":
            sc = "optional"
        kind = "path" if scope == "system" else "registry"
        out.deps.append(_dep("maven", name, v if v and "${" not in v else None, rel, find_line(text, f"<artifactId>{a}</artifactId>"),
                             sc, kind))
    for r in root.findall("./repositories/repository") + root.findall("./pluginRepositories/pluginRepository"):
        url = sub(r.findtext("url"))
        if url:
            out.indexes.append(PackageIndex(url=url, type="maven-repository", source_file=rel, line=find_line(text, url)))
    # build plugins run code at build time: record as lifecycle facts
    for p in root.findall("./build/plugins/plugin"):
        a = p.findtext("artifactId") or ""
        if a in ("exec-maven-plugin", "maven-antrun-plugin", "frontend-maven-plugin", "groovy-maven-plugin"):
            out.scripts.append(LifecycleScript(path=rel, name=a, command=f"build plugin {p.findtext('groupId')}:{a}",
                                               line=find_line(text, f"<artifactId>{a}</artifactId>"), ecosystem="maven"))
    out.manifest = Manifest(path=rel, ecosystem="maven", project_name=f"{gid}:{aid}" if aid else None,
                            dependency_count=len(out.deps))
    return out


# --------------------------------------------------------------------------- Gradle (static, best-effort)
GRADLE_CONF = {"implementation": "prod", "api": "prod", "compile": "prod", "runtimeOnly": "prod", "runtime": "prod",
               "compileOnly": "build", "annotationProcessor": "build", "kapt": "build", "classpath": "build",
               "testImplementation": "dev", "testCompile": "dev", "testRuntimeOnly": "dev", "testCompileOnly": "dev",
               "androidTestImplementation": "dev", "debugImplementation": "dev"}
_GRADLE_DEP = re.compile(r"""^\s*(\w+)\s*\(?\s*(?:platform\()?\s*['"]([\w.\-]+):([\w.\-]+)(?::([^'"@]+))?(?:@\w+)?['"]""")
_GRADLE_MAP = re.compile(r"""^\s*(\w+)\s*\(?\s*group\s*[:=]\s*['"]([^'"]+)['"]\s*,\s*name\s*[:=]\s*['"]([^'"]+)['"](?:\s*,\s*version\s*[:=]\s*['"]([^'"]+)['"])?""")


def parse_gradle(rel: str, text: str):
    from .manifests import ManifestParse
    out = ManifestParse()
    props = dict(re.findall(r"""(?:ext\.|val\s+|def\s+)?(\w+)\s*=\s*['"]([^'"$]+)['"]""", text))
    for i, line in enumerate(text.splitlines(), 1):
        m = _GRADLE_DEP.match(line) or _GRADLE_MAP.match(line)
        if m and m.group(1) in GRADLE_CONF:
            conf, g, a, v = m.groups()
            if v and "$" in v:
                key = re.sub(r"[${}]", "", v).split(".")[-1]
                v = props.get(key)
            out.deps.append(_dep("maven", f"{g}:{a}", v, rel, i, GRADLE_CONF[conf]))
        u = re.search(r"""maven\s*\{[^}]*url\s*[=(]?\s*(?:uri\()?['"]([^'"]+)['"]""", line) or \
            re.search(r"""^\s*url\s*[=(]?\s*(?:uri\()?['"](https?://[^'"]+)['"]""", line)
        if u:
            out.indexes.append(PackageIndex(url=u.group(1), type="maven-repository", source_file=rel, line=i))
    out.manifest = Manifest(path=rel, ecosystem="maven", dependency_count=len(out.deps))
    return out


# --------------------------------------------------------------------------- Go modules
def parse_go_mod(rel: str, text: str):
    from .manifests import ManifestParse
    out = ManifestParse()
    module = None
    in_block = None
    replaces = {}
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//")[0].strip()
        comment = raw.split("//", 1)[1].strip() if "//" in raw else ""
        if line.startswith("module "):
            module = line.split()[1].strip('"')
            continue
        if line.endswith("(") and line.split()[0] in ("require", "replace", "exclude", "retract"):
            in_block = line.split()[0]
            continue
        if line == ")":
            in_block = None
            continue
        kw, body = (in_block, line) if in_block else (line.split()[0] if line else "", " ".join(line.split()[1:]))
        if kw == "require" and body:
            parts = body.split()
            if len(parts) >= 2:
                out.deps.append(_dep("golang", parts[0].strip('"'), parts[1], rel, i,
                                     "prod", markers="indirect" if "indirect" in comment else None))
        elif kw == "replace" and "=>" in body:
            left, right = [x.strip().split() for x in body.split("=>", 1)]
            target = right[0]
            replaces[left[0]] = (target, right[1] if len(right) > 1 else None, i)
    for d in out.deps:
        if d.name in replaces:
            target, ver, line = replaces[d.name]
            d.kind = "path" if target.startswith((".", "/")) else "vcs"
            d.spec = f"{d.spec} => {target}" + (f" {ver}" if ver else "")
    out.manifest = Manifest(path=rel, ecosystem="golang", project_name=module, dependency_count=len(out.deps))
    return out


# --------------------------------------------------------------------------- Cargo
def parse_cargo_toml(rel: str, text: str):
    from .manifests import ManifestParse
    data = tomllib.loads(text)
    out = ManifestParse()

    def section(deps: dict, scope: str):
        for name, spec in (deps or {}).items():
            kind, sp, real = "registry", spec if isinstance(spec, str) else None, name
            if isinstance(spec, dict):
                real = spec.get("package", name)
                if "git" in spec:
                    kind, sp = "vcs", f"git+{spec['git']}" + (f"#{spec.get('rev') or spec.get('tag') or spec.get('branch')}"
                                                              if any(k in spec for k in ("rev", "tag", "branch")) else "")
                elif "path" in spec:
                    kind, sp = "path", spec["path"]
                else:
                    sp = spec.get("version")
                    if spec.get("registry"):
                        kind = "registry"
                        sp = f"{sp} (registry {spec['registry']})"
                if spec.get("workspace"):
                    sp = "workspace"
            out.deps.append(_dep("cargo", real, sp, rel, find_line(text, f"{name}"), scope, kind,
                                 extras=list(spec.get("features", [])) if isinstance(spec, dict) else []))

    section(data.get("dependencies"), "prod")
    section(data.get("dev-dependencies"), "dev")
    section(data.get("build-dependencies"), "build")
    for t in (data.get("target") or {}).values():
        section(t.get("dependencies"), "prod")
        section(t.get("dev-dependencies"), "dev")
    ws = (data.get("workspace") or {})
    section(ws.get("dependencies"), "prod")
    pkg = data.get("package") or {}
    if pkg.get("build"):
        out.scripts.append(LifecycleScript(path=rel, name="build.rs", command=f"build script {pkg['build']}",
                                           line=find_line(text, "build"), ecosystem="cargo"))
    out.manifest = Manifest(path=rel, ecosystem="cargo", project_name=pkg.get("name"), dependency_count=len(out.deps))
    return out


# --------------------------------------------------------------------------- Bundler
_GEM = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"]((?:\s*,\s*['"][^'"]+['"])*)(.*)$""")


def parse_gemfile(rel: str, text: str):
    from .manifests import ManifestParse
    out = ManifestParse()
    group_stack: list[str] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#")[0].rstrip()
        s = line.strip()
        g = re.match(r"^group\s+(.+?)\s+do\b", s)
        if g:
            group_stack.append(g.group(1))
            continue
        if re.match(r"^(source|platforms|git_source|path|install_if)\b.*\bdo\b", s):
            group_stack.append("block")
            continue
        if s == "end" and group_stack:
            group_stack.pop()
            continue
        m = re.match(r"""^source\s+['"]([^'"]+)['"]""", s)
        if m:
            out.indexes.append(PackageIndex(url=m.group(1), type="gem-source", source_file=rel, line=i))
            continue
        m = _GEM.match(line)
        if not m:
            continue
        name, vers, rest = m.groups()
        spec = ", ".join(v.strip().strip("'\"") for v in vers.split(",") if v.strip()) or None
        groups = " ".join(group_stack) + " " + (re.search(r"group[s]?:\s*\[?([^\]\n]+)", rest).group(1) if "group" in rest else "")
        scope = "dev" if re.search(r":(development|test)\b", groups) else "prod"
        kind = "vcs" if re.search(r"\b(git|github):", rest) else "path" if re.search(r"\bpath:", rest) else "registry"
        if kind != "registry":
            u = re.search(r"""(git|github|path):\s*['"]([^'"]+)['"]""", rest)
            spec = u.group(2) if u else spec
        out.deps.append(_dep("gem", name, spec, rel, i, scope, kind))
    out.manifest = Manifest(path=rel, ecosystem="gem", dependency_count=len(out.deps))
    return out


# --------------------------------------------------------------------------- Composer
def parse_composer_json(rel: str, text: str):
    from .manifests import ManifestParse
    data = json.loads(text)
    out = ManifestParse()
    for key, scope in (("require", "prod"), ("require-dev", "dev")):
        for name, spec in (data.get(key) or {}).items():
            if name == "php" or name.startswith(("ext-", "lib-")) or "/" not in name:
                continue
            kind = "vcs" if str(spec).startswith("dev-") else "registry"
            out.deps.append(_dep("composer", name, str(spec), rel, find_line(text, f'"{name}"'), scope, kind))
    for r in data.get("repositories") or []:
        if isinstance(r, dict) and r.get("url"):
            out.indexes.append(PackageIndex(url=r["url"], type=f"composer-{r.get('type', 'repository')}", source_file=rel,
                                            line=find_line(text, r["url"])))
    for name, cmd in (data.get("scripts") or {}).items():
        if name in ("pre-install-cmd", "post-install-cmd", "post-update-cmd", "pre-update-cmd", "post-autoload-dump",
                    "post-root-package-install", "post-create-project-cmd"):
            out.scripts.append(LifecycleScript(path=rel, name=name, command=json.dumps(cmd)[:300],
                                               line=find_line(text, f'"{name}"'), ecosystem="composer"))
    out.manifest = Manifest(path=rel, ecosystem="composer", project_name=data.get("name"), dependency_count=len(out.deps))
    out.namespaces = {ns: data.get("name") or "<root>" for ns in ((data.get("autoload") or {}).get("psr-4") or {})}
    return out


# --------------------------------------------------------------------------- NuGet
def parse_dotnet_project(rel: str, text: str):
    from .manifests import ManifestParse
    root = ET.fromstring(text)
    _strip_ns(root)
    out = ManifestParse()
    tags = ("PackageReference", "PackageVersion", "package")
    for el in root.iter():
        if el.tag not in tags:
            continue
        name = el.get("Include") or el.get("Update") or el.get("id")
        ver = el.get("Version") or el.get("version") or el.findtext("Version")
        if not name:
            continue
        dev = (el.get("PrivateAssets") or el.findtext("PrivateAssets") or "").lower() == "all" or \
            el.get("developmentDependency") == "true"
        out.deps.append(_dep("nuget", name, ver, rel, find_line(text, f'"{name}"'), "dev" if dev else "prod"))
    for t in root.iter("Exec"):
        out.scripts.append(LifecycleScript(path=rel, name="Exec", command=(t.get("Command") or "")[:300],
                                           line=find_line(text, "<Exec"), ecosystem="nuget"))
    name = PurePosixPath(rel).stem
    out.manifest = Manifest(path=rel, ecosystem="nuget", project_name=name, dependency_count=len(out.deps))
    return out


def parse_nuget_config(rel: str, text: str) -> list[PackageIndex]:
    root = ET.fromstring(text)
    _strip_ns(root)
    return [PackageIndex(url=a.get("value", ""), type="nuget-source", source_file=rel, line=find_line(text, a.get("value", "")))
            for a in root.findall("./packageSources/add") if a.get("value")]


def parse_poly_manifest(rel: str, text: str):
    name = PurePosixPath(rel).name
    if name == "pom.xml":
        return parse_pom(rel, text)
    if name in ("build.gradle", "build.gradle.kts"):
        return parse_gradle(rel, text)
    if name == "go.mod":
        return parse_go_mod(rel, text)
    if name == "Cargo.toml":
        return parse_cargo_toml(rel, text)
    if name == "Gemfile":
        return parse_gemfile(rel, text)
    if name == "composer.json":
        return parse_composer_json(rel, text)
    return parse_dotnet_project(rel, text)
