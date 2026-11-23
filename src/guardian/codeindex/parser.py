"""S3 Code index: walk source files, run visitors (sha256-cached), then resolve imports/calls repo-wide."""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path, PurePosixPath

from ..context import RunContext
from ..fsutil import read_text, rel, sha256_bytes, walk_files
from ..models import CodeCoverage, CodeFile, CodeIndex, ExternalService
from ..purl import normalize_pypi
from . import patterns as P
from .dist_map import build_dist_map
from .js_imports import JS_EXT, index_js
from .polyglot import EXT_LANG, PackageMapper, declared_namespaces, index_polyglot, sdk_services_for
from .visitors import FileVisitor

INDEX_VERSION = "4"


def index_polyglot_extras_js(cf: CodeFile, text: str) -> None:
    """Routes, env reads and extra sinks for JS/TS (imports come from js_imports)."""
    imports = list(cf.imports)
    urls = list(cf.string_urls)
    index_polyglot(cf, text, "javascript")
    cf.imports = imports
    cf.string_urls = urls
    cf.discovered_by = "regex"  # bump whenever the visitor output changes (invalidates the sha256 cache)
MAX_FILES = 5000
STDLIB = set(sys.stdlib_module_names) | {"__future__"}


def _module_path(path: str, roots: list[str]) -> tuple[str, bool]:
    """Module path relative to the deepest source root containing the file ('.' = repo root)."""
    parts = list(PurePosixPath(path).with_suffix("").parts)
    for r in sorted((r for r in roots if r not in ("", ".")), key=lambda x: len(PurePosixPath(x).parts), reverse=True):
        rp = PurePosixPath(r).parts
        if tuple(parts[: len(rp)]) == rp and len(parts) > len(rp):
            parts = parts[len(rp):]
            break
    is_pkg = parts[-1] == "__init__"
    if is_pkg and len(parts) > 1:
        parts = parts[:-1]
    return ".".join(parts), is_pkg


def detect_source_roots(root: Path, py_files: list[str]) -> list[str]:
    """A source root is the parent of a top-most package (dir with __init__.py whose parent has none),
    plus `src/` layouts and the repo root for flat modules. Handles `backend/app/...` monorepo layouts."""
    pkg_dirs = {str(PurePosixPath(f).parent) for f in py_files if f.endswith("__init__.py")}
    roots = set()
    for d in pkg_dirs:
        parent = str(PurePosixPath(d).parent)
        if parent not in pkg_dirs:
            roots.add(parent if parent != "" else ".")
    if (root / "src").is_dir() and any(f.startswith("src/") for f in py_files):
        roots.add("src")
    if any("/" not in f for f in py_files):
        roots.add(".")
    return sorted(roots)


def _visit_python(cf: CodeFile, text: str, module: str, is_pkg: bool) -> None:
    try:
        tree = ast.parse(text, filename=cf.path)
    except (SyntaxError, ValueError) as e:
        cf.parse_error = f"{type(e).__name__}: {e}"
        return
    v = FileVisitor(cf, module, is_pkg)
    v.visit(tree)


def build_code_index(ctx: RunContext) -> CodeIndex:
    root = ctx.root
    idx = CodeIndex()
    cache_dir = Path(ctx.settings.cache_dir) / "codeindex"
    cache_dir.mkdir(parents=True, exist_ok=True)
    files: list[tuple[str, str]] = []
    for p in walk_files(root):
        r = rel(root, p)
        suf = p.suffix.lower()
        if suf == ".py":
            files.append((r, "python"))
        elif suf in JS_EXT and not r.endswith((".min.js", ".d.ts")) and "/static/" not in f"/{r}":
            files.append((r, "javascript"))
        elif suf in EXT_LANG:
            files.append((r, EXT_LANG[suf]))
    if len(files) > MAX_FILES:
        idx.errors.append(f"file cap reached ({MAX_FILES}); remaining source files skipped")
        files = files[:MAX_FILES]
    py_files = [f for f, l in files if l == "python"]
    idx.source_roots = detect_source_roots(root, py_files)
    cov = CodeCoverage(files_total=len(files))
    for _, l in files:
        cov.languages[l] = cov.languages.get(l, 0) + 1

    for r, lang in files:
        try:
            data = (root / r).read_bytes()
        except OSError as e:
            idx.errors.append(f"{r}: {e}")
            cov.files_failed += 1
            continue
        if len(data) > 2_000_000:
            idx.errors.append(f"{r}: skipped (> 2 MB)")
            continue
        digest = sha256_bytes(data)
        cpath = cache_dir / f"{INDEX_VERSION}-{digest[:24]}-{normalize_pypi(r)[:80].replace('/', '_')}.json"
        if cpath.exists():
            try:
                cf = CodeFile.model_validate_json(cpath.read_text(encoding="utf-8"))
                cov.files_cached += 1
                idx.files.append(cf)
                if cf.parse_error:
                    cov.files_failed += 1
                else:
                    cov.files_parsed += 1
                continue
            except Exception:
                pass
        text = data.decode("utf-8", errors="replace")
        module, is_pkg = _module_path(r, idx.source_roots) if lang == "python" else (None, False)
        cf = CodeFile(path=r, language=lang, module_path=module, package_dir=str(PurePosixPath(r).parent),
                      sha256=digest, loc=text.count("\n") + 1, is_test=P.is_test_path(r))
        try:
            if lang == "python":
                _visit_python(cf, text, module or "", is_pkg)
            elif lang == "javascript":
                index_js(cf, text)
                index_polyglot_extras_js(cf, text)
            else:
                index_polyglot(cf, text, lang)
                ns = declared_namespaces(cf, text, lang)
                cf.module_path = sorted(ns)[0] if ns else None   # package / namespace declared by the file
        except Exception as e:  # fail soft
            cf.parse_error = f"{type(e).__name__}: {e}"
        if cf.parse_error:
            cov.files_failed += 1
            idx.errors.append(f"{r}: {cf.parse_error}")
        else:
            cov.files_parsed += 1
        cpath.write_text(cf.model_dump_json(), encoding="utf-8")
        idx.files.append(cf)

    _resolve(idx, ctx, cov)
    idx.coverage = cov
    return idx


def _resolve(idx: CodeIndex, ctx: RunContext, cov: CodeCoverage) -> None:
    modules: dict[str, str] = {cf.module_path: cf.path for cf in idx.files if cf.language == "python" and cf.module_path}
    defs: dict[str, set[str]] = {}
    for cf in idx.files:
        defs[cf.path] = {d.id.split("::", 1)[1] for d in cf.definitions}

    def to_internal(dotted_name: str) -> tuple[str | None, str | None]:
        """'app.payments.service.charge' -> ('app/payments/service.py', 'charge')."""
        parts = dotted_name.split(".")
        for i in range(len(parts), 0, -1):
            mod = ".".join(parts[:i])
            if mod in modules:
                return modules[mod], ".".join(parts[i:]) or None
        return None, None

    declared_py = [d.name for d in (ctx.facts.declared_dependencies if ctx.facts else []) if d.ecosystem == "pypi"]
    external_tops: set[str] = set()
    for cf in idx.files:
        if cf.language != "python":
            continue
        for imp in cf.imports:
            top = imp.name.split(".")[0]
            f, _ = to_internal(imp.name)
            if f:
                imp.kind, imp.resolved_file = "internal", f
            elif top in STDLIB:
                imp.kind = "stdlib"
            elif top:
                imp.kind = "external"
                external_tops.add(imp.name)
    idx.import_name_to_distribution = build_dist_map(declared_py, external_tops)
    for cf in idx.files:
        if cf.language != "python":
            continue
        for imp in cf.imports:
            if imp.kind == "external":
                imp.distribution = idx.import_name_to_distribution.get(imp.name.split(".")[0])
        import_kinds = {i.name.split(".")[0]: i.kind for i in cf.imports}
        for c in cf.calls:
            top = c.target.split(".")[0]
            f, qual = to_internal(c.target)
            if f is not None:
                c.kind = "internal"
                q = qual
                # walk down: 'Class.method.x' -> longest existing definition
                while q and q not in defs.get(f, set()):
                    q = q.rpartition(".")[0]
                if q:
                    c.resolved_target = f"{f}::{q}"
                    cov.internal_calls_resolved += 1
                elif qual is None and f:
                    c.resolved_target = None
                    cov.internal_calls_unresolved += 1
                else:
                    cov.internal_calls_unresolved += 1
            elif c.kind == "builtin":
                pass
            elif top in STDLIB:
                c.kind = "stdlib"
            elif import_kinds.get(top) == "external" or top in idx.import_name_to_distribution:
                c.kind = "external"
                c.import_name = top
        # external services: SDK imports + domains contacted by network calls
        seen = set()
        for imp in cf.imports:
            if imp.kind == "external":
                svc = P.sdk_service(imp.name)
                if svc and svc not in seen:
                    seen.add(svc)
                    cf.external_services.append(ExternalService(name=svc, via="sdk", import_name=imp.name.split(".")[0],
                                                                line=imp.line))
        net_funcs = {s.function for s in cf.sensitive_calls if s.category == "network"}
        for u in cf.string_urls:
            if u.function in net_funcs and u.detail and u.detail not in seen:
                seen.add(u.detail)
                cf.external_services.append(ExternalService(name=u.detail, via="url", domain=u.detail, line=u.line))
        cov.dynamic_imports += len(cf.dynamic_imports)
    for cf in idx.files:
        if cf.language != "python":
            cov.dynamic_imports += len(cf.dynamic_imports)


def link_polyglot_imports(ctx: RunContext) -> None:
    """Map non-Python imports to packages. Runs AFTER the SBOM stage (needs resolved packages and lockfile
    namespace hints such as Composer autoload), so the orchestrator calls it from the graph node."""
    if ctx.code_index:
        _resolve_polyglot(ctx.code_index, ctx, ctx.code_index.coverage)


def _resolve_polyglot(idx: CodeIndex, ctx: RunContext, cov: CodeCoverage) -> None:
    """Map non-Python imports to packages of the matching ecosystem; mark internal/stdlib."""
    cov.external_imports_unmapped = 0
    from ..purl import LANGUAGE_ECOSYSTEM
    packages: dict[str, set[str]] = {}
    for c in ctx.components:
        packages.setdefault(c.ecosystem, set()).add(c.name)
    for d in (ctx.facts.declared_dependencies if ctx.facts else []):
        packages.setdefault(d.ecosystem, set()).add(d.name)
    own: dict[str, set[str]] = {}
    for cf in idx.files:
        if cf.language not in ("python", "javascript") and cf.module_path:
            key = {"kotlin": "java", "scala": "java"}.get(cf.language, cf.language)
            own.setdefault(key, set()).add(cf.module_path)
    for m in (ctx.facts.manifests if ctx.facts else []):
        if m.ecosystem == "golang" and m.project_name:
            own.setdefault("go", set()).add(m.project_name)
        if m.ecosystem == "cargo" and m.project_name:
            own.setdefault("rust", set()).add(m.project_name.replace("-", "_"))
    mapper = PackageMapper(packages, ctx.import_hints, own)
    for cf in idx.files:
        if cf.language == "python":
            continue
        if cf.language == "javascript":
            for imp in cf.imports:
                if imp.kind == "external" and imp.distribution and imp.distribution not in packages.get("npm", set()):
                    pass  # npm package names come straight from the specifier; undeclared ones surface as discrepancies
        else:
            for imp in cf.imports:
                if imp.kind == "internal":
                    continue
                kind, pkg, status = mapper.map(cf.language, imp.name)
                imp.kind, imp.distribution = kind, pkg  # type: ignore[assignment]
                if kind in ("external", "unknown") and status == "unmapped":
                    cov.external_imports_unmapped += 1
        sdk_services_for(cf)
        _ = LANGUAGE_ECOSYSTEM


def code_index_json(idx: CodeIndex) -> str:
    return json.dumps(idx.model_dump(mode="json"), indent=2)
