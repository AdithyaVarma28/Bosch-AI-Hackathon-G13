"""Walk a repository and build the Stage 2 code index. Never executes repo code."""
import ast
import hashlib
import os
import warnings
from pathlib import Path

from guardian.models.code_index import CodeIndex, FileIndex
from guardian.stage2_code.dist_map import build_import_map, map_import
from guardian.stage2_code.import_resolver import ModuleMap
from guardian.stage2_code.pattern_visitor import PatternCollector
from guardian.stage2_code.visitors import DefinitionCollector, ImportCollector

PARSE_COUNT = 0  # number of files actually parsed (tests use it to prove caching works)
CACHE_VERSION = "2"  # bump when the analyzer or the FileIndex schema changes
MAX_BYTES = 1_000_000
SKIP_DIRS = {".venv", "venv", "env", ".env", "build", "dist", "site-packages", ".git", "__pycache__",
             "node_modules", ".tox", ".mypy_cache", ".pytest_cache", ".eggs"}


def _skipped(dirname: str) -> bool:
    return dirname in SKIP_DIRS or dirname.endswith(".egg-info")


_isjunction = getattr(os.path, "isjunction", lambda p: False)


def _is_link(path: str) -> bool:
    return os.path.islink(path) or _isjunction(path)


def iter_py_files(repo: Path) -> list[str]:
    """Python files inside the repo. Symlinks and junctions are never followed (no escaping, no loops)."""
    found: list[str] = []
    stack = [Path(repo)]
    while stack:
        try:
            entries = list(os.scandir(stack.pop()))
        except OSError:  # unreadable directory: skip it, keep scanning
            continue
        for e in entries:
            if e.is_symlink() or getattr(e, "is_junction", lambda: False)():
                continue  # never follow links: no escaping the repo, no loops
            if e.is_dir(follow_symlinks=False):
                if not _skipped(e.name):
                    stack.append(Path(e.path))
            elif e.name.endswith(".py") and e.is_file(follow_symlinks=False):
                found.append(Path(e.path).relative_to(repo).as_posix())
    return sorted(found)


def detect_source_roots(repo: Path) -> list[str]:
    src = repo / "src"
    if src.is_dir() and any(p for p in src.rglob("*.py")
                            if not any(_skipped(x) for x in p.relative_to(repo).parts)):
        return ["src"]
    roots = [d.name for d in sorted(repo.iterdir())
             if d.is_dir() and not d.name.startswith(".") and not _skipped(d.name)
             and (d / "__init__.py").exists()]
    return roots


def module_path_for(rel: str, base: str) -> str:
    p = rel
    if base and p.startswith(base + "/"):
        p = p[len(base) + 1:]
    p = p[:-3]  # drop .py
    parts = p.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _is_test(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    return (name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"
            or any(d in ("tests", "test") for d in parts[:-1]))


def index_repo(repo: Path, cache_dir: Path | None = None, resolved=None) -> CodeIndex:
    global PARSE_COUNT
    repo = Path(repo)
    roots = detect_source_roots(repo)
    base = "src" if roots == ["src"] else ""
    rels = iter_py_files(repo)
    module_to_file = {module_path_for(r, base): r for r in rels if module_path_for(r, base)}
    mmap = ModuleMap(module_to_file, rels)
    listing = "\n".join(f"{k}={v}" for k, v in sorted(module_to_file.items())) + "|" + base
    fingerprint = hashlib.sha256(listing.encode()).hexdigest()[:12]
    if cache_dir:
        Path(cache_dir).mkdir(parents=True, exist_ok=True)

    files: list[FileIndex] = []
    errors: list[str] = []
    for rel in rels:
        try:
            data = (repo / rel).read_bytes()
        except OSError as e:
            fi = FileIndex(path=rel, module_path=module_path_for(rel, base),
                           package_dir=rel.rsplit("/", 1)[0] if "/" in rel else "",
                           sha256=hashlib.sha256(b"").hexdigest(), loc=0, is_test=_is_test(rel),
                           parse_error=f"unreadable: {type(e).__name__}: {e}")
            files.append(fi)
            errors.append(f"{rel}: {fi.parse_error}")
            continue
        sha = hashlib.sha256(data).hexdigest()
        cache_file = None
        if cache_dir:
            key = hashlib.sha256(f"{CACHE_VERSION}\0{rel}\0{sha}\0{fingerprint}".encode()).hexdigest()
            cache_file = Path(cache_dir) / f"{key}.json"
            fi = _read_cache(cache_file)
            if fi is not None:
                files.append(fi)
                if fi.parse_error:
                    errors.append(f"{rel}: {fi.parse_error}")
                continue
        fi = _index_file(rel, data, sha, base, mmap)
        PARSE_COUNT += 0 if fi.parse_error == "skipped: file too large" else 1
        if cache_file:
            _write_cache(cache_file, fi)
        files.append(fi)
        if fi.parse_error:
            errors.append(f"{rel}: {fi.parse_error}")
    imap = build_import_map(resolved or [])
    mapping: dict[str, str] = {}
    for f in files:
        for imp in f.imports:
            if imp.kind == "external":
                top = imp.name.split(".")[0]
                dist = map_import(top, imap)
                if dist:
                    imp.distribution = dist
                    mapping[top] = dist
    return CodeIndex(source_roots=roots, import_name_to_distribution=mapping, files=files, errors=errors)


def _read_cache(path: Path) -> FileIndex | None:
    """A missing or corrupted cache entry is a miss, never a failure."""
    try:
        return FileIndex.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # pydantic.ValidationError is a ValueError
        return None


def _write_cache(path: Path, fi: FileIndex) -> None:
    """Atomic write so an interrupted run cannot leave a half-written entry."""
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(fi.model_dump_json(), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


def _index_file(rel: str, data: bytes, sha: str, base: str, mmap: ModuleMap) -> FileIndex:
    module_path = module_path_for(rel, base)
    package_dir = rel.rsplit("/", 1)[0] if "/" in rel else ""
    common = dict(path=rel, module_path=module_path, package_dir=package_dir,
                  sha256=sha, loc=len(data.splitlines()), is_test=_is_test(rel))
    if len(data) > MAX_BYTES:
        return FileIndex(**common, parse_error="skipped: file too large")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # invalid-escape SyntaxWarnings are noise, not findings
            tree = ast.parse(data, filename=rel)
    except SyntaxError as e:
        return FileIndex(**common, parse_error=f"SyntaxError: {e.msg} (line {e.lineno})")
    except (ValueError, RecursionError, MemoryError) as e:
        return FileIndex(**common, parse_error=f"{type(e).__name__}: {e}")
    is_pkg = rel.endswith("/__init__.py") or rel == "__init__.py"
    try:
        imports = ImportCollector(module_path, is_pkg, mmap, package_dir)
        imports.visit(tree)
        defs = DefinitionCollector(rel)
        defs.visit(tree)
        pats = PatternCollector(rel, module_path, is_pkg, mmap, tree, package_dir)
        pats.visit(tree)
    except RecursionError as e:  # e.g. a 700-term generated expression: record it, keep scanning
        return FileIndex(**common, parse_error=f"RecursionError: {e}")
    except Exception as e:  # one odd file must never kill the whole scan
        return FileIndex(**common, parse_error=f"analysis failed: {type(e).__name__}: {e}")
    return FileIndex(**common, docstring=ast.get_docstring(tree), imports=imports.imports,
                     definitions=defs.definitions, calls=pats.calls, routes=pats.routes,
                     cli_entrypoints=pats.cli, env_reads=pats.env, sensitive_calls=pats.sensitive,
                     string_urls=pats.urls, dynamic_imports=pats.dynamic)
