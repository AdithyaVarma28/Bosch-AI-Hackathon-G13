"""S1 Facts (Cartographer): one walk over the repo, every fact with evidence. Never judges."""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path, PurePosixPath

from ..context import RunContext
from ..fsutil import find_line, line_excerpt, read_text, rel, walk_files
from ..models import DocsInventory, EnvFile, LockfileHealth, RepoFacts
from ..runner import ToolFailed, git
from ..sbom.lockfiles import is_lockfile, parse_lockfile
from ..purl import normalize_name
from .ci import OTHER_CI, parse_workflow
from .docker import parse_compose, parse_dockerfile
from .history import dependency_history
from .manifests import is_manifest, parse_manifest, parse_npmrc

MANIFEST_CAP = 200
LANG_EXT = {".py": "Python", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".ts": "TypeScript", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".fs": "F#", ".vb": "VB.NET", ".swift": "Swift", ".c": "C", ".cpp": "C++", ".h": "C/C++",
            ".tsx": "TypeScript", ".jsx": "JavaScript", ".java": "Java", ".go": "Go", ".rb": "Ruby", ".rs": "Rust",
            ".php": "PHP", ".cs": "C#", ".html": "HTML", ".css": "CSS", ".sh": "Shell", ".yml": "YAML", ".yaml": "YAML"}
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
PY_LOCKS = ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock")
LOCKS = {"npm": NPM_LOCKS, "pypi": PY_LOCKS, "maven": ("gradle.lockfile",), "golang": ("go.sum",), "cargo": ("Cargo.lock",),
         "gem": ("Gemfile.lock",), "composer": ("composer.lock",), "nuget": ("packages.lock.json",)}
CONFIG_RE = re.compile(r"(^|/)(settings\.py|alembic\.ini|config/[^/]+\.(ya?ml|toml|ini|json)|conf/[^/]+\.(ya?ml|toml|ini|json)|"
                       r"app\.config\.(js|json)|config\.(ya?ml|toml|ini|json|js))$")


def _tracked_files(root: Path, ctx: RunContext) -> set[str] | None:
    if not (root / ".git").exists():
        return None
    try:
        return set(git(root, "ls-files", runner=ctx.runner).splitlines())
    except ToolFailed:
        return None


def build_repo_facts(ctx: RunContext) -> RepoFacts:
    root, store = ctx.root, ctx.store
    facts = RepoFacts()
    tracked = _tracked_files(root, ctx)
    langs: Counter = Counter()
    manifest_paths: list[str] = []
    lockfile_paths: list[str] = []
    npmrc: dict[str, tuple] = {}   # dir -> (indexes, ignored_by)
    texts: dict[str, str] = {}

    for p in walk_files(root):
        r = rel(root, p)
        name = p.name
        ext = p.suffix.lower()
        if ext in LANG_EXT:
            langs[LANG_EXT[ext]] += 1
        try:
            if is_manifest(name):
                if len(manifest_paths) >= MANIFEST_CAP:
                    if not any("manifest cap" in e for e in facts.errors):
                        facts.errors.append(f"manifest cap reached ({MANIFEST_CAP}); remaining manifests skipped")
                    continue
                t = read_text(p)
                if t is not None:
                    texts[r] = t
                    manifest_paths.append(r)
            elif is_lockfile(name):
                lockfile_paths.append(r)
            elif name.lower() == "nuget.config":
                from .manifests_poly import parse_nuget_config
                facts.package_indexes.extend(parse_nuget_config(r, read_text(p) or ""))
            elif r.endswith(".cargo/config.toml") or r.endswith(".cargo/config"):
                import tomllib
                cfg = tomllib.loads(read_text(p) or "")
                from ..models import PackageIndex
                for nm, reg in (cfg.get("registries") or {}).items():
                    if isinstance(reg, dict) and reg.get("index"):
                        facts.package_indexes.append(PackageIndex(url=reg["index"], type=f"cargo-registry({nm})", source_file=r))
                for nm, src in (cfg.get("source") or {}).items():
                    if isinstance(src, dict) and (src.get("registry") or src.get("replace-with")):
                        facts.package_indexes.append(PackageIndex(url=str(src.get("registry") or src.get("replace-with")),
                                                                  type=f"cargo-source-replacement({nm})", source_file=r))
            elif name == ".npmrc":
                t = read_text(p) or ""
                idx, ign = parse_npmrc(r, t)
                npmrc[str(PurePosixPath(r).parent)] = (idx, ign)
                facts.package_indexes.extend(idx)
            elif name.lower().startswith("dockerfile") or name.endswith(".dockerfile") or name == "Containerfile":
                t = read_text(p) or ""
                df = parse_dockerfile(r, t)
                df.evidence_id = store.add_evidence("raw", "dockerfile", f"{r}:1-{len(t.splitlines())}", t).id
                facts.dockerfiles.append(df)
            elif r.startswith(".github/workflows/") and ext in (".yml", ".yaml"):
                t = read_text(p) or ""
                wf = parse_workflow(r, t)
                wf.evidence_id = store.add_evidence("raw", "workflow", f"{r}:1-{len(t.splitlines())}", t).id
                facts.ci_workflows.append(wf)
            elif r in OTHER_CI or name in ("Jenkinsfile",):
                facts.other_ci_files.append(r)
            elif re.match(r"^(docker-)?compose(\.[\w-]+)?\.ya?ml$", name):
                facts.config.compose_services.extend(parse_compose(r, read_text(p) or ""))
            elif name.startswith(".env"):
                t = read_text(p) or ""
                names = sorted({m.group(1) for m in re.finditer(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", t, re.M)})
                facts.config.env_files.append(EnvFile(file=r, var_names=names))  # names only, never values
            elif CONFIG_RE.search(r):
                facts.config.config_files.append(r)
        except Exception as e:  # fail soft
            facts.errors.append(f"{r}: {type(e).__name__}: {e}")
        if p.is_dir():
            continue

    # migration folders
    for d in list(root.glob("**/alembic/versions")) + list(root.glob("**/migrations")):
        if d.is_dir() and not any(s in d.parts for s in ("node_modules", ".venv", "venv", "site-packages")):
            facts.config.migration_dirs.append(rel(root, d))

    # manifests (+ -r includes)
    seen = set()
    queue = list(manifest_paths)
    while queue:
        r = queue.pop(0)
        if r in seen:
            continue
        seen.add(r)
        text = texts.get(r) or read_text(root / r)
        if text is None:
            facts.errors.append(f"{r}: included file not found")
            continue
        mp = parse_manifest(r, text)
        facts.errors.extend(mp.errors)
        facts.errors.extend(f"note: {r}: {n}" for n in mp.notes)
        if mp.namespaces and mp.manifest:
            ctx.import_hints.setdefault(mp.manifest.ecosystem + ":own", {}).update(mp.namespaces)
        for kind, inc in mp.includes:
            if kind == "-r" and inc not in seen:
                queue.append(inc)
        if mp.manifest:
            facts.manifests.append(mp.manifest)
        for d in mp.deps:
            d.evidence_id = store.add_evidence("raw", "manifest", f"{d.source_file}:{d.line or 1}",
                                               line_excerpt(text, d.line) or d.name).id
            facts.declared_dependencies.append(d)
        for ix in mp.indexes:
            ix.evidence_id = store.add_evidence("raw", "manifest", f"{ix.source_file}:{ix.line or 1}",
                                                line_excerpt(text, ix.line) or ix.url).id
            facts.package_indexes.append(ix)
        for s in mp.scripts:
            s.evidence_id = store.add_evidence("raw", "manifest", f"{s.path}:{s.line or 1}",
                                               line_excerpt(text, s.line) or s.command).id
            facts.lifecycle_scripts.append(s)

    facts.ecosystems = sorted({m.ecosystem for m in facts.manifests})  # type: ignore[assignment]
    facts.languages = dict(langs.most_common())

    # lockfile health per manifest directory
    facts.lockfiles = _lockfile_health(ctx, facts, lockfile_paths, npmrc, tracked, texts)

    # docs
    facts.docs = _docs(root)

    # history
    if ctx.repo.history_available or (root / ".git").exists():
        hist, errs = dependency_history(root, ctx.settings.history_depth, ctx.runner)
        facts.dependency_history = hist
        facts.errors.extend(errs)
    return facts


def _lockfile_health(ctx, facts: RepoFacts, lockfile_paths, npmrc, tracked, texts) -> list[LockfileHealth]:
    out = []
    store, root = ctx.store, ctx.root
    by_dir: dict[str, list[str]] = {}
    for lp in lockfile_paths:
        by_dir.setdefault(str(PurePosixPath(lp).parent), []).append(lp)
    done_dirs: set[tuple[str, str]] = set()
    for m in facts.manifests:
        d = str(PurePosixPath(m.path).parent)
        if (d, m.ecosystem) in done_dirs and not PurePosixPath(m.path).name.startswith("requirements"):
            continue
        done_dirs.add((d, m.ecosystem))
        names = LOCKS.get(m.ecosystem, ())
        lock = None
        cur = PurePosixPath(d)
        while lock is None:  # same directory first, then workspace roots above it
            lock = next((lp for lp in by_dir.get(str(cur), []) if PurePosixPath(lp).name in names), None)
            if str(cur) in (".", ""):
                break
            cur = cur.parent
        h = LockfileHealth(manifest=m.path, ecosystem=m.ecosystem)
        if m.ecosystem == "npm":
            ign = (npmrc.get(d) or npmrc.get(".") or ([], None))[1]
            h.ignored_by = ign
        if lock is None and m.ecosystem == "pypi" and PurePosixPath(m.path).name.startswith("requirements"):
            # A fully pinned requirements file acts as its own lock.
            deps = [x for x in facts.declared_dependencies if x.source_file == m.path and x.kind == "registry"]
            if deps and all((x.spec or "").startswith("==") for x in deps):
                lock = m.path
        if lock is None and m.ecosystem == "golang":
            lock = m.path  # go.mod lists the full build list (Go >= 1.17) even without go.sum
        if lock:
            text = read_text(root / lock) or ""
            from ..sbom.lockfiles_poly import parse_lock_in_repo
            parsed = parse_lock_in_repo(root, m.path, lock)
            h.lockfile, h.present = lock, True
            h.committed = tracked is None or lock in tracked
            h.version, h.has_integrity = parsed.version, parsed.has_integrity
            lock_names = {normalize_name(m.ecosystem, c.name) for c in parsed.components}
            declared = {normalize_name(m.ecosystem, x.name) for x in facts.declared_dependencies
                        if x.source_file == m.path and x.kind == "registry"}
            h.in_sync = declared <= lock_names if declared else None
            h.resolution = "committed" if h.committed else "resolved_not_committed"
            if parsed.errors and not parsed.components:
                facts.errors.extend(parsed.errors)
            head = "\n".join(text.splitlines()[:12])
            h.evidence_id = store.add_evidence("raw", "lockfile", f"{lock}:1-12", f"{lock} (lock data for {m.path})\n{head}").id
        else:
            excerpt = f"no lockfile next to {m.path}" + (f"; lockfile disabled by {h.ignored_by}" if h.ignored_by else "")
            h.evidence_id = store.add_evidence("derived", "cartographer", f"{m.path}", excerpt).id
        out.append(h)
    return out


def _docs(root: Path) -> DocsInventory:
    inv = DocsInventory()
    for cand in sorted(root.glob("README*")):
        if cand.is_file():
            inv.readme = cand.name
            inv.readme_excerpt = (read_text(cand) or "")[:2000]
            break
    docs_dir = root / "docs"
    if docs_dir.is_dir():
        inv.doc_files = sorted(rel(root, p) for p in docs_dir.rglob("*") if p.suffix.lower() in (".md", ".rst", ".txt"))[:100]
    return inv
