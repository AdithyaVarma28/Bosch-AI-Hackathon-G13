# Software Supply Chain Guardian — Stage 1 & 2 Build Plan

> **Scope of this doc:** what to build *now* (Stage 1: fact collection, Stage 2: code indexing), the stack, the output formats, and who does what.
> Stage 3 (knowledge building, AI agents) and the UI come next and **depend on the output formats defined here**, so please follow them exactly.

---

## 1. What we are building (big picture)

An agentic system that takes any **Python repo** and builds a **Security Context Graph**: a clickable, minimal map of the repo showing its modules, the packages each module uses, where each package comes from, what changed over time, and how far damage from any package could spread.

```
Repo ──► Stage 1: Collect facts ──► Stage 2: Index code ──► Stage 3: Build knowledge ──► Graph + UI ──► Risk detection
          (deterministic)            (deterministic)          (algorithms + AI agent)
          ◄──────────── YOU ARE HERE ────────────►
```

Day 1 judging checkpoint: **"Show us what is in the application, what changed, and what appears risky."**
Stage 1 + 2 must give us the raw material for *"what is in it"* and *"what changed"*.

---

## 2. Ground rules (read before coding)

1. **Python repos only.** Don't add other ecosystems.
2. **Never execute the target repo's code.** `ast` parses without running anything. Dependency resolution runs **inside a throwaway Docker container** (installing packages can run `setup.py` from strangers).
3. **Record facts, never judge.** Stage 1–2 say *"Action is pinned to a tag, not a SHA"*, not *"this is risky"*. Judging happens later.
4. **Every fact carries evidence:** file path + line number (and commit hash where relevant). The UI will show *"why do we think this?"*
5. **Stable IDs everywhere:**
   - Package → **purl**, e.g. `pkg:pypi/pyyaml@6.0.1` (same format as CycloneDX SBOM and the OSV vulnerability database)
   - File → repo-relative path, e.g. `app/payments/client.py`
   - Function/class → `path::qualname`, e.g. `app/payments/client.py::get_client`
6. **Fail soft.** One broken file or network error must not crash the scan. Add it to `errors[]` and continue.
7. **Hash every file (sha256)** so re-scans only redo changed files.

---

## 3. Stack

| Purpose | Tool | Notes |
|---|---|---|
| Language | Python 3.11+ | `tomllib` built in; `sys.stdlib_module_names` needs 3.10+ |
| CLI | Typer + Rich | `guardian scan <path-or-git-url>` |
| Data contracts | Pydantic v2 | All outputs are Pydantic models → JSON |
| SBOM | **Syft** (CycloneDX JSON) | Alt: `cyclonedx-py environment` on the resolved venv |
| Manifest parsing | `packaging`, `tomllib` | requirements*.txt, pyproject.toml, setup.cfg, Pipfile.lock, poetry.lock, uv.lock |
| Transitive resolution | `pip install --dry-run --ignore-installed --report` or venv + `pipdeptree --json-tree` | Run in Docker. Prefer `--only-binary=:all:` to avoid running build scripts |
| Package metadata | PyPI JSON API (`https://pypi.org/pypi/<name>/<version>/json`) via `httpx` | Release dates, maintainers, project URLs, yanked, hashes |
| CI/CD parsing | PyYAML (`safe_load`) | `.github/workflows/*.yml` |
| Dockerfile parsing | `dockerfile-parse` | FROM, RUN pip install, ADD/COPY from URLs |
| Git history | GitPython (or `git` subprocess) | Needed for **time travel** |
| Code parsing | Python stdlib `ast` | No tree-sitter needed for Python |
| Tests | pytest | Against our own fixture repo (section 8) |
| Storage (for now) | JSON files in `output/<repo>/` | Stage 3 loads these into NetworkX |

**Planned for later (don't build yet):** NetworkX (graph), LLM API + LangGraph (agents), FastAPI (backend), React + Cytoscape.js (clickable graph UI with time slider).

---

## 4. Folder structure

```
guardian/
  cli.py                     # typer entrypoint: guardian scan ...
  models/
    facts.py                 # Pydantic models for Stage 1 output
    code_index.py            # Pydantic models for Stage 2 output
  stage1_facts/
    manifests.py             # declared deps + index URLs
    resolver.py              # transitive tree (in Docker)
    sbom.py                  # run Syft, load CycloneDX
    pypi_meta.py             # PyPI metadata per package (cached)
    cicd.py                  # GitHub Actions workflows
    docker.py                # Dockerfile(s)
    git_history.py           # dependency-file history + snapshots
    docs.py                  # README / docs inventory
  stage2_code/
    parser.py                # walks repo, runs visitors per file
    visitors.py              # ast.NodeVisitor classes
    import_resolver.py       # internal vs external vs stdlib, relative imports
    patterns.py              # route decorators, sensitive-call lists, test-file rules
    dist_map.py              # import name -> PyPI distribution
  stage3_knowledge/          # LATER
tests/
  fixtures/make_mini_shop.sh
output/
```

---

## 5. Stage 1 — Collect facts (deterministic)

**Output:** `output/<repo>/facts.json`

### 5.1 Declared dependencies (`manifests.py`)
Read every dependency file. For each entry capture:
- name, version spec, extras, environment markers
- **kind:** `registry` | `vcs` (`git+https://...`) | `url` | `local path`. VCS/URL deps bypass PyPI, so their origin matters.
- **dev or runtime:** `requirements-dev.txt`, `[project.optional-dependencies]`, `[dependency-groups]`, Poetry dev groups → `dev: true`
- source file + line
- Follow `-r other.txt` / `-c constraints.txt` includes

**Also capture package index settings:** `--index-url`, `--extra-index-url`, `[[tool.poetry.source]]`, `[[tool.uv.index]]`. An extra private index is a known supply-chain attack path (dependency confusion), so record it as a fact.

### 5.2 Resolved packages, direct + transitive (`resolver.py`)
- If a lockfile exists (poetry.lock / uv.lock / Pipfile.lock / hashed requirements) → **use it, no install needed**.
- Else → in Docker: `pip install --dry-run --ignore-installed --only-binary=:all: --report report.json -r requirements.txt`
- For each package: purl, name, version, `direct` (bool), `required_by[]`, `requires[]`, hashes, `source` (`lockfile` | `pip-report` | `sbom`).

### 5.3 SBOM (`sbom.py`)
- `syft scan dir:<repo> -o cyclonedx-json=output/<repo>/sbom.cdx.json`
- If a Docker image is built/available: also `syft scan <image> -o cyclonedx-json=...` (satisfies *"inspect at least one container image"*).
- Load it and cross-check against 5.2. Log mismatches as facts.

### 5.4 Package metadata, i.e. "where each component originates" (`pypi_meta.py`)
For every resolved package (cache responses to disk):
- upload date of *this* version, first-ever release date, number of releases
- author / maintainer fields, `project_urls` (source repo, homepage)
- yanked or not, whether only an sdist exists (sdist = build script runs on install)
- file hashes from PyPI (to compare with lockfile hashes)

### 5.5 CI/CD workflows (`cicd.py`)
For each `.github/workflows/*.yml`:
- triggers (`push`, `pull_request`, `pull_request_target`, `schedule`, ...)
- `permissions` block (or absence of it)
- every `uses:` → `owner/repo`, ref, **`pinned_to_sha`** (ref is a 40-char hex), line
- every `run:` command with line (raw text; no judging)
- secrets referenced (`${{ secrets.X }}`)

### 5.6 Containers (`docker.py`)
For each Dockerfile:
- base images: ref, tag, digest (if `@sha256:` pinned), line
- `RUN pip install ...` lines, `ADD <url>`, `curl/wget` in RUN
- multi-stage names

### 5.7 Dependency history, input for time travel (`git_history.py`)
- List commits that touched any dependency file / lockfile / Dockerfile / workflow (last N = 50 default).
- For each: hash, date, author, message, files changed, and a **diff of the package list**: added / removed / version changed.
- Ability to produce a **full Stage 1 snapshot at any commit** (`git show <hash>:<file>`). No checkout needed.

### 5.8 Docs (`docs.py`)
- README path, docs/ files, top-level docstring presence. Paths and first ~2,000 chars only (for the LLM later).

### `facts.json` shape (abbreviated)
```json
{
  "repo": {"name": "mini-shop", "commit": "a1b2c3d", "scanned_at": "2026-11-23T15:00:00Z"},
  "declared_dependencies": [
    {"name": "PyYAML", "spec": ">=5.4", "kind": "registry", "dev": false,
     "extras": [], "markers": null, "source_file": "requirements.txt", "line": 4}
  ],
  "package_indexes": [
    {"url": "https://pypi.org/simple", "type": "index-url", "source_file": "requirements.txt", "line": 1}
  ],
  "resolved_packages": [
    {"purl": "pkg:pypi/pyyaml@6.0.1", "name": "PyYAML", "version": "6.0.1",
     "direct": true, "required_by": [], "requires": [], "hashes": ["sha256:..."], "source": "pip-report"}
  ],
  "sbom_path": "output/mini-shop/sbom.cdx.json",
  "package_metadata": {
    "pkg:pypi/pyyaml@6.0.1": {"version_uploaded": "...", "first_release": "...", "release_count": 0,
      "maintainers": [], "project_urls": {}, "yanked": false, "sdist_only": false}
  },
  "ci_workflows": [
    {"file": ".github/workflows/ci.yml", "triggers": ["push"], "permissions": null,
     "actions": [{"uses": "actions/checkout", "ref": "v4", "pinned_to_sha": false, "line": 12}],
     "run_steps": [{"line": 20, "cmd": "pip install -r requirements.txt"}],
     "secrets_used": []}
  ],
  "containers": [
    {"file": "Dockerfile", "base_images": [{"ref": "python:3.11-slim", "tag": "3.11-slim", "digest": null, "line": 1}],
     "pip_installs": [{"line": 5, "cmd": "pip install -r requirements.txt"}], "remote_fetches": []}
  ],
  "dependency_history": [
    {"commit": "a1b2c3d", "date": "...", "author": "...", "message": "add analytics",
     "files_changed": ["requirements.txt"],
     "added": ["colorama"], "removed": [], "changed": [{"name": "PyYAML", "from": "5.4.1", "to": "6.0.1"}]}
  ],
  "docs": {"readme": "README.md", "doc_files": []},
  "errors": []
}
```

---

## 6. Stage 2 — Index the code (deterministic, `ast`)

**Output:** `output/<repo>/code_index.json`

Walk every `.py` file (skip `.venv`, `venv`, `build`, `dist`, `site-packages`, `.git`, `__pycache__`). Parse with `ast.parse`. On `SyntaxError` → record `parse_error`, keep going.

For **each file**, extract:

| Field | What | How |
|---|---|---|
| `path`, `module_path`, `package_dir` | `app/payments/client.py`, `app.payments.client`, `app/payments` | Detect source roots: `src/` layout, top-level packages with `__init__.py`, namespace packages |
| `sha256`, `loc`, `is_test` | | tests/: `test_*.py`, `*_test.py`, `conftest.py` → test |
| `docstring` | module docstring | `ast.get_docstring` |
| `imports[]` | name, alias, line, **kind** = `internal` / `external` / `stdlib`, `resolved_file` for internal, `in_try_except`, `conditional` | stdlib via `sys.stdlib_module_names`; internal = resolves to a repo file; resolve relative imports (`from ..db import x`) |
| `definitions[]` | functions, async functions, classes, methods: id, name, line, end_line, decorators, params, docstring | `ast.NodeVisitor` |
| `calls[]` | **which function calls what**: caller id, target (alias-resolved, e.g. `import yaml as y; y.load` → `yaml.load`), kind internal/external, line | This gives **function-level package usage** (e.g. `yaml.load` vs `yaml.safe_load`). Essential for blast radius later |
| `routes[]` | framework, HTTP method, path, handler id, line | Flask `@app.route/@bp.route/@app.post`, FastAPI `@app.get/@router.post`, Django `urls.py` `path()/re_path()` |
| `cli_entrypoints[]` | `if __name__ == "__main__"`, click/typer `@command`, argparse | plus `[project.scripts]` from pyproject (Stage 1) |
| `env_reads[]` | var name, line, how | `os.environ[...]`, `os.environ.get`, `os.getenv` |
| `sensitive_calls[]` | category + target + line | categories: `network` (requests, httpx, urllib, socket, aiohttp), `subprocess` (subprocess.*, os.system), `code_exec` (eval, exec, compile), `deserialize` (pickle, marshal, yaml.load), `file_write`, `crypto` |
| `string_urls[]` | URL / domain string literals + line | regex on `ast.Constant` strings |
| `dynamic_imports[]` | `importlib.import_module(...)`, `__import__(...)` + line | We **cannot** resolve these statically, so we record them as known unknowns |

Plus, repo-level:
- **`import_name_to_distribution`**: `yaml → PyYAML`, `cv2 → opencv-python`, `sklearn → scikit-learn`, `PIL → Pillow`, ... Build it from the resolved environment (`importlib.metadata.packages_distributions()` or each dist's `top_level.txt`), with a small fallback table for common ones. **Without this, package ↔ code linking breaks.**
- `source_roots[]`
- `errors[]`

### `code_index.json` shape (one file shown)
```json
{
  "source_roots": ["app"],
  "import_name_to_distribution": {"yaml": "PyYAML", "stripe": "stripe", "flask": "Flask"},
  "files": [
    {
      "path": "app/payments/client.py", "module_path": "app.payments.client", "package_dir": "app/payments",
      "sha256": "...", "loc": 42, "is_test": false, "parse_error": null,
      "docstring": "Stripe client factory.",
      "imports": [
        {"name": "stripe", "alias": null, "kind": "external", "line": 1, "in_try_except": false, "conditional": false},
        {"name": "os", "kind": "stdlib", "line": 2},
        {"name": "app.payments.config", "kind": "internal", "resolved_file": "app/payments/config.py", "line": 3}
      ],
      "definitions": [
        {"id": "app/payments/client.py::get_client", "type": "function", "name": "get_client",
         "line": 6, "end_line": 14, "decorators": [], "params": [], "docstring": null}
      ],
      "calls": [
        {"caller": "app/payments/client.py::get_client", "target": "stripe.Charge.create",
         "kind": "external", "import_name": "stripe", "line": 11}
      ],
      "routes": [],
      "cli_entrypoints": [],
      "env_reads": [{"var": "STRIPE_KEY", "how": "os.environ[]", "line": 8}],
      "sensitive_calls": [],
      "string_urls": [],
      "dynamic_imports": []
    }
  ],
  "errors": []
}
```

---

## 7. Who does what

| Person | Owns | Files |
|---|---|---|
| **All together (first 30–45 min)** | Agree and write the Pydantic models in `models/` + CLI skeleton | `models/*.py`, `cli.py` |
| **Dev 1: Dependencies** | 5.1 manifests, 5.2 resolver (Docker), 5.3 Syft SBOM, 5.4 PyPI metadata | `stage1_facts/manifests.py`, `resolver.py`, `sbom.py`, `pypi_meta.py` |
| **Dev 2: Pipeline & history** | 5.5 CI/CD, 5.6 Dockerfile, 5.7 git history + snapshots, 5.8 docs, **fixture repo (section 8)** | `stage1_facts/cicd.py`, `docker.py`, `git_history.py`, `docs.py`, `tests/fixtures/` |
| **Dev 3: Code index** | All of Stage 2 | `stage2_code/*` |

Models first, because once the contracts are fixed everyone can work in parallel without blocking each other.

---

## 8. Test fixture: `mini-shop` (build this early, it is also our demo)

A tiny Flask app with a **2-commit git history** and planted facts, so every extractor has something to find:

```
mini-shop/
  app/__init__.py
  app/api/routes.py          # @app.post("/checkout") -> calls payments.service.charge
  app/payments/service.py    # charge() -> client.get_client()
  app/payments/client.py     # import stripe; os.environ["STRIPE_KEY"]
  app/config/load.py         # import yaml; yaml.load(...)          (function-level usage)
  app/utils/helpers.py       # requests.post("https://<external-domain>/collect", ...)   (added in commit 2)
  tests/test_api.py
  requirements.txt           # flask, stripe, PyYAML, requests, colorama (colorama never imported)
  requirements-dev.txt       # pytest
  Dockerfile                 # FROM python:3.11-slim (tag, no digest)
  .github/workflows/ci.yml   # uses actions/checkout@v4 (tag, not SHA)
```
- **Commit 1 (baseline):** no `utils/`, no `colorama`, older PyYAML.
- **Commit 2 (today):** adds `utils/helpers.py`, adds `colorama`, bumps PyYAML.

`tests/fixtures/make_mini_shop.sh` creates this repo with both commits so anyone can regenerate it.

---

## 9. Definition of done for Stage 1–2

- [ ] `guardian scan ./mini-shop` produces `facts.json`, `code_index.json`, `sbom.cdx.json` with no crashes
- [ ] On mini-shop it finds: 1 POST route, `STRIPE_KEY` env read, `requests.post` network call, `yaml.load` call, `colorama` declared-but-not-imported (visible by comparing the two files), unpinned action, untagged-digest base image, and the commit-2 diff (added colorama, PyYAML bumped)
- [ ] Runs on **2 real open-source Flask/FastAPI repos (50–300 files)** without crashing; errors land in `errors[]`
- [ ] Every fact has a file + line (or commit)
- [ ] All JSON validates against the Pydantic models
- [ ] Re-scan of an unchanged repo is fast (sha256 cache)

---

## 10. What comes after (so you know why the formats matter)

**Stage 3: Knowledge builder** loads both JSONs into one NetworkX graph and adds meaning:
- **3A Structure engine (algorithms):** detects modules, module-to-module dependencies, entry-point reachability, package ownership, declared-vs-used, sensitive spots
- **3B Meaning engine (LLM):** writes a purpose card for each module and the repo
- **3C Investigator agent:** digs into anything odd/unclear using tools, writes conclusions with evidence
- **Time travel:** compares graphs across commits (uses 5.7)
- **Blast radius:** from any package, follows edges to files → modules → routes → secrets (uses `calls[]`, `routes[]`, `env_reads[]`)

Then risk detection (CVEs via OSV using the purls, suspicious changes) and the clickable UI sit on top of that graph.