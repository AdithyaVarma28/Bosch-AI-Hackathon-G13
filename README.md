# Software Supply Chain Guardian

> *Know what you build. Trust what you ship.*

**Continuous supply-chain analysis for Python repositories: deterministic facts, a code-level index, and the context that tells you which findings actually matter.**

![python](https://img.shields.io/badge/python-3.11%2B-blue)
![stages](https://img.shields.io/badge/stages-1%20%2B%202%20%2B%203%20built-brightgreen)
![tests](https://img.shields.io/badge/tests-115%20passing-brightgreen)
![scope](https://img.shields.io/badge/scope-Python%20only-informational)

---

## What it does

Most scanners tell you **what is present**. Guardian first works out **what your application is and how it uses what it has**, then hands that evidence to the later stages (graph, vulnerabilities, risk, remediation).

```mermaid
flowchart LR
    R[Repository] --> S1["Stage 1<br/>Collect facts<br/><i>facts.json</i>"]
    R --> S2["Stage 2<br/>Index the code<br/><i>code_index.json</i>"]
    S1 -- resolved packages --> S2
    S1 --> X{{"Cross-check<br/><i>summary.json</i>"}}
    S2 --> X
    S1 --> S3["Stage 3<br/>Knowledge graph<br/><i>graph · cards · paths · findings</i>"]
    S2 --> S3
    S3 --> S4["Stage 4 (planned)<br/>Vulnerabilities · risk"]
```

| Stage | Question it answers | Method | Status |
|---|---|---|---|
| **1. Fact collection** | What is declared, resolved, shipped and changed? | Deterministic parsers, optional Syft + PyPI | Built |
| **2. Code index** | What does the code import, call, expose and read? | Python `ast` only, nothing is executed | Built |
| **Cross-check** | Where do the two disagree? (declared but never imported, imported but never declared) | Set comparison on normalised package names | Built |
| **3. Knowledge engine** | What are the modules, how do requests flow, what is each package's blast radius, what changed? | NetworkX graph walks + evidence-checked LLM cards and one bounded investigator agent | Built |
| 4. Vulnerabilities, risk | Which known vulnerabilities matter in *this* repo? | OSV/Grype + investigation on the Stage 3 graph | Planned ([plan](docs/stage4.md)) |

**Ground rules:** Python repositories only · the target repository's code is never executed · collectors record facts and never judge · every fact carries a file and line · one broken file or network error never stops a scan (it lands in `errors[]`).

---

## Features

### Stage 1: Fact collection
| Feature | Details |
|---|---|
| **Declared dependencies** | `requirements*.txt`, `pyproject.toml`, `setup.cfg`, `Pipfile`; follows `-r`/`-c` includes; classifies registry / VCS / URL / local; flags dev dependencies; records package-index settings |
| **Resolution** | `poetry.lock`, `Pipfile.lock`, `uv.lock`, otherwise an isolated `pip install --dry-run --only-binary=:all:` report (optional `--docker`) |
| **SBOM** | CycloneDX JSON via Syft, cross-checked against the resolved packages |
| **PyPI metadata** | Upload date, first release, release count, maintainers, project URLs, yanked, sdist-only, hashes (disk-cached) |
| **CI/CD** | GitHub Actions triggers, permissions, actions with `pinned_to_sha`, run steps, secrets referenced |
| **Containers** | Dockerfile base images, tags, digests, pip installs, remote `curl`/`wget` fetches |
| **History / time travel** | Dependency-file commits with `added` / `removed` / `changed` package diffs, snapshots at any commit without a checkout |
| **Configuration** | `.env*` variable **names only** (no secrets), `docker-compose*.yml` services, migration folders |

### Stage 2: Code index
| Feature | Details |
|---|---|
| **Imports** | internal / external / stdlib, relative imports resolved, `try/except` and conditional flags, script-style sibling imports, PyPI distribution for each external import |
| **Definitions** | functions, async functions, classes, methods with ids like `app/payments/client.py::get_client`, decorators, parameters, line ranges |
| **Calls** | alias-resolved (`import yaml as y; y.load(x)` becomes `yaml.load`), attributed to the calling function: function-level package usage |
| **Sensitive calls** | `network` · `subprocess` · `code_exec` · `deserialize` · `file_write` · `crypto` (`yaml.safe_load` and `Loader=SafeLoader` are *not* flagged) |
| **Routes** | Flask and FastAPI decorators, Django `urls.py` (`path` / `re_path` / `include`) |
| **Environment** | `os.environ[...]`, `os.environ.get`, `os.getenv` reads (assignments are not reads) |
| **Other** | CLI entry points (click, typer, argparse, `__main__`), URL strings, dynamic imports recorded as *known unknowns* |
| **Robustness** | never follows symlinks or junctions, survives syntax errors, huge or unreadable files and very deep expressions, caches unchanged files by SHA-256 |

### Stage 3: Knowledge engine ([plan](docs/stage3.md) · [handoff](docs/stage3-handoff.md))
| Part | Details |
|---|---|
| **Graph** | One NetworkX `MultiDiGraph`: Repo, Module, File, Function, Class, Package, Route, CLIEntry, EnvVar, Table, ExternalService, Workflow, Action, Image, Commit. Every node and edge carries `discovered_by`, `evidence`, `confidence`, `commit`, `analyzed_at` |
| **3A Structural** | package linking (`USES_PACKAGE`, function-level `CALLS_API`), modules from folders reconciled with Louvain clusters (`seed=42`), module `DEPENDS_ON` + cycles, declared-vs-used tags, sensitive-function tags propagated to files and modules, PageRank `core` modules |
| **3B Semantic** | cards (purpose, inputs, outputs, data touched, sensitivity, evidence, confidence) for the repo, every module and sensitive/entry/changed files, leaves first. Evidence lines and IDs are validated; invalid claims get one retry, then are dropped |
| **3C Flow** | execution paths route/CLI → functions → sinks (tables, services, env vars, package APIs); blast radius per package (`none` / `internal` / `public` / `large`); time travel: light snapshots per dependency commit + baseline → HEAD diff linked to commits |
| **3D Investigator** | a prioritised queue of open questions (new outbound calls, new modules, unused packages, large blast radius, …) answered with 7 tools (`query_graph`, `get_card`, `read_code`, `grep`, `git_history`, `pypi_info`, `get_path`); at most 20 questions × 8 tool calls; a finding may only cite evidence a tool returned |
| **LLM** | Claude (`claude-opus-5-5`) behind one wrapper with an on-disk cache: same input, same output, no new calls on a re-scan. Without credentials (or with `--offline`) cards and findings come from deterministic rules instead |
| **API + dashboard** | FastAPI (`/graph`, `/node/{id}`, `/paths`, `/blast-radius/{purl}`, `/diff`, `/coverage`, `/ui-bundle`) and the static dashboard in [`ui/`](ui/) |

---

## Installation

**Prerequisites:** Python **3.11+** (tested on 3.12; Stage 1 needs `tomllib`) and Git. Optional: [Syft](https://github.com/anchore/syft) for SBOMs, Docker for isolated resolution.

<details open>
<summary><b>Linux / macOS</b></summary>

```bash
git clone <repo-url> && cd <repo-folder>
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"          # or: pip install -r requirements-dev.txt
```
</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```
</details>

<details>
<summary><b>Windows (CMD)</b></summary>

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```
</details>

---

## Usage

| Command | What it runs | Writes |
|---|---|---|
| `guardian scan <repo>` | Stages 1 → 3 (`--no-stage3` stops after Stage 2) | `facts.json`, `code_index.json`, `summary.json`, `sbom.cdx.json` (with Syft), then the Stage 3 files below |
| `guardian index <repo>` | Stage 2 only | `code_index.json` |
| `guardian knowledge <scan-dir> --repo <repo>` | Stage 3 only, on an existing Stage 1–2 output | Stage 3 files |
| `guardian serve <scan-dir>` | Stage 3 API + dashboard on http://127.0.0.1:8000/ | – |

```bash
guardian scan path/to/repo                       # standard scan
guardian scan path/to/repo --out output/my-repo  # choose the output folder (-o / --output also work)
guardian scan path/to/repo --docker              # resolve dependencies inside Docker (recommended for untrusted repos)
guardian scan path/to/repo --offline             # skip PyPI network calls
guardian scan path/to/repo --skip-sbom           # no Syft

guardian index path/to/repo --facts output/my-repo/facts.json   # Stage 2 alone, reusing Stage 1's resolved packages

guardian knowledge output/my-repo --repo path/to/repo           # Stage 3 again (LLM: Claude if credentials are set)
guardian knowledge output/my-repo --repo path/to/repo --llm offline   # deterministic cards and findings, no API calls
guardian serve output/my-repo                                   # API + dashboard
```

The LLM is used when `ANTHROPIC_API_KEY` (or another Anthropic credential) is available; `--offline` on `scan` and `--llm offline` turn it off. Budgets: at most 30 card calls and 20 investigator questions × 8 tool calls per scan; responses are cached in `<scan-dir>/.llm_cache/`.

Without installing, from a checkout: `PYTHONPATH=src python -m guardian.cli scan path/to/repo`.

### Example (real output on the `mini-shop` test fixture)
```text
mini-shop: stage 1 -> 7 declared, 18 resolved, 1 workflows, 1 dockerfiles, 0 stage-1 warnings
mini-shop: stage 2 -> 8 files, 1 routes, 2 sensitive calls, 0 errors
mini-shop: declared but never imported: ['colorama', 'sqlalchemy']; imported but not declared: none
stage 3: graph built (38 nodes, 35 edges); LLM: offline (offline mode (no LLM calls))
stage 3A: 7 modules, 0 cycles
stage 3C: 2 execution paths, 7 blast radii, 13 changes (git-files)
stage 3B: 15 cards (LLM calls: 0, cache hits: 0)
stage 3D: 8 findings, 3 notable (LLM calls: 0)
output: output/mini-shop
```

### Outputs
| File | Contents |
|---|---|
| `facts.json` | Stage 1: declared and resolved dependencies, indexes, PyPI metadata, CI, containers, history, docs, config, file hashes |
| `code_index.json` | Stage 2: per file imports, definitions, calls, sensitive calls, routes, env reads, entry points, URLs, dynamic imports |
| `sbom.cdx.json` | CycloneDX SBOM (Syft) |
| `summary.json` | Cross-check: `declared_not_imported`, `imported_not_declared`, `dynamic_imports_present` |
| `graph.json` | Stage 3 knowledge graph (NetworkX node-link) |
| `cards.json` · `paths.json` · `blast_radius.json` | 3B semantic cards · 3C execution paths · 3C blast radius per package |
| `changes.json` · `findings.json` · `coverage.json` | 3C time travel · 3D investigator findings · what was and was not understood |
| `ui_bundle.json` | everything above in the shape the dashboard's **Import scan** accepts |

---

## Project layout

```text
src/guardian/
  cli.py                  scan · index
  adapters.py             facts + code index -> graph inputs, declared-vs-used cross-check
  models/                 Pydantic contracts (facts.py, code_index.py, common.py)
  stage1_facts/           manifests · resolver · sbom · pypi_meta · cicd · docker · git_history · docs · config
  stage2_code/            parser · visitors · pattern_visitor · import_resolver · dist_map · patterns
  stage3_knowledge/       graph_builder · enrich · structural (3A) · semantic (3B) · flow + timetravel (3C)
                          investigator/ (3D) · llm · coverage · export · api · pipeline
ui/                       static Stage 3 dashboard (served by `guardian serve`)
tests/                    unit, regression, golden-syntax and end-to-end tests
docs/                     design, implementation plan, Stage 2 handoff
```

---

## Honest limits

- **Informational cross-check:** a dependency that is declared but never imported may be loaded dynamically or by a plugin. Dynamic imports are flagged, never guessed. Flat pin files also list transitive packages, so the list can be noisy when `requires` data is missing.
- **Static only:** an import shows a package is *referenced*, not that it runs. Calls on objects of unknown type (`self.client.send()`) are intentionally not recorded.
- **Routes:** OpenAPI/connexion routes (declared in YAML) are not detected.
- **Stage 1 gaps:** compose volumes (for example a `docker.sock` mount), container `USER` and exposed ports are not captured yet. When the pip report fails, resolved packages have no `requires`, so there are no dependency edges.
- **Platforms:** developed and tested on Windows; Linux and macOS are not yet verified. Syft was not available when this was tested, so SBOM generation is untested here.
- **Stage 3 is static and function-level:** a path says user input *enters* a function that *reaches* a sink, not that a specific value flows there. Blast radius is potential reach, not proof that vulnerable code runs. Stage 2 does not yet emit `input_sources`, `db_access` or `external_services`, so Stage 3 derives them (`enrich.py`: SDK table, URLs in network calls, `__tablename__`, `request.*` in definition ranges); these carry `discovered_by: algorithm`. A client object returned from a factory (`client = get_client(); client.Charge.create()`) is linked through the SDK import, with lower confidence.
- **Time travel without a baseline scan** diffs at file level from git: new files, modules, services and calls into new code are exact; changes *inside* modified files are listed, not diffed. Pass `--baseline-dir` with a Stage 1–2 output of the baseline commit for a full graph diff.
- **Accuracy:** 21 randomly sampled facts from a real repository (PyGoat) were checked against the source and all matched. That is a spot check, not a measured accuracy rate.

---

## Running the tests

```bash
pytest tests/ -v                       # Windows: pytest tests\ -v
```

The real-repository runs are skipped unless you point `GUARDIAN_TEST_REPOS` at a folder containing shallow clones of `pygoat`, `VAmPI`, `vulpy` and `shiftleft-python-demo`:

```bash
GUARDIAN_TEST_REPOS=/path/to/clones pytest tests/ -v          # PowerShell: $env:GUARDIAN_TEST_REPOS = "C:\path\to\clones"
```

Last full run: **115 passed** (with the real repositories present).

---

## Stage 3 dashboard

`guardian serve output/<repo>` serves the dashboard with the live scan. Opening [`ui/index.html`](ui/index.html) directly shows an illustrative mini-shop demo; load any `ui_bundle.json` with **Import scan**. It groups the Stage 3 output into repository overview, architecture, execution flows, dependency impact, change history, investigator findings, and scan coverage. See [`ui/README.md`](ui/README.md).

---

## Stages 4–6: vulnerabilities, anomalies, web app

`guardian scan <repo>` now runs Stages 1 → 5. Details and the deviations from the plans are in [`docs/stage4-6-handoff.md`](docs/stage4-6-handoff.md).

```bash
guardian scan path/to/repo --out output                     # Stages 1-5 (OSV, KEV, EPSS online)
guardian vulndb download                                    # OSV PyPI dump for offline scans
guardian scan path/to/repo --offline --osv-dump output/.cache/vulndb/osv-PyPI-all.zip
guardian vulns output/<repo>                                # Stage 4 only, on an existing Stage 3 output
guardian review output/<repo> F-002 --action dismiss --reason not_used --by alice
guardian demo                                               # precomputed mini-shop scans in output/scans (no network)
guardian web --root output/scans                            # API + web app on http://127.0.0.1:8000/
```

* **Stage 4** (`guardian/stage4_vulns/`): OSV / Grype / KEV / EPSS discovery, a LangGraph workflow (`Send` fan-out per vulnerability: analyst → investigator → verifier → risk rules), human review via LangGraph `interrupt` + SQLite checkpoints, `vuln_findings.json`.
* **Stage 5** (`guardian/stage5_anomalies/`): detectors D1–D6 (typosquats, unexpected changes, suspicious updates with a parse-only sandbox diff, install hooks, build environment, lockfile integrity), the same investigator/verifier/review pattern, `anomaly_findings.json`.
* **Stage 6** (`guardian/webapp/` + `web/`): one `/api` over immutable scan snapshots (live progress over SSE, unified findings, review, compare, search, SARIF/CycloneDX export) and a React + TypeScript app. Build it once with `cd web && npm install && npm run build`; `npm run dev` proxies `/api` to `guardian web`.

---

## Responsible use

Guardian analyses repositories you are authorised to scan. It parses source code without executing it, runs dependency resolution with `--only-binary=:all:` (optionally inside Docker) so package build scripts do not run, and never records secret values (environment files contribute variable names only).
