# Guardian: Software Supply Chain Guardian (Day 1 + Day 2)

Paste a GitHub URL (or a local path) and get: what is in the application, what changed, and what appears risky, with evidence for every claim.

Design: [docs/implementation_plan.md](docs/implementation_plan.md). Background: [docs/stage1and2.md](docs/stage1and2.md), [docs/multilayer_dependency_graph.md](docs/multilayer_dependency_graph.md).

## Setup (Windows PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Optional, for full coverage:
- **Docker Desktop running**: enables sandboxed dependency resolution for repos without lockfiles, plus Syft/Trivy via their images.
- **Syft / Trivy on PATH**: used directly if installed.
- **Groq API key**: enables the LLM agents (Dossier agent, Evidence Agent). Without it, explanations are rule-based.

```powershell
$env:GROQ_API_KEY = "<your key>"
$env:GROQ_MODEL = "openai/gpt-oss-120b"   # optional
```

Or put `GROQ_API_KEY=...` in a `.env` file in the folder you run `guardian` from (`.env` is git-ignored).

## Run

```powershell
.\.venv\Scripts\guardian.exe fixture output/fixtures
.\.venv\Scripts\guardian.exe scan output/fixtures/guardian-fixture
.\.venv\Scripts\guardian.exe scan https://github.com/miguelgrinberg/microblog
.\.venv\Scripts\guardian.exe serve --port 8765
```

`scan` runs **one pipeline from detection to remediation**: Day 1 detection (SBOM, graph, vulnerabilities, suspicious changes, evidence) flows straight into Day 2 (prioritize, investigate, plan fixes) and stops at the human approval gate. Use `--detect-only` to stop after detection.

Flags: `--offline` (cache only), `--no-llm`, `--no-docker`, `--history 50`, `--explain 10`, `--model <groq model>`, `--sandbox docker|local|none`, `--advisory-db`, `--registry-snapshot`, `--detect-only`.

Each run writes `output/<repo>/<run_id>/`:

| File | Content |
|---|---|
| `facts.json` | Stage 1 facts: declared deps, indexes, lockfile health, scripts, Dockerfiles, CI, compose, env var names, dependency history |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM (merged lockfile / sandbox resolution / Syft / Trivy) |
| `code_index.json` | Stage 2 `ast` index: imports, definitions, calls (resolved), routes, inputs, env reads, DB models/access, external services, sensitive calls |
| `graph.json` | Unified multi-layer graph (declared, resolved, usage, context) with evidence status per edge |
| `report.json` / `report.html` | Findings with P0â€“P3 bands, explanations, evidence, coverage; interactive graph |
| `run.db` | Immutable, content-addressed evidence store (SQLite) |

## Supported ecosystems

| Ecosystem | Manifests | Lock / resolution | Code usage layer |
|---|---|---|---|
| PyPI | requirements*.txt, pyproject.toml, setup.cfg, setup.py, Pipfile | poetry.lock, uv.lock, Pipfile.lock, pinned requirements; sandboxed `pip --report` | full `ast` index: call graph, routes, inputs, DB, env, sinks |
| npm | package.json, .npmrc | package-lock v1–v3, yarn.lock v1; sandboxed `npm --package-lock-only` | imports, Express routes, `process.env`, sinks |
| Maven / Gradle | pom.xml (properties, dependencyManagement, parent POM + BOM versions from Maven Central), build.gradle(.kts) | gradle.lockfile; sandboxed `mvn dependency:tree` | Java/Kotlin/Scala imports (groupId mapping), Spring/JAX-RS routes, `System.getenv`, sinks |
| Go | go.mod (require, `// indirect`, replace) | go.mod build list + go.sum hashes | imports (module-prefix mapping), gin/echo/net/http routes, `os.Getenv`, sinks |
| Cargo | Cargo.toml (+ .cargo/config registries) | Cargo.lock (edges, checksums) | `use` / `extern crate`, actix/axum routes, `env::var`, sinks |
| RubyGems | Gemfile (groups, sources) | Gemfile.lock (edges) | `require`, Rails/Sinatra routes, `ENV[]`, sinks |
| Composer | composer.json (repositories, scripts) | composer.lock (edges, PSR-4 autoload → import mapping) | `use` namespaces, Laravel/Symfony routes, `getenv`, sinks |
| NuGet | *.csproj/*.fsproj, packages.config, Directory.Packages.props, nuget.config | packages.lock.json (edges, content hashes) | `using`, ASP.NET routes, `GetEnvironmentVariable`, sinks |

OSV vulnerability matching, registry metadata (PyPI, npm, Maven Central, Go proxy, crates.io, RubyGems, Packagist, NuGet), history diffs, lockfile tampering and private-index (dependency confusion) checks work for all of them. Other ecosystems are inventoried through Syft/Trivy when available.

## Graph explorer (report.html)

- **Views:** Dependency tree (project → direct → transitive, layered left-to-right), Code → packages, Execution paths (route → handler → functions → secrets/tables/services/risky calls), Build & CI, Everything.
- **Encoding:** fill colour = worst finding (P0–P3), border = ecosystem, thick border = direct dependency, shape = node type, line style = relation.
- **Controls:** search, ecosystem chips, runtime/dev scope, "risky only" (risky nodes plus the paths that bring them in), depth slider, PNG export.
- **Click a node:** its upstream path is highlighted, and the side panel shows version, scope, depth, fan-in/out, registry, findings, "how it gets in" paths and the code that uses it.

## Chaos engineering

Two levels:

1. **Supply-chain what-if** (in the report, *What-if (chaos)* tab): simulate a **compromised package** or a **registry outage**. Guardian shows the blast radius: dependent packages, direct dependencies that break, source files, reachable routes, and the secrets, tables and services in the same code. This is a static estimate.
2. **Pipeline chaos experiments**: inject faults into Guardian itself and check the steady-state hypothesis. A scan always ends with an honest, complete, leak-free report, and every claim must be backed by evidence.

```powershell
.\.venv\Scripts\guardian.exe chaos output/fixtures/guardian-fixture --list
.\.venv\Scripts\guardian.exe chaos output/fixtures/guardian-fixture --monkey 3 --seed 7
```

Experiments cover:
- **Outages:** OSV and registries.
- **Tool crashes:** Syft/Trivy, git, a detector, the graph builder.
- **Bad input:** corrupted lockfiles, malformed manifests, huge/deep files, an invalid target.
- **AI failures:** LLM down, and a hallucinating / prompt-injected LLM.
- **Hostile repository text** and **network latency.**
- **Chaos monkey:** random fault combinations, reproducible with a seed.

Faults run in-process on a throwaway copy of the repo. The output is `output/chaos/<time>/chaos_report.html`, a resilience scorecard.

## Agentic pipeline (LangGraph)

```
ingest â†’ cartographer â†’ [resolver_sbom â€– code_index] â†’ graph â†’ dossier_agent â†’ supervisor
      â†’ [vuln_intel â€– change_anomaly â€– package_signals â€– container_ci â€– secrets â€– discrepancies]
      â†’ correlator â†’ evidence_agent â†’ report
```

- **Supervisor** routes with a deterministic table and records why each detector ran or was skipped.
- **Dossier agent** (LLM, optional) describes the app and its exposure; deterministic evidence wins on exposure.
- **Evidence Agent** (LLM, optional) explains the top findings with read-only, path-confined tools (max 8 tool calls, 2 repair passes).
- **Verifier** (deterministic) rejects claims citing unknown evidence or quoting tokens not in the evidence, and downgrades facts that cite only derived evidence.
- Every node fails soft and reports `ok / degraded / skipped / failed` in the Coverage panel.

## Day 2: from detection to verified remediation

Design: [docs/day2_plan.md](docs/day2_plan.md). Code: `src/guardian/day2/`.

Day 2 is not a separate tool: its stages are nodes in the same LangGraph as detection.

```
ingest → … → vuln_intel ‖ change_anomaly ‖ … → correlator → evidence_agent → report        (detection)
  → day2_start → prioritize (S10) → investigate (S11) → remediation_plan (S12) → approval_gate (S13)
  → [approved] validate (S14 + S15 rescan, S14.6 self-correction) → verify (S16) → remediation_report
  → [nothing approved] remediation_report: stop and wait for a reviewer
```

`guardian approve …` records a decision; `guardian remediate <run_dir>` resumes the same Day 2 nodes from the gate. Rescans of a fix run the detection part only (no recursion). `report.html` is one page: the findings table shows each finding's Day 2 score, bucket, plan status and verdict, and a **Remediation** tab holds the full Day 2 report.

| Stage | What it does |
|---|---|
| S10 Prioritize | 0-100 score per finding: severity + exploitability (KEV/EPSS/malicious advisory) + reachability (symbol called > route > imported > not referenced) + exposure + production use + criticality (what the using code touches) + policy. Separate confidence (data quality). Buckets: Fix now / Schedule / Monitor. |
| S11 Investigate | Non-CVE signals: lockfile/manifest diff across the commit, package archive content diff (in memory, never executed), publisher/age/provenance/repository checks, lockfile vs registry integrity. Verdict + typed claims (fact cites raw evidence, inference labelled). |
| S12 Remediate | Deterministic candidates: smallest safe upgrade, latest in major, parent upgrade for transitive vulns (graph-aware, range-floor aware), npm override / pip pin, remove/block typosquats, restore lockfile source, remove install hook, base-image tag, action SHA pin, least-privilege permissions, escalate. Each candidate is applied to a copy and re-scanned (target resolved? new advisories? policy? major-version API risk?), then ranked. |
| S13 Approve | Reviewer approves the exact plan hash (finalists, edits, diff hashes). Any change makes a new revision that needs a new approval. Approvals and audit are append-only (SQLite triggers). |
| S14 Validate | Throwaway copy with history, branch `guardian/fix-<id>`, commit. Install/build/test in the sandbox on the original and the patched tree: a regression is a test that passed before and fails after. No tests → smoke check (caps the verdict). |
| S15 Rescan | The Day 1 pipeline runs unchanged on the branch; SBOM diff, findings resolved/open/new, band and score deltas, target advisories checked against every component of the new tree. |
| S16 Verify | Policy-as-code (`src/guardian/data/default_policy.yaml`, floor rules cannot be weakened by a repo `guardian-policy.yaml`) sets the deterministic verdict; an independent verifier re-checks the evidence and can only downgrade. Report, VEX, patch export after a second approval. |

```powershell
# offline demo on the fixture (bundled advisory + registry snapshots)
.\.venv\Scripts\guardian.exe fixture output/fixtures
.\.venv\Scripts\guardian.exe scan output/fixtures/guardian-fixture --offline --advisory-db fixture --registry-snapshot fixture
.\.venv\Scripts\guardian.exe plans output/guardian-fixture/<run_id>
.\.venv\Scripts\guardian.exe approve output/guardian-fixture/<run_id> "pkg:pypi/flask@2.0.1" --hash <first 16 chars> --reviewer <name>
.\.venv\Scripts\guardian.exe remediate output/guardian-fixture/<run_id> --advisory-db fixture --registry-snapshot fixture
.\.venv\Scripts\guardian.exe export-patch output/guardian-fixture/<run_id> flask --reviewer <name>
```

- `--sandbox docker` (default) needs Docker Desktop running. `--sandbox local` is an explicit opt-in that runs the repository's install and tests on this machine (temp copy, scrubbed environment). `--sandbox none` skips build/test; the verdict is then at most *Partially verified*.
- `guardian reject` and `guardian accept-risk --reason ... --expires YYYY-MM-DD` record the other decisions; `remediate --interactive` asks in the terminal.
- Outputs in `<run_dir>/day2/`: `report.json`, `remediation.html`, `priority.json`, `investigations.json`, `remediation_plan.json`, `verification/*.json`, `vex.cdx.json`, `patches/`. The Day 1 `report.json` fields `remediation`, `validation` and `vex` point to them.
- API: `POST /runs` runs the whole pipeline (`"remediate": false` for detection only); `POST /runs/{id}/remediate` resumes Day 2, `GET /runs/{id}/plans`, `POST /runs/{id}/decisions`, `POST /runs/{id}/patches`, `GET /runs/{id}/remediation(.html)`.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The suite runs offline (no network, Docker or LLM) against the generated `guardian-fixture` repo. Day 2 tests replace Docker with a deterministic fake runner (git still runs for real on the throwaway branch) and use a scripted, deliberately lying LLM to check the guardrails.

## Known limitations (Day 1)

- Static analysis only: imports and calls are evidence of reference, not proof of runtime reachability.
- Call graphs and route → function → sink execution paths are Python-only; other languages are linked at file level.
- Java import → Maven coordinate mapping is a groupId heuristic; unused-dependency findings are skipped for Maven, NuGet and Composer.
- Without Docker, Maven/Gradle projects get direct dependencies only (versions from parent POMs/BOMs), no transitive tree.
- Python files are parsed with the running interpreter's grammar; newer syntax (for example Python 3.14 `except A, B:`) is recorded as a parse error.
- `bun.lock` and `pnpm-lock.yaml` are detected but not parsed; those projects fall back to resolution or declared dependencies.
- Without Docker, pinned `requirements.txt` projects have no transitive dependency data.
- Priority thresholds are unvalidated starting values.

## Known limitations (Day 2)

- Automatic edits exist for npm (`package.json`, `package-lock.json` v1-v3) and pip `requirements*.txt`; other ecosystems get a suggested version and an escalation.
- Without Docker or npm, lockfile edits are done by Guardian itself; integrity values unknown offline are left out, and npm must record them on the next install.
- Parent upgrades are searched for depth-2 paths (direct parent -> vulnerable package); deeper chains get an override.
- Base-image digests and GitHub Action SHAs need network access (registry / GitHub API); offline they are escalated.
- The bundled `fixture_*` snapshots are demo data for air-gapped runs; live OSV and registries are authoritative.
