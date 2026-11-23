# Guardian: Software Supply Chain Guardian (Day 1)

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

Flags: `--offline` (cache only), `--no-llm`, `--no-docker`, `--history 50`, `--explain 10`, `--model <groq model>`.

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

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The suite runs offline (no network, Docker or LLM) against the generated `guardian-fixture` repo.

## Known limitations (Day 1)

- Static analysis only: imports and calls are evidence of reference, not proof of runtime reachability.
- Call graphs and route → function → sink execution paths are Python-only; other languages are linked at file level.
- Java import → Maven coordinate mapping is a groupId heuristic; unused-dependency findings are skipped for Maven, NuGet and Composer.
- Without Docker, Maven/Gradle projects get direct dependencies only (versions from parent POMs/BOMs), no transitive tree.
- Python files are parsed with the running interpreter's grammar; newer syntax (for example Python 3.14 `except A, B:`) is recorded as a parse error.
- `bun.lock` and `pnpm-lock.yaml` are detected but not parsed; those projects fall back to resolution or declared dependencies.
- Without Docker, pinned `requirements.txt` projects have no transitive dependency data.
- Priority thresholds are unvalidated starting values.
