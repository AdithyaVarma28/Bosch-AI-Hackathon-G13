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
- Python files are parsed with the running interpreter's grammar; newer syntax (for example Python 3.14 `except A, B:`) is recorded as a parse error.
- `bun.lock` and `pnpm-lock.yaml` are detected but not parsed; those projects fall back to resolution or declared dependencies.
- Without Docker, pinned `requirements.txt` projects have no transitive dependency data.
- Priority thresholds are unvalidated starting values.
