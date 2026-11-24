# Stages 4–6 handoff

**Status (2026-11-23):** Stages 4, 5 and 6 are built on top of Stages 1–3. `guardian scan` runs Stages 1 → 5, and `guardian web` serves the API and the web app. Tests: `pytest tests --deselect tests/test_stage1.py` passes. The deselected file is the known Windows `bash`/cp1252 issue from the Stage 3 handoff.

**Not verified yet:**
- No run with a real Claude API key. The AI paths (analyst, investigator agent, verifier, explanation) are validated against tool-returned evidence, but without a key everything ran on the deterministic paths.
- No real Grype run. It is supported when `grype` is on PATH or `GUARDIAN_GRYPE` points to it, but downloading the binary was blocked in this session. Grype parsing is tested against a sample written to Grype's documented JSON format, not real output.
- Docker sandbox isolation (`GUARDIAN_SANDBOX=docker`) is written but untested here, because the Docker daemon was not running. The default sandbox is a separate, time-limited process that only parses archives and never installs, builds or imports a package.

## Test fixture

`tests/fixtures/make_mini_shop_full.py` builds the team's two-commit mini-shop and adds five more commits (stage4.md §14, stage5.md §10), plus `fake-pypi/`: a PyPI-style JSON index holding harmless fake packages. Their only network destination is `example.invalid`. Every vulnerable version was checked against live OSV first. `tests/data/osv_minishop.zip` holds those real OSV records in the same layout as the official dump, so the tests run offline. Refresh it with `tests/fixtures/record_osv_subset.py`.

Fixture choices:

| Case | Choice |
|---|---|
| Unsafe loading, symbol called | PyYAML 5.3.1 (GHSA-8q59, 9.8), called through `yaml.load(..., Loader=yaml.FullLoader)` at startup (`app/__init__.py`) |
| Package used, vulnerable symbol not called | joblib 1.1.0 (`Parallel(pre_dispatch=)`, 9.8). The code only calls `joblib.dump`, from a `__main__` job |
| Vulnerable transitive package | idna 3.7 via requests. A `poetry.lock` gives Stage 1 the dependency edges, because pip cannot resolve PyYAML 5.3.1 on modern Python |
| Dev-only | pytest 8.0.0, already in the fixture and flagged by OSV |

The team's `make_mini_shop.sh` is unchanged, so the Stage 3 tests are unaffected.

## Results on the full fixture (offline)

**Stage 4** (one finding per CVE; GHSA and PYSEC records for the same CVE are merged):

| Package | Usage / reachability | Project risk | Notes |
|---|---|---|---|
| PyYAML | `symbol_called`, `internal_only` | High (rule 4) | |
| joblib | `package_used_symbol_not_found`, `internal_only` | Medium (rule 5) | Downgrade guard pauses for review |
| idna | path `requirements.txt:5 → requests → idna` | Low | |
| pytest | dev scope | Low | |
| requests ×3, Flask | | Low | |

**Stage 5:**

| Subject | Signals | Result |
|---|---|---|
| reqeusts | D1 + D4 strong | Critical, `install_path` |
| requests | D6 hash mismatch + lockfile-only change | Critical |
| `.github/workflows/ci.yml` | `pull_request_target` checks out the PR head | Critical |
| `send_event()` | D2 strong | Critical |
| minishop-utils 1.1 | D3 deep check: base64 + exec | High |
| shopfront-theme 2.4.1 | normal explanation found and verified | Medium (Low suspicion) |
| colorama, python:latest, postgres:16 | | Medium |

## Where the plans contradict themselves (rules were followed)

- **stage4 §14 expects the PyYAML case to trigger the downgrade guard.** By §9, the guard only fires when CVSS ≥ 9 ends at Medium or Low, and rule 4 makes PyYAML High. The joblib case triggers the guard instead. If the team wants Critical → High to pause too, change `review_reasons` in `stage4_vulns/risk.py`.
- **stage5 §10 expects `send_event()` → High and the legitimate update → Low.** The suspicion × exposure table gives Critical (verified strong behaviour × `runtime_public`) and Medium (Low suspicion × `runtime_public`).

## Other deviations

- **Human review is a separate LangGraph graph per finding**, opened by the report step: one SQLite-checkpointed thread per finding in `review.sqlite`. This way the report is never blocked waiting for people, and each finding resumes on its own. `triage.json` reuses a decision only when the package version and the evidence-file hashes are unchanged.
- **Reachability rules:** routes and argument-parsing CLIs (click, typer, argparse) count as public. `__main__` scripts and module-level startup code count as internal.
- **New exposure value `installed_unused`:** in the install set, never imported, with no install hooks. It uses the same risk column as `not_in_install_set`.
- **"Commit message doesn't mention it"** is treated as context only and never creates a finding on its own.
- **Without an LLM, the analyst extracts vulnerable symbols with fixed rules** from the advisory text: backticks, dotted names, `name()`, and "X method/class". Symbols are prefixed with the package's import name and validated like LLM output.
- **Stage 6 lives in `web/`**, not `ui/src`, so the existing `ui/` dashboard keeps working. It uses React, Vite, Router, TanStack Query, Tailwind and Cytoscape. Components are hand-written rather than generated by shadcn, and there are no OpenAPI-generated TypeScript types yet. The `.gitignore` ignores every `lib/` folder, so don't add `web/src/lib`.

## Changed outside the new folders

- `stage3_knowledge/structural.py`: `CALLS_API` edges also store `api=`. When `graph.json` is reloaded, the `target` attribute is overwritten by the edge's end node, and the API name was lost. Edge `source` has the same problem; Stage 4 works around it.
- `stage3_knowledge/schema.py`: new node and edge types.
- `stage3_knowledge/api.py`: attaches the Stage 4 endpoints and allows POST.
- `cli.py`: the `vulns`, `vulndb`, `review`, `web` and `demo` commands, plus Stages 4–5 in `scan`.
- `requirements.txt` and `pyproject.toml`: `langgraph`, `langgraph-checkpoint-sqlite`, `cvss`.
