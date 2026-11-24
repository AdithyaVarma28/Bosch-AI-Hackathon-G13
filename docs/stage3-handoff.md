# Stage 3 handoff: knowledge engine (`guardian/stage3_knowledge/`)

**Status (2026-11-23):** Stage 3 is built on top of the merged Stage 1–2 code (`7bb12bb`) and runs end to end from `guardian scan`. `pytest tests/test_stage3.py` gives **14 passed** (the real Stage 1–2 scan of the `make_mini_shop.sh` fixture, then Stage 3; a fake LLM provider covers the AI paths). On the whole suite this machine shows 123 passed, 5 skipped, 1 failed, 1 error. The failure and the error are Windows environment issues that also fail without the Stage 3 changes (see "Known issues").

## Run it
```bash
guardian scan path/to/repo --out output                   # Stage 1 -> 3
guardian scan path/to/repo --offline --skip-sbom          # no PyPI and no LLM calls
guardian knowledge output/<repo> --repo path/to/repo      # Stage 3 only, on an existing Stage 1-2 output
guardian knowledge output/<repo> --repo path/to/repo --baseline-dir output/<repo>-baseline   # full graph diff
guardian serve output/<repo>                              # API + dashboard on http://127.0.0.1:8000/
```
`pip install -r requirements.txt` now also installs `networkx`, `fastapi`, `uvicorn` and `anthropic`.
LLM: Claude `claude-opus-5-5` when an Anthropic credential is available (`GUARDIAN_LLM=auto|anthropic|offline`, `GUARDIAN_MODEL`), otherwise deterministic cards and findings. Requests use the server-side refusal fallback (`fallbacks: "default"`). Responses are cached in `output/<repo>/.llm_cache/`.

## Outputs (`output/<repo>/`)
`graph.json` (NetworkX node-link, `edges` key) · `cards.json` · `paths.json` · `blast_radius.json` · `changes.json` · `findings.json` · `coverage.json` · `ui_bundle.json` (dashboard import format).

## Results on `mini-shop` (spec section 11, team fixture, offline)
| Expected | Result |
|---|---|
| Modules `api`, `payments`, `config`, `utils`, `tests` + `models` | ✅ (plus `app` for `app/__init__.py`) |
| `api → payments`, `api → utils`, `payments → models` | ✅ |
| `colorama` tagged `declared_unused` | ✅ (`SQLAlchemy` too: the team fixture never imports it) |
| Path `POST /checkout (request.json) → checkout → charge → Stripe + orders + STRIPE_KEY` | ✅ except `orders`: the team fixture's `charge()` never writes to the DB. `table:orders` is found from `__tablename__`, and DB writes are detected when code does them |
| Path `POST /checkout → checkout → send_event → <external-domain>` | ✅ `analytics.external-service.com` |
| Blast radius `stripe` large, `PyYAML` internal, `colorama` none | ✅ |
| Diff: `+colorama`, PyYAML bump, `+module utils`, `+CONTACTS → domain` | ✅ all four, linked to commit `CHANGED_IN` edges |
| Payments card: purpose, sensitivity high, valid evidence | ✅ high + valid evidence. Offline, the purpose is "Defines get_client, charge. Observed: contacts Stripe; reads STRIPE_KEY…"; with an LLM it is written by Claude from the same facts |
| 3D finding on `send_event()` with evidence + commit, `notable: true` | ✅ |
| 3D finding on `colorama`: no usage, added in the same recent commit | ✅ |

Definition of done (section 12): end-to-end ✅ · every node/edge has `discovered_by` ✅ (tested) · no AI claim without tool-returned evidence ✅ (tested) · re-scan uses the cache, no new calls ✅ (tested) · API returns renderable data ✅ (tested; dashboard renders every page with a real bundle). **Not yet done:** a run with a real Claude key, and the two real 50–300-file Flask/FastAPI repos within budget. This repo itself (60 files) runs cleanly: 988/997 internal calls resolved, 41 paths, 0 graph errors.

## What Stage 4 can use directly
- **Graph** (`ctx.G` from `run_stage3(...)`, or `api.load_context(output_dir)` to reload from disk):
  - `Package` nodes keyed by purl, with `name`, `version`, `direct`, `dev`, `scope` (`prod|dev|unknown`, from `adapters.components_from_facts`), `tags` (`declared_unused`, `test_only`, `dev_used_in_runtime`, `undeclared_import`, `radius:*`), `blast_radius`, and declaration evidence (`requirements.txt:6`).
  - `REQUIRES` (dependent → dependency) for transitive paths back to the direct dependency; `USES_PACKAGE` file → package; `CALLS_API` function → package with `target` such as `yaml.load` (fingerprint matching).
  - Functions: `inputs` (`request.json`, `HTTP request`, `command-line arguments`) = the `input_sources(function_id)` tool; `reachable_from` (routes/CLI); reverse `CALLS` for `trace_callers`.
- **Blast radius**: `blast_radius.json[purl]` → `radius`, `routes_reaching`, `functions`, `api_calls`, `secrets_nearby`, `tables_nearby`, `services_nearby`, `via_direct`.
- **Tools**: `investigator/tools.py::Toolbox` (subclass it and add `t_<name>` methods plus a spec in `TOOL_SPECS`). The `EvidenceLedger` implements Stage 4's "every claim cites evidence a tool returned" rule.
- **LLM**: `llm.LLM` (`complete_json` with a JSON schema, `create` for tool loops, sha256 cache, per-purpose call counters for budgets).
- **API**: `/blast-radius/{purl}` already exists; add `/vulns` next to it in `api.py`.

## Deviations from the Stage 3 plan (deliberate)
- **Stage 2 does not emit `resolved_target`, `input_sources`, `db_models`, `db_access` or `external_services`.** Stage 3 resolves dotted internal call targets itself through `module_path`, and `enrich.py` derives the rest: an SDK table, URL literals inside functions that make network calls, `__tablename__`/`db_table`/Django models, and `request.*` within definition line ranges. It reads only line ranges already in the index, never executes anything, and labels everything `discovered_by: algorithm`. If Stage 2 adds those fields later, the builder uses them and `enrich` skips that file.
- **No `temperature: 0`:** Claude Opus 5.5 rejects sampling parameters. Determinism comes from the sha256 response cache.
- **3D uses a plain tool-calling loop**, which the plan allows instead of LangGraph. Stage 4's plan uses LangGraph for its own workflow.
- **Pipeline order:** 3A → 3C → 3B → 3D. 3C is pure graph walking, and 3B uses its reachability and recent-change marks.
- **Time travel without a baseline Stage 1–2 output** uses `git diff --name-status` (mode `git-files`): new files, modules, services and calls into new code are exact; edits inside modified files are listed, not diffed.
- **Offline**, low-confidence module cards are not queued for 3D (only an LLM can explain code without docstrings); coverage lists them instead.

## Known issues
- `tests/test_stage1.py` calls `bash`, which on Windows resolves to the WSL launcher (`System32\bash.exe`) and mangles the path. `test_module_entrypoint_actually_runs` decodes `--help` output as cp1252. Both fail on this machine with and without Stage 3 (fix: use Git Bash's path, and `encoding="utf-8"` in `subprocess.run`). `tests/test_stage3.py` already handles the bash case.
- Calls through package re-exports (`from .pipeline import run_stage3` in an `__init__.py`) stay unresolved, because Stage 2 records only the module of such imports. They are counted in coverage.
- Stage 1 offline resolution failed for the fixture (`PyYAML==6.0.1` has no wheel for this Python), so there are no transitive packages and no `REQUIRES` edges on mini-shop. Transitive blast radius works when `requires` is present.
- Fixed in passing: `ui/app.js` did not parse (`class="title-suffix"` inside double-quoted strings), so the dashboard rendered blank. The dashboard now also loads the live bundle when served by `guardian serve`.
