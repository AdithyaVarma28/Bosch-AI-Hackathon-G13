# Stage 2 handoff: code index (`code_index.json`)

**Status (2026-11-23, ~4:00 pm):** Stage 2 is built, independently reviewed (10 findings, all Critical/Important fixed) and tested: `pytest` gives **104 passed** with the sample repos present (the 5 real-repo tests skip without `GUARDIAN_TEST_REPOS`). Real runs: PyGoat (116 files), VAmPI (11), vulpy (57), shiftleft-python-demo (7) all finish with 0 errors; Django (2,943 files, 44,188 definitions, 73,361 calls) finishes with 1 error, a deliberate syntax-error fixture in Django's own tests.

**Accuracy spot-check:** 21 random PyGoat facts (6 calls, 5 sensitive calls, 5 routes, 5 env reads) were compared with the source lines: 21/21 correct. This is a sample, not a measured accuracy rate.

**Speed:** PyGoat about 0.2–1 s. Django (about 3,000 files) about 30 s cold and 3–18 s warm; the spread comes from thousands of small cache files and Windows file scanning (a single-file cache is a possible follow-up).

## Run it
```powershell
cd C:\Desktop\Bosch_hack
$env:PYTHONPATH = "src"
python -m guardian.cli scan <path-to-repo> --offline --skip-sbom   # Stage 1 + Stage 2 linked: facts.json, code_index.json, summary.json
python -m guardian.cli index <path-to-repo> --out output     # Stage 2 only: writes output/<repo>/code_index.json
python -m guardian.cli index <path-to-repo> --out output --facts <facts.json>   # Stage 1 resolved packages sharpen the import-name map
python -m pytest -q                                          # all tests
$env:GUARDIAN_TEST_REPOS = "<folder with clones of pygoat, VAmPI, vulpy, shiftleft-python-demo>"; python -m pytest -q   # real-repo runs
```
Python API: `from guardian.stage2_code.parser import index_repo` → `index_repo(repo_path, cache_dir=None, resolved=None) -> CodeIndex`.
Pass Stage 1's `resolved_packages` as `resolved=` so import names map to the right PyPI distributions (otherwise only the curated table applies, e.g. `yaml`→PyYAML but not `django`).

## What is in the file (models: `src/guardian/models/code_index.py`)
Per file: `path`, `module_path`, `package_dir`, `sha256`, `loc`, `is_test`, `parse_error`, `docstring`, then
- `imports[]` (internal / external / stdlib, relative imports resolved, `in_try_except`, `conditional`, `resolved_file`, `distribution`)
- `definitions[]` (ids like `app/x.py::C.method`, nested `f.<locals>.g`)
- `calls[]` (alias-resolved: `import yaml as y; y.load` → `yaml.load`; caller is the enclosing function id or `path::<module>`)
- `sensitive_calls[]` (network, subprocess, code_exec, deserialize, file_write, crypto; `yaml.safe_load` is not flagged)
- `env_reads[]`, `routes[]` (Flask, FastAPI, Django `path()/re_path()/include()`), `cli_entrypoints[]`, `string_urls[]`, `dynamic_imports[]`
Repo level: `source_roots`, `import_name_to_distribution`, `errors[]` (syntax errors, oversized files).

## Real results so far (PyGoat)
116 files, 458 definitions, 322 imports, 222 routes (173 Flask-style, 49 Django), `yaml.load`, `eval`, `pickle.loads` found, env vars such as `JWT_SECRET`, `DATABASE_URL`.

## Adapters for Stage 3 (`src/guardian/adapters.py`, tested)
- `components_from_facts(facts) -> (components, edges)`: prod/dev scope (transitive packages follow their roots; `unknown` if no root declares them), `DEPENDS_ON` edges from dependent to dependency, never an edge to an unresolved package, `sdist_only` from package metadata.
- `declarations_from_facts(facts)`: requested range, scope and file:line per declared dependency.
- `usage_from_index(index)`: external imports become `UsageRef`s (`mapped` with a normalised package name, `unmapped`, `stdlib`, `dynamic_unresolved`); internal imports are skipped.

## Known gaps (not bugs: scope or heuristics)
- Duplicate definition ids for property getter/setter pairs (`m.py::C.x` twice); two repos with the same folder name overwrite each other's `output/<name>/`.
- **OpenAPI/connexion routes** (VAmPI) are declared in YAML, not decorators, so `routes` is empty there.
- **Namespace packages** (directories without `__init__.py`, e.g. vulpy `lib/`) are still classed external.
- `yaml.load(x, Loader=SafeLoader)` is flagged as `deserialize` (it does not inspect the Loader argument).
- Scope-insensitive alias table: a local variable shadowing an imported name can mislabel a call.
- Calls on objects of unknown type (`self.client.send()`) are intentionally not recorded.
- Static imports show a package is *referenced*, not that it runs at runtime.

## How Stage 3 should consume it
`usage_from_index(index)` (Task 1B, not built yet) turns `imports[]` with `kind == "external"` and a `distribution` into `UsageRef`s; `calls[]` + `routes[]` + `env_reads[]` give function-level package use and blast-radius paths.
