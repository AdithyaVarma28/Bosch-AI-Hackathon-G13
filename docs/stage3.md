# Software Supply Chain Guardian: Stage 3 Build Plan

**Version:** final v1 · **Scope:** Python repos only · **Depends on:** `STAGE_1_2_PLAN.md`

> **What Stage 3 does:** it takes the raw facts from Stage 1–2 (`facts.json`, `code_index.json`, `sbom.cdx.json`) and turns them into **one connected, evidence-backed knowledge graph** of the repo.
> That graph is what the UI shows and what risk detection (CVEs, suspicious changes, evidence) runs on.

```
facts.json ─┐
code_index ─┼─► Graph builder ─► 3A Structural ─► 3B Semantic ─► 3C Flow ─► 3D Investigator ─► Knowledge graph ─► UI + risk detection
sbom.json  ─┘                    (algorithms)     (LLM cards)    (walks)    (1 bounded agent)
```

After Stage 2 we have **separate lists of facts**. After Stage 3 we have **the picture**: modules, what each does, how requests flow, blast radius, what changed, and explanations of odd things.

---

## 1. Ground rules

1. **Facts come from Stage 1–2; AI only explains.** No edge is ever invented by the LLM. AI writes descriptions, labels and findings, always with evidence + confidence.
2. **One shared graph.** All four parts read from and write to the same graph. Nothing rescans the repo.
3. **Every node and edge carries:** `discovered_by` (`ast` | `manifest` | `syft` | `pypi` | `git` | `algorithm` | `ai`), `evidence` (file+line or commit), `confidence` (1.0 for deterministic, model-given for AI), `commit`, `analyzed_at`.
4. **Still no risk verdicts.** Stage 3 records understanding (*"utils sends order data to an external domain, added 5 days ago"*). Risk detection judges it later. 3D may set `notable: true` with a reason, which risk detection treats as a hint.
5. **Bounded AI.** Fixed budgets for LLM calls and agent steps. Same input means same cached output.
6. **Honest coverage.** Report what was understood and what wasn't.

---

## 2. Stack

| Purpose | Tool |
|---|---|
| Graph | **NetworkX** `MultiDiGraph` (in-memory), saved as node-link JSON |
| Community detection | `networkx.community.louvain_communities` (fixed `seed` for reproducible results) |
| Schemas | Pydantic v2 (cards, findings, paths) |
| LLM | Any tool-calling LLM API behind one wrapper `llm.py` (so we can switch providers) · temperature 0 · JSON output validated by Pydantic |
| Agent (3D only) | **LangGraph** (or a plain tool-calling loop if short on time) |
| Cache | `diskcache` or JSON files keyed by sha256 of the LLM input |
| API for UI | FastAPI (section 9) |

---

## 3. Folder structure

```
guardian/stage3_knowledge/
  graph_builder.py      # load Stage 1–2 JSON -> NetworkX graph
  schema.py             # node/edge types, Pydantic models (cards, paths, findings)
  structural.py         # 3A
  semantic.py           # 3B
  prompts/              # 3B + 3D prompt templates
  flow.py               # 3C: execution paths + blast radius
  timetravel.py         # 3C: snapshots + diff
  investigator/         # 3D
    queue.py            # builds open-question queue
    tools.py            # agent tools
    agent.py            # LangGraph loop
  coverage.py
  export.py             # writes output files
  llm.py                # LLM wrapper + cache
```

---

## 4. The graph: node and edge types

### Nodes
| Type | ID example | Key attributes |
|---|---|---|
| `Repo` | `repo:mini-shop` | commit, card |
| `Module` | `module:app/payments` | files, centrality, tags, card |
| `File` | `file:app/payments/service.py` | sha256, loc, is_test, tags, card (optional) |
| `Function` / `Class` | `fn:app/payments/service.py::charge` | lines, params, tags |
| `Package` | `pkg:pypi/stripe@7.0.0` | direct, dev, origin metadata, tags |
| `Route` | `route:POST /checkout` | framework, handler |
| `CLIEntry` | `cli:app/manage.py` | |
| `EnvVar` | `env:STRIPE_KEY` | name only |
| `Table` | `table:orders` | model class |
| `ExternalService` | `svc:Stripe`, `svc:<domain>` | via (sdk/url) |
| `Workflow` / `Action` / `Image` | `action:actions/checkout@v4` | pinned_to_sha / digest |
| `Commit` | `commit:a1b2c3d` | date, author, message |

### Edges
| Edge | From → To | Source |
|---|---|---|
| `CONTAINS` | Repo → Module → File → Function | 3A |
| `IMPORTS` | File → File | Stage 2 |
| `DEPENDS_ON` | Module → Module (weight = number of imports) | 3A |
| `USES_PACKAGE` | File → Package | Stage 2 + dist map |
| `CALLS` | Function → Function | Stage 2 `resolved_target` |
| `CALLS_API` | Function → Package (attr: `target` = e.g. `yaml.load`) | Stage 2 |
| `REQUIRES` | Package → Package (transitive) | Stage 1 |
| `HANDLES` | Route → Function | Stage 2 |
| `RECEIVES_INPUT` | Function → Route (attr: `request.json`) | Stage 2 |
| `READS_ENV` | Function → EnvVar | Stage 2 |
| `READS` / `WRITES` | Function → Table | Stage 2 |
| `MAPS_TO` | Class → Table | Stage 2 |
| `CONTACTS` | Function → ExternalService | Stage 2 |
| `USES_ACTION` / `USES_IMAGE` | Workflow → Action, Repo → Image | Stage 1 |
| `CHANGED_IN` | Package / File → Commit (attr: added/removed/version from→to) | Stage 1 + 3C |

---

## 5. 3A: Structural Mapper (algorithms, no AI)

**Input:** the graph from `graph_builder.py`. **Output:** modules, module edges, tags, centrality.

1. **Link code to packages.** For each external import: import name → distribution (`import_name_to_distribution`) → purl → `USES_PACKAGE` / `CALLS_API` edges. Unmatched imports get the tag `unresolved_import`.
2. **Detect modules.**
   - a. **Seeds:** each folder with `__init__.py` under a source root becomes a candidate module.
   - b. **Clusters:** build an undirected file graph from internal `IMPORTS` (weight = import count) and run Louvain (`seed=42`).
   - c. **Reconcile:**
     - folder ≈ cluster → module confirmed
     - one folder splits into two or more clusters → submodules (`app/payments/a`, `…/b`) only if each has ≥ 3 files; otherwise keep the folder
     - a cluster spans several folders → keep the folders, tag them `tightly_coupled_with: [...]`, and add a question for 3D
     - flat repos (no packages) → clusters become modules
   - d. Test files go into a separate `tests` module.
3. **Module dependencies.** Roll file `IMPORTS` up to module `DEPENDS_ON` with weights. Detect cycles (`simple_cycles` on the module graph) and tag them.
4. **Declared vs used.**
   - Direct runtime package with no `USES_PACKAGE` edge from non-test files → `declared_unused`
   - External import with no declared package (could be transitive) → `undeclared_import`
   - Package used only by tests → `test_only`; dev-declared but used in runtime code → `dev_used_in_runtime`
5. **Tags on functions, propagated up to files and then modules:** `entry_point`, `receives_user_input`, `reads_secret_env`, `writes_db`, `reads_db`, `contacts_external`, `network`, `subprocess`, `code_exec`, `deserialize`.
6. **Centrality.** PageRank on the module graph gives the `core` modules (the top 20%).

---

## 6. 3B: Semantic Understanding (LLM cards)

**Goal:** add *meaning* that algorithms can't produce, as structured cards with evidence.

### What gets a card
- **Always:** every module, plus one repo card.
- **Files, eagerly:** files with a route or CLI entry, files tagged sensitive (secret / DB write / external / exec), files changed in the last 5 dependency commits.
- **Everything else:** lazily, when the UI or 3D asks for it.

### Order: leaves first
Module graph → condense cycles (`condensation`) → reverse topological order. Each module's prompt includes the cards of the modules it depends on, so understanding builds bottom-up.

### Prompt input (facts only, capped at about 3–4k tokens)
File list, docstrings, function signatures, routes, input sources, env var names, DB models/access, external services, packages used (with API calls), tags from 3A, cards of dependency modules. **No full source by default**; at most 1–2 short function bodies (≤ 40 lines) when a function is sensitive and has no docstring.

### Card schema (Pydantic)
```json
{
  "id": "module:app/payments",
  "purpose": "Processes customer payments through Stripe and records orders.",
  "responsibilities": ["Create Stripe charges", "Persist orders"],
  "inputs": ["amount from /checkout request"],
  "outputs": ["Stripe charge", "row in orders table"],
  "data_touched": ["table:orders", "env:STRIPE_KEY"],
  "external": ["svc:Stripe"],
  "sensitivity": "high",
  "sensitivity_reasons": ["reads secret STRIPE_KEY", "writes orders", "reachable from public route"],
  "confidence": 0.9,
  "evidence": [{"file": "app/payments/service.py", "lines": "5-8"}],
  "open_questions": []
}
```

### Validation (important)
- Every `evidence` file and line range must exist in `code_index.json`; every ID in `data_touched` / `external` must exist in the graph. If not, retry once, then drop the claim and lower confidence.
- If `confidence < 0.6` or `open_questions` is non-empty → push to the 3D queue.

---

## 7. 3C: Relationship & Flow Mapper (graph walks, no AI)

### 7.1 Execution paths
From every `Route` and `CLIEntry`: DFS over `HANDLES` → `CALLS` (max depth 8, no revisits). Record a path whenever it reaches a **sink**: `Table`, `ExternalService`, `EnvVar`, a `CALLS_API` edge, or a sensitive-call tag.
```json
{"entry": "route:POST /checkout", "input": "request.json",
 "steps": ["fn:app/api/routes.py::checkout", "fn:app/payments/service.py::charge"],
 "sinks": ["svc:Stripe", "table:orders", "env:STRIPE_KEY"],
 "evidence": [{"file": "app/api/routes.py", "line": 10}, {"file": "app/payments/service.py", "line": 7}]}
```
Paths are function-level, not variable-level. We say *"user input enters checkout() and checkout() reaches the orders write"*, not that a specific variable flows there.

### 7.2 Blast radius (for every package)
Reverse walk from a package node:
- package ← `REQUIRES` ← packages that pull it in (up to the direct dependency)
- ← `USES_PACKAGE` / `CALLS_API` ← files and functions
- ← `CALLS` ← callers, up to entry points

Output per package:
```json
{"package": "pkg:pypi/stripe@7.0.0", "via_direct": ["pkg:pypi/stripe@7.0.0"],
 "files": 1, "functions": ["fn:app/payments/service.py::charge"], "modules": ["module:app/payments"],
 "routes_reaching": ["route:POST /checkout"], "secrets_nearby": ["env:STRIPE_KEY"], "tables_nearby": ["table:orders"],
 "api_calls": ["stripe.Charge.create"], "radius": "large", "reasons": ["reachable from public route", "same function reads secret"]}
```
`radius` rule (simple and explainable):
- `none`: no code uses it
- `internal`: used, but no route reaches it
- `public`: reachable from a route
- `large`: public **and** near a secret, DB write or external service

This is **potential** reach, not proof that a vulnerable function runs.

### 7.3 Time travel
- For each commit in `facts.dependency_history` (max 10), build a **light snapshot**: packages, versions, CI actions, base images. Use `git show`, without a full code parse.
- Full graphs (with code) only for **HEAD** and one **baseline** commit (default: the oldest in range, or user-chosen).
- `diff(a, b)` → added / removed / changed nodes and edges, e.g. `+package colorama`, `PyYAML 5.4.1 → 6.0.1`, `+module app/utils`, `+CONTACTS fn:send_event → svc:<domain>`.
- Each change is attached to its `Commit` node via `CHANGED_IN`.

---

## 8. 3D: Contextual Investigator (the agent)

**One bounded agent.** It doesn't roam the repo: it works a queue of specific questions.

### 8.1 Queue: where questions come from
| Source | Example question |
|---|---|
| 3B low confidence / `open_questions` | "What does `app/utils` actually do?" |
| New in time-travel diff | "Why was module `app/utils` added in commit a1b2c3?" |
| `declared_unused` package | "Is `colorama` used anywhere (scripts, configs, entry points)?" |
| `undeclared_import` | "Where does `X` come from: transitive, vendored, or missing?" |
| Function with `contacts_external` + `receives_user_input` on one path | "What data does `send_event()` send, and where?" |
| Module tagged `tightly_coupled_with` | "Are `api` and `utils` really separate modules?" |
| Package with `radius: large` | "Which exact `stripe` APIs are used, and with what data?" |
| `dynamic_imports` present | "What can `importlib.import_module(name)` load?" |

**Priority:** new in diff > touches secret / input / external > large radius > low confidence > other. **Budget:** max 20 questions per scan, max 8 tool steps per question.

### 8.2 Tools
| Tool | Returns |
|---|---|
| `query_graph(node_id, edge_types, direction, depth)` | neighbours / callers / callees |
| `get_card(node_id)` | existing card (triggers a lazy 3B card if missing) |
| `read_code(file, start, end)` | source lines, max 120 per call |
| `grep(pattern, glob)` | file:line matches, max 50 |
| `git_history(file_or_package)` | commits, authors, messages, diffs (trimmed) |
| `pypi_info(package)` | Stage 1 metadata |
| `get_path(entry, sink)` | 3C paths |

### 8.3 Loop
```
pick question → plan → call tools → enough evidence? ─no→ call more tools (within budget)
                                         │yes
                                         ▼
                        write Finding (+ maybe new questions) → next question
```

### 8.4 Finding schema
```json
{
  "question": "What does send_event() send, and where?",
  "answer": "Sends order_id and amount via HTTP POST to <external-domain>/collect on every checkout. Added in commit a1b2c3 (5 days ago).",
  "subject": "fn:app/utils/helpers.py::send_event",
  "evidence": [{"file": "app/utils/helpers.py", "lines": "4-9"}, {"commit": "a1b2c3"}],
  "confidence": 0.85,
  "status": "resolved",
  "notable": true,
  "notable_reason": "user data leaves the system to a domain introduced in a recent commit",
  "new_questions": [],
  "steps_used": 4
}
```
**Validation:** every evidence item must have been returned by a tool call in this run. If not, the claim is dropped. Unanswered questions are kept with `status: unresolved`.

---

## 9. Outputs and the API for the UI

**Files in `output/<repo>/`:**
`graph.json` (node-link) · `cards.json` · `paths.json` · `blast_radius.json` · `changes.json` · `findings.json` · `coverage.json`

**FastAPI endpoints (for the clickable UI):**
| Endpoint | Gives |
|---|---|
| `GET /graph?level=repo` | modules + `DEPENDS_ON` (the zoomed-out map) |
| `GET /graph?level=module&id=…` | files, packages, routes, tables, services of one module |
| `GET /node/{id}` | node attributes + card + evidence + findings |
| `GET /paths?entry=…` | execution paths from a route |
| `GET /blast-radius/{purl}` | blast radius of a package |
| `GET /diff?from=…&to=…` | time-travel changes |
| `GET /coverage` | coverage report |

### `coverage.json`
```json
{"files_parsed": "9/9", "internal_calls_resolved": "14/15", "modules": 5, "modules_carded": 5,
 "files_carded": "4/9", "questions": {"resolved": 3, "unresolved": 1},
 "known_unknowns": ["1 dynamic import in app/plugins.py:12"]}
```

---

## 10. Who does what

| Person | Owns |
|---|---|
| **Dev A** | `graph_builder.py`, `schema.py`, 3A `structural.py` (**start first**; everyone depends on the graph) |
| **Dev B** | 3C: `flow.py` (paths, blast radius), `timetravel.py` |
| **Dev C** | 3B: `semantic.py`, prompts, validation, `llm.py` + cache |
| **Lead** | 3D investigator (queue, tools, LangGraph loop), `export.py`, FastAPI, integration |

Until `graph_builder.py` is ready, B, C and the lead work against a **hand-written mini-shop graph JSON** so nobody is blocked.

---

## 11. Expected results on `mini-shop`

- [ ] Modules: `api`, `payments`, `config`, `utils`, `tests` (+ `models` file under the app root)
- [ ] `api → payments`, `api → utils`, `payments → models` dependencies
- [ ] `colorama` tagged `declared_unused`
- [ ] Path: `POST /checkout (request.json) → checkout() → charge() → Stripe + orders + STRIPE_KEY`
- [ ] Path: `POST /checkout → checkout() → send_event() → <external-domain>`
- [ ] Blast radius: `stripe` = `large`, `PyYAML` = `internal`, `colorama` = `none`
- [ ] Diff baseline → HEAD: `+colorama`, `PyYAML` bumped, `+module utils`, `+CONTACTS → <external-domain>`
- [ ] Payments card: purpose correct, sensitivity high, evidence lines valid
- [ ] 3D finding on `send_event()` with evidence + commit, `notable: true`
- [ ] 3D finding on `colorama`: no usage anywhere, added in the same recent commit

---

## 12. Definition of done

- [ ] `guardian scan ./mini-shop` runs Stage 1 → 3 end to end and writes all output files
- [ ] Every section 11 item passes
- [ ] Runs on 2 real Flask/FastAPI repos (50–300 files) within budget: ≤ 30 LLM calls for 3B, ≤ 20 questions for 3D
- [ ] No AI claim without valid evidence; every node/edge has `discovered_by`
- [ ] Re-scan of an unchanged repo uses the cache (no new LLM calls)
- [ ] All API endpoints return data the UI can render

---

## 13. What comes next

**Day 1 slide steps 3–5** run on this graph:
- **Vulnerabilities:** query OSV with every package purl, attach CVEs to package nodes, and rank them using blast radius.
- **Suspicious changes:** typosquat check on package names, plus diff items, `notable` findings, unpinned actions/images, and install-script checks.
- **Evidence:** component, dependency path (from `REQUIRES` + blast radius), supporting evidence (cards, findings, lines), initial risk level.