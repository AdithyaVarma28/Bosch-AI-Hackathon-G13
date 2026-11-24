# Software Supply Chain Guardian: Stage 4 Build Plan
## Vulnerability Investigation Engine (Day 1, slide step 3)

**Version:** final v1 · **Scope:** Python repos + one container image · **Depends on:** `STAGE_1_2_PLAN.md`, `STAGE_3_PLAN.md`

> **What Stage 4 does:** finds known vulnerabilities **deterministically** (OSV, Grype), then uses a **LangGraph agent workflow** to investigate whether each one actually matters *in this repo*: is the vulnerable API used, can untrusted input reach it, and what's the evidence?
>
> A scanner says *"PyYAML, Critical, upgrade."* We say *"the vulnerable function is called here, its input comes from there, this is the proof, this is how sure we are, and a human signed off."*

```
1 Discovery ─► 2 Prioritize ─► 3 Advisory analyst ─► 4 Repo investigator ─► 5 Verifier* ─► 6 Risk ─► 7 Human review* ─► 8 Report
 no AI          no AI           AI (1 call)           AI agent (tools)        AI (conditional)  rules     interrupt (conditional)  no AI
```
`*` runs only when needed (see 5 and 7).

---

## 1. Ground rules

1. **AI never creates vulnerability data.** IDs, affected versions, CVSS and fixed versions come only from OSV / Grype / KEV / EPSS.
2. **Three separate values; never overwrite one with another:**
   | Value | Meaning | Who sets it |
   |---|---|---|
   | **Severity** (CVSS) | How bad the vulnerability is in general | Database |
   | **Project risk** | How much it matters in *this* repo | Rule table (section 8) |
   | **Confidence** | How sure our investigation is | Evidence quality (section 8) |
3. **"No path found" ≠ safe.** Static analysis misses dynamic imports, reflection, runtime config. The wording is always *"no path found"*, never *"not exploitable"*.
4. **Every claim cites evidence** that a tool actually returned (file + lines, graph path, advisory URL). Uncited claims are dropped.
5. **Bounded agents.** Fixed tool budgets, one retry, then `unknown`. Unknown is an acceptable answer.
6. **Downgrade guard.** If a CVSS ≥ 9 runtime vulnerability ends up below High, a human must approve.
7. **Reuse Stage 3.** Same graph, same tools as the 3D investigator. Nothing rescans the repo.

---

## 2. Stack

| Purpose | Tool | Notes |
|---|---|---|
| Python package vulns | **OSV.dev API**: `POST https://api.osv.dev/v1/querybatch` (purls) → IDs; `GET https://api.osv.dev/v1/vulns/{id}` → details | Free, no key. Covers PyPA advisories + GitHub advisories |
| Offline fallback | OSV PyPI data dump (`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`) | Download before the demo in case Wi-Fi fails (verify the URL beforehand) |
| Cross-check | `pip-audit` (can use OSV) | Optional sanity check |
| Container image vulns | **Grype**: `grype sbom:output/<repo>/sbom.cdx.json -o json` and `grype <image> -o json` | OS packages in the base image |
| CVSS score from vector | `cvss` Python library | OSV gives vectors like `CVSS:3.1/AV:N/...` |
| Actively exploited | CISA KEV JSON feed (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) | Cache once per day |
| Exploit probability | EPSS API (`https://api.first.org/data/v1/epss?cve=CVE-…`) | Batch CVEs |
| Workflow | **LangGraph** (`StateGraph`, `Send` for per-vuln fan-out, `interrupt` + checkpointer for human review) | `SqliteSaver` checkpointer so review survives restarts |
| LLM | Same `llm.py` wrapper as Stage 3 (temperature 0, Pydantic-validated JSON, cached) | |

---

## 3. Folder structure

```
guardian/stage4_vulns/
  discovery.py          # 1: OSV + Grype + KEV + EPSS + transitive paths
  prioritize.py         # 2: triage queue
  analyst.py            # 3: advisory -> fingerprint
  investigator.py       # 4: agent (uses stage3 investigator/tools.py + 2 new tools)
  verifier.py           # 5
  risk.py               # 6: rule table + confidence
  review.py             # 7: interrupt + triage store
  report.py             # 8: write results + graph update
  workflow.py           # LangGraph wiring
  schema.py             # Pydantic: VulnMatch, Fingerprint, Investigation, Verdict, Finding
  prompts/
```

---

## 4. Step 1: Discovery (deterministic)

**Input:** all `Package` nodes (purls) from the Stage 3 graph + the SBOM.

1. **OSV batch query** with every purl. For each hit, fetch the full record.
2. **Grype** on the SBOM and the container image. Image-level OS packages are tagged `scope: container_os`.
3. **Normalize** each match into a `VulnMatch`:
```json
{
  "vuln_id": "GHSA-xxxx-xxxx-xxxx",
  "aliases": ["CVE-XXXX-YYYY", "PYSEC-XXXX-NN"],
  "package": "pkg:pypi/pyyaml@5.3.1",
  "summary": "…",
  "details": "… full advisory text …",
  "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/…", "score": 9.8, "band": "critical"},
  "affected_ranges": [{"introduced": "0", "fixed": "5.4"}],
  "fixed_versions": ["5.4"],
  "references": [{"type": "FIX", "url": "https://github.com/…/commit/…"}, {"type": "ADVISORY", "url": "…"}],
  "kev": false,
  "epss": {"score": 0.02, "percentile": 0.87},
  "source": ["osv"],
  "scope": "runtime"
}
```
4. **Scope** from the graph: `runtime` | `dev` | `test_only` | `build` | `container_os`.
5. **Transitive path.** Walk `REQUIRES` back to the direct dependency and its manifest line:
   `urllib3@x ← requests@y ← stripe@z ← requirements.txt:2`. This satisfies *"trace vulnerable transitive dependencies back to their source"*, and it tells us which direct dependency must change.
6. Deduplicate by alias (the same CVE from OSV and Grype counts once).

---

## 5. Step 2: Prioritization queue (deterministic)

Score for the **order of investigation only** (this is not the risk):
```
priority = 100·kev + 10·cvss + 20·(blast_radius == "large") + 10·(blast_radius == "public")
         + 5·(scope == "runtime") + 10·epss_percentile − 30·(scope in {test_only, dev})
```
- **Deep investigation:** top 25 by priority.
- **Light pass** (no agent; risk from rules with `usage: unknown`): the rest, plus all `container_os` (usage `not_applicable`).
- If a package has **zero `USES_PACKAGE` edges and isn't required by a used package**, go straight to `usage: package_not_imported` with no agent.

---

## 6. Step 3: Advisory analyst (AI, one call per vuln)

Reads `summary` + `details` (+ optionally the FIX commit diff, trimmed to the changed function names) and outputs a **fingerprint**:
```json
{
  "vuln_id": "GHSA-…",
  "vulnerable_symbols": ["yaml.load", "yaml.full_load", "yaml.FullLoader"],
  "safe_alternatives": ["yaml.safe_load", "yaml.SafeLoader"],
  "trigger_conditions": [
    {"type": "untrusted_input", "text": "attacker controls YAML passed to the loader"},
    {"type": "argument", "text": "Loader is not SafeLoader"}
  ],
  "impact": "remote code execution",
  "attack_vector": "network",
  "symbols_source": "advisory_text",
  "confidence": 0.8,
  "evidence": [{"advisory": "GHSA-…", "quote_span": "…short span…"}]
}
```
Rules:
- `symbols_source`: `advisory_text` | `fix_commit` | `none`.
- If no symbol can be identified → `vulnerable_symbols: []`, `symbols_source: none`. The investigator then checks package-level usage only, and the usage verdict can be at most `package_used_symbol_unknown`.
- Validate that every symbol starts with an import name of the affected package (via `import_name_to_distribution`). Drop the ones that don't.

---

## 7. Step 4: Repository investigator (AI agent)

**Input:** `VulnMatch` + fingerprint + Stage 3 graph.
**Goal:** answer three questions with evidence:
1. **Usage:** is a vulnerable symbol called, or at least the package?
2. **Reachability:** is there a path from an entry point to that call?
3. **Conditions:** do the trigger conditions hold (untrusted input, unsafe argument, config flag)?

### Tools (reused from Stage 3 `investigator/tools.py`, plus 2 new)
| Tool | Use |
|---|---|
| `query_graph(node, edges, direction, depth)` | `CALLS_API` edges to `yaml.load`, `USES_PACKAGE` |
| `trace_callers(function_id, max_depth)` | callers up to routes / CLI / startup (reverse `CALLS`) |
| `get_path(entry, function_id)` | Stage 3 execution paths |
| `input_sources(function_id)` | Stage 2 `input_sources` on the function and its callers (function-level, not variable-level dataflow) |
| `read_code(file, start, end)` | ≤ 120 lines per call; check arguments like `Loader=` |
| `search_code(pattern, glob)` | symbols, aliases, config flags |
| `git_history(file)` | when the call was introduced |
| **new** `advisory(vuln_id)` | the full `VulnMatch` + fingerprint |
| **new** `verify_evidence(file, lines, claim)` | checks the lines exist, returns them for self-check |

### Budget
Max **10 tool calls** per vuln, max **120 lines** per read. When the budget runs out, return what's proven and mark the rest `unknown`.

### Output: `Investigation`
```json
{
  "vuln_id": "GHSA-…", "package": "pkg:pypi/pyyaml@5.3.1",
  "usage": "symbol_called",
  "usage_sites": [{"function": "fn:app/config/load.py::load_config", "file": "app/config/load.py", "lines": "12-12",
                   "code": "data = yaml.load(f)", "unsafe_argument": true}],
  "reachability": "internal_only",
  "paths": [["startup:app/__init__.py", "fn:app/config/load.py::load_config"]],
  "conditions": [
    {"condition": "untrusted_input", "status": "not_shown", "note": "input is a local file path from settings, no route input found"},
    {"condition": "argument", "status": "met", "note": "no Loader argument"}
  ],
  "unknowns": ["whether the config file can be modified by users at runtime"],
  "claims": [
    {"text": "yaml.load is called without a safe loader", "evidence": [{"file": "app/config/load.py", "lines": "12-12"}]}
  ],
  "tool_calls_used": 6
}
```
Allowed values:
- `usage`: `symbol_called` | `package_used_symbol_not_found` | `package_used_symbol_unknown` | `package_not_imported` | `not_applicable` (container OS)
- `reachability`: `public_path` (from a route / CLI with user input) | `internal_only` (startup, jobs) | `no_path_found` | `unknown`
- condition `status`: `met` | `not_shown` | `unknown`

---

## 8. Step 5: Verifier (AI, conditional)

**Runs only when any of these is true** (to save calls):
- project risk would be **lower** than the CVSS band (a downgrade)
- project risk is **Critical**
- confidence would be medium or low
- the investigator's claims rely on `read_code` only (no graph edge backs them)
- usage and reachability disagree (e.g. `public_path` but `symbol_not_found`)

**What it does:** for each claim, re-fetch the cited lines (`verify_evidence`) and ask: does this text actually show the claim? If a claim fails, send it back to the investigator **once** with the objection. If it fails again, drop the claim and lower confidence. Output: `verified: true/false`, plus per-claim results.

---

## 9. Step 6: Risk assessment (rules decide, AI explains)

### Project risk rule table (first match wins)
| # | Condition | Project risk |
|---|---|---|
| 1 | `kev` and usage ∉ {`package_not_imported`} and scope = runtime | **Critical** |
| 2 | CVSS ≥ 9 and `symbol_called` and `public_path` and no trigger condition `not_shown` | **Critical** |
| 3 | CVSS ≥ 7 and `symbol_called` and reachability ∈ {`public_path`, `unknown`} | **High** |
| 4 | CVSS ≥ 9 and `symbol_called` (any reachability) | **High** |
| 5 | CVSS ≥ 9 and usage ∈ {`package_used_symbol_unknown`, `package_used_symbol_not_found`} and runtime | **High** if `public_path` reaches the package, else **Medium** |
| 6 | CVSS ≥ 7 and runtime and usage ≠ `package_not_imported` | **Medium** |
| 7 | CVSS 4–7 and `symbol_called` | **Medium** |
| 8 | `container_os` | CVSS band, capped at **High** unless KEV |
| 9 | `package_not_imported` and runtime | **Low** (still ships, so fix it cheaply) |
| 10 | test_only / dev / build | **Low** |
| 11 | anything else | **Low** |

**Downgrade guard:** if CVSS ≥ 9, scope is runtime, and the result is Medium or Low, then `needs_human_review = true`.

### Confidence
| Confidence | When |
|---|---|
| **High** | usage + reachability backed by graph edges and verified lines; trigger conditions `met` or `not_shown` with evidence |
| **Medium** | partly graph-backed, or some condition `unknown`, or verifier corrected something |
| **Low** | symbol unknown, budget exhausted, verifier failed, or `no_path_found` with dynamic imports present in the affected module |

### Explanation (AI)
One LLM call writes 2–3 plain-English sentences **from the verified claims only**, plus a recommendation that uses the `fixed_versions` / `safe_alternatives` (e.g. *"Upgrade to 5.4+ or switch to `yaml.safe_load`"*). It must not change the risk.

---

## 10. Step 7: Human review (LangGraph `interrupt`, conditional)

**Pause for a human when:** the downgrade guard fires, confidence is Low, the verifier failed, or the project risk is Critical (confirm before it's shown as Critical in the report).

**Reviewer sees:** the finding card (section 11) + evidence snippets.
**Actions:** `confirm` · `dismiss` (reason required: *false positive / not used / accepted risk / mitigated elsewhere*) · `override` (new project risk + reason).

**Stored in** `output/<repo>/triage.json`, keyed by `(vuln_id, purl, sha256 of the usage-site files)`. On re-scan, the decision is reused **only if** the package version and those files are unchanged. Otherwise it's re-opened.

Implementation: `interrupt({...finding...})` inside the review node; resume with `Command(resume={"action": "...", "reason": "..."})`; `SqliteSaver` checkpointer. The UI calls `POST /review/{finding_id}`.

---

## 11. Step 8: Report & graph update (deterministic)

**Graph:** new node type `Vulnerability` (`vuln:GHSA-…`), with edges:
- `AFFECTS` Vulnerability → Package (attrs: ranges, fixed versions)
- `USED_AT` Vulnerability → Function (usage sites)
- `REACHED_VIA` Vulnerability → Route / CLIEntry (paths)

**Finding card (what the UI and judges see):**
```json
{
  "finding_id": "F-007",
  "component": "pkg:pypi/pyyaml@5.3.1",
  "vuln_id": "GHSA-…", "aliases": ["CVE-…"],
  "severity": {"cvss": 9.8, "band": "critical", "vector": "CVSS:3.1/…"},
  "kev": false, "epss_percentile": 0.87,
  "dependency_path": ["requirements.txt:3", "pkg:pypi/pyyaml@5.3.1"],
  "usage": "symbol_called",
  "reachability": "internal_only",
  "project_risk": "high",
  "confidence": "medium",
  "explanation": "The vulnerable loader is called without a safe Loader in load_config(), which runs at startup. Its input is a local config file; no path from a public route was found. Whether users can modify that file at runtime was not verified.",
  "evidence": [
    {"type": "code", "file": "app/config/load.py", "lines": "12-12", "snippet": "data = yaml.load(f)"},
    {"type": "path", "path": ["startup", "load_config"]},
    {"type": "advisory", "url": "…"}
  ],
  "fix": {"upgrade_to": "5.4", "code_change": "use yaml.safe_load"},
  "review": {"status": "confirmed", "by": "…", "reason": null},
  "verified": true,
  "discovered_by": ["osv", "ai"]
}
```
This covers slide step 5: what was detected, which component, dependency path, supporting evidence, initial risk level.

**Files:** `output/<repo>/vulns.json` (all matches) · `vuln_findings.json` (cards) · `triage.json` (human decisions)

**API (for the UI):**
| Endpoint | Gives |
|---|---|
| `GET /vulns?risk=&scope=` | list of finding cards |
| `GET /vulns/{finding_id}` | full card + investigation trace (tool calls, for transparency) |
| `GET /blast-radius/{purl}` | from Stage 3, now with attached vulns |
| `POST /review/{finding_id}` | human decision → resumes the workflow |

---

## 12. LangGraph wiring

```python
class VulnState(TypedDict):
    match: VulnMatch
    fingerprint: Fingerprint | None
    investigation: Investigation | None
    verification: Verification | None
    verdict: Verdict | None
    review: Review | None

# main graph
discover -> prioritize -> Send("investigate_one", match) for each deep item
                        -> light_pass for the rest
investigate_one subgraph:
  analyst -> investigator -> (needs_verifier? verifier : risk)
  verifier -> (retry_once? investigator : risk)
  risk -> (needs_review? review[interrupt] : report)
  review -> report
```
- Fan-out with `Send` lets deep investigations run in parallel (cap concurrency at about 4 for LLM rate limits).
- Store each node's input/output, so the UI can show the **investigation trace**. Judges love seeing the agent's reasoning steps.

---

## 13. Who does what

| Person | Owns |
|---|---|
| **Dev A** | `discovery.py` (OSV, Grype, KEV, EPSS, CVSS, transitive paths, offline dump), `prioritize.py` |
| **Dev B** | `analyst.py` + prompts + fingerprint validation |
| **Dev C** | `investigator.py`, the 2 new tools, `verifier.py` |
| **Lead** | `workflow.py` (LangGraph), `risk.py`, `review.py`, `report.py`, API + UI finding cards |

Until discovery is ready, B and C work from a **hand-written `VulnMatch` for PyYAML**.

---

## 14. Fixture update: `mini-shop` vulnerable versions

Add to `mini-shop` so that every branch of the rule table is exercised:
- **PyYAML** pinned to an old version that OSV flags for unsafe loading, used via `yaml.load` in `config/load.py`. Expected: `symbol_called`, `internal_only`, **High**, review triggered (downgrade guard).
- **A package OSV flags, but whose vulnerable symbol we don't call** (e.g. an old version of a library where we only use a safe function). Expected: `package_used_symbol_not_found`, **Medium** or **High** per rule 5.
- **A vulnerable transitive package** pulled in by a direct one. Expected: dependency path traced to the manifest line.
- **A vulnerable package only in `requirements-dev.txt`.** Expected: **Low**.
- **The Docker base image.** Expected: some `container_os` findings from Grype.

⚠ **Before freezing the fixture, query OSV for each chosen version to confirm it's actually flagged.** Don't rely on memory.

---

## 15. Definition of done

- [ ] `guardian scan ./mini-shop` runs Stage 1 → 4 and writes `vulns.json`, `vuln_findings.json`
- [ ] Every fixture case in section 14 lands on its expected usage / reachability / risk
- [ ] CVSS, project risk and confidence are always separate fields
- [ ] Every AI claim in a finding has verified evidence; no vuln ID, version or CVSS comes from the LLM
- [ ] Downgrade guard triggers the review pause; confirm/dismiss/override resumes the workflow and is persisted
- [ ] Re-scan with no changes reuses cache and triage decisions
- [ ] Budget held: ≤ 25 deep investigations, ≤ 10 tool calls each, ≤ 1 verifier retry
- [ ] Works offline with the OSV dump
- [ ] UI shows finding cards + the investigation trace

---

## 16. What comes next

- **Stage 5 (slide step 4): suspicious changes.** Typosquats, unexpected dependencies, suspicious updates, unsafe install scripts, untrusted images, modified lockfiles. It uses the same agent pattern (fingerprint → investigate → verify → risk → review) on the time-travel diff and 3D's `notable` findings.
- **Day 2: remediation.** Uses `fix.upgrade_to` and `safe_alternatives`, checks whether the upgrade breaks dependents (`REQUIRES` constraints), proposes a change, and a human approves before it's applied, followed by a rescan.