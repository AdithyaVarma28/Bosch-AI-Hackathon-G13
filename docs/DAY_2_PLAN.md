# Software Supply Chain Guardian: Day 2 Build Plan
## Brain & Shield: prioritize, remediate, approve, verify

**Goal (slide):** *"Show us how the Guardian takes a finding from detection to verified remediation."*
Prioritized risk → recommended fix → human approval → build & test → rescan → verified remediation.

Day 2 continues Stages 4–6. It is **not** a new "Stage 7". All new code goes in `guardian/day2/`. The UI gets one new page, **Remediation (page 4)**.

---

## 0. Ground rules

1. **The AI judges inputs, rules decide outcomes.** The LLM answers narrow questions and cites evidence IDs. Deterministic tables compute the decision, priority and confidence. The LLM never sets a priority or a confidence directly.
2. **Every AI output is checked.** Any cited evidence ID that doesn't exist, or any version or symbol that isn't in the tool results, causes rejection. Then we fall back to the deterministic path, as in Stage 4.
3. **Nothing touches the original repo.** Patches are applied only in a temporary `git worktree`. Applying the fix creates a local branch `guardian/fix-<id>`. We never merge to the main branch and never push.
4. **Every code change needs human patch approval,** whatever its confidence.
5. **Works without an LLM.** Without a key, everything runs deterministically: prioritization from the CVSS vector, template remediations. AI only makes things better.
6. **Don't depend on 120B.** 20B is the default. 120B is used only for the "Revise with agent" button, and we fall back to 20B if its quota is gone.
7. **Never Docker, never real Grype.** The sandbox is a `git worktree` plus a throwaway venv in a subprocess with timeouts.
8. **No new agent types or technologies beyond this document.**

---

## 1. Folder structure

```
guardian/day2/
  __init__.py
  schema.py          # RegisterEntry, Decision, Remediation, Candidate, Proposal, CheckResult, AuditEvent
  register.py        # unified findings register (Stage 4 + Stage 5)
  ssvc.py            # decision tables (CVE tree + supply-chain table) + priority mapping
  prioritize.py      # gathers inputs, calls the AI classifier, computes decision/priority/confidence
  candidates.py      # deterministic remediation candidates (versions, removal, block, code fix)
  skills.py          # SKILL.md discovery + progressive loading
  skills/
    upgrade-dependency/SKILL.md
    replace-unsafe-api/SKILL.md
    remove-or-block-package/SKILL.md
    harden-ci-cd/SKILL.md
  agent.py           # remediation agent (LangGraph tool loop, budgeted)
  tools.py           # agent tools (reuse stage4_vulns/tools.py where possible)
  critic.py          # static checks + AI critic + fix_confidence rules
  sandbox.py         # worktree, venv, build, tests, rescan, SBOM diff (Phase B)
  workflow.py        # LangGraph remediation graph with two human interrupts
  history.py         # risk_history.json + audit.jsonl (append-only)
  vex.py             # optional OpenVEX output (last item)
  api.py             # FastAPI routes, attached like stage4_vulns/api.py
  cache.py           # content-hash cache for all AI + candidate results
  prompts/
    classify_system.md   # SSVC inputs (Automatable, Technical impact)
    remediate_system.md  # remediation agent
    critic_system.md     # "does this patch remove the cited vulnerable path?"
```

**Output files** (in `output/scans/<scan>/`): `register.json`, `remediations.json`, `remediation.sqlite` (LangGraph checkpoints), `risk_history.json`, `audit.jsonl`, `validation/<rid>/…` (logs, SBOM diff), and optionally `vex.json`.

**CLI:**
- `python -m guardian.cli prioritize <scan>`
- `python -m guardian.cli remediate <scan> [--finding F-007]`
- `python -m guardian.cli validate <scan> <rid>`

`scan` runs prioritize and candidate generation automatically after Stage 5. The agent runs inside `scan` only if `GUARDIAN_LLM_PURPOSES` includes `remediate`. Otherwise it runs on demand.

---

## 2. Unified findings register (`register.py`)

There is one list for Stage 4 vulnerability findings and Stage 5 suspicious findings. Each finding type keeps its own evidence, and **fields that don't apply stay `null`**. A typosquat gets no fake CVSS or EPSS.

```jsonc
{
  "finding_id": "F-007",                 // existing id, unchanged
  "kind": "vulnerability" | "suspicious",
  "subtype": "cve" | "typosquat" | "install_hook" | "lockfile_integrity" | "ci_workflow" | "unexpected_change" | "suspicious_update" | "base_image",
  "component": "pkg:pypi/pyyaml@5.3.1",  // or file path for CI/code findings
  "title": "...",
  "cvss":  { "score": 9.8, "vector": "CVSS:3.1/AV:N/..." } | null,
  "epss":  { "probability": 0.012, "percentile": 0.84, "date": "..." } | null,   // keep both
  "kev":   true | false | null,
  "stage_risk": "High",                  // Stage 4 rule table / Stage 5 suspicion×exposure (kept, not replaced)
  "stage_confidence": "Medium",
  "usage": "...", "reachability": "...", "scope": "runtime|dev|test|build",
  "sensitivity": { "level": "high|medium|low", "reasons": ["reads secret STRIPE_KEY", "writes db orders"] },
  "evidence_ids": ["E-12", "E-13"],
  "links": { "evidence": "/scans/:id/findings/F-007", "modules": [...], "files": [...] }
}
```

**Sensitivity source:** Stage 3 `semantic.sensitivity()` gives each module a level plus reasons (secrets, DB writes, external services, dangerous calls, routes). For each finding, take the **maximum** over the modules that contain its usage sites. For suspicious findings, use the modules that import the package, or for CI findings, the workflow's secrets and permissions.

---

## 3. Risk prioritization (`ssvc.py`, `prioritize.py`)

### 3.1 Naming (be precise in the UI and the pitch)
We use **SSVC-inspired decision points following CISA's SSVC guide**. We do **not** claim full CISA SSVC compliance. In the UI the label is "Decision (SSVC-inspired)".

Each finding keeps **four separate fields**, never merged:

| Field | Meaning | Values |
|---|---|---|
| `cvss` | Original severity from the advisory | number or null |
| `decision` | What to do | Act · Attend · Track\* · Track |
| `priority` | Project priority used for ordering | Critical · High · Medium · Low |
| `finding_confidence` | How sure we are that the finding is real and correctly assessed here | High · Medium · Low |

### 3.2 Decision points for CVE findings

| Decision point | Values | Who decides | How |
|---|---|---|---|
| **Exploitation** | none · poc · active | Rules | `active` if KEV. `poc` if an advisory reference is tagged EXPLOIT/POC, or EPSS percentile ≥ 0.90. Otherwise `none`. |
| **Automatable** | yes · no | **AI**, rule fallback | Fallback: `yes` if the CVSS vector has AV:N, PR:N and UI:N. The AI also uses the analyst's trigger conditions (for example "attacker must control the YAML input" plus whether our input is attacker-controlled). |
| **Technical impact** | partial · total | **AI**, rule fallback | Fallback: `total` if C:H, I:H and A:H, or the advisory says RCE/code execution. The AI also uses **what the vulnerable call site touches in this repo** (graph: DB writes, secrets, exec, network). |
| **Mission & well-being** | low · medium · high | Rules (graph) | `high` = sensitivity high **and** runtime, **or** reachable from a public route that touches secrets, payments, auth or DB writes. `medium` = runtime with public reach, or sensitivity medium. `low` = internal-only with low sensitivity, or dev/test/build scope. |

**Decision table (CVE).** Encode it from CISA's published tree and **double-check it against the CISA SSVC guide before the demo**. Columns are mission & well-being low / medium / high:

| Exploitation | Automatable | Tech. impact | low | medium | high |
|---|---|---|---|---|---|
| none | no | partial | Track | Track | Track |
| none | no | total | Track | Track | Track\* |
| none | yes | partial | Track | Track | Attend |
| none | yes | total | Track | Track | Attend |
| poc | no | partial | Track | Track | Track\* |
| poc | no | total | Track | Track\* | Attend |
| poc | yes | partial | Track | Track | Attend |
| poc | yes | total | Track | Track\* | Attend |
| active | no | partial | Track | Track | Attend |
| active | no | total | Track | Attend | Act |
| active | yes | partial | Attend | Attend | Act |
| active | yes | total | Attend | Act | Act |

### 3.3 Decision for suspicious (non-CVE) findings
SSVC is about vulnerabilities, so suspicious findings use a separate table, recorded as `decision_model: "guardian-supplychain"`. Inputs are the existing Stage 5 **suspicion** (Low/Medium/High/Verified-strong) and **exposure** (`install_path`, `runtime_public`, `runtime_internal`, `ci_with_secrets`, `not_in_install_set`/`installed_unused`).

| Suspicion \ Exposure | install_path / ci_with_secrets | runtime_public | runtime_internal | not installed / unused |
|---|---|---|---|---|
| Verified strong | Act | Act | Attend | Track\* |
| High | Act | Attend | Attend | Track |
| Medium | Attend | Track\* | Track\* | Track |
| Low | Track\* | Track | Track | Track |

### 3.4 Priority (separate from decision)
`priority = base(decision)`, then the modifiers below in order:

| Base | Act → Critical · Attend → High · Track\* → Medium · Track → Low |
|---|---|
| Modifier 1 | Scope `dev`/`test` with no CI-secret exposure → **cap at Low** |
| Modifier 2 | `not_in_install_set` / `installed_unused` → **cap at Low** (still fix cheaply: remove it) |
| Modifier 3 | Sensitivity high **and** the decision came from the fallback rules (no AI) → **+1 band**, capped at High |
| Modifier 4 | KEV and runtime → **at least High** |

Store `priority_reasons[]`, one line per rule that fired, so the UI can show "why this rank".

**Ordering inside the same priority band:** decision, then KEV, then EPSS probability, then CVSS, then sensitivity, then the number of affected modules.

### 3.5 The AI classifier (one call, no tool loop)
- **Model:** 20B, structured JSON. We send an **evidence pack**, not a free tool loop: advisory summary, analyst trigger conditions, usage sites with code snippets, sensitivity reasons, and route paths. All of this is already collected in Stage 4/5.
- **Output:** `{automatable, technical_impact, rationale, evidence_ids[]}`. The verifier rejects unknown evidence IDs and falls back to the rules.
- **Self-consistency:** for findings whose provisional priority is Critical/High, ask **twice**. If the two answers disagree, `classifier_agreement = false`.
- **Only for CVE findings.** Suspicious findings already have Stage 5 investigator output, so no extra call is needed.

### 3.6 Finding confidence
Start from `stage_confidence` (the Stage 4/5 rules), then:
- **Lower one level** if the `stage_risk` band and the new `priority` differ by ≥ 2 bands (rules and context disagree).
- **Lower one level** if `classifier_agreement == false`.
- **Lower to at most Medium** if the AI output was rejected and the fallback was used for a Critical/High finding.

Each step adds a line to `confidence_reasons[]`.

### 3.7 History (`history.py`) — never overwrite silently
`risk_history.json` is keyed by `(kind, subject, component)` and is append-only. Each entry stores `scan_id`, `timestamp`, `priority`, `decision`, `inputs` (all decision points), `evidence_hash`, `change_reason` (for example "EPSS percentile 0.62 → 0.93", "new public route reaches yaml.load"), and the human decision if there was one. The UI shows "Priority changed High → Critical on <date>: <reason>".

---

## 4. Remediation

**Unit of remediation ≠ unit of finding.** One upgrade can fix several CVEs of the same package. A remediation has `rid` (`R-003`), `finding_ids[]`, and a `target` (package, file or workflow).

### 4.1 Step A: deterministic candidates (`candidates.py`), for every finding

**Version candidates** (`upgrade-dependency`). List the versions from the configured index (`GUARDIAN_PYPI_URL`, otherwise PyPI, using the Stage 1 `pypi_meta` cache), then filter:
1. The version is greater than the current one and **fixes every open vuln of this package** (OSV ranges).
2. **Available** on the configured index (not yanked).
3. `requires_python` is compatible with the project's Python (`pyproject`/CI matrix/Dockerfile; if unknown, use the running interpreter and mark it unknown).
4. **Satisfies the `REQUIRES` constraints** of every dependent in the graph. Transitive conflicts get resolved with the Stage 1 resolver.
5. **OSV query on the candidate version** returns no known vuln, so we don't introduce new ones.

Rank the survivors by: same major first, then fewest constraint changes, then lowest version. Keep the **top 3**, each with `compatibility_notes` (major bump? Python change? constraints touched?).

**Other candidate types:**

| Situation | Candidate | Skill |
|---|---|---|
| `package_not_imported` / `installed_unused` | Remove from the manifest and lockfile | remove-or-block-package |
| Typosquat / verified malicious package | Remove and replace with the intended package (e.g. `reqeusts` → `requests`), add a block-list entry | remove-or-block-package |
| Vulnerable symbol called and a safe API exists (from the analyst's `safe_alternatives`, e.g. `yaml.load` → `yaml.safe_load`) | Code change at each usage site | replace-unsafe-api |
| `pull_request_target` checks out the PR head / write-all permissions / unpinned actions | Workflow hardening | harden-ci-cd |
| No safe version exists | **Escalate to security review** (no patch) | — |
| Hash mismatch / base image (later) | Pin hash / bump base image | *later skills* |

**Template plan (no AI).** Every remediation gets a deterministic plan: the action, the generated patch for simple version bumps, removals and block entries, before → after risk, and rollback (`git revert` of the fix commit, or restoring the previous pin). This is all that Medium/Low findings get unless a user asks for more.

### 4.2 Step B: remediation agent with Skills (`agent.py`, `skills.py`)

**When:** for priority Critical/High (in `scan` if enabled, otherwise lazily when page 4 opens the item), and whenever the user clicks **Regenerate with agent** or **Revise with agent**.

**How Skills are loaded (we implement this ourselves; SKILL.md is just the format):**
1. `skills.py` scans `day2/skills/*/SKILL.md` and parses the frontmatter (`name`, `description`).
2. The agent's first prompt contains **only the names and descriptions**, plus the candidates from Step A.
3. The agent calls `load_skill(name)`, and only then does the full body enter the context (progressive disclosure).
4. A skill body contains: when to use it, steps, patch rules (what files may change), required checks, and one worked example.

**Initial skills (4):** `upgrade-dependency`, `replace-unsafe-api`, `remove-or-block-package`, `harden-ci-cd`. Add `pin-hash` and `bump-base-image` later.

**Tools** (budget: 8 calls on 20B, 12 on 120B; reuse `stage4_vulns/tools.py`):

| Tool | Returns |
|---|---|
| `load_skill(name)` | Skill body |
| `get_evidence(finding_id)` | The finding card plus evidence snippets |
| `graph_usage(package)` | Call sites and symbols our code uses from the package |
| `read_file(path, start, end)` | Lines (repo-relative, read-only) |
| `list_candidates(rid)` | Step A candidates |
| `check_constraints(package, version)` | Resolver result |
| `osv_query(package, version)` | Known vulns in that version |
| `symbols_in_version(package, version)` | Public symbols, from parsing the sdist/wheel with the existing Stage 5 archive sandbox (no install) |
| `make_patch(edits[])` | Unified diff plus the `git apply --check` result in a scratch worktree |

**Output (`Proposal`):**
```jsonc
{ "rid": "R-003", "version": 2, "author": "agent:gpt-oss-20b" | "template" | "agent:gpt-oss-120b",
  "skill": "replace-unsafe-api",
  "action": "Replace yaml.load(..., FullLoader) with yaml.safe_load at app/__init__.py:14",
  "patch": "--- a/app/__init__.py\n+++ b/...",
  "expected_risk": { "before": "High", "after": "Low", "why": "vulnerable loader no longer called; package still ≤5.3.1 → upgrade advised" },
  "compatibility": ["safe_load rejects python/object tags; config.yaml uses none (checked)"],
  "rollback": "git revert <fix commit> / restore line 14",
  "alternatives_rejected": [{ "candidate": "upgrade to 6.0.2", "why": "user asked to keep 5.x" }],
  "evidence_ids": ["E-12"], "human_feedback_applied": "keep 5.x, just switch to safe_load" }
```

### 4.3 Step C: critic (`critic.py`)

**Static checks** (always, deterministic):

| Check | Pass when |
|---|---|
| `patch_applies` | `git apply --check` in a scratch worktree |
| `candidate_clean` | OSV reports no known vulns for the target version |
| `constraints_resolve` | The resolver accepts the new set |
| `runtime_compatible` | `requires_python` OK (unknown → `unknown`) |
| `available` | The version exists on the configured index |
| `symbols_exist` | Every symbol our code uses exists in the target version (unknown if the archive isn't available) |
| `lockfile_consistent` | Manifest pins match the lockfile entries after the patch (or the lockfile is flagged "regenerate") |
| `scope_ok` | The patch only touches files the skill allows |

**AI critic** (20B, one call): *"Given the cited vulnerable path [evidence], does this patch remove it or make it unreachable? Answer yes/no/unsure plus evidence IDs."*

**Validation checks** (Phase B, sandbox): `build`, `tests`, `security_regression`, `rescan_resolved`, `no_new_vulns`, `sbom_diff`. See §6.

**Fix confidence (rules):**

| Fix confidence | When |
|---|---|
| **High** | All static checks pass, the AI critic says yes, **and** either Phase B passed (build + tests + rescan resolved, no new vulns) **or** it is a same-major version bump where none of our used symbols changed |
| **Medium** | Static checks pass, but the critic is unsure, or some checks are `unknown` (offline), or it's a major-version bump |
| **Low** | Any static check fails, the critic says no, Phase B tests fail, or the remediation is "escalate" |

A failing check **never** gets hidden. It is shown in red, and the remediation can still be approved with a reason, or revised.

---

## 5. Human-in-the-loop (`workflow.py`)

### 5.1 Which findings need a human
```python
needs_proposal_review = (
    priority in ("Critical", "High")
    and (finding_confidence != "High" or fix_confidence != "High")
)
```

| Priority | Confidence | Tab on page 4 | Behaviour |
|---|---|---|---|
| Critical/High | either < High | **Needs your decision** | Proposal review required |
| Critical/High | both High | **Ready** | Auto-planned. Proposal review optional, **patch review still required** before apply |
| Medium/Low | finding_confidence Low | **Unresolved** | Shown as "needs more evidence". User can open it, revise, or ask the agent |
| Medium/Low | otherwise | **Auto-planned** | Template plan. Patch review is required only if someone chooses to apply it |

### 5.2 Two different approvals
1. **Proposal approval:** "I agree with this approach" (upgrade to X / switch to safe_load / remove). After this, Phase B can start.
2. **Patch approval:** "I approve these tested code changes." The reviewer sees the final diff plus the validation results. Only after this do we commit to the local `guardian/fix-<rid>` branch. **Every applied patch needs this approval, whatever its confidence.**

### 5.3 LangGraph graph (one thread per remediation, `SqliteSaver` → `remediation.sqlite`)
```
candidates → propose (template | agent) → critic ─┬─ gate? no → planned (Ready / Auto-planned)
                                                   └─ yes → interrupt(PROPOSAL_REVIEW)
PROPOSAL_REVIEW:
  approve      → validate (Phase B) → interrupt(PATCH_REVIEW)
  reject       → reason required → closed_rejected
  revise       → feedback text → propose(agent, feedback) → critic → PROPOSAL_REVIEW   (max 3 revisions)
  alternative  → pick candidate k → propose(template k) → critic → PROPOSAL_REVIEW
PATCH_REVIEW:
  approve      → apply_branch (commit to guardian/fix-<rid>, never main, never push) → verified
  reject       → reason → closed_rejected
  revise       → as above (back to PROPOSAL_REVIEW)
```
- Resume with `Command(resume={"stage": "proposal"|"patch", "action": ..., "reason": ..., "feedback": ..., "alternative": k, "reviewer": ...})`. This is the same pattern as `stage4_vulns/review.py`.
- **"Planned"** items enter the graph at `PROPOSAL_REVIEW` when the user opens one and clicks Approve, Revise or Validate.
- **Reject reasons:** *disagree with approach / breaks compatibility / will fix manually / accepted risk / not affected*.

### 5.4 Revise from anywhere
- **Page 4:** "Revise with agent" takes a text box. It uses 120B if available, otherwise 20B.
- **Page 3 evidence report:** a "Suggest remediation" box posts to the **same** `revise` action with `source: "evidence_page"`. The suggestion is passed to the agent as human feedback.
- **"Regenerate with agent"** is for template plans: the agent writes a first proposal.

### 5.5 Audit trail (`audit.jsonl`, append-only)
Every event is one line: `proposal_created` (version, author, skill), `critic_result`, `review_decision` (stage, action, reason, feedback, reviewer, timestamp), `validation_result`, `branch_applied` (commit sha), `priority_changed`. Page 4 shows this per remediation as a timeline.

### 5.6 OpenVEX (optional, last)
**Rejecting a fix ≠ "not affected".** We write an OpenVEX `not_affected` statement only when the reject reason is *not affected* **and** the evidence backs it:
- usage `package_not_imported` → `component_not_present` / `vulnerable_code_not_present`;
- or `package_used_symbol_not_found` with finding_confidence High → `vulnerable_code_not_in_execute_path`.

Otherwise the statement is `under_investigation` or `affected`.

---

## 6. Phase B: sandbox validation (`sandbox.py`)

The order is: AI patch → temporary worktree → apply, build, test, rescan → human reviews the final diff → local branch.

1. `git worktree add <tmp>/guardian-<rid> HEAD` in the target repo. This is never the user's working copy.
2. `git apply` the proposal patch. Regenerate or adjust the lockfile entry if needed.
3. **Build:** create a throwaway venv and run `pip install -r requirements.txt` (and the dev requirements), plus `poetry check` if `pyproject` exists. Timeout 180 s; network only to the configured index.
4. **Tests:** run `pytest -q` in the worktree, timeout 180 s. Record pass/fail counts **before** (baseline at HEAD, cached) and **after**. A test that failed before and still fails is not a regression.
5. **Security regression check:** a vulnerability-specific probe from the skill, e.g. grep/AST that `yaml.load(` with an unsafe Loader is gone, or that the package version is ≥ the fixed version in the resolved set.
6. **Rescan:** run `python -m guardian.cli scan <worktree> --stages 1,2,4,5 --offline-ok` (about 26 s on mini-shop). Compare against the original scan:
   - **SBOM diff:** components added, removed, version-changed;
   - **Vulns:** resolved / remaining / **newly introduced**;
   - **Suspicious findings:** resolved / new.
7. Save logs and diffs to `validation/<rid>/` and update fix_confidence (§4.3).
8. Remove the worktree after patch review. If approved, first commit the patch to `guardian/fix-<rid>`.

**If install isn't possible offline,** `build` and `tests` become `skipped (offline)`. They are shown honestly and fix confidence can't reach High through Phase B.

---

## 7. Models, budget, cache

| Task | Model |
|---|---|
| SSVC inputs (Automatable, Technical impact) | 20B, structured JSON, 1–2 calls per CVE finding |
| Template remediations | No AI |
| Critical/High remediation agent | 20B |
| "Revise with agent" | 120B on demand, fall back to 20B |
| Critic | 20B plus the deterministic checks |

- **Environment variables:**
  - `GUARDIAN_MODEL` (existing, 20B);
  - **new** `GUARDIAN_MODEL_LARGE=openai/gpt-oss-120b`;
  - `GUARDIAN_LLM_PURPOSES` gains `prioritize`, `remediate` and `critic`. The default for free models is `card,explain,prioritize,critic`; `remediate` runs on demand.
- **Cache** (`day2/cache.py`, stored under `output/.cache/day2/`). The key is a hash of everything the result depends on. Change any of it and the entry is invalid:
  - advisory analysis: advisory ID + modified date;
  - prioritization inputs/results: finding evidence hash + EPSS date + KEV date + sensitivity reasons + the relevant graph edges;
  - candidates: package + current version + index snapshot + constraints;
  - proposals: candidates hash + skill + feedback text + model;
  - critic results: patch hash + candidate.
- **Demo safety:** cached results for the demo scan are built before the demo. A no-AI backup scan is kept, as on Day 1.

---

## 8. API (attach like `stage4_vulns/api.py`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/scans/{scan}/register` | Unified register with decision, priority, confidences, reasons |
| GET | `/api/scans/{scan}/remediations?tab=decide\|ready\|auto\|unresolved\|decided` | Page 4 table |
| GET | `/api/scans/{scan}/remediations/{rid}` | Drawer: proposal versions, candidates, checks, validation, audit timeline, history |
| POST | `/api/scans/{scan}/remediations/{rid}/decision` | `{stage, action, reason?, feedback?, alternative?, reviewer}` |
| POST | `/api/scans/{scan}/remediations/{rid}/regenerate` | `{model: "default"\|"large", feedback?}` |
| POST | `/api/scans/{scan}/remediations/{rid}/validate` | Starts Phase B. Progress over SSE, like the live scan |
| POST | `/api/scans/{scan}/findings/{fid}/suggest` | Page-3 "Suggest remediation" → `revise` on that finding's remediation |
| GET | `/api/scans/{scan}/audit` | Whole audit log |

---

## 9. UI: page 4 "Remediation" (`/scans/:scanId/remediation`)

Keep it as calm as pages 1–3: one table and one drawer.

**Top strip** (counts only): Needs your decision · Ready · Auto-planned · Unresolved · Decided.

**Table** (sorted by rank):

| Rank | Finding | Decision | Priority | Proposed action | Finding conf. | Fix conf. | Status |
|---|---|---|---|---|---|---|---|
| 1 | reqeusts (typosquat) | Act | Critical | Replace with `requests`, block `reqeusts` | High | Medium | Needs decision |

**Drawer** (on row click):
1. **Why this rank:** decision chips (Exploitation · Automatable · Tech impact · Mission) with AI / rule badges, `priority_reasons`, CVSS / EPSS (probability + percentile) / KEV, or "n/a" for non-CVE findings, and the priority history line.
2. **Proposed fix:** action, skill, author (template/agent), diff viewer, before → after risk, compatibility, rollback.
3. **Checks:** static checks and validation (Build · Tests · Rescan), green/red/grey, with the SBOM diff summary.
4. **Alternatives:** the other candidates, each with "Use this".
5. **Buttons:**
   - **Approve proposal** / **Approve patch**, depending on the stage;
   - **Reject** (reason required);
   - **Revise with agent** (text box);
   - **Regenerate with agent**;
   - **Run validation**;
   - **View evidence →**, which goes to page 3 for that finding.
6. **Timeline:** audit events for this remediation.

**Page 3 addition:** a small "Suggest remediation" box plus a "Go to remediation →" link on each evidence report.

> Pages 1–3 are being reorganised in the other session. Check the final route names before adding the nav link.

---

## 10. Build order (end-to-end early, then deeper)

1. **Unified register** (`schema.py`, `register.py`), with tests on the mini-shop full fixture.
2. **Prioritization:** decision tables, fallback rules, the AI classifier, finding confidence, `risk_history.json`.
3. **Deterministic candidates and template plans:** upgrade/remove/block/replace/escalate, plus static critic checks.
4. **Human approval workflow:** LangGraph graph with both interrupts, decisions, `audit.jsonl`, API. *Working demo point:* templates plus approvals, no agent yet.
5. **Remediation agent plus 4 Skills:** tools, budget, regenerate/revise, 120B on demand.
6. **AI critic, fix-confidence rules, Phase B sandbox:** worktree, build, tests, rescan, SBOM diff, branch apply.
7. **Page 4 UI** and the page-3 "Suggest remediation" box.
8. *(Optional)* OpenVEX, plus the `pin-hash` / `bump-base-image` skills.

---

## 11. Tests (`tests/test_day2.py`, offline, no LLM unless marked)

- The register merges Stage 4 and 5. Non-CVE findings have `cvss/epss/kev = null`.
- The decision tables give the exact cell for every combination (table-driven test).
- Fallback: CVSS vector `AV:N/PR:N/UI:N` → Automatable yes; `C:H/I:H/A:H` → total.
- Priority modifiers: a dev-scope finding is capped at Low; KEV + runtime is at least High.
- Confidence drops on rule/context disagreement and on classifier disagreement (stub LLM).
- A classifier output that cites an unknown evidence ID is rejected and the fallback is used.
- Candidates: excluded when the version fails a constraint, when it's yanked, or when OSV reports it as vulnerable. Same major is ranked first.
- Each skill's frontmatter parses, and `load_skill` returns the body only on request.
- Critic: a broken patch makes `patch_applies` fail, and fix confidence becomes Low.
- Workflow: approve → validate → patch approve → branch exists and main is unchanged. Reject requires a reason. Revise loops at most 3 times. The resume works after a process restart (SQLite).
- Reject with "disagree" writes **no** VEX `not_affected`.
- History: a changed EPSS input appends an entry with `change_reason` and never overwrites.
- Phase B on mini-shop (marked slow): the PyYAML fix resolves its CVE in the rescan, with no new vulns.

**Expected demo results get fixed after the first real run.** Don't hard-code guesses in tests. For example, PyYAML's call is internal-only at startup, so the contextual decision may come out lower than the Stage 4 rule risk. That disagreement is itself a good gate example.

---

## 12. Demo script (about 3 minutes)

1. **Page 4, "Needs your decision".** `reqeusts` is ranked first: decision Act, Critical, verified install-hook behaviour on the install path. Proposal: replace with `requests` and block it. **Approve proposal → Run validation** (build ✓, tests ✓, rescan: suspicious finding resolved, SBOM diff: −reqeusts). **Approve patch**, and the branch `guardian/fix-R-001` is created.
2. **PyYAML.**
   - Rules said High, but the context (internal startup call) lowered it, so the confidence is not High and the item goes to the gate.
   - The agent proposes upgrading to 6.x. The critic flags a major bump, so fix confidence is Medium.
   - The human clicks **View evidence** (page 3), sees the single `yaml.load` call site, and types *"keep 5.x for now, switch to safe_load"* → **Revise with agent** (120B).
   - The new proposal uses the `replace-unsafe-api` skill; the critic says yes.
   - Validation: tests ✓; the rescan shows the symbol no longer called and the risk drops. The remaining risk is still visible: "package still ≤5.3.1, upgrade scheduled".
3. **Timeline:** every proposal, check and decision, with who, when and why. This is the slide-5 "complete story".

---

## 13. Definition of done

- `guardian scan` produces `register.json` and `remediations.json` on mini-shop, offline, without an LLM.
- With Groq 20B: the classifier and critic run and are cached; a second scan makes **0** new LLM calls when nothing changed.
- Page 4 shows the gate tabs correctly, and both approvals work end to end through the API and the UI.
- Revise with agent works from page 4 and from page 3.
- Phase B produces build/test/rescan results and an SBOM diff, and creates a local fix branch only after patch approval. The original working tree is untouched (`git status` clean).
- `audit.jsonl` and `risk_history.json` are written, and the UI shows them.
- `pytest tests --deselect tests/test_stage1.py` passes.

---

## 14. Implementation status (2026-11-24): built and verified

**Code:** `guardian/day2/` (common, register, ssvc, prioritize, history, candidates, patches, critic, skills + 4 `skills/*/SKILL.md`, agent, sandbox, workflow, api, prompts/). UI page 4 is in the `ui/` dashboard ("Remediation" nav item, `ui/remediate.css`), with a "Suggest a remediation" box and "Plan the fix →" links on the page-3 reports. Tests: `tests/test_day2.py` (12 tests, offline).

**How to run**
- New scans run Day 2 automatically as progress stage 6 "Prioritize & remediate" (`guardian web`, `guardian scan`, `guardian demo`). `guardian scan --no-day2` skips it.
- Existing scan folder: `python -m guardian.cli remediate output/scans/<scan> [--offline --osv-dump tests/data/osv_minishop.zip] [--llm groq] [--agent]`.
- Demo: set `GUARDIAN_PYPI_URL=output/demo-fixture/fake-pypi/pypi` before `guardian web` (as on Day 1), then open Remediation.
- `GUARDIAN_MODEL_LARGE` (default `openai/gpt-oss-120b` with a Groq key) is used for "Revise / Regenerate with agent"; it falls back to the default model. `GUARDIAN_SANDBOX_INSTALL=1` adds a pip install into a throwaway venv during validation.

**Verified**
- Offline on mini-shop: 17 findings → 15 remediations. Approve → worktree → build ✓ → tests ✓ (before/after) → rescan resolved A-002, SBOM diff `−reqeusts` → patch approve → branch `guardian/fix-r-004`. The working copy stayed clean.
- Groq 20B: classifier (4 calls, self-consistency caught a disagreement on PyYAML) and critic (one per patch).
- Groq 120B agent, triggered from the page-3 suggestion box: it loaded `replace-unsafe-api`, read the route, and removed the `send_event()` call. The critic agreed; validation was *partial* (A-001 critical → low, dead code remains). Approving that patch required a reason.
- Real repo (microblog, 75 findings → 31 remediations) in 3 s offline.
- Full suite: 171 passed; the only 2 failures are the known Windows environment issues (`.env` model override, cp1252).

**Deviations from sections 3–6 (decided while building)**
1. **Downgrade limit (new priority modifier 5).** If the contextual priority is 2+ bands below the Stage 4/5 rule-based risk, it is limited to one band below and flagged. The review gate also catches these (`priority ∈ {Critical, High} or downgrade_limited`). Without this, almost every CVE without KEV/PoC would silently become Track/Low. Example: PyYAML (rules High, context Track) → Medium, waiting for a human.
2. **Every thread pauses at proposal review.** The gate only decides the tab (decide / ready / auto / unresolved). Patch approval is always required before a branch is created.
3. **Patches are exact-snippet edits** (`old_text` must occur exactly once). This is stricter than `git apply` and works with any line endings. The unified diff is derived for display.
4. **"Build" without network** means byte-compiling all Python files plus parsing the requirements, poetry.lock and workflow YAML. Installing dependencies is opt-in, and when skipped this is stated in the UI.
5. **Validation outcome `partial`.** If the rescan shows the risk lowered but not gone while the proposal claimed "resolved", the outcome is partial, not passed. Approving such a patch needs a reason, and its fix confidence stays Medium.
6. **Removal safety.** "Remove" is proposed only when dependency edges exist, nothing requires the package, no code imports it (by import name), and no Dockerfile/Procfile/script/config mentions it. Known command-line tools (gunicorn, setuptools, …) are never removed. A flagged package that the code imports is escalated, never removed. Found on microblog, where a pip-freeze requirements file has no dependency edges.
7. **The agent's submission is re-labelled honestly.** A safe-API swap on a still-vulnerable version is forced to effect "reduced". If the agent did not load the skill it claims, a note says so. Scope is still enforced either way.
8. **Model purposes.** Free models now also get `prioritize` and `critic` by default (cheap JSON calls). The agent (`remediate`) runs on request, or at scan time with `--agent` / `GUARDIAN_LLM_PURPOSES`.
9. **OpenVEX (section 5.6) is not built** (optional). Rejecting a fix never writes "not affected".
