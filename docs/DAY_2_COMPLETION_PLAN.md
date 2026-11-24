# Day 2 completion plan: fixed repository, security tests, running app, report

**Goal (slide):** *"Show us how the Guardian takes a finding from detection to verified remediation."*

**The story we demo, end to end:**

> Microblog had **61 known vulnerabilities** and **could not even be installed** on the Python its Dockerfile uses.
> Guardian prioritised them, proposed fixes, a person approved them, Guardian **wrote security tests that fail before and pass after**, built a **fixed repository you can download**, and showed the **app running** again with **zero regressions**.

This plan extends [DAY_2_PLAN.md](DAY_2_PLAN.md). Pages 1–4 stay as they are. We add page 5 (**Fixed repository**) and page 6 (**Report**), plus three engines behind them: security test generation, app boot check, and the combined "fixed repo" build.

---

## 1. Where we are (checked on 2026-11-24)

| Piece | Status | Notes |
|---|---|---|
| Prioritisation (SSVC-inspired + supply-chain table) | Done | `day2/prioritize.py`, `ssvc.py` |
| Remediation page (page 4): proposals, two approvals, agent revise | Done | `day2/workflow.py`, `ui/app.js` |
| Sandbox validation: real dependency install, `pip check`, project tests before/after, proof-of-fix probe | Done | `day2/runtime.py`, `probe.py`, `sandbox.py` |
| **Rescan** of the patched copy, SBOM diff, "nothing new introduced" | **Done**, runs inside validation | It starts **automatically when the proposal is approved**. Not yet automatic before approval, and not on the combined fix (see §4). |
| Fix branch `guardian/fix-<rid>` after patch approval | Done | `sandbox.apply_branch` |
| Clickable validation report ("how we know this fix is safe") | Done | |
| Security tests per vulnerability (2–3, written into the repo) | **Missing** | §5 |
| All approved fixes combined into one repo + download | **Missing** | §7 (page 5) |
| App boots before/after ("it was not running, now it runs") | **Missing** | §6 |
| Report page | **Missing** | §8 (page 6) |

---

## 2. What other tools do, and what we take from them

| Tool / work | How it validates a fix | What we adopt |
|---|---|---|
| Dependabot / Renovate | Opens a version-bump PR; trusts your CI; Renovate adds "merge confidence" from other users' test results | One commit per fix, a readable changelog, our own test evidence instead of crowd data |
| Google CodeMender | Builds the code and runs a **proof-of-concept exploit**; an LLM judge plus re-running tests to check behaviour is preserved; a developer approves | Exploit test that must fail before and pass after, plus a regression test that must pass on both, plus human approval |
| OpenAI Aardvark (now Codex Security) | Triggers the vulnerability in an **isolated sandbox** to confirm it; Codex patch, one-click human approval | Sandbox only, never the user's checkout; one-click approve |
| Research on LLM "vulnerability-witness" / proof-of-vulnerability tests (VULEUT, PoVSmith, GPT-4 PoV studies) | The test calls the library the way the app does and shows a **behavioural difference between the vulnerable and patched versions**; self-correction loops raise the success rate; without a reference exploit, success is low | Generate → run on both versions → feed failures back (max 3); keep the test **only if the difference is observed**; give the model the full advisory text and the app's call site |

**Our rule (stricter than most of the above):** a generated test counts as evidence only if Guardian **ran it on both versions and saw the expected result**. Nothing is claimed from the model's say-so.

---

## 3. Demo repository: microblog (verified)

[miguelgrinberg/microblog](https://github.com/miguelgrinberg/microblog): a real Flask app, 54 pinned dependencies, its own unittest suite (`tests.py`), SQLite by default.

Facts checked on this machine:
- 61 known vulnerabilities and 14 supply-chain findings in the scan; Werkzeug alone has 7 CVEs, which one upgrade fixes.
- **Does not install on Python 3.13:** `psycopg2-binary==2.9.9` fails to build (no wheel, needs `pg_config`). The Dockerfile says `FROM python:slim`, which means the newest Python, so **the app cannot be deployed as written**.
- On Python 3.11 it installs in about 10 s with `uv`, `flask db upgrade` works, `/auth/login` returns 200, and its 4 tests pass.

So "before: not running, after: running" is real and honest. **It comes from build-health fixes (outdated pins), not from the CVEs themselves**; the UI and the report must say so. **Backup:** the offline mini-shop fixture (no network, no LLM) for tests and a no-AI demo.

### 3.1 Final demo repo: chosen last, by a scripted check

After everything is built, we pick the final demo repository by running every candidate **through the real product from its GitHub link**: paste the link on the New scan page → full pipeline → page 4 → page 5 → page 6. A small helper, `python -m guardian.cli demo-check <github-url>`, runs the same steps headless and prints a pass/fail table, so the choice is evidence-based.

**Selection criteria (all must pass):**

| Criterion | Threshold |
|---|---|
| Python web app, public GitHub link, clones without auth | yes |
| Own test suite | ≥ 3 tests, and they pass on a working Python |
| Medium size | about 2k–20k lines of Python, 20–80 pinned dependencies (a big enough graph, a scan under 5 minutes) |
| Runnable without external services | boots with SQLite / no Redis, Elasticsearch or Postgres required (optional services may be unset) |
| Has real findings | ≥ 10 known vulnerabilities in pinned dependencies, with **released fixed versions**, at least one on a code path the app uses |
| Fixable end to end | after Guardian's approved fixes: installs, boots, all tests pass, the rescan shows fewer vulnerabilities and nothing new |
| Stable | `demo-check` passes **twice in a row** (cached AI on the second run), so it does not depend on luck |

**Candidates.**
- **Primary: `miguelgrinberg/microblog`.** Verified here: 61 vulnerabilities, 4 tests, boots on SQLite.
- **To evaluate in the same way:** `miguelgrinberg/flasky` and one or two other maintained Flask/FastAPI tutorial apps with pinned `requirements.txt` and tests.

The candidates other than microblog are **unverified until `demo-check` passes**. We pick the one that passes everything with the clearest before/after, record its link and commit in `docs/DEMO.md`, and pre-warm its caches.

---

## 4. Part A: automatic validation and rescan (page 4)

The rescan already runs inside every sandbox validation. Two changes make it automatic:

1. **Auto-validate queue.** After a scan, and after any new proposal, every remediation with a patch and priority Critical/High is queued for sandbox validation (install → tests → proof-of-fix → **rescan**). A single background worker runs them one at a time. The page shows "validating… (2 of 5)".
   - When the reviewer approves a proposal whose current version is already validated, the workflow jumps straight to patch review. No second run.
   - Medium/Low items are validated on demand ("Run validation"), or by "Validate all" on page 4.
   - Setting: `GUARDIAN_AUTO_VALIDATE=high|all|off` (default `high`).
2. **Combined rescan.** Page 5 rescans the repository with **all** approved fixes applied together (§7), because fixes validated one at a time can still interact.

---

## 5. Part B: security tests per vulnerability (2–3 each)

New module `guardian/day2/testgen.py`. For every remediation it writes **one pytest file** into the repository: `tests/guardian/test_<rid>_<package>.py`. Each test has a clear expectation:

| Test | Meaning | Expected before → after | Written by | When |
|---|---|---|---|---|
| **T1: exploit test** | Calls the vulnerable API the way the advisory describes and asserts the **safe** behaviour, e.g. `safe_join(base, "example/NUL") is None` | **FAIL → PASS** | AI agent (proof-of-fix loop, reused) | Kept **only if** it really failed on the old version and passed on the new one |
| **T2: guard test** | Asserts the fix is in place: installed version ≥ first fixed version, unsafe call gone (AST), typosquat not installed, workflow hardened | **FAIL → PASS** | Template (no AI) | Always |
| **T3: feature test** | Exercises **this app's** code that uses the package (from the evidence: call site, route) and asserts it still works (status < 500, expected output) | **PASS → PASS** | AI agent, or a route smoke-test template as fallback | Kept only if it passes on both versions |

So every vulnerability gets **at least 2 tests (T2 + T3) without any AI**, and **3 when the exploit is reproduced**. T1 is per CVE (up to 3 per remediation, aliases merged). T2 and T3 are per package.

**Templates by fix kind:**

| Fix kind | T1 | T2 | T3 |
|---|---|---|---|
| upgrade / pin | exploit test | `importlib.metadata.version(pkg) >= fixed` | route/feature test |
| replace unsafe API (`yaml.load` → `safe_load`) | payload test: the app's loader rejects `!!python/object` | AST: no unsafe call left in the file | feature test of the loader |
| remove typosquat | `import reqeusts` fails / not installed | not in any requirements file | app smoke |
| harden CI | workflow has no `pull_request_target` + PR-head checkout | permissions not `write-all`, actions pinned | — (2 tests) |

**How the tests run (before/after matrix).** The same test files run in two sandbox environments: **before** (original dependencies) and **after** (patched dependencies). For each test we store `before`, `after`, `expected` and `as_expected`. Anything not "as expected" is shown in red, never hidden.

**Safety.** Generated code passes the existing AST safety check: no network, process, shell, eval, file deletion, or reading the version to fake a verdict. T2 is the only test allowed to read versions, and it is labelled "guard, not proof". Tests run with timeouts in the sandbox.

**Where they live.**
- The `upgrade-dependency`, `replace-unsafe-api`, `remove-or-block-package` and `harden-ci-cd` skills allow `tests/guardian/**`, so the tests are part of the fix commit and of the downloaded repo.
- A `tests/guardian/conftest.py` adds the marker `guardian`, so `pytest -m guardian` runs only Guardian's tests.
- A unittest-only project still runs them, because pytest runs both kinds of test.

**Page 4** gets a "Security tests" block under validation: one row per test, with T1/T2/T3, before ✕/✓, after ✕/✓, and a link to the code.

---

## 6. Part C: run the app (before and after)

New module `guardian/day2/appboot.py`.

1. **Target Python** (the platform the project says it runs on), in this order:
   - `GUARDIAN_TARGET_PYTHON`;
   - a Dockerfile pin (`python:3.11`);
   - `.python-version` / `runtime.txt`;
   - `python:slim` / `latest` → the newest Python `uv` has.

   For microblog this is 3.13.
2. **Install check on the target Python**, before and after: "installs ✓/✕" with the failing package and the error line.
3. **Boot check.**
   - Detect the framework: Flask (`.flaskenv` `FLASK_APP`, `Flask(__name__)`, `create_app`); FastAPI (`FastAPI(` → `uvicorn module:app`); Django (`manage.py runserver`); otherwise "not detected → skipped".
   - Prepare the database on a temporary SQLite URL (`DATABASE_URL`), and run `flask db upgrade` when `migrations/` exists.
   - Start the server on a free port, then request `/` and up to 5 parameter-free GET routes from the code graph.
   - Healthy = no 5xx and at least one 2xx/3xx. Stop the server afterwards.
   - Record status codes, the page `<title>`, and the time to first response.
4. **Build-health fixes ("makes it run").**
   - When the install on the target Python fails, parse the error (`Failed to build pkg==x`) and propose the **smallest newer version that ships a wheel for that Python**. That version must also satisfy the dependents' constraints and have no known CVEs.
   - Repeat until the install succeeds (at most 6 packages).
   - These appear on page 4 as remediations tagged **"build health"**: no CVE, the same two approvals, and the same tests (T2 guard + T3 smoke).
   - They are kept clearly separate from the vulnerability fixes in the report.
5. **Live demo button (page 5).** "Run fixed app" starts the after-version on `http://127.0.0.1:<port>` from the sandbox, links to it, and has a Stop button. It stops automatically after 15 minutes.

---

## 7. Part D: page 5 "Fixed repository"

**Purpose:** turn the approved fixes into one repository that installs, runs, passes the tests, and can be downloaded.

**Engine:** `guardian/day2/fixed_repo.py`, started by **"Build fixed repository"**, which runs in the background with step-by-step progress.

1. **Collect** the remediations whose **patch was approved** (status `applied`), in rank order. Unapproved items are listed as "not included" with their status.
2. **Compose.**
   - Create a fresh worktree at HEAD and apply each fix's edits plus its test file with `apply_edits`, making **one commit per fix**. The message carries the rid, the findings and the approver.
   - If an edit conflicts with an earlier fix, skip that fix, mark it "conflicts with R-00x → re-validate", and continue.
3. **Add `GUARDIAN_FIXES.md`.** One short table: fix, findings, versions, tests, approver. Plus how to run the Guardian tests and how to roll back.
4. **Final verification** (automatic, before and after):
   - install on the target Python;
   - the full test suite (project tests + `tests/guardian`), giving the matrix from §5;
   - the boot check;
   - the **combined rescan**, compared with the original scan: vulnerabilities by priority, supply-chain findings, resolved / remaining / new, SBOM diff.
5. **Publish.**
   - Create the local branch `guardian/fixed-<scan>`. Never check it out, never push.
   - Write `output/scans/<scan>/fixed/`: `fixed-repo.zip` (`git archive`), `fixes.patch` (`git format-patch`, one patch per fix), and `result.json`.

**Page layout** (same calm style as pages 1–4):
- **Top strip** (4 numbers, before → after): known vulnerabilities `61 → 9` · Critical/High `… → …` · tests `4 → 4 + 21 new, 0 regressions` · app `✕ won't install on 3.13 → ✓ running`.
- **"Included fixes"** table: fix · findings · tests (✓ 3/3 as expected) · commit. Followed by "not included" (pending / rejected / conflicts).
- **"Proof"**: the test matrix (collapsible per fix), install and boot before/after with the error and the status lines, and the rescan diff.
- **Downloads:** **Download fixed repo (.zip)** · **Download patches** · branch name with a copy button. Under them, a "How to use it" block of 3 commands (`unzip`, `pip install -r requirements.txt`, `pytest`).
- **Run fixed app** button (§6.5).

---

## 8. Part E: page 6 "Report"

A one-page, minimalist, printable summary for a security lead.

1. **Header:** repo, commit before → fixed branch, dates, who approved, and a one-line verdict: *"52 of 61 vulnerabilities fixed, app runs on Python 3.13, 0 test regressions, 9 remaining (3 accepted)."*
2. **Before → after table:** known vulnerabilities by priority · supply-chain findings · installs on target Python · app boots · tests passing.
3. **What Guardian fixed:** one row per fix, with action, findings (CVE ids), priority and why (one line from `priority_reasons`), tests (T1/T2/T3 before → after), fix confidence and approver.
4. **Test evidence:** the full matrix, grouped by fix, collapsed by default.
5. **Remaining and accepted risk:** not fixed (escalated / no safe version / rejected with reason). Accepted risk shows the reviewer's reason. Optionally an OpenVEX `not_affected` statement only where the evidence supports it (rule from DAY_2_PLAN §5.6).
6. **Audit trail:** a condensed timeline of proposals, decisions, validations and commits from `audit.jsonl`.
7. **How it was checked:** 5 lines naming the methods: SSVC-inspired prioritisation; sandbox install; project tests; generated tests (as expected or not); combined rescan.

**Export:** "Download report", as a standalone HTML file (inline CSS, prints cleanly to PDF) or as Markdown. `report.json` is the single source for the page and both exports. No charts, no decoration.

---

## 9. Files and API

**New backend modules**

| File | Job |
|---|---|
| `guardian/day2/testgen.py` | T1/T2/T3 generation, safety check, the before/after matrix runner |
| `guardian/day2/appboot.py` | target Python, install check, framework detection, boot + route probe, live run |
| `guardian/day2/fixed_repo.py` | compose fixes, final verification, zip/patch/branch, `result.json` |
| `guardian/day2/report.py` | builds `report.json` and the HTML/Markdown exports |
| `guardian/day2/queue.py` | the auto-validate background worker |
| `guardian/cli.py` `demo-check` | headless run of the whole flow on a GitHub link; prints the criteria table from §3.1 |
| `guardian/day2/prompts/testgen_system.md` | prompt for T1/T3 (T1 reuses the probe prompt rules) |

**Changes to existing files**
- `candidates.py`: the build-health candidate kind `compat_upgrade`.
- `sandbox.py`: calls testgen during validation, stores the matrix, commits the tests with the fix.
- `workflow.py`: skips re-validation when the current version is already validated; queue hooks.
- `skills/*/SKILL.md`: allow `tests/guardian/**`.
- `api.py`: the routes below.
- `ui/app.js` + CSS: pages 5 and 6, and the test block on page 4.

**API** (attached like the existing Day 2 routes)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/scans/{id}/remediations/validate-all` | queue validation for all items with a patch |
| GET | `/api/scans/{id}/queue` | auto-validate queue state |
| POST | `/api/scans/{id}/fixed-repo` | build the fixed repository (background) |
| GET | `/api/scans/{id}/fixed-repo` | status, progress steps, result |
| GET | `/api/scans/{id}/fixed-repo/download?what=zip\|patch` | file download |
| POST / DELETE | `/api/scans/{id}/fixed-repo/run` | start / stop the live app |
| GET | `/api/scans/{id}/report` | `report.json` |
| GET | `/api/scans/{id}/report/download?format=html\|md` | export |

**Outputs** in `output/scans/<scan>/`: `fixed/result.json`, `fixed/fixed-repo.zip`, `fixed/fixes.patch`, `fixed/logs/`, `report.json`. Each per-remediation validation also holds its `tests` matrix.

---

## 10. Build order (one shot, end to end early)

1. **testgen T2 + T3 templates** (no AI) + the matrix runner, wired into sandbox validation and committed with the fix. *Checkpoint:* R-001 Werkzeug on microblog shows T2 FAIL → PASS and T3 PASS → PASS.
2. **T1 exploit tests** from the probe loop, written as pytest and kept only when the difference is observed. Cache by (vuln id, versions, prompt).
3. **appboot:** target Python, install check, Flask boot + route probe. *Checkpoint:* microblog before on 3.13 = "won't install (psycopg2-binary)", and on 3.11 = "boots, /auth/login 200".
4. **Build-health candidates** (`compat_upgrade`) shown on page 4. *Checkpoint:* the microblog install on 3.13 succeeds after the proposed bumps.
5. **fixed_repo:** compose, `GUARDIAN_FIXES.md`, final verification, combined rescan, zip/patch/branch.
6. **Auto-validate queue** + the "already validated" shortcut.
7. **report.py** + exports.
8. **UI:** page 4 test block, page 5, page 6, nav links (check the final route names in `ui/app.js`).
9. Tests (§11), then a full dry run of the demo (§12) with cached AI results.
10. **Choose the final demo repo (§3.1).** Run `demo-check` on the candidates from their GitHub links, pick the one that passes every criterion twice, and write `docs/DEMO.md` (link, commit, expected numbers, pre-demo steps).

---

## 11. Tests (`tests/test_day2_finish.py`; offline unless marked)

- **T2 templates:** a generated guard test fails with the old version installed and passes with the new one (tiny fake package in a temp venv, marked slow) or with a monkeypatched `importlib.metadata`.
- **T1 is kept only if fail → pass:**
  - a stub model returning a tautology is rejected;
  - a stub returning a correct test is kept with `as_expected = true`.
- **The safety check** rejects network, subprocess and version reading in T1/T3.
- **Composition:** two non-overlapping fixes give 2 commits; overlapping edits mark the second fix "conflicts" and skip it; the zip contains the patched `requirements.txt` and `tests/guardian/`.
- **The user's working copy stays clean** (`git status --porcelain` empty), and only `guardian/fixed-*` is created.
- **appboot:**
  - Flask detection on a tiny fixture app that boots and answers 200;
  - a broken fixture that raises on import → "does not boot";
  - an unknown framework → skipped, not failed.
- **compat candidate:** a parsed `Failed to build \`x==1\`` gives the smallest newer version that has a matching wheel (fake index).
- **Report:** `report.json` counts match the register and the fixed-repo result, and the HTML export is self-contained (no external URLs).
- **Queue:** auto-validate runs only Critical/High by default, and approving an already-validated proposal goes straight to patch review.
- **Slow, online, marked:** microblog end to end produces a fixed repo that installs on 3.13, boots, passes all tests, and has fewer vulnerabilities in the rescan.

---

## 12. Demo script (about 4 minutes)

1. **Page 4.** Werkzeug (7 CVEs, one fix). Validation has already run automatically:
   - **Security tests:** T1 exploit `safe_join(…, "example/NUL")` ✕ → ✓; T2 guard ✕ → ✓; T3 `/auth/login` ✓ → ✓.
   - **Project tests:** 4/4 → 4/4.
   - **Rescan:** 7 resolved, 0 new.
   - Click **Approve tested patch**.
2. Approve 3–4 more, including the **build-health** item (psycopg2-binary etc.: "the app could not be installed on Python 3.13").
3. **Page 5.** Click **Build fixed repository**.
   - The progress runs: compose → install → tests → boot → rescan.
   - The top strip shows: vulnerabilities `61 → N`, the app `✕ won't install → ✓ running`, tests `0 regressions, M new tests as expected`.
   - Click **Run fixed app**, which opens microblog's login page live.
   - Click **Download fixed repo**.
4. **Page 6, the report:** the one-line verdict, what was fixed and why, remaining and accepted risk, and the audit trail. Download it as HTML.

Pre-demo checklist:
- Run the full flow the evening before, so the AI results (T1, T3, critic) sit in the LLM cache. The Groq free tier caps the 120B model at 200k tokens a day.
- Warm the `uv` cache.
- Keep the mini-shop no-AI backup scan.

---

## 13. Risks and mitigations

| Risk | Mitigation |
|---|---|
| LLM quota or weak model, so no T1 | T2 + T3 still give 2 tests per vulnerability without AI; pre-generate and cache; large model first, then fall back to the 20B |
| A generated test is wrong | It is kept only if the expected fail/pass was **observed**; the code is visible; T2 is labelled "guard, not proof" |
| Network or PyPI down during the demo | `uv` cache warmed; a pre-built fixed repo from the dry run; offline mini-shop backup |
| Fixes conflict when combined | One commit per fix; conflicts are skipped and reported, never silently merged |
| The app needs Redis/Elasticsearch/Postgres | Temporary SQLite `DATABASE_URL`; optional services stay unset (microblog tolerates this, checked) |
| Final verification is slow (two installs + rescan + boot ≈ 3–5 min) | Background job with live steps; results cached per set of fix commits |
| Overclaiming | The report separates vulnerability fixes from build-health fixes and lists remaining risk first-class |

---

## 14. Definition of done

- On microblog, page 4 shows auto-validation results with **2–3 security tests per vulnerability** and their before/after outcome.
- Page 5 builds `guardian/fixed-<scan>`. The zip downloads, and it contains the patched manifests, `tests/guardian/` and `GUARDIAN_FIXES.md`.
- The fixed repository **installs on the target Python, boots, and passes all tests**, and **Run fixed app** opens it in the browser. The before state is shown honestly ("won't install on 3.13").
- The combined rescan shows fewer vulnerabilities and nothing new. Page 6 shows the report, and it exports as HTML and Markdown.
- The user's checkout is untouched, and nothing is pushed.
- **The final demo repo was chosen by `demo-check`.** Pasting its GitHub link into the New scan page runs the whole flow (pages 1–6) without manual steps, twice in a row, and `docs/DEMO.md` records it.
- `pytest tests --deselect tests/test_stage1.py` passes, apart from the 2 failures that were already there at commit `3b4b828`.

**Out of scope:** pushing branches or opening PRs, Docker image builds, non-Python ecosystems, writing fixes for CVEs that have no released fixed version (these stay "escalate").

---

## Sources

- [Google CodeMender](https://cloud.google.com/security/codemender): runs proof-of-concept exploits, an LLM judge, and behaviour-preservation tests before a developer applies the patch.
- [OpenAI Aardvark / Codex Security](https://openai.com/index/introducing-aardvark): confirms exploitability in an isolated sandbox; Codex patch for one-click human approval.
- [Renovate Merge Confidence](https://docs.renovatebot.com/merge-confidence) and the [Dependabot compatibility score study](https://arxiv.org/html/2403.09012v1): crowd test data, unavailable for 83% of updates.
- [How well does LLM generate security tests?](https://arxiv.org/html/2310.00710v3): without a reference exploit, generated tests rarely succeed, so we give the model the full advisory text and the app's call site.
- [Proof-of-vulnerability test generation (PoVSmith)](https://www.alphaxiv.org/abs/2605.03956): agents build call paths, generate, run and refine tests that show the difference between vulnerable and patched versions.
- [LLM vulnerability-witness unit tests with self-correction](https://arxiv.org/abs/2506.11559v1) and [VULEUT](https://arxiv.org/pdf/2409.16701v3): reachability plus unit tests to confirm exploitability after an upgrade.

---

## 15. What was built (2026-11-24) and deviations

Built as planned: `testgen.py` (T1/T2/T3 + before/after matrix), `appboot.py` (target Python, install, boot, live run,
build-health search), `fixed_repo.py`, `report.py`, `queue.py`, `democheck.py` + `guardian demo-check`, pages 5 and 6,
the security-tests block on page 4, `tests/test_day2_finish.py` (14 tests). Demo: see [DEMO.md](DEMO.md).

Deviations, all found while running it on microblog:
- **Target Python is 3.14**, not 3.13: `python:slim` means the newest stable CPython, and uv provides 3.14.7.
- **Build health also fixes import-time crashes**: after the install works, the app is started; if it crashes inside
  a pinned package (SQLAlchemy 2.0.23, typing_extensions 4.8.0 on 3.14), that pin moves to the first release published
  after the target Python came out. The sandbox validates build-health fixes with an install *and* a boot on 3.14.
- **T1 also from curated reference exploits** (`exploits.py`: Werkzeug safe_join device names, PyJWT unknown `crit`
  header), kept by the same observed fail → pass rule; AI probes still run. T3 is template-only (no AI).
- **The before/after matrix uses two environments on the same Python** (the before venv is no longer upgraded in place),
  and a separate worktree at HEAD for the before run.
- **Composition re-applies each fix's exact-line edits** instead of `git cherry-pick`: cherry-pick reported fixes on
  neighbouring requirement lines as conflicts. A real overlap (the same line) is still skipped and reported.
- **"New behaviour in update" on the package a fix upgrades on purpose is "needs a look", not a failure**; a CVE,
  install-hook behaviour, or behaviour in a package the fix did not touch still fails validation.
- **Route names:** `GET /api/scans/{id}/report` already existed (SARIF/CycloneDX), so the report is
  `/remediation-report` (+ `/download?format=html|md`). Added `/bulk-approve` ("Approve all validated fixes": both
  approvals for fixes whose validation passed, then an automatic rebuild) and `?which=before|after` on `/fixed-repo/run`
  (the original, vulnerable version can be run next to the fixed one).
- `output/scans/demo.json` pins the scan the dashboard opens first; `START_DEMO.bat` starts the server and the browser.
