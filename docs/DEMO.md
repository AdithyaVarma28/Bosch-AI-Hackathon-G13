# Guardian demo

## Main demo: vulpy, code-level vulnerabilities fixed by changing the code

**Repository:** https://github.com/fportantier/vulpy (Flask + SQLite). **Scan:** `output/scans/vulpy-20261124-114315`
(pinned; `START_DEMO.bat` opens its Remediation page).

1. **Remediation:** C-003 *SQL injection in login()* (critical), C-005 *password_change()* (critical), C-004 *create()*
   (high). Open C-003: the diff rewrites the SQL to a parameterized query. Sandbox validation **passed**, fix confidence **high**.
   Security tests: T1 exploit (`' OR '1'='1` login bypass) ✕ → ✓, T2 guard ✕ → ✓, T3 normal login ✓ → ✓.
2. Click **✓ Approve all validated fixes (3)** → confirm. The fixed repository builds by itself (about 1–2 minutes).
3. **Fixed repository:** SQL-injection sites in the code **6 → 3** (the 3 left are low priority: setup scripts and the
   `good/` folder), 9/9 security tests as expected, the app runs before and after, 0 regressions.
   - **Run original (vulnerable) app** → Sign in with username `admin`, password `' OR '1'='1` → **logged in without the password**.
   - **Run fixed app** → the same input → **"Invalid user or password"**; `admin` / `SuperSecret` still logs in.
4. **Report:** the verdict, the before → after table, the fixes, the remaining risk, the audit trail; download it as HTML.

Checked on 2026-11-24 with a dry run on a throwaway copy of the scan (deleted afterwards): build done, 3 fixes
included, 0 skipped; injection logs in on BEFORE, is rejected on AFTER; the real password works on both.

## Second demo: microblog, dependency CVEs + "won't install → runs"

Open http://127.0.0.1:8000/ui/?scan=microblog-20261124-104249. There is no built-in user: register any user
(e.g. `demo` / `demo@example.com` / `demo1234`) in each app, then sign in.

**Repository:** https://github.com/miguelgrinberg/microblog (commit `a975ef6`)
**Prepared scan:** `output/scans/microblog-20261124-104249` (pinned in `output/scans/demo.json`, opens first)
**Chosen by:** `python -m guardian.cli demo-check https://github.com/miguelgrinberg/microblog`, 10 of 11 criteria pass
(the only miss: 1,843 lines of Python, slightly under the 2k guideline).

## Start

Double-click **`START_DEMO.bat`** in the project folder. It starts the Guardian server and opens
http://127.0.0.1:8000/ui/?scan=microblog-20261124-104249#/overview. Keep the "Guardian server" window open (minimised).

## What the audience sees (about 4 minutes)

1. **Overview → Architecture → Risk detection**: 61 known vulnerabilities, 14 supply-chain findings, 35 routes.
2. **Remediation (page 4)**
   - Strip at the top: *Build health · Python 3.14: does not install* (`psycopg2-binary==2.9.9` has no wheel).
     B-001 makes it install **and run**: psycopg2-binary, multidict, greenlet (no wheel), SQLAlchemy and
     typing_extensions (crashed at import on 3.14), all found automatically.
   - Open **R-001 Werkzeug**: validated in the sandbox before anyone opened it. *Security tests*:
     T1 exploit `safe_join("C:/srv/uploads", "example/NUL")` ✕ → ✓, T2 guard ✕ → ✓, T3 app routes ✓ → ✓;
     project tests 4/4 → 4/4; rescan: 7 CVEs resolved.
   - Click **✓ Approve all validated fixes (5)** (PyJWT, requests, urllib3, setuptools, dnspython). The dialog lists them;
     each gets both approvals under your reviewer name, and the fixed repository rebuilds by itself (about 4–5 minutes).
     Each of these 5 is marked "needs a look": the rescan saw new code in the release the fix upgrades to
     (e.g. requests 2.33 changes adapters.py). That is expected for an upgrade and shown openly.
3. **Fixed repository (page 5)**, already built with B-001, R-001, R-007:
   vulnerabilities **61 → 52**, Critical/High **20 → 13**, tests **4/4 → 4/4 + 7 new security tests, 0 regressions**,
   app on Python 3.14 **✕ won't install → ✓ running**; all 11 tests pass on 3.14.
   - **See it live**: *Run original (vulnerable) app* (Python 3.11, because it does not install on 3.14) and
     *Run fixed app* (Python 3.14). Both open microblog's Sign In page.
   - **Download fixed repo (.zip)** / **Download patches**; branch `guardian/fixed-microblog-20261124-104249`.
4. **Report (page 6)**: one-line verdict, before → after table, what was fixed and why, build health separately,
   remaining risk, test evidence, audit trail; **Download report (HTML)**.

## Say it honestly

- The "did not install → runs" story comes from **build-health fixes (old pins)**, not from the CVEs. The report says so.
- The first 3 fixes were approved by the `demo-check` script (reviewer **"demo-check"** in the audit trail) to prepare
  the pages; the remaining 5 are approved live by you.
- T1 exploit tests: Werkzeug and PyJWT use **curated reference exploits** (verified by running them). The AI probe
  could not reproduce the other CVEs (the Groq 120B daily quota was used up), so those fixes have T2 + T3 only.
- **Flask 3.1.3 (R-006) failed validation**: it does not install with the pinned Werkzeug. It stays for a human decision.
- `gunicorn` is only a deployment tool here; the R-007 fix is low priority.

## If something goes wrong

- Page blank or "cannot connect": double-click `START_DEMO.bat` again.
- "Run fixed app" says the environment is gone (the temp folder was cleaned or the PC restarted):
  click **Rebuild fixed repository** on page 5 (about 4–5 minutes), then Run again.
- Backup without network or AI: the mini-shop scans (`demo-minishop-head`) in the scan list.

## Candidates considered

| Repo | Result |
|---|---|
| miguelgrinberg/microblog | **chosen**: 10/11 criteria, full flow from the GitHub link |
| openhackai/pentestbench | not suitable: a 17-app multi-language monorepo, no test suite, no single app at the root to install or boot; its 761 vulnerabilities are planted code bugs in a private catalog, not dependency CVEs with released fixes |
