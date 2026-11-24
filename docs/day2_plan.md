# Guardian: Day 2 Plan (Brain & Shield)

**Status:** draft for team review
**Builds on:** [implementation_plan.md](implementation_plan.md) (Day 1, stages S0 to S9)

> Day 2 checkpoint: **"Show us how the Guardian takes a finding from detection to verified remediation."**

Day 1 already finds the risks and backs each one with evidence (stages S0 to S9: facts, SBOM, code index, graph, detectors, P0–P3 bands, Evidence Agent, Verifier). Day 2 builds on that output. It does not redo it. It adds seven stages, S10 to S16, that run after the Day 1 report:

```
Day 1 report (findings, graph.json, sbom.cdx.json, code_index.json, run.db)
  │
[S10 Prioritize]       explainable risk score + confidence → ranked queue
  │
[S11 Investigate]      deep dive on suspicious (non-CVE) changes, fact vs. inference split
  │
[S12 Remediate]        generate candidate fixes, simulate them on the graph, pick the best
  │
[S13 Human approval]   approve / edit / reject / accept risk, all recorded
  │
[S14 Validate]         apply in a sandbox branch → build → tests
  │
[S15 Rescan + diff]    rerun the Day 1 pipeline on the patched tree → before/after SBOM + findings
  │
[S16 Verify & report]  verdict, remaining risk, confidence, audit trail, optional PR
```

---

## 1. Ground rules for Day 2

1. **Never change the user's repo directly.** Every fix is applied to a throwaway copy or branch inside a container.
2. **Deterministic tools decide, the LLM suggests.** Version choices come from OSV fixed ranges and registry data. Build and test results come from real execution. The LLM may only rank candidates, explain them and write prose, and the Day 1 Verifier checks those claims.
3. **No auto-merge.** A human approval gate is required before validation runs, and again before any PR is opened.
4. **A fix counts as successful only if the rescan proves it.** "Tests passed" is not enough. The target finding must be gone from the new scan, and no new P0 or P1 finding may appear.
5. **Every decision is logged** (who, what, when, why) in the same append-only `run.db` evidence store.
6. **Treat repo code as untrusted while running it.** Builds and tests run with no network, except a pinned registry mirror, plus resource limits and a timeout. They run with no secrets mounted.
7. **Approval is bound to the exact plan.** The approval records a hash of the plan. Any change to the plan, including one made by self-correction, invalidates the approval (see S13).
8. **Rules live in a policy file, not in code.** Pass/fail decisions in S15 and S16 come from a versioned policy evaluated deterministically (see section 9).
9. **Deterministic checks decide the verdict, agents explain it.** The independent verifier agent audits the result but cannot override the deterministic checks.

### Feature map

| Feature | Where it lives |
|---|---|
| Contextual Risk Intelligence (incl. component criticality) | S10 |
| Evidence-Driven Threat Investigation | S11 |
| Graph-Aware Remediation | S12.1 |
| Multi-Candidate Compatibility Analysis | S12.2 |
| Remediation Tournament | S12.3 + S14 |
| Immutable Human Approval Gate | S13 |
| Agentic Self-Correction | S14.6 |
| Policy-as-Code Engine | Section 9, applied in S15 and S16 |
| Independent Remediation Verification | S16 |
| Evidence-Based Audit Trail | Ground rule 5, S16 timeline |

---

## 2. S10: Prioritize risks ("focus on what truly matters")

**Input:** the Day 1 findings with their axes: severity, exploitability (KEV/EPSS), trust alerts, context and confidence.

**What it adds:**
- **A numeric score next to the band.** Day 1 bands (P0–P3) stay the coarse triage order. Day 2 adds a 0–100 score so items within a band can be ranked. The score combines five factors, each shown in the report:
  - **Severity:** CVSS, or the weight of a strong or weak signal for non-CVE findings.
  - **Exploitability:** KEV entry, EPSS probability, public exploit, malicious-package advisory.
  - **Reachability:** an upgraded version of Day 1's "statically referenced from an exposed route". Use the code index call graph to check whether the vulnerable symbol is called, or only the package is imported. The levels are *function reachable*, *package imported*, *declared but unused*, or *unknown*.
  - **Exposure:** network-facing vs. CLI/library (from the Dossier), plus whether the container exposes ports or the CI workflow handles secrets.
  - **Production use:** runtime vs. dev/test/build scope, direct vs. transitive, and dependency depth.
  - **Component criticality:** what the code using the component touches. This comes from the Day 1 code index: sensitive calls (exec, deserialization, crypto), DB access, auth-related routes, secrets read and external services. A vulnerable parser used only in a CLI helper scores lower than the same parser handling uploads next to the user table.
- **Confidence, scored separately from risk.** Confidence reflects data quality: lockfile-resolved vs. guessed versions, SBOM cross-check agreement, and whether reachability was proven or only inferred. A high-risk, low-confidence item is flagged "needs human look".
- **Explainability.** Each score comes with a short breakdown, e.g. "+30 critical, +25 KEV, +20 reachable from `/upload`, −0 prod, confidence: high (lockfile)". The breakdown is built from rules, so it is reproducible.
- **Urgent vs. later.** The queue is split into *Fix now* (P0/P1, reachable or exposed), *Schedule* (P2) and *Monitor/accept* (P3, dev-only, unreachable). Only *Fix now* items go into the remediation loop automatically. The user can promote others.

**Output:** `priority.json`, a ranked queue with the score breakdown and confidence per finding.

---

## 3. S11: Investigate suspicious changes ("look beyond known CVEs")

At least one non-CVE supply-chain risk must be investigated in depth. Day 1 detectors already flag candidates: typosquats, install scripts, lockfile tampering, dependency confusion, untrusted base images and unpinned CI actions. S11 investigates them further:

- **Version and lockfile comparison.** For the suspicious package, diff the old and new versions using git history from the Day 1 history module. The diff covers manifest line changes, lockfile integrity-hash changes, resolved-URL changes (registry swap) and new transitive dependencies that appeared.
- **Package content inspection (static only).** Download both versions' tarballs into the sandbox and diff them. Look for new `postinstall`/`setup.py` code, obfuscated or base64 blobs, network or exec calls in install hooks, and files that don't match the source repo.
- **Provenance checks.** Check publisher change, maintainer added recently, package age, download count, whether the repository link is missing or mismatched, missing provenance or signature (npm provenance, PyPI attestations, Sigstore), and the gap between version publish time and git tag time.
- **Integrity checks.** Compare lockfile hashes against registry hashes and report any mismatch. For images, check whether the base image is pinned by digest or by a mutable tag.
- **Separate verified evidence from AI inference.** Every statement in the investigation is a `Claim` typed *fact* (cites evidence IDs: file+line, hash, registry response), *inference* (AI reasoning, labelled as such) or *unknown*. The Day 1 Verifier rejects facts without evidence. The UI shows facts and inferences in visibly different styles.

**Output:** an investigation dossier per suspicious finding, with a verdict: *likely malicious*, *suspicious*, *benign change* or *inconclusive*.

---

## 4. S12: Recommend safe remediation ("suggest the right action")

For each queued finding, **generate candidates, simulate each, then rank**.

### 4.1 Candidate generation (deterministic)

| Action | When it applies | Data source |
|---|---|---|
| Upgrade to safe version | OSV gives a fixed version | Smallest version that is not vulnerable, preferring patch, then minor, then major |
| Pin a trusted version | Suspicious new version, older one clean | History + registry: the last known-good version |
| Replace the dependency | Abandoned, malicious or no fix exists | Curated alternatives list + registry popularity |
| Remove the dependency | Declared but unused (code index shows no imports) | Code index + graph |
| Update the container base image | Vulnerable OS packages or a mutable tag | Newer digest of the same image line, or a slim/distroless variant |
| Block the component | Confirmed malicious | Deny rule in the policy file + lockfile removal |
| Escalate for security review | Low confidence, no safe fix, or breaking change too large | Always available as a fallback |

For a transitive vulnerability, the "upgrade" candidate means one of three things: bump the *direct* parent that pulls in a fixed version, use an override/resolution (npm `overrides`, pip constraints), or pin the transitive package explicitly. Use the Day 1 graph paths to find the parent.

### 4.2 Simulation on the graph (before touching anything)

Re-resolve the dependency set with the candidate change in the sandbox, without installing scripts. The simulation answers:
- Does the target finding disappear?
- Does the change pull in new packages or new vulnerabilities (run OSV against the simulated set)?
- Is it a major-version jump? Did the APIs the code uses change? Check the symbols from the code index against the changelog or the new package's exports.

### 4.3 Ranking (Remediation Tournament, round 1)

The tournament has two rounds so it stays affordable. Round 1 is cheap: every candidate is simulated (4.2) and scored. Round 2 is expensive and runs only the top 2–3 candidates through a real build and tests (S14). The winner is picked on security, compatibility and test results together.

Each candidate gets:
- **Expected risk reduction:** which findings it closes, and the score delta.
- **Compatibility impact:** *low* (patch, no API change), *medium* (minor version or new transitive packages) or *high* (major version, replacement, removed APIs used by the code).
- **Rollback option:** the exact revert, e.g. the previous lockfile hash, the previous image digest, the git revert of the remediation commit.

The LLM may write the human-readable rationale and order close ties. It cannot invent versions: any version it mentions that is not in the candidate list is rejected by the Verifier.

**Output:** `remediation_plan.json`, with a recommended action plus alternatives per finding.

---

## 5. S13: Human approval

A UI card per finding shows the finding, the recommended fix, the alternatives, the risk reduction, the compatibility impact and the rollback. The reviewer can **approve**, **edit** (choose another candidate or version), **reject** or **accept the risk** (with a reason and expiry date). The decision, reviewer, timestamp and reason go to the audit log. Nothing proceeds to S14 without an approval record.

**Immutable approval gate:**
- The reviewer approves a **plan**, not a finding. The plan is the exact set of changes: manifest/lockfile diff, target versions, image digests, and the list of tournament finalists that may be tried.
- Guardian computes a **plan hash** (sha256 of the normalized plan) and stores it in the approval record, which is append-only.
- Before S14 applies anything, it recomputes the hash of what it is about to apply. If the hashes differ, it stops and asks for fresh approval.
- Any change, whether a reviewer edit, a self-correction candidate (S14.6) or a regenerated lockfile with different resolved versions, produces a new hash and therefore needs a new approval.
- Opening a PR is a second, separate approval bound to the final diff hash.

---

## 6. S14: Validate the fix ("test before you trust")

1. **Controlled branch/sandbox:** copy the repo at the scanned commit into a container and create branch `guardian/fix-<finding-id>`. Apply the change: manifest edit, lockfile regeneration, Dockerfile `FROM` update, or override.
2. **Build:** detect the build command per ecosystem (`pip install` + import check, `npm ci && npm run build`, `mvn package`, `go build`, `docker build`). Record the exit code and logs.
3. **Tests:** run the unit and integration tests the repo defines (pytest, npm test, mvn test, go test). Run tests on the **original** tree too, so pre-existing failures are not blamed on the fix. A fix only counts as breaking something if a test passes before and fails after.
4. **No tests in the repo:** fall back to a smoke check: install succeeds, the app imports/starts, and the routes from the code index respond. Report it honestly as *"validated by smoke test only"*, which lowers confidence.
5. **Tournament round 2:** run steps 1–4 for each approved finalist (top 2–3 from S12), each in its own branch and container. Rank finalists on: target resolved (from the S15 rescan), tests broken, new findings introduced, compatibility impact. The best one goes forward; the rest are kept in the report as evidence of what was tried.
6. **Agentic self-correction:** if every finalist fails the build or tests:
   - An agent reads the build/test logs (read-only tool access) and classifies the failure: API removed, peer-dependency conflict, lockfile conflict, flaky or unrelated test, environment problem.
   - It proposes a **new** candidate, e.g. a lower fixed version, an added peer-dependency bump, or an override instead of a direct bump. Any version it proposes must exist in the registry and OSV data; otherwise the Verifier rejects it.
   - The new candidate goes through S12 simulation and then **back to S13 for fresh approval**, because its plan hash is new.
   - Bounded: at most 2 self-correction rounds per finding. After that, escalate for security review with the collected logs.

**Output:** `validation.json`, with build status, test pass/fail counts before vs. after, logs, duration, tournament results and self-correction attempts.

---

## 7. S15: Rescan and compare

Run the **Day 1 pipeline unchanged** on the patched tree. This produces new facts, a new SBOM, a new graph and new findings. Then diff:

- **SBOM diff:** components added, removed and changed in version, plus changes in license and origin.
- **Findings diff:** *resolved* (the target, plus any bonus fixes), *still open*, and *newly introduced*: new CVEs, new suspicious packages, new install scripts, new transitive dependencies.
- **Risk delta:** the total score before vs. after and the band counts before vs. after.

**Regression gate:** if the target is not resolved, or any new P0/P1 finding appears, the fix is marked **not verified**, even when the build and tests passed. The gate is evaluated by the policy engine (section 9), so the rules are visible and versioned instead of hard-coded.

---

## 8. S16: Verify and report ("show the complete story")

The final report per remediated finding contains:
1. **Original finding + supporting evidence** (from Day 1/S11).
2. **Recommended and approved action**, with who approved it and the alternatives considered.
3. **Build and test results**, before and after.
4. **Before-and-after risk status**: the SBOM diff and findings diff from S15.
5. **Remaining or accepted risk**: what is still open, and what was accepted with reason and expiry.
6. **Final confidence + audit trail**: one verdict (*Verified*, *Partially verified* or *Not verified*), the confidence level with its reasons, and a timeline of every step with evidence IDs.
7. **Policy results**: each policy rule with pass/fail and the evidence it was evaluated on.

**Independent remediation verification:**
- **Step 1, deterministic verdict.** Computed from facts only: the S15 rescan diff, S14 test results, the policy evaluation and the approval hash match. This sets the verdict.
- **Step 2, independent verifier agent.** A separate agent, with its own prompt, that never sees the remediation agent's reasoning. It gets only the raw evidence (original finding, approved plan, applied diff, logs, rescan diff, policy results) and checks: is the vulnerable version really gone from *every* path in the new graph? Was the applied diff what was approved? Are there new findings the gate missed because of low confidence? Do the claims in the report match the evidence?
- The verifier agent can **downgrade** a verdict (e.g. Verified → Partially verified) and must cite evidence for it. It can never upgrade a verdict the deterministic step failed. Its claims go through the Day 1 Verifier like every other AI claim.

Optional: generate a PR or patch file (diff + report summary as the description), opened only after a second human confirmation. Also optional: a VEX statement for findings judged not exploitable.

---

## 9. Policy-as-code engine

A versioned policy file (e.g. `guardian-policy.yaml`) in the scanned repo, or a default shipped with Guardian. Rules are simple, declarative conditions over the Day 1/Day 2 data, for example:

| Rule | Meaning |
|---|---|
| `no-critical-in-prod` | No open Critical vulnerability in runtime scope |
| `no-kev` | No open finding listed in CISA KEV, any scope |
| `no-malicious` | No component with a malicious-package advisory or a *likely malicious* S11 verdict |
| `resolved-prod-deps` | Every prod dependency has a resolved version (no unresolved or guessed versions) |
| `pinned-base-images` | Container base images pinned by digest |
| `pinned-ci-actions` | Third-party CI actions pinned by commit SHA |
| `approved-changes-only` | The applied diff hash equals an approved plan hash |
| `no-new-high` | The fix introduces no new P0/P1 finding |
| `risk-acceptance-expiry` | Every accepted risk has a reason, an owner and an unexpired expiry date |

How it is used:
- **S10:** policy violations raise a finding into the *Fix now* bucket.
- **S12:** candidates that would violate a policy are discarded before the tournament.
- **S15/S16:** the regression gate and the final verdict are a policy evaluation. Each rule result is stored with the evidence IDs it used.
- Each rule has a severity: **block** (fails the verdict) or **warn** (reported only). The policy file's hash is recorded in the report, so the verdict can be reproduced later.

---

## 10. New data contracts (in addition to the Day 1 models)

| Model | Holds |
|---|---|
| **RiskScore** | finding ID, factor contributions, total, confidence + reasons, queue bucket |
| **Investigation** | finding ID, version/lockfile/content diffs, provenance checks, claims (fact/inference/unknown), verdict |
| **RemediationCandidate** | action type, target change, simulated resolved set, findings closed, new findings, compatibility, rollback, rank |
| **RemediationPlan** | finding ID, finalist candidates, normalized change set, plan hash |
| **ApprovalRecord** | plan hash, decision, reviewer, reason, timestamp, risk-acceptance expiry, superseded-by (for re-approvals) |
| **ValidationResult** | branch, build result, tests before/after, smoke-only flag, logs evidence ID, tournament rank |
| **CorrectionAttempt** | failure classification, log evidence IDs, proposed candidate, new plan hash, outcome |
| **RescanDiff** | SBOM added/removed/changed, findings resolved/open/new, score delta, regression gate result |
| **PolicyResult** | policy file hash, rule ID, block/warn, pass/fail, evidence IDs |
| **VerifierReview** | independent agent's checks, claims, downgrade (if any) with evidence |
| **VerificationReport** | all of the above + verdict + final confidence + audit timeline |

---

## 11. Orchestration

Extend the existing LangGraph app with an S10→S16 subgraph that runs **per finding** and **pauses at S13** (a LangGraph interrupt; the existing SQLite checkpointer makes the pause resumable). The edges are conditional: tournament round 2 picks the best finalist; if all fail, self-correction loops back through S12 and S13 (fresh approval) up to 2 times, then escalates; a policy failure in S15 leads to not verified. Each stage fails soft, as on Day 1: a crashed step becomes a recorded degraded state, never a fake success.

The remediation agent (S12 rationale, S14.6 self-correction) and the verifier agent (S16) are separate agents with separate prompts and tool sets. The verifier has read-only access to evidence only.

**UI/API additions:** a prioritized queue view, an investigation panel (facts and inferences shown visually distinct), a remediation card with approve/reject buttons, a live validation log, and a before/after comparison (SBOM diff + graph with removed nodes greyed out and new ones highlighted).

---

## 12. Image → stage mapping

| Image column | Stage |
|---|---|
| 1 Prioritize Risks | S10 |
| 2 Investigate Suspicious Changes | S11 |
| 3 Recommend Safe Remediation | S12 |
| (Human approval in the outcome strip) | S13 |
| 4 Validate the Proposed Fix | S14 + S15 |
| 5 Verify & Report | S16 |

---

## 13. Suggested demo script (about 5 minutes)

1. Scan the fixture repo and show the prioritized queue, then open the top item's score breakdown (including component criticality).
2. Open a **non-CVE** finding (e.g. the typosquat or tampered lockfile in the fixture) and show the investigation: facts and AI inferences side by side.
3. Open a **CVE** finding. Show the tournament candidates with risk reduction, compatibility and rollback, then click **Approve**. Point out the plan hash on the approval.
4. Watch the finalists build, test and rescan live, and the tournament pick a winner.
5. Show the before/after: the finding is resolved, nothing new was introduced, the SBOM diff and the score drop, every policy rule passes, the independent verifier agrees, the verdict is **Verified** with high confidence, and the audit trail is visible.
6. Bonus: show a fix that **fails** (e.g. a major bump that breaks a test or pulls in a new CVE). Self-correction proposes a new candidate, Guardian asks for **fresh approval** because the plan hash changed, and the policy gate marks the failed attempt not verified. This shows the system is trustworthy, not just successful.

**Build order if time is short:**
1. Core loop: S12 upgrade/pin only → S13 with plan hash → S14 single candidate → S15 diff → S16 report.
2. Policy engine with 4–5 rules, wired into S15/S16.
3. Independent verifier agent.
4. Tournament round 2 (multiple finalists).
5. Self-correction.
6. S10 criticality and scoring polish, S11 tarball diff, extra remediation types.
