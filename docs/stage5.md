# Software Supply Chain Guardian: Stage 5 Build Plan
## Suspicious Change Investigator (Day 1, slide step 4)

**Version:** final v2 · **Depends on:** Stages 1–4 plans

> **What Stage 5 does:** finds supply-chain **anomalies**, things that look suspicious **even when no CVE exists** (typosquats, hijacked updates, malicious install hooks, tampered lockfiles, untrusted build environments). Deterministic **detectors** raise signals. Signals are **grouped per subject**, and the **same investigator pattern as Stage 4** (no new agent architecture) investigates each group once and produces **one evidence-backed finding**.
>
> Slide requirement: *"Identify at least one supply-chain anomaly."* The 6 core detectors cover all 6 slide examples.

```
1 Detectors ─► 2 Group + prioritize ─► 3 Investigator agent ─► 4 Verifier* ─► 5 Suspicion · exposure · risk ─► 6 Human review* ─► 7 Report
 no AI          no AI                   AI (Stage 4 pattern)     conditional     rules                          interrupt           no AI
```

---

## 1. Ground rules

1. **Detectors are deterministic and explainable.** Each signal states the exact rule and data that triggered it.
2. **A signal is not a verdict, and metadata alone never proves malice.** Young package, few releases, no source repo, low downloads, recent release, maintainer change: legit packages have these too. Metadata-only signals are **weak or medium, never strong**. Escalation needs **behaviour evidence** (code, hashes, install hooks).
3. **Never use the word "malicious" unless behaviour is proven.** Wording is *"suspicious behaviour found"* / *"malicious intent not established"*.
4. **Separate capability from exposure:**
   - **Capability:** the package/file *contains* dangerous behaviour (e.g. `setup.py` makes a network call).
   - **Exposure:** that behaviour is *likely to run in your environment* (in the install set, on the install path, imported by reachable code).
   - Our scan never runs anything, so we never claim *"executed"*. The strongest exposure claim is *"will run when this project is installed"*.
5. **Four separate values per finding:** **Suspicion** · **Exposure** · **Project risk** · **Confidence**.
6. **One finding per subject.** A package with 5 signals = one finding listing 5 evidence-backed signals, not 5 alarming cards.
7. Same tools, budgets, evidence rules, verifier and review store as Stage 4.

---

## 2. The 6 core detectors

All read the Stage 3 graph, `facts.json`, `changes.json` and 3D findings. Each emits `Signal`s with a fixed `strength`.

### D1. Typosquatting (slide: typosquatted package)
- Reference: **top ~5,000 PyPI packages** (public "top-pypi-packages" dataset, cached; verify the source before the demo) + `allowlist.yaml` for legit near-names.
- PEP 503 name normalization; for each package **not** in the top list:
  - Damerau-Levenshtein distance ≤ 2 (`rapidfuzz`) · separator tricks (`python_dateutil`) · affixes (`requests-py`, `py-requests`) · lookalikes (`l`↔`1`, `o`↔`0`, `rn`↔`m`)
- **Strength:** name match alone = **medium**; name match + any behaviour finding from D4 = **strong**. Metadata (young, 1 release, no repo) only adds context, never strength.

### D2. Unexpected changes (slide: unexpected dependency; *absorbs suspicious code changes*)
- New direct dependency that is `declared_unused`, or used only by a file added in the same commit → **medium**
- New transitive package with no manifest/parent version change → **medium**
- **Code behaviour changes** from the Stage 3 diff + 3D `notable` findings: new outbound domain, new secret env read, new `exec`/`subprocess` in a recent commit → **medium**; **strong** if user/secret data is sent to a domain introduced in the same change
- Commit message doesn't mention the dependency → **weak** (context only)

### D3. Suspicious package updates (slide: suspicious package update)
For each version change in the diff:
- release < 7 days before the commit that pulled it in → **weak**
- author / maintainer / `project_urls` changed between versions → **medium**
- previous versions had wheels, new one is **sdist-only** (build code now runs on install) → **medium**
- new install-time dependencies in `requires_dist`, or yanked version → **medium**
- **Deep check** (only when ≥ 1 medium signal): download old + new distributions into the sandbox (section 3), unpack, diff, run Stage 2 AST visitors on **changed files only**. New network calls / `exec`/`eval` / `base64`+`exec` / `subprocess` / env harvesting / new domains → **strong**.

### D4. Unsafe install behaviour (slide: unsafe install script)
For sdist-only packages, VCS/URL dependencies, and anything flagged by D1/D3:
- AST-scan `setup.py`, custom build backends, `cmdclass` hooks: network, subprocess, `exec`/`eval`, writes outside the build dir, env reads, obfuscation (long base64, `compile`+`exec`) → **strong**
- Wheels: **`.pth` files containing code** (run on every Python start) → **strong**; unexpected `console_scripts` → **weak**

### D5. Untrusted build environment (slide: untrusted image; *absorbs CI/CD*)
- **Images:** base image not digest-pinned / `latest` / no tag → **weak**; non-official namespace or unknown registry → **medium**; `ADD <url>` or `curl|sh` / `wget|bash` in `RUN` → **medium**; packages installed in the Dockerfile but not in the manifests (shadow deps) → **medium**
- **CI/CD subchecks:** third-party action not SHA-pinned → **weak**; `pull_request_target` + checkout of PR head → **strong**; `write-all` / missing `permissions` → **weak**; `curl|bash` or secrets in PR-triggered workflows → **medium**

### D6. Lockfile integrity & provenance (slide: modified lockfile; *absorbs dependency confusion*)
- lockfile changed with no manifest change → **medium**
- lockfile hash ≠ PyPI's published hash for the same file → **strong**
- a package's source changed (registry → git URL / other index) → **medium**
- index URL changed / extra index added → **medium**
- **Dependency confusion:** extra index configured **and** an internal-looking name (not in the top list) also exists on public PyPI → **medium**; **strong** if the resolved file came from the public index while an internal index exists

### `Signal` shape
```json
{
  "signal_id": "S-003", "detector": "D1", "check": "typosquat_edit_distance",
  "subject": "pkg:pypi/reqeusts@2.31.0",
  "data": {"looks_like": "requests", "distance": 1},
  "context": {"first_release": "…", "release_count": 1, "has_source_repo": false},
  "commit": "a1b2c3d",
  "evidence": [{"file": "requirements.txt", "line": 6}, {"pypi": "reqeusts"}],
  "strength": "medium"
}
```
`data` = what triggered the rule; `context` = metadata shown to the agent and user but **not** used for strength.

---

## 3. Sandbox for package analysis (strict)

Used by D3 deep check and D4. **Our tool must never become the attacker's execution environment.**
- Disposable container per analysis, **deleted afterwards**; non-root user; read-only root FS except a scratch dir.
- **No network inside the sandbox.** Downloads happen *outside* via the PyPI JSON file URLs, and we **verify the sha256 against PyPI's published hash** before passing the file in.
- **Never** run `pip install`, build backends, `setup.py`, or import any package code. Parse only (`ast`, text, `zipfile`/`tarfile` listing).
- Limits: CPU 1 core, memory 512 MB, timeout 60 s, archive ≤ 50 MB, extracted total ≤ 200 MB, ≤ 5,000 files, max depth 10.
- Safe extraction: reject absolute paths, `..`, symlinks/hardlinks outside the target, device files; stop on decompression-ratio > 100 (zip-bomb guard).
- Output = facts JSON only (changed files, AST facts, line ranges). The agent reads package files through `read_package_file`, never directly.

---

## 4. Group + prioritize (deterministic)

1. **Group signals by subject** (package, image, workflow, lockfile, or code file).
2. Assign a **priority band**:
   - **P1:** any strong signal; or medium signal + exposure `install_path` / `runtime_public`
   - **P2:** 2+ medium signals; or medium signal with meaningful blast radius
   - **P3:** weak signals, metadata-only concerns
3. Within a band, order by an internal sort key (number/strength of signals, blast radius, new-in-diff). This key is **for ordering only** and is never shown as a score.
4. **Deep investigation:** all P1 + P2 up to **15 subjects**. P3 gets a light pass (rules only, `confidence: low`, no agent).

---

## 5. Investigator agent (Stage 4 pattern, reused)

Same LangGraph subgraph, budget (≤ 10 tool calls, ≤ 120 lines per read) and verifier logic as Stage 4. **One investigation per grouped subject.**

**Extra tools** (added to the shared toolset):
| Tool | Returns |
|---|---|
| `pypi_info(name, version)` | metadata, release history, maintainers, files, hashes |
| `compare_names(name)` | closest top packages, distances, popularity |
| `package_diff(name, old, new)` | changed files + AST facts on them (via sandbox) |
| `read_package_file(name, version, path, start, end)` | lines from the unpacked distribution, ≤ 120 |
| `scan_install_hooks(name, version)` | D4 results for that version |
| `exposure(subject)` | install-set membership, install path type (sdist build / wheel), `.pth`, importers, blast radius |

**The agent answers, per subject:**
1. **Is there a normal explanation?** (popular project's routine release, intended rename, commit message explains it, same maintainer org)
2. **What behaviour is actually present?** Concrete, with file/lines.
3. **What's the exposure?** Is it in the install set, does its code run on install or on import, and who imports it?

**Output `AnomalyInvestigation`:**
```json
{
  "subject": "pkg:pypi/reqeusts@2.31.0",
  "signals": ["S-003", "S-011", "S-012"],
  "normal_explanation": null,
  "behaviour": [{"type": "install_network_call", "package_file": "setup.py", "lines": "14-18"}],
  "capability": "install-time network request found in setup.py",
  "exposure": "install_path",
  "exposure_note": "In the resolved install set; sdist-only, so setup.py runs whenever this project is installed (e.g. in CI). Not executed during our scan.",
  "usage_in_repo": {"imported_by": ["file:app/utils/helpers.py"], "blast_radius": "public"},
  "claims": [{"text": "setup.py performs an HTTP request at install time", "evidence": [{"package_file": "setup.py", "lines": "14-18"}]}],
  "unknowns": ["destination server's purpose"],
  "tool_calls_used": 7
}
```

---

## 6. Suspicion, exposure, risk, confidence (rules)

### Suspicion (how anomalous)
| Suspicion | When |
|---|---|
| **High** | a **strong** signal whose behaviour is **verified** in code/package lines, or a hash mismatch |
| **Medium** | a strong signal without verified behaviour, or 2+ medium signals |
| **Low** | single medium/weak signal, metadata-only, or a **verified normal explanation** |

### Exposure (will it run here?)
| Exposure | Meaning |
|---|---|
| `install_path` | in the resolved install set and its code runs on install (sdist build hook) or on every Python start (`.pth`) |
| `runtime_public` | imported by code reachable from a public route |
| `runtime_internal` | imported by code, no public path found |
| `build_env` | CI workflow / Docker image used to build or run the app |
| `not_in_install_set` | present in files/history but not resolved for installation |
| `unknown` | couldn't determine |

### Project risk = suspicion × exposure
| Suspicion ↓ / Exposure → | `install_path` · `runtime_public` · `build_env` | `runtime_internal` | `not_in_install_set` · `unknown` |
|---|---|---|---|
| **High** | Critical | High | Medium (*"capability found, exposure not shown"*) |
| **Medium** | High | Medium | Low |
| **Low** | Medium | Low | Low |

- A suspicious `setup.py` found in a package that **isn't** in the install set is **not** auto-High. It's shown as *capability found, exposure not shown*.
- **Downgrade guard:** a **strong** signal that ends at Low (because of a "normal explanation") → human review required.

### Confidence
**High** = behaviour + exposure backed by verified lines and graph edges · **Medium** = metadata or exposure partly inferred · **Low** = budget exhausted, unknowns, or light pass.

---

## 7. Human review and report

- Same `interrupt` review node, actions (`confirm` / `dismiss` with reason / `override`), and `triage.json` as Stage 4.
- Graph: node `Anomaly` (`anomaly:A-004`), edges `FLAGS` → Package / File / Image / Workflow / Commit.
- **Finding card** = Stage 4 shape with `type: "anomaly"`, plus `detectors[]`, `signals[]` (each with its own evidence), `suspicion`, `exposure`, `capability`, `normal_explanation`.
- Shown in the **same unified findings inbox** as vulnerabilities (distinct type icon and fields).
- Files: `signals.json`, `anomaly_findings.json`. API: covered by the unified `GET /findings` and `GET /findings/{id}` (Stage 6).

---

## 8. Folder structure

```
guardian/stage5_anomalies/
  detectors/  d1_typosquat.py  d2_unexpected.py  d3_updates.py
              d4_install.py    d5_build_env.py   d6_lockfile.py
  data/       top_pypi.json  allowlist.yaml
  sandbox/    runner.py  safe_extract.py  Dockerfile
  group.py  prioritize.py  tools.py  rules.py  workflow.py  schema.py
  # investigator + verifier + review are imported from stage4_vulns (shared)
```

---

## 9. Who does what

| Person | Owns |
|---|---|
| **Dev A** | D1, D2, D6 + top-list data + allowlist |
| **Dev B** | D3, D4 + sandbox (safe extraction, limits, no-network) + `package_diff` |
| **Dev C** | D5 + `exposure()` tool + grouping/prioritization |
| **Lead** | new agent tools wired into the shared investigator, `rules.py`, report |

---

## 10. Fixture additions (`mini-shop`), harmless only

Run a **local PyPI-style index** in Docker (e.g. `pypiserver`) with **harmless fake packages**. Never use real malicious packages.
- `reqeusts` (typosquat, sdist-only): `setup.py` contains an HTTP call to `https://example.invalid` that is **never executed** by us (we only parse it). Expected: D1 + D4 → suspicion High, exposure `install_path` → **Critical**.
- `colorama` added unused (from Stage 1–2). Expected: D2 medium, Low/Medium.
- `send_event()` new outbound domain (from Stage 3). Expected: D2 strong (order data to a new domain) → High.
- Fake `mini-utils` 1.0 (wheel) → 1.1 (sdist-only, adds `base64`+`exec` of a harmless string). Expected: D3 deep check strong.
- **Legit-looking case:** a fake package with a recent release but the same maintainer, wheels and no behaviour change. Expected: agent finds a **normal explanation** → Low. This proves we don't just alarm.
- Lockfile-only commit with one altered hash. Expected: D6 strong.
- Dockerfile `FROM python:latest` + `RUN curl … | sh` (local harmless script). Workflow with a third-party action by tag + `pull_request_target`. Expected: D5 findings.

---

## 11. Definition of done

- [ ] 6 detectors run; every fixture case raises its expected signals with the right strength
- [ ] Signals are grouped: one finding per subject, each signal with its own evidence
- [ ] Metadata-only signals never exceed medium; "malicious" never appears without verified behaviour
- [ ] Capability and exposure are separate fields; no finding claims "executed"
- [ ] Sandbox: no network, no install/import, limits enforced, unsafe archives rejected, container deleted
- [ ] The legit-looking fixture is correctly explained as normal (verified)
- [ ] Downgrade guard + review work; decisions persist
- [ ] Findings appear in the unified inbox next to Stage 4 vulnerabilities

**Later enhancements (not Day 1):** full CI/CD rule set, more dependency-confusion heuristics, popularity data from download stats, signature/attestation checks (e.g. PEP 740 attestations) where available.