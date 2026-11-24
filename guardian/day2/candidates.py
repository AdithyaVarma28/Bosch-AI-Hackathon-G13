"""Step A: deterministic remediation candidates (docs/DAY_2_PLAN.md section 4.1).

Every candidate carries a ready patch (exact-snippet edits) when one can be generated without AI, its checks, a
rollback and the expected risk after the fix. One remediation can fix several findings (one upgrade covers every
CVE of a package)."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .common import BANDS, CONF, DECISIONS, band_idx, conf_idx, load_config, norm_name

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None


def V(s) -> Optional[Version]:
    try:
        return Version(str(s))
    except (InvalidVersion, TypeError):
        return None


# ------------------------------------------------------------------ repository files
class RepoFiles:
    def __init__(self, repo: Optional[Path]):
        self.repo = repo
        self.req_files = sorted(p.relative_to(repo).as_posix() for p in repo.glob("requirements*.txt")) if repo else []
        self.lock_deps: dict[str, list[tuple[str, str]]] = {}     # dependency -> [(dependent, spec)]
        self.lock_versions: dict[str, str] = {}
        self.lock_text = self.text("poetry.lock")
        if self.lock_text and tomllib:
            try:
                data = tomllib.loads(self.lock_text)
                for p in data.get("package", []):
                    self.lock_versions[norm_name(p["name"])] = p.get("version")
                    for dep, spec in (p.get("dependencies") or {}).items():
                        s = spec if isinstance(spec, str) else (spec or {}).get("version", "*")
                        self.lock_deps.setdefault(norm_name(dep), []).append((p["name"], s))
            except Exception:
                pass

    def text(self, rel: str) -> Optional[str]:
        if not self.repo:
            return None
        try:
            with open(self.repo / rel, "r", encoding="utf-8", newline="") as fh:
                return fh.read()
        except (FileNotFoundError, OSError):
            return None

    SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "site-packages", "dist", "build"}
    TOOLS = {"gunicorn", "uwsgi", "uvicorn", "hypercorn", "waitress", "setuptools", "pip", "wheel", "celery", "alembic",
             "flask-migrate", "honcho", "supervisor", "pytest", "tox", "black", "flake8", "mypy", "coverage"}

    def _texts(self) -> list[tuple[str, str]]:
        if getattr(self, "_cache", None) is None:
            self._cache = []
            if self.repo:
                n = 0
                for p in self.repo.rglob("*"):
                    if n > 3000 or not p.is_file() or set(p.relative_to(self.repo).parts) & self.SKIP_DIRS:
                        continue
                    rel = p.relative_to(self.repo).as_posix()
                    if rel.startswith("requirements") or rel in ("poetry.lock", "Pipfile.lock") or p.stat().st_size > 300_000:
                        continue
                    if p.suffix in (".py", ".sh", ".yml", ".yaml", ".cfg", ".ini", ".toml", ".json") or \
                            p.name in ("Procfile", "Makefile") or p.name.startswith("Dockerfile"):
                        try:
                            self._cache.append((rel, p.read_text(encoding="utf-8", errors="ignore")))
                            n += 1
                        except OSError:
                            pass
        return self._cache

    def references(self, name: str) -> list[str]:
        """Where the repository uses a package outside the manifests: imports under its module names, or mentions in
        Dockerfiles, Procfiles, scripts, CI and config. Empty = no reference found."""
        low = name.lower()
        mods = {low.replace("-", "_").replace(".", "_"), low.split("-")[-1].replace(".", "_")}
        if low.startswith("python-"):
            mods.add(low[7:].replace("-", "_"))
        imp = re.compile(r"^\s*(?:from|import)\s+(" + "|".join(re.escape(m) for m in mods) + r")\b", re.M | re.I)
        word = re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", re.I)
        hits = []
        for rel, txt in self._texts():
            if (rel.endswith(".py") and imp.search(txt)) or (not rel.endswith(".py") and word.search(txt)):
                hits.append(rel)
        return hits[:5]

    def can_remove(self, name: str, required_by: list[str], dep_info: bool) -> tuple[bool, str]:
        if norm_name(name) in self.TOOLS:
            return False, f"{name} is usually run as a command, not imported"
        if required_by:
            return False, f"required by {', '.join(required_by[:3])}"
        if not dep_info:
            return False, "no lockfile / dependency edges: it may be a dependency of another package"
        refs = self.references(name)
        if refs:
            return False, f"referenced in {', '.join(refs)}"
        return True, "never imported, not referenced, and no installed package requires it"

    @staticmethod
    def name_re(name: str) -> str:
        return "[-_.]".join(re.escape(p) for p in re.split(r"[-_.]+", name))

    def req_lines(self, name: str) -> list[tuple[str, str, re.Match]]:
        """[(file, full line incl. newline, match)] for lines declaring the package."""
        out = []
        rx = re.compile(rf"^[ \t]*({self.name_re(name)})(\[[^\]]*\])?[ \t]*(==|>=|~=|<=|!=|>|<)?[ \t]*([^\s;#]*)([^\r\n]*)(\r?\n|$)",
                        re.I | re.M)
        for f in self.req_files:
            t = self.text(f) or ""
            for m in rx.finditer(t):
                if m.group(0).strip():
                    out.append((f, m.group(0), m))
        return out

    def lock_block(self, name: str) -> Optional[str]:
        if not self.lock_text:
            return None
        rx = re.compile(rf'\[\[package\]\]\r?\nname = "{self.name_re(name)}"\r?\n.*?(?=\r?\n\[\[package\]\]|\r?\n\[metadata\]|\Z)',
                        re.I | re.S)
        m = rx.search(self.lock_text)
        return m.group(0) if m else None


# ------------------------------------------------------------------ version checks
class VersionTools:
    def __init__(self, out: Path, repo: RepoFiles):
        from guardian.stage4_vulns.pipeline import vulndb_dir
        from guardian.stage4_vulns.sources import HttpCache, OSVClient
        cfg = load_config(out)
        self.offline = bool(cfg.get("offline"))
        cache = HttpCache(vulndb_dir(Path(out)), offline=self.offline)
        dump = cfg.get("osv_dump")
        self.osv = OSVClient(cache, Path(dump) if dump else None, prefer_dump=bool(dump))
        self.cache = cache
        self.pypi_url = cfg.get("pypi_url")
        self.repo = repo
        self._proj: dict[str, Optional[dict]] = {}
        self._osv: dict[tuple[str, str], list[dict]] = {}
        self.python = self._project_python()

    def _project_python(self) -> tuple[Optional[str], str]:
        df = self.repo.text("Dockerfile") or ""
        m = re.search(r"FROM\s+python:(\d+\.\d+)", df)
        if m:
            return m.group(1), "Dockerfile base image"
        return f"{sys.version_info.major}.{sys.version_info.minor}", "running interpreter (project version unknown)"

    def project(self, name: str) -> Optional[dict]:
        if name not in self._proj:
            try:
                from guardian.stage5_anomalies.pypi import PyPIClient
                self._proj[name] = PyPIClient(self.cache, base=self.pypi_url).project(name)
            except Exception:
                self._proj[name] = None
        return self._proj[name]

    def releases(self, name: str) -> Optional[dict[str, dict]]:
        p = self.project(name)
        if not p or not p.get("releases"):
            return None
        out = {}
        for ver, files in (p.get("releases") or {}).items():
            files = files or []
            out[ver] = {"yanked": bool(files) and all(f.get("yanked") for f in files),
                        "requires_python": next((f.get("requires_python") for f in files if f.get("requires_python")), None)}
        return out

    def vulns_of(self, name: str, version: str) -> list[str]:
        key = (name, version)
        if key not in self._osv:
            try:
                recs = self.osv.query([key]).get(key, [])
            except Exception:
                recs = None
            self._osv[key] = recs
        recs = self._osv[key]
        if recs is None:
            return None
        return sorted({r.get("id") for r in recs if r.get("id")})

    def check(self, name: str, version: str) -> dict:
        """Static checks for one candidate version."""
        res: dict = {}
        vul = self.vulns_of(name, version)
        if vul is None or (self.osv.mode == "none"):
            res["candidate_clean"] = {"status": "unknown", "detail": "no OSV data available (offline, no dump)"}
        elif vul:
            res["candidate_clean"] = {"status": "fail", "detail": f"{version} is affected by {', '.join(vul[:4])}"}
        else:
            res["candidate_clean"] = {"status": "pass", "detail": f"OSV ({self.osv.mode}) lists no vulnerability for {name} {version}"}
        deps = self.repo.lock_deps.get(norm_name(name), [])
        if not deps:
            res["constraints_resolve"] = {"status": "pass" if self.repo.lock_text else "unknown",
                                          "detail": "no other locked package constrains it" if self.repo.lock_text
                                          else "no lockfile: dependents' constraints unknown"}
        else:
            bad = []
            for dep, spec in deps:
                try:
                    if spec not in ("*", "") and V(version) not in SpecifierSet(spec):
                        bad.append(f"{dep} requires {name}{spec}")
                except InvalidSpecifier:
                    pass
            res["constraints_resolve"] = ({"status": "fail", "detail": "; ".join(bad)} if bad else
                                          {"status": "pass", "detail": "satisfies " + ", ".join(f"{d} ({s})" for d, s in deps[:4])})
        rel = self.releases(name)
        if rel is None:
            res["available"] = {"status": "unknown", "detail": "release list not available from the configured index"}
            res["runtime_compatible"] = {"status": "unknown", "detail": "requires_python unknown"}
        else:
            info = rel.get(version)
            if info is None:
                res["available"] = {"status": "fail", "detail": f"{version} is not on the configured index"}
            elif info["yanked"]:
                res["available"] = {"status": "fail", "detail": f"{version} is yanked"}
            else:
                res["available"] = {"status": "pass", "detail": f"{version} is available"}
            rp = (info or {}).get("requires_python")
            py, src = self.python
            try:
                ok = not rp or V(py) in SpecifierSet(rp)
                res["runtime_compatible"] = {"status": "pass" if ok else "fail",
                                             "detail": f"requires_python {rp or 'any'} vs Python {py} ({src})"}
            except (InvalidSpecifier, TypeError):
                res["runtime_compatible"] = {"status": "unknown", "detail": f"requires_python {rp!r} unreadable"}
        return res


# ------------------------------------------------------------------ edit builders
def upgrade_edits(rf: RepoFiles, name: str, old: str, new: str, declared: bool) -> tuple[list[dict], list[str]]:
    edits, notes = [], []
    for f, line, m in rf.req_lines(name):
        if m.group(3) == "==" and m.group(4) == old:
            edits.append({"path": f, "old_text": line.rstrip("\r\n"), "new_text": line.rstrip("\r\n").replace(f"=={old}", f"=={new}", 1)})
    if not edits and rf.req_files and not declared:
        f = "requirements.txt" if "requirements.txt" in rf.req_files else rf.req_files[0]
        t = rf.text(f) or ""
        last = [l for l in t.splitlines() if l.strip()]
        if last and t.count(last[-1]) == 1:
            edits.append({"path": f, "old_text": last[-1], "new_text": f"{last[-1]}\n{name}>={new}  # guardian: pin patched transitive dependency"})
            notes.append(f"{name} is transitive: added a direct minimum-version constraint")
    block = rf.lock_block(name)
    if block:
        vline = re.search(rf'version = "{re.escape(old)}"', block)
        if vline:
            nb = block.replace(vline.group(0), f'version = "{new}"', 1)
            nb2 = re.sub(r"files = \[[^\]]*\]", "files = []", nb, flags=re.S)
            if nb2 != nb:
                notes.append("lockfile hashes for the new version must be regenerated (poetry lock)")
            edits.append({"path": "poetry.lock", "old_text": block, "new_text": nb2})
    return edits, notes


def remove_edits(rf: RepoFiles, name: str, keep_lock: bool) -> list[dict]:
    edits = [{"path": f, "old_text": line, "new_text": ""} for f, line, _ in rf.req_lines(name)]
    block = rf.lock_block(name)
    if block and not keep_lock:
        edits.append({"path": "poetry.lock", "old_text": "\n" + block if ("\n" + block) in (rf.lock_text or "") else block,
                      "new_text": ""})
    return edits


SAFE_API = [  # (regex on the call site, replacement, label)
    (re.compile(r"yaml\.load\(\s*([^,()]+?)\s*,\s*Loader\s*=\s*yaml\.(?:Full|Unsafe)?Loader\s*\)"), r"yaml.safe_load(\1)",
     "yaml.load(..., FullLoader) → yaml.safe_load(...)"),
    (re.compile(r"yaml\.load\(\s*([^,()]+?)\s*\)"), r"yaml.safe_load(\1)", "yaml.load(...) → yaml.safe_load(...)"),
    (re.compile(r"yaml\.unsafe_load\(\s*([^,()]+?)\s*\)"), r"yaml.safe_load(\1)", "yaml.unsafe_load → yaml.safe_load"),
]


def safe_api_edits(rf: RepoFiles, sites: list[dict]) -> tuple[list[dict], list[str]]:
    edits, labels = [], []
    for s in sites:
        code, f = (s.get("code") or "").strip(), s.get("file")
        if not code or not f or s.get("in_test"):
            continue
        for rx, rep, label in SAFE_API:
            if rx.search(code):
                new = rx.sub(rep, code)
                if (rf.text(f) or "").count(code) == 1 and not any(e["old_text"] == code for e in edits):
                    edits.append({"path": f, "old_text": code, "new_text": new})
                    labels.append(label)
                break
    return edits, labels


# ------------------------------------------------------------------ candidates
def _cand(kind, skill, label, edits=None, **kw) -> dict:
    return {"kind": kind, "skill": skill, "label": label, "edits": edits or [], "checks": kw.pop("checks", {}),
            "notes": kw.pop("notes", []), "compatibility": kw.pop("compatibility", []),
            "rollback": kw.pop("rollback", "git revert the Guardian fix commit (branch guardian/fix-<id>)"),
            "expected_after": kw.pop("expected_after", "resolved"), **kw}


def package_candidates(rf: RepoFiles, vt: VersionTools, purl_findings: list[dict], gpkg: dict) -> list[dict]:
    first = purl_findings[0]
    name, cur = first["component_name"], first["component_version"]
    declared = bool((gpkg or {}).get("declared") or rf.req_lines(name))
    required_by = (gpkg or {}).get("required_by") or [d for d, _ in rf.lock_deps.get(norm_name(name), [])]
    cands = []
    # removal: a runtime package the code never imports, nothing references, and no other package needs
    removable = False
    if all(f.get("usage") == "package_not_imported" for f in purl_findings) and first.get("scope") == "runtime":
        removable, _why = rf.can_remove(name, required_by, dep_info=bool(rf.lock_deps))
    if removable:
        cands.append(_cand("remove", "remove-or-block-package", f"Remove unused {name} {cur}",
                           remove_edits(rf, name, keep_lock=False),
                           notes=["the code never imports it, nothing references it, and no other package requires it"],
                           compatibility=["nothing imports it, so removing it cannot break the code"],
                           rollback=f"re-add {name}=={cur} to the manifest"))
    # minimal version that fixes every open vulnerability of this package
    needed, unfixable = None, []
    curv = V(cur)
    for f in purl_findings:
        fixes = sorted(v for v in (V(x) for x in f.get("fixed_versions") or []) if v and curv and v > curv)
        if not fixes:
            unfixable.append(f["finding_id"])
        elif needed is None or fixes[0] > needed:
            needed = fixes[0]
    if needed is not None:
        pool = {str(v) for f in purl_findings for v in (V(x) for x in f.get("fixed_versions") or []) if v and v >= needed}
        rel = vt.releases(name)
        if rel:
            pool |= {v for v in rel if V(v) and V(v) >= needed and not V(v).is_prerelease}
        ordered = sorted(pool, key=V)
        same = [v for v in ordered if curv and V(v).major == curv.major]
        trial = list(dict.fromkeys(same[:4] + ordered[:4] + ordered[-2:]))
        evaluated = []
        for v in trial:
            checks = vt.check(name, v)
            fail = [k for k, c in checks.items() if c["status"] == "fail"]
            evaluated.append((v, checks, fail))
        good = sorted([e for e in evaluated if not e[2]],
                      key=lambda e: (V(e[0]).major != (curv.major if curv else -1),
                                     sum(c["status"] == "unknown" for c in e[1].values()), V(e[0])))
        for v, checks, _ in good[:3]:
            major = curv and V(v).major != curv.major
            edits, notes = upgrade_edits(rf, name, cur, v, declared)
            compat = [f"major version change {cur} → {v}: check the release notes for breaking changes"] if major else \
                     [f"same major version ({cur} → {v}): API breaks are unlikely"]
            sites = sorted({s.get("symbol") for f in purl_findings for s in f.get("usage_sites") or [] if s.get("symbol")})
            if sites:
                compat.append("your code uses " + ", ".join(sites[:4]) + " from it")
            cands.append(_cand("upgrade", "upgrade-dependency", f"Upgrade {name} {cur} → {v}", edits, target_version=v,
                               checks=checks, notes=notes + ([f"{', '.join(unfixable)} has no fixed version"] if unfixable else []),
                               compatibility=compat, rollback=f"pin {name}=={cur} again (git revert the fix commit)",
                               expected_after="resolved" if not unfixable else "partly resolved"))
        for v, checks, fail in [e for e in evaluated if e[2]][:3]:
            cands.append(_cand("upgrade", "upgrade-dependency", f"Upgrade {name} {cur} → {v} (excluded)", [],
                               target_version=v, checks=checks, excluded=True,
                               notes=[f"excluded: {checks[k]['detail']}" for k in fail]))
    # replace the unsafe call with a safe API (keeps the version; lowers the risk, does not remove the CVE)
    sites = [s for f in purl_findings for s in f.get("usage_sites") or []]
    edits, labels = safe_api_edits(rf, sites)
    if edits:
        cands.append(_cand("replace_api", "replace-unsafe-api", f"Replace the unsafe call: {labels[0]}", edits,
                           compatibility=["safe_load only builds plain Python types (dict, list, str, numbers); "
                                          "config files using python/object tags would stop loading"],
                           rollback="restore the original call (git revert the fix commit)",
                           expected_after="reduced", notes=[f"{name} {cur} stays installed: the advisory still matches "
                                                            "the version, but the vulnerable call is no longer made"]))
    if not [c for c in cands if not c.get("excluded")]:
        cands.append(_cand("escalate", None, f"Escalate {name} {cur} for security review",
                           notes=["no fixed version and no safe code change is known"], expected_after="unchanged",
                           rollback="nothing to roll back"))
    return cands


def git_prev_version(repo: Optional[Path], name: str, cur: str, files: list[str]) -> Optional[str]:
    if not repo:
        return None
    rx = re.compile(rf"^\s*{RepoFiles.name_re(name)}\s*==\s*([^\s;#]+)", re.I | re.M)
    for f in files:
        try:
            shas = subprocess.run(["git", "-C", str(repo), "log", "--format=%H", "--", f], capture_output=True, text=True,
                                  timeout=30).stdout.split()
        except (OSError, subprocess.TimeoutExpired):
            return None
        for sha in shas:
            txt = subprocess.run(["git", "-C", str(repo), "show", f"{sha}:{f}"], capture_output=True, text=True,
                                 timeout=30).stdout
            m = rx.search(txt)
            if m and m.group(1) != cur:
                return m.group(1)
    return None


def anomaly_candidates(rf: RepoFiles, vt: VersionTools, e: dict, py: str) -> list[dict]:
    st, comp = e["subtype"], e.get("component") or ""
    sig = {s.get("check"): s for s in e.get("signals") or []}
    name, cur = e.get("component_name"), e.get("component_version")
    if comp.startswith("pkg:"):
        from .common import purl_name_version
        name, cur = purl_name_version(comp)
    if st in ("typosquat", "install_hook"):
        target = (sig.get("typosquat_edit_distance") or {}).get("data", {}).get("looks_like")
        has_target = bool(target and rf.req_lines(target))
        refs = [r for r in rf.references(name) if r.endswith(".py")]
        if refs:      # the code imports it: removing would break the app, so a person decides
            high = (e.get("suspicion") or "low") == "high"
            return [_cand("escalate", None,
                          (f"Replace {name}: suspicious install behaviour, but your code imports it" if high else
                           f"Verify {name}" + (f" (flagged as look-alike of {target})" if target else " (install script flagged)")
                           + ": your code imports it, keep it and pin it by hash if legitimate"),
                          notes=[f"imported in {', '.join(refs)}: removing it would break the code",
                                 "confirm it is the intended project on PyPI (maintainers, repository, release history)"],
                          expected_after="unchanged", rollback="nothing to roll back")]
        edits = remove_edits(rf, name, keep_lock=False)
        if target and not has_target:
            edits = [{"path": f, "old_text": line, "new_text": line.replace(m.group(1), target, 1)}
                     for f, line, m in rf.req_lines(name)]
        return [_cand("remove", "remove-or-block-package",
                      f"Remove {name}" + (f" (typosquat of {target}; {target} is already declared)" if has_target
                                          else f" and depend on {target}" if target else ""), edits,
                      notes=["also block the name in your package proxy / allow-list",
                             "rotate secrets on machines that installed it (its install hook ran there)"],
                      compatibility=["nothing imports it" if not (sig.get("new_dependency_unused") or {}).get("data", {}).get("imported_by") else "check imports"],
                      rollback="none needed: the package is malicious")]
    if st == "lockfile_integrity":
        mm = (sig.get("hash_mismatch") or {}).get("data", {})
        removed = (sig.get("lockfile_only_change") or {}).get("data", {}).get("hashes_removed") or []
        bad, good = mm.get("lock_hash"), next((h for h in removed if h in (mm.get("published") or [])), None)
        lock = rf.lock_text or ""
        if bad and good and lock.count(f"sha256:{bad}") == 1:
            return [_cand("restore_hash", "remove-or-block-package", f"Restore the published hash of {name} {cur} in poetry.lock",
                          [{"path": "poetry.lock", "old_text": f"sha256:{bad}", "new_text": f"sha256:{good}"}],
                          notes=["the replacement hash is the one published on the package index",
                                 "then reinstall from the official index and compare hashes"],
                          compatibility=["no version change"])]
        return [_cand("escalate", None, f"Regenerate the lockfile for {name} from the official index", expected_after="unchanged")]
    if st == "ci_workflow":
        path = comp.split(":", 1)[1]
        t = rf.text(path) or ""
        edits, done = [], []
        if re.search(r"^\s*pull_request_target:", t, re.M):
            m = re.search(r"^(\s*)pull_request_target:", t, re.M)
            edits.append({"path": path, "old_text": m.group(0), "new_text": f"{m.group(1)}pull_request:"})
            done.append("pull_request_target → pull_request (no secrets for PR code)")
        m = re.search(r"\n([ \t]*)with:\s*\n[ \t]*ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\}\}[ \t]*", t)
        if m:
            edits.append({"path": path, "old_text": m.group(0), "new_text": ""})
            done.append("stop checking out the PR head commit explicitly")
        if not re.search(r"^permissions:", t, re.M) and "\njobs:" in t and t.count("\njobs:") == 1:
            edits.append({"path": path, "old_text": "\njobs:", "new_text": "\npermissions:\n  contents: read\n\njobs:"})
            done.append("least-privilege token: permissions contents: read")
        if not edits:
            return [_cand("escalate", "harden-ci-cd", f"Review {path} manually", expected_after="unchanged")]
        unpinned = (sig.get("action_not_sha_pinned") or {}).get("data", {}).get("action")
        secrets = (sig.get("secrets_in_pr_workflow") or {}).get("data", {}).get("secrets") or []
        return [_cand("harden_ci", "harden-ci-cd", f"Harden {path}: " + "; ".join(done), edits,
                      notes=([f"pin {unpinned} to a full commit SHA (needs the action's repository)"] if unpinned else [])
                      + ([f"the job still receives {', '.join(secrets)}: move steps that need it to a separate trusted "
                          "workflow (fork PRs get no secrets under pull_request)"] if secrets else []),
                      compatibility=["PRs from forks run without repository secrets; jobs that need secrets must move "
                                     "to a separate trusted workflow"],
                      expected_after="reduced" if (unpinned or "secrets_in_pr_workflow" in sig) else "resolved")]
    if st == "base_image":
        ref = comp.split(":", 1)[1]
        img, _, tag = ref.partition(":")
        if tag == "latest" and img == "python":
            df = rf.text("Dockerfile") or ""
            line = next((l for l in df.splitlines() if re.match(rf"\s*FROM\s+{re.escape(ref)}\b", l)), None)
            if line and df.count(line) == 1:
                return [_cand("pin_image", None, f"Pin {ref} to python:{py}-slim", [{"path": "Dockerfile", "old_text": line,
                              "new_text": line.replace(ref, f"python:{py}-slim")}],
                              notes=["for full protection pin by digest (python:<tag>@sha256:…) from your registry"],
                              compatibility=[f"the app will run on Python {py}; run the tests on that version"],
                              expected_after="reduced")]
        return [_cand("escalate", None, f"Pin {ref} by digest", notes=["needs a registry lookup for the digest"],
                      expected_after="unchanged")]
    if st == "suspicious_update" and name:
        prev = git_prev_version(rf.repo, name, cur, rf.req_files)
        out = []
        if prev:
            edits, notes = upgrade_edits(rf, name, cur, prev, True)
            out.append(_cand("pin_back", "upgrade-dependency", f"Pin {name} back to {prev} (last version before the suspicious update)",
                             edits, target_version=prev, checks=vt.check(name, prev), notes=notes + ["review the new release's code before upgrading again"],
                             compatibility=[f"returns to the version the project used before {cur}"]))
        if (e.get("suspicion") or "low") == "low":      # a normal explanation was found and verified
            out.insert(0, _cand("accept", None, f"No change: keep {name} {cur} and monitor (a normal explanation was verified)",
                                expected_after="unchanged", rollback="nothing to roll back"))
        if out:
            return out
    if st == "unexpected_change" and name and not comp.startswith("file:") and \
            not (sig.get("new_dependency_unused") or {}).get("data", {}).get("imported_by") and "new_dependency_unused" in sig:
        req_by = [d for d, _ in rf.lock_deps.get(norm_name(name), [])]
        refs = rf.references(name)
        if refs or norm_name(name) in rf.TOOLS:
            return [_cand("escalate", None, f"Check whether {name} is needed before removing it",
                          notes=[f"Stage 5 found no import, but it is referenced in {', '.join(refs)}" if refs
                                 else f"{name} is usually run as a command, not imported"],
                          expected_after="unchanged", rollback="nothing to roll back")]
        return [_cand("remove", "remove-or-block-package", f"Remove the unused dependency {name}",
                      remove_edits(rf, name, keep_lock=bool(req_by)),
                      notes=[f"still installed through {', '.join(req_by)} (lock entry kept)"] if req_by else [],
                      compatibility=["nothing imports it"])]
    if (e.get("stage_risk") or "low") == "low" or (e.get("suspicion") == "low" and "normal" in (e.get("recommendation") or "").lower()):
        return [_cand("accept", None, "No change: keep monitoring (a normal explanation was found)", expected_after="unchanged",
                      rollback="nothing to roll back")]
    return [_cand("escalate", None, "Escalate for security review: " + (e.get("recommendation") or "confirm the behaviour"),
                  notes=["no safe automatic code change is known; use “Revise with agent” to draft one"],
                  expected_after="unchanged", rollback="nothing to roll back")]


# ------------------------------------------------------------------ grouping
def build_units(out: Path, register: list[dict]) -> list[dict]:
    """Remediation units: one per vulnerable package (all its CVEs), one per suspicious finding."""
    from .common import repo_path
    from .register import GraphView
    repo = repo_path(out)
    rf = RepoFiles(repo)
    vt = VersionTools(out, rf)
    gv = GraphView(out)
    py = vt.python[0]
    units: list[dict] = []
    by_pkg: dict[str, list[dict]] = {}
    for e in register:
        if e["kind"] == "vulnerability":
            by_pkg.setdefault(e["component"], []).append(e)
    for e in register:
        if e["kind"] == "vulnerability":
            if e["component"] not in by_pkg:
                continue
            group = by_pkg.pop(e["component"])
            cands = package_candidates(rf, vt, group, gv.packages.get(e["component"]))
            units.append(_unit(group, cands, "package", e["component"], f"{e['component_name']} {e['component_version']}"))
        else:
            units.append(_unit([e], anomaly_candidates(rf, vt, e, py), e["subtype"], e["component"],
                               e.get("component_name") or e["component"]))
    units.sort(key=lambda u: (-band_idx(u["priority"]), min(u["ranks"])))
    for i, u in enumerate(units, 1):
        u["rid"] = f"R-{i:03d}"
    return units


def _unit(findings: list[dict], cands: list[dict], kind: str, target: str, label: str) -> dict:
    for i, c in enumerate(cands):
        c["cid"] = i
    top = max(findings, key=lambda f: (band_idx(f["priority"]), DECISIONS.index(f["decision"])))
    return {
        "rid": None, "target": target, "target_label": label, "target_kind": kind,
        "finding_ids": [f["finding_id"] for f in findings], "ranks": [f["rank"] for f in findings],
        "priority": top["priority"], "decision": top["decision"], "decision_model": top["decision_model"],
        "stage_risk": max((f.get("stage_risk") or "low" for f in findings), key=band_idx),
        "downgrade_limited": any(f.get("downgrade_limited") for f in findings),
        "finding_confidence": min((f["finding_confidence"] for f in findings), key=conf_idx),
        "candidates": cands, "proposals": [], "status": "new",
    }
