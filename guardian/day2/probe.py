"""Proof-of-fix probes: dynamic evidence that a version upgrade really removes a vulnerability.

The rescan only proves that the new version is outside the advisory's affected range (a database lookup).
A probe shows the behaviour itself: an LLM writes a small script that exercises the vulnerable API, and the
same script is run in two isolated venvs, one with the OLD version (must print VULNERABLE) and one with the NEW
version (must print SAFE). It is a small agent loop: write -> run on both -> if it crashes, cannot reproduce the
bug, or reports VULNERABLE on both (a probe that tests its own input), both outputs go back to the model, up to
three attempts.

Trust rules: the model never decides the verdict, the observed output does. Scripts that read the package version
are rejected (a version check proves nothing). Every script passes an AST safety check before it runs, runs with -I
in a temp directory with a minimal environment and a timeout, and is shown to the reviewer together with the number
of attempts. A probe that cannot show the difference is reported as inconclusive, never as a pass.
"""
from __future__ import annotations

import ast
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Callable, Optional

from .common import REGISTER_FILE, read_json
from .runtime import Env, _run, _tail, create_env

PROMPTS = Path(__file__).parent / "prompts"
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {"probe_code": {"type": "string"}, "what_it_checks": {"type": "string"},
                   "vulnerable_behaviour": {"type": "string"}},
    "required": ["probe_code", "what_it_checks", "vulnerable_behaviour"],
}
MAX_PROBES = 3
MARK = re.compile(r"GUARDIAN_PROBE:\s*(VULNERABLE|SAFE)", re.I)
BANNED_MODULES = {"subprocess", "socket", "shutil", "ctypes", "multiprocessing", "requests", "urllib", "http", "httpx",
                  "ftplib", "smtplib", "telnetlib", "pty", "webbrowser", "paramiko", "importlib", "signal", "asyncio"}
BANNED_CALLS = {"eval", "exec", "compile", "__import__", "breakpoint", "input"}
BANNED_ATTRS = {"system", "popen", "remove", "unlink", "rmdir", "removedirs", "rmtree", "kill", "fork", "chmod",
                "chown", "execv", "execve", "execl", "execlp", "execvp", "spawnl", "spawnv", "startfile", "putenv"}


def safety_check(code: str) -> tuple[bool, str]:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return False, f"syntax error: {exc}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            bad = [a.name for a in node.names if a.name.split(".")[0] in BANNED_MODULES]
            if bad:
                return False, f"imports {', '.join(bad)}"
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in BANNED_MODULES:
                return False, f"imports from {node.module}"
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in BANNED_CALLS:
                return False, f"calls {f.id}()"
            if isinstance(f, ast.Attribute) and f.attr in BANNED_ATTRS:
                return False, f"calls .{f.attr}()"
    if "GUARDIAN_PROBE" not in code:
        return False, "never prints the GUARDIAN_PROBE verdict line"
    if re.search(r"__version__|pkg_resources|\bmetadata\b|get_distribution|\bversion\s*\(", code):
        return False, "reads the package version (the behaviour must be observed, not the version number)"
    return True, "no network, process, shell, eval, file-deletion or version-reading calls"


def run_probe(env: Env, code: str, timeout: int = 20) -> dict:
    d = Path(tempfile.mkdtemp(prefix="guardian-probe-"))
    try:
        (d / "probe.py").write_text(code, encoding="utf-8")
        keep = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE") if k in os.environ}
        code_, out = _run([str(env.python), "-I", "probe.py"], cwd=d, timeout=timeout, env={**keep, "PYTHONIOENCODING": "utf-8"})
    finally:
        shutil.rmtree(d, ignore_errors=True)
    m = MARK.findall(out)
    marker = m[-1].upper() if m else ("TIMEOUT" if code_ == 124 else "ERROR")
    return {"marker": marker, "exit": code_, "output": _tail(out, 900)}


def _vulns(out: Path, unit: dict) -> list[dict]:
    reg = {e["finding_id"]: e for e in read_json(out / REGISTER_FILE, []) or []}
    cards = {c.get("finding_id"): c for c in read_json(out / "vuln_findings.json", []) or []}
    seen, res = set(), []
    for fid in unit["finding_ids"]:
        e = reg.get(fid) or {}
        if e.get("kind") != "vulnerability" or not e.get("vuln_id"):
            continue
        key = (e.get("summary") or e["vuln_id"]).lower()
        if key in seen:                 # the same bug filed twice (GHSA + PYSEC): one probe is enough
            continue
        seen.add(key)
        res.append({**e, "details": (cards.get(fid) or {}).get("details") or ""})
    res.sort(key=lambda e: -((e.get("cvss") or {}).get("score") or 0))
    return res


def _prompt(e: dict, pkg: str, old: str, new: str, feedback: Optional[str]) -> str:
    refs = [r.get("url") for r in e.get("references") or [] if r.get("url")][:6]
    conds = [c.get("text") for c in e.get("conditions") or [] if c.get("text")]
    parts = [f"Package: {pkg} (PyPI). Vulnerable version: {old}. Fixed version under test: {new}.",
             f"Advisory: {e.get('vuln_id')} ({', '.join(e.get('aliases') or [])})",
             f"Summary: {e.get('summary')}",
             f"Advisory details:\n{(e.get('details') or e.get('explanation') or '')[:2500]}",
             "Trigger conditions: " + ("; ".join(conds) if conds else "not extracted"),
             "References: " + ", ".join(refs),
             f"The probe runs on {'Windows' if os.name == 'nt' else 'Linux/macOS'} (sys.platform={sys.platform!r})."]
    if feedback:
        parts.append(f"\nYOUR PREVIOUS ATTEMPT DID NOT WORK.\n{feedback}\nWrite a corrected script. Base the verdict "
                     "only on what the package returned or raised for your input.")
    return "\n".join(parts)


class _Models:
    """Large model first (better at code); when its quota is gone, fall back to the default model."""

    def __init__(self, llms: list):
        self.llms = [m for m in llms if m is not None]
        self.used_model: Optional[str] = None

    @property
    def available(self) -> bool:
        return any(m.available for m in self.llms)

    @property
    def model(self) -> Optional[str]:
        return self.used_model or next((m.model for m in self.llms if m.available), None)

    def errors(self) -> list[str]:
        return [e for m in self.llms for e in m.errors[-1:]]

    def complete_json(self, *a, **kw):
        for m in self.llms:
            if not m.available:
                continue
            res = m.complete_json(*a, **kw)
            if res:
                self.used_model = m.model
                return res
        return None


def run_probes(out: Path, unit: dict, proposal: dict, python_version: str, work: Path, llm,
               step: Callable[[str], None]) -> dict:
    """Returns a check dict with the per-vulnerability results attached under "probes".
    `llm` is one LLM or a list tried in order (large model first)."""
    llm = _Models(llm if isinstance(llm, list) else [llm])
    if proposal.get("kind") not in ("upgrade", "pin_back"):
        return {"status": "n/a", "detail": "proof-of-fix probes apply to version changes"}
    m = re.match(r"pkg:pypi/([^@]+)@(.+)$", unit.get("target") or "")
    old, new = (m.group(2) if m else proposal.get("_current_version")), proposal.get("target_version")
    pkg = m.group(1) if m else None
    vulns = _vulns(out, unit)
    if not (pkg and old and new and vulns):
        return {"status": "n/a", "detail": "no CVE with a known package version to probe"}
    if not llm.available:
        return {"status": "skipped", "detail": "needs an LLM to write the probe scripts (none available)"}
    vulns = vulns[:MAX_PROBES]
    system = (PROMPTS / "probe_system.md").read_text(encoding="utf-8")
    envs: dict[str, Env] = {}
    results: list[dict] = []
    try:
        for label, ver in (("old", old), ("new", new)):
            step(f"proof-of-fix: installing {pkg} {ver} ({'vulnerable' if label == 'old' else 'fixed'} version) in its own environment…")
            env, err = create_env(work / f"probe-{label}", python_version)
            if env is None:
                return {"status": "skipped", "detail": f"could not create the probe environment: {err}"}
            code, o, _ = env.install([f"{pkg}=={ver}"], timeout=300)
            if code != 0:
                return {"status": "skipped", "detail": f"could not install {pkg} {ver}: {(o.strip().splitlines() or [''])[-1]}"}
            envs[label] = env
        for e in vulns:
            r = {"finding_id": e["finding_id"], "vuln_id": e.get("vuln_id"), "summary": e.get("summary"), "attempts": []}
            feedback = None
            for attempt in (1, 2, 3):
                step(f"proof-of-fix: the agent is writing a probe for {e.get('vuln_id')} (attempt {attempt})…")
                gen = llm.complete_json("probe", system, _prompt(e, pkg, old, new, feedback), SCHEMA)
                if not gen or not gen.get("probe_code"):
                    r["attempts"].append({"error": "the model did not answer"})
                    break
                ok, why = safety_check(gen["probe_code"])
                a = {"code": gen["probe_code"], "what": gen.get("what_it_checks"), "safety": why, "safe": ok}
                r["attempts"].append(a)
                if not ok:
                    feedback = f"The safety check rejected the script: {why}."
                    continue
                a["old"], a["new"] = run_probe(envs["old"], a["code"]), run_probe(envs["new"], a["code"])
                mo, mn = a["old"]["marker"], a["new"]["marker"]
                if mo == "VULNERABLE" and mn == "SAFE":
                    break
                feedback = (f"With {pkg} {old} (vulnerable) it printed {mo}:\n{a['old']['output'][-500:]}\n"
                            f"With {pkg} {new} (fixed) it printed {mn}:\n{a['new']['output'][-500:]}\n"
                            + ("It reports VULNERABLE on both versions, so it is testing something the fix did not "
                               "change (often its own input) instead of the package's behaviour." if mo == mn == "VULNERABLE"
                               else "It must print VULNERABLE on the vulnerable version."))
            ran = [a for a in r["attempts"] if a.get("old")]
            final = ran[-1] if ran else None
            if not final:
                r["verdict"], r["why"] = "error", "no runnable probe was produced"
            else:
                r.update(code=final["code"], what=final.get("what"), old=final["old"], new=final["new"],
                         tries=len(r["attempts"]))
                mo, mn = final["old"]["marker"], final["new"]["marker"]
                if mo == "VULNERABLE" and mn == "SAFE":
                    r["verdict"], r["why"] = "proven", f"vulnerable behaviour seen on {old}, gone on {new}"
                elif mo == mn == "VULNERABLE":
                    r["verdict"], r["why"] = "still_vulnerable", f"the probe reports VULNERABLE on {new} too"
                elif mo != "VULNERABLE":
                    r["verdict"], r["why"] = "not_reproduced", f"the probe could not show the bug on {old} ({mo.lower()})"
                else:
                    r["verdict"], r["why"] = "error", f"the probe crashed on {new}"
            results.append(r)
    finally:
        for label in ("old", "new"):
            shutil.rmtree(work / f"probe-{label}", ignore_errors=True)
    proven = [r for r in results if r.get("verdict") == "proven"]
    still = [r for r in results if r.get("verdict") == "still_vulnerable"]
    n = len(results)
    unanswered = all(all("error" in a for a in r["attempts"]) for r in results)
    if unanswered:
        err = "; ".join(llm.errors())
        quota = "rate limit" in err.lower() or "quota" in err.lower()
        return {"status": "skipped", "detail": ("the LLM quota is used up, no probe could be written — re-run validation later"
                                                if quota else "the LLM did not answer, no probe could be written"),
                "probes": results, "package": pkg, "old": old, "new": new, "llm_error": err[:300]}
    if still and not proven:
        status, detail = "unknown", (f"inconclusive: for {', '.join(r['vuln_id'] for r in still)} the probe reports "
                                     f"VULNERABLE on {new} too (the fix may be incomplete or the probe wrong — read it)")
    elif proven:
        status, detail = "pass", (f"proven for {len(proven)} of {n} probed CVE(s): vulnerable behaviour reproduced on "
                                  f"{old} and gone on {new}")
    else:
        status, detail = "unknown", f"inconclusive: the agent could not reproduce any of the {n} probed CVE(s) on {old}"
    return {"status": status, "detail": detail, "probes": results, "package": pkg, "old": old, "new": new,
            "python": envs["old"].full_version, "model": getattr(llm, "model", None)}
