"""Security tests per remediation (docs/DAY_2_COMPLETION_PLAN.md section 5).

For every remediation Guardian writes ONE pytest file into the repository, tests/guardian/test_<rid>_<name>.py:

  T1 exploit test  FAIL -> PASS  from a proof-of-fix probe the agent wrote AND Guardian ran (VULNERABLE on the old
                                 version, SAFE on the new one); kept only if the same fail->pass is observed again in
                                 the project's own environments
  T2 guard test    FAIL -> PASS  template, no AI: the fix is in place (installed version >= fixed version, package no
                                 longer declared, unsafe call gone, workflow hardened, ...). "guard, not proof"
  T3 feature test  PASS -> PASS  template: the app's own code that uses the package still works (Flask test client
                                 on parameter-free GET routes, or importing the modules that use the package);
                                 kept only if it passes on both versions

The same file runs in two sandbox environments, BEFORE (original code + dependencies) and AFTER (patched), and every
test gets {before, after, expected, as_expected}. Nothing is claimed from what a model says: only observed results.
"""
from __future__ import annotations

import os
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from .common import norm_name, read_json
from .runtime import Env, _run, _tail

TEST_DIR = "tests/guardian"
CONFTEST = '''"""Guardian security tests. Run only these with: pytest -m guardian tests/guardian"""


def pytest_configure(config):
    config.addinivalue_line("markers", "guardian: security tests written by Guardian (see GUARDIAN_FIXES.md)")
'''
EXPECT = {"T1": ("fail", "pass"), "T2": ("fail", "pass"), "T3": ("pass", "pass")}
UNSAFE_RX = [r"yaml\.load\((?![^)]*SafeLoader)", r"yaml\.unsafe_load\(", r"shell\s*=\s*True"]


def _slug(s: str, n: int = 40) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (s or "").lower()).strip("_")[:n] or "x"


def file_name(unit: dict, proposal: dict) -> str:
    m = re.match(r"pkg:pypi/([^@]+)@", unit.get("target") or "")
    what = m.group(1) if m else ("build_health" if proposal.get("kind") == "compat_upgrade" else proposal.get("kind") or "fix")
    return f"{TEST_DIR}/test_{_slug(unit['rid'], 10)}_{_slug(what, 30)}.py"


def _pkg(unit: dict) -> tuple[Optional[str], Optional[str]]:
    m = re.match(r"pkg:pypi/([^@]+)@(.+)$", unit.get("target") or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def _modules_using(out: Path, pkg: Optional[str]) -> list[str]:
    """Modules of the application (not tests) that import the package, from the Stage 2 code index."""
    if not pkg:
        return []
    ci = read_json(Path(out) / "code_index.json", {}) or {}
    want = norm_name(pkg)
    mods = []
    for f in ci.get("files") or []:
        if f.get("is_test") or not str(f.get("path", "")).endswith(".py"):
            continue
        if any(norm_name(i.get("distribution") or "") == want for i in f.get("imports") or []):
            parts = Path(f["path"]).with_suffix("").parts
            if parts and parts[-1] == "__init__":
                parts = parts[:-1]
            if parts and all(p.isidentifier() for p in parts) and parts[0] not in ("tests", "test", "migrations"):
                mods.append(".".join(parts))
    return sorted(set(mods))[:12]


def _import_name(out: Path, pkg: Optional[str]) -> Optional[str]:
    ci = read_json(Path(out) / "code_index.json", {}) or {}
    for imp, dist in (ci.get("import_name_to_distribution") or {}).items():
        if norm_name(dist) == norm_name(pkg or ""):
            return imp
    return None


# ------------------------------------------------------------------ test blocks
HEADER = '''"""Guardian security tests for {rid}: {label}.

Written by Guardian (see GUARDIAN_FIXES.md). Each test states what it expects on the code BEFORE the fix and AFTER it;
Guardian ran this file on both versions and keeps a test only when the expected result was observed.
Run: pytest -m guardian {rel}
"""
import importlib
import importlib.metadata
import re
import runpy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.guardian


def _v(s):
    return tuple(int(x) for x in re.findall(r"\\d+", str(s))[:4])
'''


def t2_blocks(unit: dict, proposal: dict) -> list[dict]:
    kind, pkg = proposal.get("kind"), _pkg(unit)[0]
    tv = proposal.get("target_version")
    out = []
    if kind in ("upgrade", "pin_back") and pkg and tv:
        op, word = (">=", "at least") if kind == "upgrade" else ("==", "exactly")
        out.append({"name": f"test_t2_guard_{_slug(pkg)}_version", "title": f"installed {pkg} is {word} {tv}",
                    "code": f'''def test_t2_guard_{_slug(pkg)}_version():
    """T2 guard (not proof): the installed {pkg} is {word} {tv}, the version the fix moves to."""
    assert _v(importlib.metadata.version({pkg!r})) {op} _v({tv!r})
'''})
    elif kind == "compat_upgrade":
        bumps = proposal.get("bumps") or []
        body = "\n".join(f"    assert _v(importlib.metadata.version({b['package']!r})) >= _v({b['to']!r})" for b in bumps)
        out.append({"name": "test_t2_guard_build_health_pins", "title": "the bumped pins are installed: " + ", ".join(f"{b['package']} {b['to']}" for b in bumps),
                    "code": f'''def test_t2_guard_build_health_pins():
    """T2 guard (not proof): packages that had no wheel for the target Python are at the bumped versions."""
{body or "    pass"}
'''})
    elif kind == "remove" and pkg:
        rx = r"^\s*" + "[-_.]".join(re.escape(p) for p in re.split(r"[-_.]+", pkg)) + r"\s*(==|>=|~=|\[|$|;|#)"
        out.append({"name": f"test_t2_guard_{_slug(pkg)}_not_declared", "title": f"{pkg} is not declared in any requirements file",
                    "code": f'''def test_t2_guard_{_slug(pkg)}_not_declared():
    """T2 guard (not proof): {pkg} is no longer declared in any requirements file."""
    rx = re.compile({rx!r}, re.I | re.M)
    left = [p.name for p in ROOT.glob("requirements*.txt") if rx.search(p.read_text(encoding="utf-8"))]
    assert not left, f"still declared in {{left}}"
'''})
    elif kind == "replace_api":
        files = sorted({e["path"] for e in proposal.get("edits") or [] if e["path"].endswith(".py")})
        out.append({"name": "test_t2_guard_no_unsafe_call", "title": "no unsafe call left in " + ", ".join(files),
                    "code": f'''def test_t2_guard_no_unsafe_call():
    """T2 guard (not proof): the patched files no longer make the unsafe call."""
    pats = [re.compile(p) for p in {UNSAFE_RX!r}]
    left = [f for f in {files!r} if any(p.search((ROOT / f).read_text(encoding="utf-8")) for p in pats)]
    assert not left, f"unsafe call still in {{left}}"
'''})
    elif kind == "harden_ci":
        files = sorted({e["path"] for e in proposal.get("edits") or []})
        out.append({"name": "test_t2_guard_workflow_hardened", "title": "no pull_request_target / PR-head checkout; token permissions set",
                    "code": f'''def test_t2_guard_workflow_hardened():
    """T2 guard (not proof): the workflow no longer runs PR code with secrets and has least-privilege permissions."""
    for f in {files!r}:
        t = (ROOT / f).read_text(encoding="utf-8")
        assert "pull_request_target" not in t and "pull_request.head.sha" not in t, f
        assert re.search(r"^permissions:", t, re.M), f + " has no top-level permissions"
'''})
    if not out and proposal.get("edits"):        # any other fix: the reviewed change is in the files
        checks = [(e["path"], e.get("old_text") or "", e.get("new_text") or "") for e in proposal["edits"]]
        out.append({"name": "test_t2_guard_change_in_place", "title": "the reviewed change is in the files",
                    "code": f'''def test_t2_guard_change_in_place():
    """T2 guard (not proof): every edit of the approved patch is present in the repository."""
    for path, old, new in {checks!r}:
        p = ROOT / path
        text = p.read_text(encoding="utf-8").replace("\\r\\n", "\\n") if p.exists() else ""
        if new.strip():
            assert new.replace("\\r\\n", "\\n") in text, f"{{path}}: patched text missing"
        if old.strip() and old.strip() not in new:
            assert old.replace("\\r\\n", "\\n") not in text, f"{{path}}: old text still present"
'''})
    for b in out:
        b["kind"] = "T2"
        b["source"] = "template"
    return out


def t3_blocks(out: Path, unit: dict, proposal: dict, wt: Path) -> list[dict]:
    from .appboot import detect_app
    kind, (pkg, _) = proposal.get("kind"), _pkg(unit)
    if kind == "harden_ci":
        files = sorted({e["path"] for e in proposal.get("edits") or []})
        return [{"kind": "T3", "source": "template", "name": "test_t3_feature_workflow_still_defines_jobs",
                 "title": "the workflow still defines its jobs",
                 "code": f'''def test_t3_feature_workflow_still_defines_jobs():
    """T3 feature: the hardened workflow still has its trigger and jobs."""
    for f in {files!r}:
        t = (ROOT / f).read_text(encoding="utf-8")
        assert re.search(r"^on:|^\\"on\\":|^'on':", t, re.M) and re.search(r"^jobs:", t, re.M), f
'''}]
    mods = _modules_using(out, pkg)
    info = detect_app(wt)
    label = f"the app's routes{' that use ' + pkg if pkg else ''} still answer without a server error"
    if info["framework"] == "flask" and info.get("mode") != "script":
        return [{"kind": "T3", "source": "template", "name": "test_t3_feature_app_routes_answer", "title": label,
                 "code": f'''FLASK_APP = {info["app"]!r}
PREFER_MODULES = {mods!r}   # modules of this app that import {pkg or "the changed package"} (Guardian code index)


def _flask_app():
    sys.path.insert(0, str(ROOT))
    mod, _, attr = FLASK_APP.partition(":")
    if mod.endswith(".py"):
        mod = mod[:-3].replace("/", ".").replace("\\\\", ".")
    m = importlib.import_module(mod)
    if attr:
        return getattr(m, attr[:-2])() if attr.endswith("()") else getattr(m, attr)
    for name in ("app", "application"):
        if hasattr(getattr(m, name, None), "test_client"):
            return getattr(m, name)
    return m.create_app()


def test_t3_feature_app_routes_answer(tmp_path, monkeypatch):
    """T3 feature: {label} (Flask test client, temporary SQLite)."""
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "t3.db").as_posix())
    for k in ("REDIS_URL", "ELASTICSEARCH_URL", "MAIL_SERVER"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.chdir(tmp_path)
    app = _flask_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with app.app_context():
        db = app.extensions.get("sqlalchemy")
        if db is not None and hasattr(db, "create_all"):
            db.create_all()
    rules = [r for r in app.url_map.iter_rules() if "GET" in (r.methods or ()) and not r.arguments
             and not r.rule.startswith("/static") and not re.search("logout|delete|remove|reset", r.rule)]
    assert rules, "the app has no parameter-free GET route"
    fn = lambda r: getattr(app.view_functions.get(r.endpoint), "__module__", "")
    rules.sort(key=lambda r: (fn(r) not in PREFER_MODULES, r.rule != "/", r.rule))
    client = app.test_client()
    seen = {{r.rule: client.get(r.rule).status_code for r in rules[:8]}}
    bad = {{k: v for k, v in seen.items() if v >= 500}}
    assert not bad, f"server errors: {{bad}} (all: {{seen}})"
'''}]
    imp = _import_name(out, pkg)
    if mods or imp:
        targets = mods or [imp]
        what = f"the modules of this app that use {pkg} still import" if mods else f"{pkg} still imports as {imp}"
        return [{"kind": "T3", "source": "template", "name": "test_t3_feature_modules_import", "title": what,
                 "code": f'''def test_t3_feature_modules_import(tmp_path, monkeypatch):
    """T3 feature: {what}."""
    monkeypatch.chdir(tmp_path)
    sys.path.insert(0, str(ROOT))
    for m in {targets!r}:
        importlib.import_module(m)
'''}]
    return []


def t1_blocks(unit: dict, probe: Optional[dict]) -> list[dict]:
    """Exploit tests from probes that were PROVEN (VULNERABLE on old, SAFE on new). The probe script is stored next
    to the test; the test runs it and requires the SAFE verdict."""
    out = []
    for r in (probe or {}).get("probes") or []:
        if r.get("verdict") != "proven" or not r.get("code"):
            continue
        vid = r.get("vuln_id") or r.get("finding_id")
        pf = f"{TEST_DIR}/probes/{_slug(unit['rid'], 10)}_{_slug(vid, 40)}.py"
        name = f"test_t1_exploit_{_slug(vid, 40)}"
        what = (r.get("what") or r.get("summary") or vid).replace('"""', "'")
        out.append({"kind": "T1", "source": f"ai:{probe.get('model') or 'agent'}", "name": name, "vuln_id": vid,
                    "title": f"{vid}: {r.get('what') or r.get('summary') or ''}"[:200], "probe_file": pf, "probe_code": r["code"],
                    "code": f'''def test_t1_exploit_{_slug(vid, 40)}(capsys):
    """T1 exploit ({vid}): {what}
    Expected: FAILS on the vulnerable version (the probe prints VULNERABLE), PASSES on the fixed one (SAFE)."""
    runpy.run_path(str(ROOT / {pf!r}), run_name="__main__")
    out = capsys.readouterr().out
    assert "GUARDIAN_PROBE: SAFE" in out, out[-600:]
'''})
    return out


def _vuln_ids(out: Path, unit: dict) -> set[str]:
    reg = {e["finding_id"]: e for e in read_json(Path(out) / "register.json", []) or []}
    ids: set[str] = set()
    for fid in unit.get("finding_ids") or []:
        e = reg.get(fid) or {}
        ids |= {x for x in [e.get("vuln_id"), *(e.get("aliases") or [])] if x}
    return ids


def curated_t1(out: Path, unit: dict, proposal: dict) -> list[dict]:
    from .exploits import for_unit
    pkg = _pkg(unit)[0]
    if proposal.get("kind") not in ("upgrade", "pin_back") or not pkg:
        return []
    ids = _vuln_ids(out, unit)
    return [{"kind": "T1", "source": "curated", "name": f"test_t1_exploit_{e['slug']}", "title": e["title"],
             "vuln_id": ", ".join(sorted(i for i in e["ids"] & ids if i.startswith("GHSA"))[:3]) or sorted(e["ids"] & ids)[0],
             "covers": sorted(e["ids"] & ids), "code": e["code"]} for e in for_unit(pkg, ids)]


def generate(out: Path, unit: dict, proposal: dict, wt: Path, probe: Optional[dict] = None) -> dict:
    if unit.get("target_kind") == "code":
        from .codefix import test_blocks
        tests, pre = test_blocks(out, unit, wt)
        for t in tests:
            t["expected"] = dict(zip(("before", "after"), EXPECT[t["kind"]]))
        fn = (unit.get("target") or "").rpartition("::")[2]
        return {"rel": f"{TEST_DIR}/test_{_slug(unit['rid'], 10)}_sqli_{_slug(fn, 30)}.py", "tests": tests, "rid": unit["rid"],
                "label": proposal.get("action") or unit.get("target_label"), "preamble": pre}
    cur = curated_t1(out, unit, proposal)
    covered = {i for t in cur for i in t["covers"]}
    ai = [t for t in t1_blocks(unit, probe) if t.get("vuln_id") not in covered]
    tests = cur + ai + t2_blocks(unit, proposal) + t3_blocks(out, unit, proposal, wt)
    for t in tests:
        t["expected"] = dict(zip(("before", "after"), EXPECT[t["kind"]]))
    return {"rel": file_name(unit, proposal), "tests": tests, "rid": unit["rid"], "label": proposal.get("action") or unit.get("target_label")}


def render(gen: dict, keep: Optional[set] = None) -> dict[str, str]:
    """{relative path: content} for the test file, its probe scripts and the shared conftest."""
    tests = [t for t in gen["tests"] if keep is None or t["name"] in keep]
    files = {f"{TEST_DIR}/conftest.py": CONFTEST}
    body = HEADER.format(rid=gen["rid"], label=(gen["label"] or "").replace('"""', "'"), rel=gen["rel"]) + (gen.get("preamble") or "")
    for t in tests:
        body += "\n\n" + t["code"]
        if t.get("probe_file"):
            files[t["probe_file"]] = t["probe_code"]
    files[gen["rel"]] = body
    return files


def write(root: Path, files: dict[str, str]) -> list[str]:
    for rel, text in files.items():
        p = Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return sorted(files)


# ------------------------------------------------------------------ running
def test_env() -> dict:
    keep = dict(os.environ)
    for k in ("PYTHONPATH", "VIRTUAL_ENV", "DATABASE_URL"):
        keep.pop(k, None)
    keep.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8"})
    return keep


def run_pytest(root: Path, env: Env, rels: list[str], junit: Path, timeout: int = 300) -> dict:
    """{"results": {test name: pass|fail|error|skip}, "summary", "log"}."""
    junit.parent.mkdir(parents=True, exist_ok=True)
    if junit.exists():
        junit.unlink()
    cmd = [str(env.python), "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-header", "-o", "addopts=",
           f"--junitxml={junit}", *rels]
    code, out = _run(cmd, cwd=root, timeout=timeout, env=test_env())
    res: dict[str, str] = {}
    try:
        for tc in ET.parse(junit).getroot().iter("testcase"):
            st = "pass"
            for child in tc:
                if child.tag in ("failure", "error", "skipped"):
                    st = {"failure": "fail", "error": "error", "skipped": "skip"}[child.tag]
            res[tc.get("name", "").split("[")[0]] = st
    except (ET.ParseError, FileNotFoundError, OSError):
        pass
    lines = [l for l in out.strip().splitlines() if l.strip()]
    return {"results": res, "code": code, "summary": lines[-1][:200] if lines else f"exit {code}", "log": _tail(out, 2500)}


def matrix(gen: dict, before: Optional[dict], after: Optional[dict]) -> list[dict]:
    rows = []
    for t in gen["tests"]:
        b = (before or {}).get("results", {}).get(t["name"], "not run") if before else "not run"
        a = (after or {}).get("results", {}).get(t["name"], "not run") if after else "not run"
        exp = t["expected"]
        ok = (b == exp["before"] or (exp["before"] == "fail" and b == "error")) and a == exp["after"]
        keep = t["kind"] == "T2" or ok
        why = None
        if not keep:
            why = {"T1": "dropped: the exploit test did not fail on the old version and pass on the new one in the project's environment",
                   "T3": "dropped: the feature test did not pass on both versions"}[t["kind"]]
        rows.append({"name": t["name"], "kind": t["kind"], "title": t["title"], "source": t["source"],
                     "vuln_id": t.get("vuln_id"), "covers": t.get("covers"), "expected": f"{exp['before']} → {exp['after']}", "before": b, "after": a,
                     "as_expected": ok, "kept": keep, "note": why})
    return rows


def run_suite(gen: dict, before_root: Optional[Path], before_env: Optional[Env], after_root: Path,
              after_env: Optional[Env], work: Path, step=lambda m: None) -> dict:
    """Write the tests into both trees, run them, drop T1/T3 that did not behave as expected, rewrite the file in the
    after tree. Returns the stored "security_tests" record."""
    files = render(gen)
    rec = {"file": gen["rel"], "python": getattr(after_env, "full_version", None)}
    if after_env is None:
        rec.update(status="skipped", detail="not run: the dependencies did not install", tests=matrix(gen, None, None),
                   files=write(after_root, render(gen, {t["name"] for t in gen["tests"] if t["kind"] == "T2"})))
        return rec
    write(after_root, files)
    before = None
    if before_root is not None and before_env is not None:
        write(before_root, files)
        step(f"security tests: running {len(gen['tests'])} test(s) on the code BEFORE the fix…")
        before = run_pytest(before_root, before_env, [gen["rel"]], work / "junit-before.xml")
    step(f"security tests: running them on the code AFTER the fix…")
    after = run_pytest(after_root, after_env, [gen["rel"]], work / "junit-after.xml")
    rows = matrix(gen, before, after)
    kept = {r["name"] for r in rows if r["kept"]}
    final = render(gen, kept)
    for rel in files:                              # remove probe scripts of dropped exploit tests
        if rel not in final:
            (Path(after_root) / rel).unlink(missing_ok=True)
    write(after_root, final)
    k = [r for r in rows if r["kept"]]
    bad = [r for r in k if not r["as_expected"]]
    if before is None:
        status, detail = "unknown", "ran only after the fix (no before environment): fail → pass not observed"
    elif bad:
        status, detail = "fail", "not as expected: " + "; ".join(f"{r['kind']} {r['name']} {r['before']} → {r['after']}" for r in bad)
    elif len(k) >= 2:
        n1 = sum(1 for r in k if r["kind"] == "T1")
        status, detail = "pass", (f"{len(k)} security test(s) behave as expected"
                                  + f" ({', '.join(f'{n}×{kd}' for kd, n in ((kd, sum(1 for r in k if r['kind'] == kd)) for kd in ('T1', 'T2', 'T3')) if n)})"
                                  + ("" if n1 else "; no exploit test (T1): the agent could not reproduce the bug"))
    else:
        status, detail = "unknown", f"only {len(k)} test kept"
    rec.update(status=status, detail=detail, tests=rows, files=sorted(final), dropped=[r["name"] for r in rows if not r["kept"]],
               before_run={k_: v for k_, v in (before or {}).items() if k_ != "results"} if before else None,
               after_run={k_: v for k_, v in after.items() if k_ != "results"}, code=final[gen["rel"]])
    return rec
