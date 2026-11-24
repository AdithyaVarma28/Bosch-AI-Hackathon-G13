"""Day 2 completion (docs/DAY_2_COMPLETION_PLAN.md section 11): security tests, app boot, build health, fixed
repository composition, report and the auto-validate queue. Offline; tests that need `uv` or Flask skip without them."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from guardian.day2 import appboot, fixed_repo, queue as aq, report, testgen
from guardian.day2.common import write_json
from guardian.day2.probe import safety_check

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]


def _git(repo, *a):
    return subprocess.run([*GIT, "-C", str(repo), *a], capture_output=True, text=True, check=True).stdout.strip()


# ------------------------------------------------------------------ T2 / T1 / matrix
def _upgrade_unit():
    return {"rid": "R-001", "target": "pkg:pypi/demo-pkg@1.0.0", "target_label": "demo-pkg 1.0.0", "finding_ids": ["F-1"]}


def _run_block(code: str, version: str, monkeypatch):
    import importlib.metadata as md
    monkeypatch.setattr(md, "version", lambda name: version)
    ns: dict = {"__file__": "/r/tests/guardian/t.py"}
    exec(compile(testgen.HEADER.format(rid="R", label="x", rel="t.py") + code, "t.py", "exec"), ns)
    fn = next(v for k, v in ns.items() if k.startswith("test_t2"))
    fn()


def test_t2_guard_fails_on_old_version_and_passes_on_new(monkeypatch):
    blocks = testgen.t2_blocks(_upgrade_unit(), {"kind": "upgrade", "target_version": "1.2.0", "edits": [{"path": "requirements.txt"}]})
    assert len(blocks) == 1 and blocks[0]["kind"] == "T2"
    with pytest.raises(AssertionError):
        _run_block(blocks[0]["code"], "1.0.0", monkeypatch)
    _run_block(blocks[0]["code"], "1.2.0", monkeypatch)
    _run_block(blocks[0]["code"], "1.10.0", monkeypatch)


def test_t2_remove_and_generic_templates(tmp_path):
    rm = testgen.t2_blocks({"rid": "R-2", "target": "pkg:pypi/reqeusts@1.0"}, {"kind": "remove", "edits": [{"path": "requirements.txt"}]})
    assert "not_declared" in rm[0]["name"]
    gen = testgen.t2_blocks({"rid": "R-3", "target": "x"}, {"kind": "pin_image", "edits": [{"path": "Dockerfile", "old_text": "FROM python:latest", "new_text": "FROM python:3.12-slim"}]})
    assert gen[0]["name"] == "test_t2_guard_change_in_place"


def _gen(tests):
    for t in tests:
        t.setdefault("source", "template")
        t.setdefault("title", t["name"])
        t["expected"] = dict(zip(("before", "after"), testgen.EXPECT[t["kind"]]))
    return {"rel": "tests/guardian/test_x.py", "tests": tests, "rid": "R-1", "label": "x"}


def test_matrix_drops_tautological_t1_and_keeps_a_real_one():
    g = _gen([{"kind": "T1", "name": "test_t1_tautology"}, {"kind": "T1", "name": "test_t1_real"},
              {"kind": "T2", "name": "test_t2_guard"}, {"kind": "T3", "name": "test_t3_feature"}])
    before = {"results": {"test_t1_tautology": "pass", "test_t1_real": "fail", "test_t2_guard": "fail", "test_t3_feature": "pass"}}
    after = {"results": {"test_t1_tautology": "pass", "test_t1_real": "pass", "test_t2_guard": "pass", "test_t3_feature": "pass"}}
    rows = {r["name"]: r for r in testgen.matrix(g, before, after)}
    assert rows["test_t1_tautology"]["kept"] is False and rows["test_t1_tautology"]["note"]
    assert rows["test_t1_real"]["kept"] and rows["test_t1_real"]["as_expected"]
    assert rows["test_t2_guard"]["as_expected"] and rows["test_t3_feature"]["as_expected"]


def test_matrix_keeps_t2_even_when_not_as_expected_and_drops_failing_t3():
    g = _gen([{"kind": "T2", "name": "test_t2_guard"}, {"kind": "T3", "name": "test_t3_feature"}])
    rows = {r["name"]: r for r in testgen.matrix(g, {"results": {"test_t2_guard": "pass", "test_t3_feature": "fail"}},
                                                  {"results": {"test_t2_guard": "pass", "test_t3_feature": "fail"}})}
    assert rows["test_t2_guard"]["kept"] and not rows["test_t2_guard"]["as_expected"]      # shown red, never hidden
    assert not rows["test_t3_feature"]["kept"]


def test_render_includes_only_kept_tests_and_their_probe_files():
    g = _gen([{"kind": "T1", "name": "test_t1_a", "code": "def test_t1_a():\n    pass\n", "probe_file": "tests/guardian/probes/a.py", "probe_code": "print(1)"},
              {"kind": "T2", "name": "test_t2_b", "code": "def test_t2_b():\n    pass\n"}])
    files = testgen.render(g, {"test_t2_b"})
    assert "tests/guardian/probes/a.py" not in files and "test_t1_a" not in files["tests/guardian/test_x.py"]
    assert "pytestmark = pytest.mark.guardian" in files["tests/guardian/test_x.py"] and "tests/guardian/conftest.py" in files


def test_curated_exploit_matches_by_alias(tmp_path):
    write_json(tmp_path / "register.json", [{"finding_id": "F-1", "vuln_id": "PYSEC-2026-2046", "aliases": ["GHSA-hgf8-39gv-g3f2"]}])
    unit = {"rid": "R-1", "target": "pkg:pypi/Werkzeug@3.0.1", "finding_ids": ["F-1"]}
    t = testgen.curated_t1(tmp_path, unit, {"kind": "upgrade"})
    assert len(t) == 1 and t[0]["source"] == "curated" and t[0]["kind"] == "T1"
    assert not testgen.curated_t1(tmp_path, unit, {"kind": "replace_api"})


def test_safety_check_rejects_network_process_and_version_reading():
    base = "print('GUARDIAN_PROBE: SAFE')\n"
    assert not safety_check("import socket\n" + base)[0]
    assert not safety_check("import subprocess\n" + base)[0]
    assert not safety_check("import werkzeug\nprint(werkzeug.__version__)\n" + base)[0]
    assert safety_check("from werkzeug.security import safe_join\nsafe_join('a', 'b')\n" + base)[0]


# ------------------------------------------------------------------ appboot
def test_parse_failure_and_wheel_tags():
    f = appboot.parse_failure("error: Failed to build `psycopg2-binary==2.9.9`\n  cause: ...")
    assert f == {"package": "psycopg2-binary", "version": "2.9.9", "reason": f["reason"]}
    assert appboot.parse_failure("all good") is None
    plat = appboot.platform_tags()[0]
    good = "win_amd64" if plat.startswith("win") else "manylinux_2_17_x86_64" if not plat.startswith("macosx") else "macosx_11_0_arm64"
    assert appboot.wheel_fits(f"x-1.0-cp314-cp314-{good}.whl", "3.14")
    assert not appboot.wheel_fits(f"x-1.0-cp313-cp313-{good}.whl", "3.14")
    assert appboot.wheel_fits("x-1.0-py3-none-any.whl", "3.14")
    assert appboot.wheel_fits(f"x-1.0-cp39-abi3-{good}.whl", "3.14")


class _FakeVT:
    def __init__(self, rel, vulns=None):
        self.rel, self.vulns = rel, vulns or {}

    def project(self, name):
        return {"releases": self.rel}

    def vulns_of(self, name, v):
        return self.vulns.get(v, [])


def test_compatible_upgrade_picks_smallest_version_with_a_wheel_and_no_vulns():
    plat = "win_amd64" if appboot.platform_tags()[0].startswith("win") else "manylinux_2_17_x86_64"
    rel = {"1.0": [{"filename": f"p-1.0-cp311-cp311-{plat}.whl"}],
           "1.1": [{"filename": "p-1.1.tar.gz"}],
           "1.2": [{"filename": f"p-1.2-cp314-cp314-{plat}.whl"}],
           "1.3": [{"filename": f"p-1.3-cp314-cp314-{plat}.whl"}],
           "1.4rc1": [{"filename": f"p-1.4rc1-cp314-cp314-{plat}.whl"}]}
    assert appboot.compatible_upgrade(_FakeVT(rel), "p", "1.0", "3.14")[0] == "1.2"
    assert appboot.compatible_upgrade(_FakeVT(rel, {"1.2": ["CVE-1"]}), "p", "1.0", "3.14")[0] == "1.3"
    assert appboot.compatible_upgrade(_FakeVT({"1.0": []}), "p", "1.0", "3.14")[0] is None


def test_target_python_from_dockerfile(tmp_path, monkeypatch):
    monkeypatch.delenv("GUARDIAN_TARGET_PYTHON", raising=False)
    (tmp_path / "Dockerfile").write_text("FROM python:3.11-slim\n")
    assert appboot.target_python(tmp_path)["version"] == "3.11"
    (tmp_path / "Dockerfile").write_text("FROM python:slim\n")
    monkeypatch.setattr(appboot, "newest_python", lambda: "3.14")
    t = appboot.target_python(tmp_path)
    assert t["version"] == "3.14" and "newest" in t["source"]


def _host_env():
    env = appboot.Env(Path(sys.prefix), f"{sys.version_info.major}.{sys.version_info.minor}", "pip")
    env.python = Path(sys.executable)
    env.full_version = sys.version.split()[0]
    return env


def test_boot_flask_fixture_healthy_broken_and_unknown(tmp_path):
    pytest.importorskip("flask")
    ok = tmp_path / "ok"
    ok.mkdir()
    (ok / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/')\ndef index():\n    return '<title>hi</title>ok'\n")
    r = appboot.boot(ok, _host_env(), tmp_path / "w1")
    assert r["framework"] == "flask" and r["status"] == "healthy", r
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "app.py").write_text("from flask import Flask\nraise RuntimeError('boom')\napp = Flask(__name__)\n")
    r = appboot.boot(bad, _host_env(), tmp_path / "w2")
    assert r["status"] == "failed"
    other = tmp_path / "other"
    other.mkdir()
    (other / "main.py").write_text("print('cli tool')\n")
    r = appboot.boot(other, _host_env(), tmp_path / "w3")
    assert r["status"] == "skipped"


# ------------------------------------------------------------------ fixed repository composition
def _mk_fix(repo: Path, base: str, rid: str, path: str, old: str, new: str) -> str:
    wt = repo.parent / f"wt-{rid}"
    _git(repo, "worktree", "add", "--detach", str(wt), base)
    p = wt / path
    p.write_text(p.read_text().replace(old, new))
    (wt / "tests" / "guardian").mkdir(parents=True, exist_ok=True)
    (wt / "tests" / "guardian" / "conftest.py").write_text(testgen.CONFTEST)
    (wt / "tests" / "guardian" / f"test_{rid.lower()}.py").write_text("def test_t2_guard_x():\n    assert True\n")
    _git(wt, "add", "-A")
    _git(wt, "commit", "-q", "-m", f"guardian {rid}")
    sha = _git(wt, "rev-parse", "HEAD")
    _git(repo, "worktree", "remove", "--force", str(wt))
    return sha


def _unit(rid, sha, rank, edit):
    return {"rid": rid, "target": f"pkg:pypi/{rid.lower()}@1", "target_label": rid, "target_kind": "package", "finding_ids": [],
            "ranks": [rank], "priority": "high", "status": "applied", "current": 0,
            "proposals": [{"version": 1, "action": f"fix {rid}", "edits": [edit], "fix_confidence": "high"}],
            "decisions": [{"stage": "proposal", "action": "approve", "reviewer": "ana"}, {"stage": "patch", "action": "approve", "reviewer": "ben"}],
            "validation": {"commit": sha, "status": "passed", "security_tests": {"file": f"tests/guardian/test_{rid.lower()}.py",
                           "tests": [{"name": "test_t2_guard_x", "kind": "T2", "kept": True, "as_expected": True, "expected": "fail → pass"}]}}}


@pytest.mark.skipif(not shutil.which("uv") and os.name == "nt", reason="needs uv for the throwaway environments")
def test_compose_one_commit_per_fix_skips_conflicts_and_keeps_checkout_clean(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_SANDBOX_INSTALL", "0")
    monkeypatch.setenv("GUARDIAN_TARGET_PYTHON", f"{sys.version_info.major}.{sys.version_info.minor}")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.txt").write_text("alpha\n")
    (repo / "b.txt").write_text("beta\n")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    base = _git(repo, "rev-parse", "HEAD")
    s1 = _mk_fix(repo, base, "R-001", "a.txt", "alpha", "ALPHA")
    s2 = _mk_fix(repo, base, "R-002", "b.txt", "beta", "BETA")
    s3 = _mk_fix(repo, base, "R-003", "a.txt", "alpha", "alpha-2")          # overlaps R-001
    out = tmp_path / "scan"
    write_json(out / "day2_config.json", {"repo_path": str(repo), "offline": True})
    write_json(out / "scan.json", {"scan_id": "t-scan", "offline": True})
    write_json(out / "remediations.json", [_unit("R-001", s1, 1, {"path": "a.txt", "old_text": "alpha", "new_text": "ALPHA"}),
                                            _unit("R-002", s2, 2, {"path": "b.txt", "old_text": "beta", "new_text": "BETA"}),
                                            _unit("R-003", s3, 3, {"path": "a.txt", "old_text": "alpha", "new_text": "alpha-2"})])
    import guardian.webapp.store as store
    monkeypatch.setattr(store, "run_pipeline", lambda *a, **k: None)      # the rescan is covered elsewhere
    res = fixed_repo.build(out, log=lambda m: None)
    assert [r["rid"] for r in res["included"]] == ["R-001", "R-002"]
    assert res["skipped"][0]["rid"] == "R-003" and "R-001" in res["skipped"][0]["why"]
    branch = res["publish"]["branch"]
    assert branch == "guardian/fixed-t-scan"
    log = _git(repo, "log", "--format=%s", f"{base}..{branch}").splitlines()
    assert len(log) == 3 and log[0].startswith("guardian: add GUARDIAN_FIXES.md")
    assert "Approved by: ana (proposal), ben (tested patch)" in _git(repo, "log", "-1", "--format=%B", f"{branch}~1")
    names = zipfile.ZipFile(out / "fixed" / "fixed-repo.zip").namelist()
    assert "repo-fixed/GUARDIAN_FIXES.md" in names and "repo-fixed/tests/guardian/test_r-001.py" in names
    assert (out / "fixed" / "fixes.patch").read_text().count("Subject:") == 3
    assert _git(repo, "status", "--porcelain") == ""                       # the user's checkout is untouched
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") in ("master", "main")
    assert [b.strip("* ") for b in _git(repo, "branch").splitlines() if "guardian" in b] == [branch]
    rep = report.build(out)
    assert [f["rid"] for f in rep["fixed"]] == ["R-001", "R-002"]
    html = report.to_html(rep)
    assert "<link" not in html and "<script" not in html and "http://" not in html.replace("http://127.0.0.1", "")
    assert "# Guardian remediation report" in report.to_md(rep)
    fixed_repo._rm_worktree(repo, fixed_repo.work_root(out) / "before")
    fixed_repo._rm_worktree(repo, fixed_repo.work_root(out) / "repo")


# ------------------------------------------------------------------ queue + "already validated" shortcut
def _rem(rid, prio, validated=False):
    u = {"rid": rid, "priority": prio, "status": "awaiting_proposal_review", "ranks": [1], "current": 0, "finding_ids": [],
         "proposals": [{"version": 1, "edits": [{"path": "requirements.txt"}], "checks": {}}], "candidates": [],
         "finding_confidence": "high", "stage_risk": prio}
    if validated:
        u["validation"] = {"proposal_version": 1, "finished_at": "2026-01-01T00:00:00Z", "status": "passed", "checks": {}}
    return u


def test_queue_validates_only_critical_and_high_by_default(monkeypatch):
    monkeypatch.delenv("GUARDIAN_AUTO_VALIDATE", raising=False)
    assert aq.policy() == "high"
    assert aq.eligible(_rem("R-1", "high")) and aq.eligible(_rem("R-2", "critical"))
    assert not aq.eligible(_rem("R-3", "medium")) and aq.eligible(_rem("R-3", "medium"), everything=True)
    assert not aq.eligible(_rem("R-4", "high", validated=True))


def test_approving_an_already_validated_proposal_goes_straight_to_patch_review(tmp_path, monkeypatch):
    from guardian.day2 import sandbox, workflow
    write_json(tmp_path / "remediations.json", [_rem("R-1", "high", validated=True)])
    monkeypatch.setattr(sandbox, "validate", lambda *a, **k: pytest.fail("the sandbox must not run again"))
    workflow.do_validate(tmp_path, "R-1")
    u = json.loads((tmp_path / "remediations.json").read_text())[0]
    assert u["status"] == "awaiting_patch_review"
    assert any(json.loads(l)["event"] == "validation_reused" for l in (tmp_path / "audit.jsonl").read_text().splitlines())
