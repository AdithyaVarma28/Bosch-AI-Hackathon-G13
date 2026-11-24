"""Day 2 (Brain & Shield): prioritize, investigate, remediate, approval gate, sandbox validation, rescan, verify.

Everything runs offline with the bundled fixture snapshots. The Docker sandbox is replaced by a fake runner that
answers `docker run ...` deterministically (tests fail for Flask 3.x, as a real API break would), while git
commands still run for real on the throwaway branch.
"""
from __future__ import annotations

import json
import re
import sqlite3
from importlib import resources
from pathlib import Path

import pytest

import guardian.runner as runner_mod
from guardian.context import Settings
from guardian.day2 import versions as V
from guardian.day2.approval import ApprovalMismatch, compute_plan_hash, decide
from guardian.day2.decisions import export_patch, open_d2, record
from guardian.day2.models import Edit
from guardian.day2.patcher import PatchError, apply_edits
from guardian.day2.pipeline import run_day2
from guardian.day2.policy import load_policy
from guardian.detectors.osv import LocalOsvClient
from guardian.orchestrator import run_pipeline
from guardian.runner import RunResult, default_runner

DATA = Path(str(resources.files("guardian.data")))
ADV = DATA / "fixture_advisories.json"
REG = DATA / "fixture_registry.json"


# ----------------------------------------------------------------------------- helpers
def fake_docker(fail_flask_major: int | None = 3):
    """docker info/run are simulated; everything else (git) runs for real."""
    calls = []

    def run(cmd, cwd=None, timeout=300):
        if cmd[:2] == ["docker", "info"]:
            return RunResult(0, "27.0.0", "")
        if cmd[:2] == ["docker", "run"]:
            calls.append(cmd)
            mount = cmd[cmd.index("-v") + 1].rsplit(":/w", 1)[0]
            reqs = (Path(mount) / "requirements.txt").read_text(encoding="utf-8") if (Path(mount) / "requirements.txt").exists() else ""
            m = re.search(r"flask==(\d+)", reqs, re.I)
            if "pytest" in cmd and "-rA" in cmd:          # the test run, not `pip install pytest`
                if fail_flask_major is not None and m and int(m.group(1)) >= fail_flask_major:
                    out = ("FAILED tests/test_api.py::test_app_exists - ImportError: cannot import name 'escape' from 'flask'\n"
                           "1 failed in 0.20s\n")
                    return RunResult(1, out, "")
                return RunResult(0, "PASSED tests/test_api.py::test_app_exists\n1 passed in 0.10s\n", "")
            return RunResult(0, "ok\n", "")
        return default_runner(cmd, cwd, timeout)
    run.calls = calls
    return run


def settings(tmp: Path, **kw) -> Settings:
    base = dict(offline=True, use_llm=False, use_docker=False, cache_dir=tmp / "cache", advisory_db=ADV, registry_snapshot=REG,
                sandbox="none", max_queue=8)
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def day1(fixture_repo, tmp_path):
    res = run_pipeline(str(fixture_repo), tmp_path / "out", settings(tmp_path))
    assert res.report_path and res.report_path.exists()
    return res.run_dir, tmp_path


def plan_by(d2, prefix):
    return next(p for p in d2.plans() if p.plan_key.startswith(prefix))


# ----------------------------------------------------------------------------- unit: versions, advisories, policy, patcher
def test_versions_and_ranges():
    assert V.compare("npm", "1.2.10", "1.2.9") == 1 and V.compare("npm", "1.0.0-rc.1", "1.0.0") == -1
    assert V.compare("pypi", "2.2.5", "2.10") == -1
    assert V.npm_satisfies("1.2.8", "^1.2.6") and not V.npm_satisfies("2.0.0", "^1.2.6")
    assert V.npm_satisfies("0.2.4", "^0.2.4") and not V.npm_satisfies("0.3.0", "^0.2.4")
    assert V.npm_satisfies("1.3.0", "1.x") and V.npm_satisfies("1.2.9", "~1.2.3") and not V.npm_satisfies("1.3.0", "~1.2.3")
    assert V.npm_satisfies("2.1.0", "^1.0.0 || ^2.0.0") and V.npm_satisfies("0.0.8", "0.0.8")
    assert V.max_satisfying("npm", ["1.2.5", "1.2.8", "2.0.0"], "^1.2.5") == "1.2.8"
    assert V.range_floor("npm", "^1.2.6") == "1.2.6" and V.range_floor("pypi", "==2.0.1") == "2.0.1"
    assert V.bump_kind("npm", "0.0.8", "0.2.4") == "major" and V.bump_kind("pypi", "2.0.1", "2.2.5") == "minor"
    assert V.bump_kind("npm", "0.5.1", "0.5.6") == "patch"


def test_local_osv_snapshot_matching():
    osv = LocalOsvClient(ADV)
    assert set(osv.matches("npm", "minimist", "0.0.8")) == {"GHSA-xvch-5gv4-984h", "GHSA-vh95-rmgr-6w4m"}
    assert osv.matches("npm", "minimist", "1.2.5") == ["GHSA-xvch-5gv4-984h"]
    assert osv.matches("npm", "minimist", "0.2.4") == [] and osv.matches("npm", "minimist", "1.2.8") == []
    assert osv.matches("pypi", "Flask", "2.0.1") and not osv.matches("pypi", "flask", "2.2.5")
    assert osv.matches("pypi", "flask", "2.3.1") and not osv.matches("pypi", "flask", "2.3.2")


def test_policy_floor_rules_cannot_be_weakened(tmp_path):
    base = load_policy()
    (tmp_path / "guardian-policy.yaml").write_text(
        "blocked_packages:\n  - {ecosystem: npm, name: event-stream, reason: compromised}\n"
        "rules:\n  - {id: target-resolved, severity: warn}\n  - {id: no-new-high, enabled: false}\n"
        "  - {id: pinned-ci-actions, severity: block}\n", encoding="utf-8")
    p = load_policy(tmp_path)
    assert p.rule("target-resolved")["severity"] == "block" and p.rule("no-new-high")
    assert p.rule("pinned-ci-actions")["severity"] == "block"
    assert any(b["name"] == "event-stream" for b in p.blocked)
    assert p.sha256 != base.sha256 and any("floor" in n for n in p.notes)


def test_patcher_edits_and_confinement(tmp_path):
    (tmp_path / "package.json").write_text('{\n  "name": "x",\n  "dependencies": {\n    "mkdirp": "0.5.1"\n  }\n}\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==2.0.1  # web\nrequests==2.25.1\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM node:latest\nRUN echo hi\n", encoding="utf-8")
    (tmp_path / "ci.yml").write_text("on: push\npermissions: write-all\njobs:\n  a: {}\n", encoding="utf-8")
    apply_edits(tmp_path, [Edit(kind="npm_set_dep", file="package.json", params={"name": "mkdirp", "spec": "0.5.6"}),
                           Edit(kind="npm_override", file="package.json", params={"name": "minimist", "spec": "^1.2.6"}),
                           Edit(kind="pip_set_pin", file="requirements.txt", params={"name": "Flask", "version": "2.2.5"}),
                           Edit(kind="docker_from", file="Dockerfile", params={"old": "node:latest", "new": "node:22-slim", "line": 1}),
                           Edit(kind="gha_permissions", file="ci.yml", params={"permissions": {"contents": "read"}})])
    pj = json.loads((tmp_path / "package.json").read_text())
    assert pj["dependencies"]["mkdirp"] == "0.5.6" and pj["overrides"] == {"minimist": "^1.2.6"}
    assert (tmp_path / "requirements.txt").read_text() == "flask==2.2.5  # web\nrequests==2.25.1\n"
    assert (tmp_path / "Dockerfile").read_text().startswith("FROM node:22-slim\n")
    assert "permissions:\n  contents: read\n" in (tmp_path / "ci.yml").read_text()
    with pytest.raises(PatchError):
        apply_edits(tmp_path, [Edit(kind="pip_remove", file="../outside.txt", params={"name": "x"})])


# ----------------------------------------------------------------------------- S10-S12 on the fixture
def test_detection_to_plans(day1):
    run_dir, tmp = day1
    rep = json.loads((run_dir / "report.json").read_text())
    vulns = {f["signals"]["advisory_id"]: f for f in rep["findings"] if f["cls"] == "vuln"}
    assert "GHSA-xvch-5gv4-984h" in vulns and vulns["GHSA-xvch-5gv4-984h"]["signals"]["path"][0].startswith("pkg:npm/mkdirp")
    res = run_day2(run_dir, settings(tmp))
    assert res.status == "awaiting_approval" and all(s == "ok" for s in res.node_status.values()), res.node_status
    st, d2 = open_d2(run_dir)
    try:
        d2rep = json.loads((run_dir / "day2" / "report.json").read_text())
        # S10: explainable score with factors and a separate confidence
        top = d2rep["priority"][0]
        assert top["bucket"] == "fix_now" and {f["name"] for f in top["factors"]} >= {"severity", "reachability", "exposure"}
        # S11: at least one non-CVE signal investigated with fact/inference separation
        invs = d2rep["investigations"].values()
        post = next(i for i in invs if i["signal"] == "install_script")
        assert post["verdict"] == "likely_malicious"
        assert {c["type"] for c in post["claims"]} >= {"fact", "inference"}
        # S12: graph-aware remediation for the transitive minimist vulnerability
        mm = plan_by(d2, "pkg:npm/minimist")
        actions = {c.action for c in mm.candidates}
        assert {"parent_upgrade", "override", "escalate"} <= actions
        best = mm.candidate(mm.finalists[0])
        assert best.action == "parent_upgrade" and best.to_version == "0.5.6" and best.floor_safe
        assert best.simulation.target_resolved and "minimist" in best.diff and best.diff_sha256
        weaker = next(c for c in mm.candidates if c.to_version == "0.5.5")
        assert weaker.floor_safe is False                     # ^1.2.5 floor is still vulnerable
        flask = plan_by(d2, "pkg:pypi/flask")
        tos = [flask.candidate(c).to_version for c in flask.finalists]
        assert tos[0] == "2.2.5" and "3.0.3" in tos
        assert flask.candidate(flask.finalists[-1]).compatibility == "high"   # major bump of a package the code imports
        assert plan_by(d2, "secret:").status == "escalated"
        lod = plan_by(d2, "pkg:npm/lodash")
        assert lod.candidate(lod.finalists[0]).action == "restore_lock_source"
        assert not any(c.action in ("block", "remove") for c in lod.candidates)   # the entry is the problem, not lodash
        assert plan_by(d2, "anomaly:install_script").candidate(plan_by(d2, "anomaly:install_script").finalists[0]).action == "remove_script"
        assert compute_plan_hash(mm) == mm.plan_hash
        assert (run_dir / "day2" / "remediation.html").stat().st_size > 5000
    finally:
        st.close()


# ----------------------------------------------------------------------------- S13 approval gate
def test_approval_gate_is_hash_bound_and_append_only(day1):
    run_dir, tmp = day1
    run_day2(run_dir, settings(tmp), only=["pkg:pypi/flask@2.0.1"])
    st, d2 = open_d2(run_dir)
    try:
        plan = plan_by(d2, "pkg:pypi/flask")
        with pytest.raises(ApprovalMismatch):
            decide(d2, plan, "approve", "alice", plan_hash="0" * 64)
        with pytest.raises(ValueError):
            record(run_dir, plan.plan_key, "approve", "alice", "deadbeef")            # too short to be a reviewed hash
        tampered = plan.model_copy(deep=True)
        tampered.candidates[0].edits[0].params["version"] = "9.9.9"
        with pytest.raises(ApprovalMismatch):
            decide(d2, tampered, "approve", "alice", plan_hash=plan.plan_hash)
        with pytest.raises(ValueError):
            record(run_dir, plan.plan_key, "accept_risk", "alice", plan.plan_hash, reason="")   # needs reason + expiry
    finally:
        st.close()
    new = record(run_dir, "flask", "approve", "alice", plan.plan_hash[:16], "ok",
                 candidate=[plan.finalists[1]])                                    # reviewer edit -> new revision
    assert new.revision == plan.revision + 1 and new.plan_hash != plan.plan_hash and new.status == "approved"
    st, d2 = open_d2(run_dir)
    try:
        assert d2.plan(plan.plan_key, plan.revision).status == "superseded"
        assert [a.plan_hash for a in d2.approvals(plan.plan_key)] == [new.plan_hash]
        with pytest.raises(sqlite3.DatabaseError):
            d2.conn.execute("UPDATE d2_approvals SET reviewer='mallory'")
        with pytest.raises(sqlite3.DatabaseError):
            d2.conn.execute("DELETE FROM d2_audit")
    finally:
        st.close()


# ----------------------------------------------------------------------------- S14-S16 end to end
def test_verified_remediation_with_tournament_rescan_and_patch(day1, monkeypatch):
    run_dir, tmp = day1
    s = settings(tmp, sandbox="docker")
    run_day2(run_dir, s, only=["pkg:pypi/flask@2.0.1", "pkg:npm/minimist@0.0.8"])
    st, d2 = open_d2(run_dir)
    hashes = {p.plan_key: p.plan_hash for p in d2.plans()}
    st.close()
    for key in ("pkg:pypi/flask@2.0.1", "pkg:npm/minimist@0.0.8"):
        record(run_dir, key, "approve", "alice", hashes[key][:16], "reviewed")
    fake = fake_docker()
    monkeypatch.setattr(runner_mod, "_docker_ok", None)
    from guardian.day2 import pipeline as pl
    orig = pl.load_context

    def load(rd, st_):
        ctx = orig(rd, st_)
        ctx.runner = fake
        return ctx
    monkeypatch.setattr(pl, "load_context", load)
    res = run_day2(run_dir, s, only=["pkg:pypi/flask@2.0.1", "pkg:npm/minimist@0.0.8"])
    reps = {r.plan_key: r for r in res.reports}
    fr = reps["pkg:pypi/flask@2.0.1"]
    assert fr.verdict == "Verified", (fr.verdict, fr.confidence_reasons)
    win = next(v for v in fr.tournament if v.winner)
    assert fr.chosen.to_version == "2.2.5" and not win.regressions
    assert "tests/test_api.py::test_app_exists" in win.tests_after.passed_ids and "npm:all" in win.tests_after.passed_ids
    loser = next(v for v in fr.tournament if fr.chosen and v.candidate_id != fr.chosen.id and v.status == "failed")
    assert loser.regressions == ["tests/test_api.py::test_app_exists"]           # Flask 3.x broke the test
    assert fr.rescan.target_resolved and {"name": "flask", "ecosystem": "pypi", "from": "2.0.1", "to": "2.2.5"} in fr.rescan.sbom_changed
    assert all(p.passed for p in fr.policy if p.severity == "block")
    assert {c.check for c in fr.verifier.checks if c.ok} >= {"vulnerable_versions_absent", "applied_diff_matches_approval"}
    assert win.branch.startswith("guardian/fix-") and win.commit
    assert any(t.stage == "S13" and t.actor == "alice" for t in fr.timeline)
    mr = reps["pkg:npm/minimist@0.0.8"]
    assert mr.verdict in ("Verified", "Partially verified") and mr.rescan.target_resolved
    assert not mr.rescan.vulnerable_versions_left
    vex = json.loads((run_dir / "day2" / "vex.cdx.json").read_text())
    assert any(v["analysis"]["state"] == "resolved" for v in vex["vulnerabilities"])
    d1 = json.loads((run_dir / "report.json").read_text())
    assert d1["remediation"]["path"] == "day2/report.json" and d1["validation"]
    patch = export_patch(run_dir, "flask", "bob")
    text = patch.read_text()
    assert "flask==2.2.5" in text and "export approved by bob" in text
    st, d2 = open_d2(run_dir)
    try:
        assert any(a.kind == "pr" and a.reviewer == "bob" for a in d2.approvals())
    finally:
        st.close()


def test_self_correction_needs_fresh_approval(day1, monkeypatch):
    run_dir, tmp = day1
    s = settings(tmp, sandbox="docker")
    run_day2(run_dir, s, only=["pkg:pypi/flask@2.0.1"])
    st, d2 = open_d2(run_dir)
    plan = plan_by(d2, "pkg:pypi/flask")
    major3 = next(c for c in plan.candidates if c.to_version == "3.0.3")
    st.close()
    record(run_dir, "flask", "approve", "alice", plan.plan_hash[:16], "try latest", candidate=[major3.id])
    fake = fake_docker()
    monkeypatch.setattr(runner_mod, "_docker_ok", None)
    from guardian.day2 import pipeline as pl
    orig = pl.load_context
    monkeypatch.setattr(pl, "load_context", lambda rd, st_: (lambda c: (setattr(c, "runner", fake), c)[1])(orig(rd, st_)))
    res = run_day2(run_dir, s, only=["pkg:pypi/flask@2.0.1"])
    rep = res.reports[0]
    assert rep.verdict == "Awaiting approval"
    assert rep.corrections and rep.corrections[0].failure_class == "api_removed"
    st, d2 = open_d2(run_dir)
    try:
        latest = d2.plan(plan.plan_key)
        assert latest.status == "awaiting_approval" and latest.parent_hash and latest.plan_hash == rep.corrections[0].new_plan_hash
        proposed = latest.candidate(latest.finalists[0])
        assert proposed.source == "self-correction" and V.compare("pypi", proposed.to_version, "3.0.3") < 0
    finally:
        st.close()
    # the corrected plan only runs after a fresh approval of its new hash
    record(run_dir, "flask", "approve", "alice", latest.plan_hash[:16], "corrected")
    res = run_day2(run_dir, s, only=["pkg:pypi/flask@2.0.1"])
    assert res.reports[0].verdict == "Verified"


def test_no_sandbox_caps_verdict(day1):
    run_dir, tmp = day1
    run_day2(run_dir, settings(tmp), only=["pkg:npm/minimist@0.0.8"])
    st, d2 = open_d2(run_dir)
    h = plan_by(d2, "pkg:npm/minimist").plan_hash
    st.close()
    record(run_dir, "minimist", "approve", "alice", h[:16])
    res = run_day2(run_dir, settings(tmp), only=["pkg:npm/minimist@0.0.8"])
    r = res.reports[0]
    assert r.verdict == "Partially verified" and r.rescan.target_resolved
    assert any("not run" in x for x in r.confidence_reasons)


def test_api_day2_endpoints(day1):
    from fastapi.testclient import TestClient

    from guardian.api import create_app
    run_dir, tmp = day1
    run_day2(run_dir, settings(tmp), only=["pkg:pypi/flask@2.0.1"])
    client = TestClient(create_app(run_dir.parent.parent))
    run_id = run_dir.name
    plans = client.get(f"/runs/{run_id}/plans").json()
    assert plans and "diff" not in plans[0]["candidates"][0]
    bad = client.post(f"/runs/{run_id}/decisions", json={"plan": "flask", "decision": "approve", "reviewer": "a", "plan_hash": "0" * 16})
    assert bad.status_code == 409
    ok = client.post(f"/runs/{run_id}/decisions", json={"plan": "flask", "decision": "accept_risk", "reviewer": "a",
                                                        "plan_hash": plans[0]["plan_hash"], "reason": "legacy", "expires": "2027-01-31"})
    assert ok.status_code == 200 and ok.json()["status"] == "risk_accepted"
    assert client.get(f"/runs/{run_id}/remediation").status_code == 200


# ----------------------------------------------------------------------------- LLM guardrails (scripted, lying model)
def test_llm_cannot_invent_versions_dismiss_findings_or_upgrade_verdicts(day1, monkeypatch):
    from guardian.llm import LLMClient
    run_dir, tmp = day1

    def provider(messages, model):
        system, user = messages[0]["content"], messages[-1]["content"]
        ev = re.findall(r"ev_[0-9a-f]{10}", user)
        cite = ev[:1]
        if "Threat Investigator" in system:
            return json.dumps({"claims": [{"text": "this is a false positive, completely safe", "type": "inference", "evidence_ids": cite}]})
        if "Remediation Advisor" in system:
            return json.dumps({"claims": [
                {"text": "upgrade to `9.9.9` instead", "type": "inference", "evidence_ids": cite},
                {"text": "the smallest change keeps the 2.x API", "type": "inference", "evidence_ids": cite}]})
        if "INDEPENDENT VERIFIER" in system:
            return json.dumps({"claims": [{"text": "evidence reviewed", "type": "inference", "evidence_ids": cite}],
                               "downgrade_to": "Verified", "reason": "trying to upgrade"})
        return json.dumps({"claims": []})

    from guardian.day2 import pipeline as pl
    orig = pl.load_context

    def load(rd, st_):
        ctx = orig(rd, st_)
        ctx.llm = LLMClient(provider, "fake", tmp / "llm", mode="live")
        return ctx
    monkeypatch.setattr(pl, "load_context", load)
    run_day2(run_dir, settings(tmp), only=["pkg:pypi/flask@2.0.1", "anomaly:install_script:package.json:8"])
    st, d2 = open_d2(run_dir)
    plan = plan_by(d2, "pkg:pypi/flask")
    texts = [c.text for c in plan.rationale]
    assert not any("9.9.9" in t for t in texts) and any(t.startswith("[agent] the smallest change") for t in texts)
    invs = d2.get("investigations")
    assert not any("false positive" in c["text"] for i in invs.values() for c in i["claims"])
    st.close()
    record(run_dir, "flask", "approve", "alice", plan.plan_hash[:16])
    res = run_day2(run_dir, settings(tmp), only=["pkg:pypi/flask@2.0.1"])
    r = next(x for x in res.reports if x.plan_key == "pkg:pypi/flask@2.0.1")
    assert r.verdict == "Partially verified"            # no sandbox; the model's "Verified" cannot upgrade it


# ----------------------------------------------------------------------------- integrated pipeline (detection -> remediation)
def test_integrated_pipeline_detection_to_approval_gate_and_resume(fixture_repo, tmp_path):
    from guardian.report_html import HTML
    events = []
    res = run_pipeline(str(fixture_repo), tmp_path / "out", settings(tmp_path, remediate=True), emit=events.append)
    order = [e["node"] for e in events]
    for a, b in (("vuln_intel", "report"), ("report", "day2_start"), ("day2_start", "prioritize"),
                 ("prioritize", "investigate"), ("investigate", "remediation_plan"), ("remediation_plan", "approval_gate"),
                 ("approval_gate", "remediation_report")):
        assert order.index(a) < order.index(b), (a, b, order)
    assert "validate" not in order                                    # nothing runs past the gate without approval
    assert "failed" not in res.node_status.values()
    assert res.day2 is not None and res.day2.status == "awaiting_approval" and res.day2.plans
    rep = json.loads(res.report_path.read_text())
    byf = rep["remediation"]["by_finding"]
    vuln = next(f for f in rep["findings"] if f["cls"] == "vuln")
    assert byf[vuln["id"]]["plan_key"] and byf[vuln["id"]]["bucket"]
    html = (res.run_dir / "report.html").read_text(encoding="utf-8")
    assert 'data-p="remediation"' in html and '"by_finding"' in html and 'data-p="remediation"' in HTML
    # resume after approval with the same Day 2 nodes; rescans are detection-only (no recursion into Day 2)
    flask = next(p for p in res.day2.plans if p.plan_key.startswith("pkg:pypi/flask"))
    record(res.run_dir, flask.plan_key, "approve", "alice", flask.plan_hash[:16])
    again = run_day2(res.run_dir, settings(tmp_path))
    r = next(x for x in again.reports if x.plan_key == flask.plan_key)
    assert r.verdict == "Partially verified" and r.rescan.target_resolved
    assert not any(k.startswith(("day2_start", "prioritize")) for k in r.rescan.node_status)
    rep = json.loads(res.report_path.read_text())
    assert rep["remediation"]["by_finding"][next(i for i in flask.finding_ids)]["verdict"] == "Partially verified"


# ----------------------------------------------------------------------------- Advisory Analyst agent
def test_advisory_analyst_answers_six_questions(day1):
    run_dir, tmp = day1
    run_day2(run_dir, settings(tmp), only=["pkg:pypi/flask@2.0.1", "pkg:npm/minimist@0.0.8"])
    st, d2 = open_d2(run_dir)
    try:
        advs = {a["advisory_id"]: a for a in d2.get("advisories").values()}
        fl = advs["GHSA-m2qf-hxjv-5gpq"]
        assert fl["affects_installed"]["value"] == "yes" and fl["affects_installed"]["verifier_status"] == "verified"
        assert fl["relevance"]["value"] in ("relevant", "likely_relevant")          # flask is imported by the app
        assert fl["mitigations"] and "Cache-Control" in fl["mitigations"][0]["text"]  # advisory workaround extracted
        assert fl["recommended"]["value"] == "upgrade" and fl["missing_evidence"]
        mm = advs["GHSA-xvch-5gv4-984h"]
        assert mm["recommended"]["value"] == "pin" and len(mm["usage_paths"][0]) == 2   # transitive via mkdirp
        flask = plan_by(d2, "pkg:pypi/flask")
        assert any(c.action == "mitigate" and not c.edits for c in flask.candidates)    # manual, never auto-applied
        assert any("safest action: upgrade" in c.text for c in flask.rationale)
        pri = {s["finding_id"]: s for s in json.loads((run_dir / "day2" / "priority.json").read_text())}
        assert any(f["name"] == "advisory_relevance" for s in pri.values() for f in s["factors"])
        rep = json.loads((run_dir / "day2" / "report.json").read_text())
        assert rep["advisories"] and "Advisory analysis" in (run_dir / "day2" / "remediation.html").read_text(encoding="utf-8")
        # inline reviewer comment travels in the approved diff
        c = flask.candidate(flask.finalists[0])
        assert "# guardian: upgraded flask 2.0.1 -> 2.2.5 (fixes GHSA-m2qf-hxjv-5gpq)" in c.diff
    finally:
        st.close()


def test_advisory_analyst_llm_guardrails(day1, monkeypatch):
    from guardian.day2.advisory_agent import assess
    from guardian.llm import LLMClient
    from guardian.day2 import pipeline as pl
    run_dir, tmp = day1

    def provider(messages, model):
        user = messages[-1]["content"]
        cite = re.findall(r"ev_[0-9a-f]{10}", user)[:1]
        return json.dumps({"action": "answer",
                           "relevance": {"value": "unlikely_relevant", "text": "this is a false positive and safe", "type": "inference", "evidence_ids": cite},
                           "feature_usage": {"value": "likely_unused", "text": "no `session.permanent` assignment found", "type": "inference", "evidence_ids": cite},
                           "affects_installed": {"value": "maybe", "text": "x", "evidence_ids": cite},
                           "recommended": {"value": "accept_risk_temporarily", "text": "accept it", "evidence_ids": cite},
                           "missing": ["proxy cache configuration of the deployment"]})
    ctx = pl.load_context(run_dir, settings(tmp))
    ctx.llm = LLMClient(provider, "fake", tmp / "llm", mode="live")
    f = next(x for x in ctx.store.list_findings() if x.signals.get("advisory_id") == "GHSA-m2qf-hxjv-5gpq")
    a = assess(ctx, f)
    assert a.relevance.by == "rules"                       # dismissal language rejected by the Verifier
    assert a.affects_installed.value == "yes"              # invalid enum ignored, rule answer kept
    assert a.recommended.value == "upgrade"                # cannot accept risk while a fix exists
    assert any("accepting the risk" in n for n in a.notes)
    assert "proxy cache configuration of the deployment" in a.missing_evidence
    ctx.store.close()


# ----------------------------------------------------------------------------- Threat Investigator agent (S11)
def _threat_ctx(run_dir, tmp, script):
    from guardian.day2 import pipeline as pl
    from guardian.day2.registry import RegistryClient
    from guardian.httpcache import CachedHttp
    from guardian.llm import LLMClient
    ctx = pl.load_context(run_dir, settings(tmp))
    state = {"turn": 0}

    def provider(messages, model):
        state["turn"] += 1
        return json.dumps(script(messages, state["turn"]))
    ctx.llm = LLMClient(provider, "fake-agent", tmp / "llm", mode="live")
    reg = RegistryClient(CachedHttp(tmp / "cache", offline=True), REG)
    return ctx, reg


def test_threat_agent_decides_label_with_tools_and_guardrails(day1):
    from guardian.day2.threat import investigate_finding
    run_dir, tmp = day1

    # 1) lodash entry moved to a non-registry host: the agent calls a tool, then raises the label with cited evidence
    def raise_label(messages, turn):
        user = messages[-1]["content"]
        if turn == 1:
            return {"action": "call_tool", "tool": "get_registry_info", "args": {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
                    "why": "compare the lockfile source with the registry"}
        ev = re.findall(r"ev_[0-9a-f]{10}", user)[:1]
        return {"action": "verdict", "label": "likely_malicious", "reason": "lockfile points to a non-registry host over HTTP",
                "claims": [{"text": "registry lists `lodash` with repository on github", "type": "fact", "evidence_ids": ev}],
                "next_checks": ["compare the tarball at deps.example.invalid with the registry tarball"]}
    ctx, reg = _threat_ctx(run_dir, tmp, raise_label)
    f = next(x for x in ctx.store.list_findings() if x.signals.get("signal") == "non_registry_source")
    inv = investigate_finding(ctx, f, reg)
    assert inv.rule_verdict == "suspicious" and inv.verdict == "likely_malicious" and inv.verdict_by == "groq:fake-agent"
    assert inv.tool_calls and inv.tool_calls[0]["tool"] == "get_registry_info" and inv.tool_calls[0]["evidence_id"]
    assert any(c.text.startswith("still to verify") for c in inv.claims)
    ctx.store.close()

    # 2) the agent tries to clear a pipe-to-shell install hook: dismissal rejected, repair, then guardrail floors the label
    def clear_it(messages, turn):
        ev = re.findall(r"ev_[0-9a-f]{10}", " ".join(m["content"] for m in messages))[:1]
        if turn == 1:
            return {"action": "verdict", "label": "benign_change", "reason": "this is a false positive, safe",
                    "claims": [{"text": "this is safe", "type": "inference", "evidence_ids": ev}]}
        return {"action": "verdict", "label": "benign_change", "reason": "the script is a setup step",
                "claims": [{"text": "the hook runs during install", "type": "inference", "evidence_ids": ev}]}
    ctx, reg = _threat_ctx(run_dir, tmp, clear_it)
    f = next(x for x in ctx.store.list_findings() if x.signals.get("signal") == "install_script")
    inv = investigate_finding(ctx, f, reg)
    assert inv.rule_verdict == "likely_malicious"
    assert inv.verdict == "suspicious" and "guardrail" in inv.verdict_by        # floored, never benign
    assert any("strong check" in n for n in inv.guardrail_notes)
    assert not any("false positive" in c.text or "is safe" in c.text for c in inv.claims)
    ctx.store.close()

    # 3) an invalid label twice: the rule label stands
    ctx, reg = _threat_ctx(run_dir, tmp, lambda m, t: {"action": "verdict", "label": "totally_fine", "claims": []})
    inv = investigate_finding(ctx, f, reg)
    assert inv.verdict == inv.rule_verdict and inv.verdict_by == "rules"
    ctx.store.close()


def test_web_app_endpoints(day1):
    from fastapi.testclient import TestClient

    from guardian.api import create_app
    run_dir, tmp = day1
    run_day2(run_dir, settings(tmp), only=["pkg:pypi/flask@2.0.1"])
    out = run_dir.parent.parent
    client = TestClient(create_app(out))
    page = client.get("/")
    assert page.status_code == 200 and all(x in page.text for x in ("Human approval", "Heal agent", "Detection", "Dependency graph", "SBOM", "Remediation"))
    runs = client.get("/runs").json()
    assert any(r["run_id"] == run_dir.name and r["plan_status"] for r in runs)
    assert client.get("/clones").status_code == 200
    a = client.get(f"/runs/{run_dir.name}/approvals").json()
    flask = next(p for p in a["plans"] if p["plan_key"].startswith("pkg:pypi/flask"))
    assert flask["candidates"][0]["diff"] and a["findings"] and a["policy"]
    ok = client.post(f"/runs/{run_dir.name}/decisions", json={"plan": flask["plan_key"], "decision": "approve", "reviewer": "ui",
                                                              "plan_hash": flask["plan_hash"]})
    assert ok.status_code == 200 and ok.json()["status"] == "approved"
    a = client.get(f"/runs/{run_dir.name}/approvals").json()
    assert a["approvals"][-1]["reviewer"] == "ui"
    assert client.post("/heal", json={"repo": str(tmp)}).status_code == 422       # outside output/clones: refused
    # every earlier view is reachable inside the app: report pages render fresh with an embed mode
    r1 = client.get(f"/runs/{run_dir.name}/report.html?embed=1")
    assert r1.status_code == 200 and 'has("embed")' in r1.text and "Dependency graph" in r1.text and "SBOM" in r1.text
    r2 = client.get(f"/runs/{run_dir.name}/remediation.html?embed=1")
    assert r2.status_code == 200 and "Advisory analysis" in r2.text and 'has("embed")' in r2.text
    assert client.get("/chaos").status_code == 200 and client.get("/chaos/experiments").json()
    assert client.post("/chaos", json={"target": str(tmp / "nope")}).status_code == 422
