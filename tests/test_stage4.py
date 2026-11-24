"""Stage 4 on the full mini-shop fixture (tests/fixtures/make_mini_shop_full.py), offline.

OSV data comes from tests/data/osv_minishop.zip (real records, dump layout), so the offline-dump
path is what runs here. Expected results: docs/stage4.md section 14.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardian.cli import app
from guardian.stage4_vulns.risk import project_risk
from guardian.stage4_vulns.schema import CVSS, ConditionResult, Investigation, ReviewDecision, VulnMatch
from guardian.stage4_vulns.sources import grype_records, is_affected

ROOT = Path(__file__).resolve().parents[1]
DUMP = ROOT / "tests" / "data" / "osv_minishop.zip"


@pytest.fixture(scope="module")
def full(tmp_path_factory):
    if not shutil.which("git"):
        pytest.skip("git is needed")
    base = tmp_path_factory.mktemp("stage4")
    r = subprocess.run([sys.executable, str(ROOT / "tests/fixtures/make_mini_shop_full.py"), str(base)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture failed: {r.stderr[-300:]}")
    out = base / "output"
    env_vulndb = base / "vulndb"
    import os
    os.environ["GUARDIAN_VULNDB"] = str(env_vulndb)
    res = CliRunner().invoke(app, ["scan", str(base / "mini-shop"), "--output", str(out), "--offline",
                                   "--skip-sbom", "--osv-dump", str(DUMP), "--no-stage5"])
    assert res.exit_code == 0, res.output
    return {"base": base, "dir": out / "mini-shop", "log": res.output}


def cards(d):
    return json.loads((d / "vuln_findings.json").read_text(encoding="utf-8"))


def by_pkg(d, name):
    return [c for c in cards(d) if c["component_name"].lower() == name]


def test_outputs_written(full):
    for f in ("vulns.json", "vuln_findings.json", "vuln_traces.json", "triage.json", "review.sqlite"):
        assert (full["dir"] / f).exists(), f
    assert "stage 4:" in full["log"]


def test_pyyaml_symbol_called_internal_high(full):
    c = by_pkg(full["dir"], "pyyaml")[0]
    assert c["vuln_id"] == "GHSA-8q59-q68h-6hv4" and "PYSEC-2021-142" in c["aliases"]   # deduped by alias
    assert c["usage"] == "symbol_called" and c["reachability"] == "internal_only"
    assert c["project_risk"] == "high" and c["severity"]["cvss"] == 9.8
    assert any(e["type"] == "code" and e["file"] == "app/config/load.py" for e in c["evidence"])
    assert c["fix"]["upgrade_to"] == "5.4"


def test_joblib_symbol_not_found_medium_with_guard(full):
    c = by_pkg(full["dir"], "joblib")[0]
    assert c["usage"] == "package_used_symbol_not_found" and c["reachability"] == "internal_only"
    assert c["project_risk"] == "medium" and c["review"]["downgrade_guard"]
    assert c["review"]["status"] == "pending" and c["review"]["thread_id"]


def test_transitive_path_traced(full):
    c = by_pkg(full["dir"], "idna")[0]
    assert c["dependency_path"][0] == "requirements.txt:5"
    assert c["dependency_path"][-1] == "pkg:pypi/idna@3.7" and "pkg:pypi/requests@2.31.0" in c["dependency_path"]
    assert c["usage"] == "package_used_symbol_unknown" and c["project_risk"] == "low"


def test_dev_only_low(full):
    c = by_pkg(full["dir"], "pytest")[0]
    assert c["scope"] == "dev" and c["project_risk"] == "low"


def test_values_separate_and_evidence_verified(full):
    for c in cards(full["dir"]):
        assert {"severity", "project_risk", "confidence"} <= set(c)
        assert c["severity"]["cvss"] is None or isinstance(c["severity"]["cvss"], float)
        for cl in c["claims"]:
            assert cl["evidence"], cl
        assert c["investigation"]["tool_calls_used"] <= 10
    trace = json.loads((full["dir"] / "vuln_traces.json").read_text(encoding="utf-8"))
    assert any(s["tool"] == "trace_callers" for s in trace["F-001"])


def test_graph_has_vulnerability_nodes(full):
    g = json.loads((full["dir"] / "graph.json").read_text(encoding="utf-8"))
    ids = {n["id"] for n in g["nodes"]}
    assert "vuln:GHSA-8q59-q68h-6hv4" in ids
    types = {e["type"] for e in g["edges"]}
    assert {"AFFECTS", "USED_AT", "REACHED_VIA"} <= types


def test_review_resume_and_rescan_reuse(full, tmp_path):
    d = full["dir"]
    jid = by_pkg(d, "joblib")[0]["finding_id"]
    res = CliRunner().invoke(app, ["review", str(d), jid, "--action", "dismiss"])
    assert res.exit_code != 0                                 # dismiss needs a reason
    res = CliRunner().invoke(app, ["review", str(d), jid, "--action", "dismiss", "--reason", "not_used", "--by", "tester"])
    assert res.exit_code == 0, res.output
    c = by_pkg(d, "joblib")[0]
    assert c["review"]["status"] == "dismissed" and c["review"]["by"] == "tester"
    triage = json.loads((d / "triage.json").read_text(encoding="utf-8"))
    assert len(triage["decisions"]) == 1
    # re-run Stage 4 on unchanged inputs: the decision is reused, not re-opened
    res = CliRunner().invoke(app, ["vulns", str(d), "--offline", "--osv-dump", str(DUMP)])
    assert res.exit_code == 0, res.output
    c = by_pkg(d, "joblib")[0]
    assert c["review"]["status"] == "dismissed" and c["review"].get("reused")


def test_api(full):
    from fastapi.testclient import TestClient
    from guardian.stage3_knowledge.api import create_app
    cl = TestClient(create_app(full["dir"]))
    assert cl.get("/vulns", params={"risk": "high"}).json()
    one = cl.get("/vulns/F-001").json()
    assert one["card"]["finding_id"] == "F-001" and one["trace"]
    assert "vulnerabilities" in cl.get("/blast-radius/pyyaml").json()
    pend = [c for c in cl.get("/vulns").json() if c["review"]["status"] == "pending"]
    if pend:
        r = cl.post(f"/review/{pend[0]['finding_id']}", json={"action": "override", "new_risk": "high", "reason": "seen in prod"})
        assert r.status_code == 200 and r.json()["project_risk"] == "high"
        assert r.json()["project_risk_by_rules"]


# --------------------------------------------------------------------------- units

def _m(score, scope="runtime", kev=False):
    return VulnMatch(match_id="x", vuln_id="GHSA-x", package="pkg:pypi/a@1", package_name="a",
                     cvss=CVSS(score=score, band="critical" if score >= 9 else "high"), scope=scope, kev=kev)


def test_rule_table():
    inv = Investigation(vuln_id="x", package="p", usage="symbol_called", reachability="public_path")
    assert project_risk(_m(9.8), inv) == ("critical", 2)
    inv.conditions = [ConditionResult(condition="untrusted_input", status="not_shown")]
    assert project_risk(_m(9.8), inv) == ("high", 3)
    assert project_risk(_m(5.0, kev=True), inv)[0] == "critical"
    inv2 = Investigation(vuln_id="x", package="p", usage="package_not_imported", reachability="no_path_found")
    assert project_risk(_m(9.8), inv2) == ("low", 9)
    assert project_risk(_m(9.8, scope="container_os"), Investigation(vuln_id="x", package="p", usage="not_applicable"))[0] == "high"


def test_osv_range_semantics():
    rec = {"affected": [{"package": {"ecosystem": "PyPI", "name": "PyYAML"},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]}
    assert is_affected(rec, "pyyaml", "5.3.1") and not is_affected(rec, "pyyaml", "5.4.1")


def test_grype_normalization():
    doc = {"matches": [{"vulnerability": {"id": "CVE-2023-1234", "severity": "High", "description": "x. y",
                                          "fix": {"versions": ["1.2"], "state": "fixed"}, "urls": ["https://a"],
                                          "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                                    "metrics": {"baseScore": 9.8}}]},
                        "relatedVulnerabilities": [{"id": "DLA-1"}],
                        "artifact": {"name": "openssl", "version": "1.1", "type": "deb", "purl": "pkg:deb/debian/openssl@1.1"}}]}
    r = grype_records(doc)[0]
    assert r["cvss"].score == 9.8 and r["fixed_versions"] == ["1.2"] and r["aliases"] == ["DLA-1"]


def test_decision_validation():
    from guardian.stage4_vulns.review import ReviewError, validate_decision
    with pytest.raises(ReviewError):
        validate_decision(ReviewDecision(action="override", new_risk="low"))
    validate_decision(ReviewDecision(action="confirm"))
