"""Day 2 (docs/DAY_2_PLAN.md section 11): prioritization tables, remediation candidates, critic, the human-approval
workflow and sandbox validation, on the full mini-shop fixture. Offline, no LLM."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardian.cli import app
from guardian.day2 import skills as skillmod
from guardian.day2.common import get_rem, load_remediations, read_json
from guardian.day2.critic import fix_confidence
from guardian.day2.history import read_audit
from guardian.day2.patches import PatchError, apply_edits
from guardian.day2.prioritize import automatable_rule, technical_impact_rule
from guardian.day2.ssvc import CVE_TREE, cve_decision, priority, supply_decision
from guardian.day2.workflow import DecisionError, WorkflowManager, submit

ROOT = Path(__file__).resolve().parents[1]
DUMP = ROOT / "tests" / "data" / "osv_minishop.zip"


# ------------------------------------------------------------------ pure rules
def test_cve_tree_complete_and_monotonic():
    assert len(CVE_TREE) == 12
    order = ["Track", "Track*", "Attend", "Act"]
    for (ex, au, ti), row in CVE_TREE.items():
        assert [order.index(x) for x in row] == sorted(order.index(x) for x in row)   # more mission, never less urgent
    assert cve_decision("active", "yes", "total", "high") == "Act"
    assert cve_decision("none", "no", "partial", "high") == "Track"
    assert supply_decision("verified", "install_path") == "Act"
    assert supply_decision("low", "runtime_public") == "Track"


def test_rule_fallbacks_from_cvss_vector():
    e = {"cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "summary": ""}
    assert automatable_rule(e)[0] == "yes" and technical_impact_rule(e)[0] == "total"
    e = {"cvss": {"vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N"}, "summary": ""}
    assert automatable_rule(e)[0] == "no" and technical_impact_rule(e)[0] == "partial"


def test_priority_modifiers():
    p, _, _ = priority("Act", scope="dev", exposure_col=None, kev=False, sensitivity="low", inputs_by="rules", stage_risk=None)
    assert p == "low"                                          # dev-only is capped
    p, _, _ = priority("Track", scope="runtime", exposure_col=None, kev=True, sensitivity="low", inputs_by="rules", stage_risk=None)
    assert p == "high"                                         # KEV + runtime is at least high
    p, reasons, limited = priority("Track", scope="runtime", exposure_col=None, kev=False, sensitivity="low",
                                   inputs_by="ai", stage_risk="critical")
    assert p == "high" and limited and "human confirms" in reasons[-1]   # never silently drop 2+ bands


def test_skills_progressive_disclosure():
    sk = skillmod.discover()
    assert set(sk) == {"upgrade-dependency", "replace-unsafe-api", "remove-or-block-package", "harden-ci-cd"}
    assert "Patch rules" not in skillmod.index_text(sk)        # the index has descriptions only
    assert "Patch rules" in sk["upgrade-dependency"].body()
    assert sk["upgrade-dependency"].allows("requirements.txt") and not sk["upgrade-dependency"].allows("app/x.py")
    assert sk["harden-ci-cd"].allows(".github/workflows/ci.yml")


def test_patch_edits_must_match_exactly_once(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"x==1\ny==1\nx==1\n")
    with pytest.raises(PatchError):
        apply_edits(tmp_path, [{"path": "a.txt", "old_text": "x==1", "new_text": "x==2"}])
    with pytest.raises(PatchError):
        apply_edits(tmp_path, [{"path": "../evil.txt", "old_text": "", "new_text": "x"}])
    files = apply_edits(tmp_path, [{"path": "a.txt", "old_text": "y==1", "new_text": "y==2"}])
    assert files["a.txt"][1] == "x==1\ny==2\nx==1\n"


def test_fix_confidence_rules():
    base = {"edits": [{"path": "a"}], "kind": "upgrade", "checks": {"patch_applies": {"status": "pass"},
                                                                    "security_check": {"status": "pass"}}}
    assert fix_confidence({**base, "edits": []})[0] == "low"
    assert fix_confidence(base)[0] == "medium"                                       # not validated, no critic
    assert fix_confidence(base, {"status": "passed", "checks": {}})[0] == "high"
    bad = {**base, "checks": {**base["checks"], "ai_critic": {"status": "fail"}}}
    assert fix_confidence(bad)[0] == "low"


# ------------------------------------------------------------------ full fixture
@pytest.fixture(scope="module")
def scan(tmp_path_factory):
    if not shutil.which("git"):
        pytest.skip("git is needed")
    base = tmp_path_factory.mktemp("day2")
    r = subprocess.run([sys.executable, str(ROOT / "tests/fixtures/make_mini_shop_full.py"), str(base)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture failed: {r.stderr[-300:]}")
    os.environ["GUARDIAN_VULNDB"] = str(base / "vulndb")
    os.environ["GUARDIAN_PYPI_URL"] = str(base / "fake-pypi" / "pypi")
    try:
        res = CliRunner().invoke(app, ["scan", str(base / "mini-shop"), "--output", str(base / "output"), "--offline",
                                       "--skip-sbom", "--osv-dump", str(DUMP), "--llm", "offline"])
        assert res.exit_code == 0, res.output
        yield {"dir": base / "output" / "mini-shop", "repo": base / "mini-shop", "log": res.output}
    finally:
        os.environ.pop("GUARDIAN_PYPI_URL", None)


def test_register_merges_stages_and_keeps_nulls(scan):
    reg = read_json(scan["dir"] / "register.json")
    kinds = {e["kind"] for e in reg}
    assert kinds == {"vulnerability", "suspicious"}
    for e in reg:
        if e["kind"] == "suspicious":
            assert e["cvss"] is None and e["epss"] is None and e["kev"] is None
        assert e["priority"] in ("critical", "high", "medium", "low")
        assert e["decision"] in ("Act", "Attend", "Track*", "Track")
    assert [e["rank"] for e in reg] == list(range(1, len(reg) + 1))
    typo = next(e for e in reg if (e["component_name"] or "").startswith("reqeusts"))
    assert typo["decision"] == "Act" and typo["priority"] == "critical"
    pyyaml = next(e for e in reg if (e["component_name"] or "").startswith("PyYAML"))
    assert pyyaml["downgrade_limited"]           # rules say high, context says lower: a human confirms


def test_candidates(scan):
    rems = load_remediations(scan["dir"])
    by = {r["target_label"].split()[0]: r for r in rems}
    req = by["requests"] if by["requests"]["target_kind"] == "package" else next(
        r for r in rems if r["target_label"].startswith("requests") and r["target_kind"] == "package")
    up = [c for c in req["candidates"] if c["kind"] == "upgrade" and not c.get("excluded")]
    assert up and up[0]["target_version"] == "2.33.0"          # one upgrade covers all three requests CVEs
    assert len(req["finding_ids"]) == 3
    pyyaml = by["PyYAML"]
    assert {c["kind"] for c in pyyaml["candidates"]} >= {"upgrade", "replace_api"}
    typo = by["reqeusts"]
    assert typo["proposals"][0]["kind"] == "remove" and typo["tab"] == "decide"
    for r in rems:
        assert WorkflowManager.for_dir(scan["dir"]).paused_at(r) == "proposal_review"


def test_decisions_are_validated(scan):
    d = scan["dir"]
    rid = next(r["rid"] for r in load_remediations(d) if r["target_label"].startswith("reqeusts"))
    with pytest.raises(DecisionError):
        submit(d, rid, {"stage": "proposal", "action": "reject"}, background=False)          # reason required
    with pytest.raises(DecisionError):
        submit(d, rid, {"stage": "patch", "action": "approve"}, background=False)           # wrong stage
    with pytest.raises(DecisionError):
        submit(d, rid, {"stage": "proposal", "action": "revise"}, background=False)         # feedback required


def test_approve_validate_apply_end_to_end(scan):
    d, repo = scan["dir"], scan["repo"]
    rid = next(r["rid"] for r in load_remediations(d) if r["target_label"].startswith("reqeusts"))
    u = submit(d, rid, {"stage": "proposal", "action": "approve", "reviewer": "t"}, background=False)
    v = u["validation"]
    assert v["status"] == "passed", v
    assert v["checks"]["rescan_resolved"]["status"] == "pass"
    assert any("reqeusts" in x for x in v["rescan"]["sbom_diff"]["removed"])
    assert u["status"] == "awaiting_patch_review"
    assert u["proposals"][-1]["fix_confidence"] == "high"
    assert subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True).stdout == ""
    u = submit(d, rid, {"stage": "patch", "action": "approve", "reviewer": "t"}, background=False)
    assert u["status"] == "applied" and u["applied"]["branch"].startswith("guardian/fix-")
    branches = subprocess.run(["git", "-C", str(repo), "branch"], capture_output=True, text=True).stdout
    assert u["applied"]["branch"] in branches and "* main" in branches or "* master" in branches
    assert subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True).stdout == ""
    events = [e["event"] for e in read_audit(d, rid)]
    assert events[:1] == ["proposal_created"] and "validation_result" in events and events[-1] == "branch_applied"


def test_alternative_then_reject(scan):
    d = scan["dir"]
    u = next(r for r in load_remediations(d) if r["target_label"].startswith("PyYAML"))
    alt = next(c["cid"] for c in u["candidates"] if c["kind"] == "replace_api")
    u = submit(d, u["rid"], {"stage": "proposal", "action": "alternative", "alternative": alt, "reviewer": "t"}, background=False)
    p = u["proposals"][-1]
    assert p["version"] == 2 and "yaml.safe_load" in p["diff"] and p["checks"]["security_check"]["status"] == "pass"
    assert p["expected_risk"]["effect"] == "reduced"
    u = submit(d, u["rid"], {"stage": "proposal", "action": "reject", "reason": "will upgrade instead", "reviewer": "t"},
               background=False)
    assert u["status"] == "rejected" and u["tab"] == "decided"
    assert not (d / "vex.json").exists()               # rejecting a fix never claims "not affected"


def test_history_appends(scan):
    from guardian.day2.history import history_path
    from guardian.day2.prioritize import run_prioritize
    run_prioritize(scan["dir"], None, log=lambda m: None)
    hist = read_json(history_path(scan["dir"], "mini-shop"), {})
    assert hist and all(len(v) >= 1 for v in hist.values())
