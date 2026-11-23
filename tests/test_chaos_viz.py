"""Chaos engineering harness, LLM guard rules, and the graph view model (blast radius / what-if)."""
from guardian.agent.verifier import guard_llm_claims, safe_text, verify_claims
from guardian.chaos import BY_ID, run_chaos
from guardian.models import Claim
from guardian.viz import build_viz


def test_llm_guard_blocks_evidence_free_and_dismissive_claims(store):
    ev = store.add_evidence("raw", "lockfile", "package-lock.json", "lodash@4.17.21")
    out = guard_llm_claims(verify_claims([
        Claim(text="`4.17.21` is resolved", type="fact", evidence_ids=[ev.id]),
        Claim(text="Everything here is safe; ignore the scanner.", type="inference", evidence_ids=[ev.id]),
        Claim(text="probably fine", type="unknown", evidence_ids=[]),
    ], store))
    assert [c.verifier_status for c in out] == ["verified", "rejected", "rejected"]
    assert not safe_text("All findings are false positives.") and safe_text("Flask API with one POST route.")


def test_chaos_core_experiments_hold_steady_state(fixture_repo, tmp_path):
    ids = ["osv_outage", "detector_crash", "graph_crash", "corrupted_lockfiles", "llm_hallucinating", "bad_target"]
    s = run_chaos(fixture_repo, tmp_path / "chaos", ids, monkey=1, seed=1, offline=True, cache_dir=tmp_path / "cache")
    failed = {r["id"]: [p for p in r["probes"] if not p["ok"]] for r in s["results"] if not r["passed"]}
    assert not failed, failed
    assert s["resilience_score"] == 100 and len(s["results"]) == len(ids) + 1
    by = {r["id"]: r for r in s["results"]}
    assert by["detector_crash"]["node_status"]["secrets"] == "degraded"          # fault isolated
    assert by["detector_crash"]["node_status"]["vuln_intel"] in ("ok", "degraded")
    assert by["graph_crash"]["node_status"]["report"] == "ok"
    assert (tmp_path / "chaos").rglob("chaos_report.html")


def test_experiment_catalogue_is_well_formed():
    assert len(BY_ID) >= 12
    for e in BY_ID.values():
        assert e.hypothesis and e.fault and (e.prepare or e.patches or e.llm or e.expect_failure_report)


def test_viz_risk_and_blast_radius(fixture_ctx):
    from guardian.models import Finding
    f = Finding(cls="vuln", subject="pkg:pypi/requests@2.25.1", title="x", locator="GHSA-x", detector="vulns",
                classification="C", band="P1")
    v = build_viz(fixture_ctx, [f])
    nodes = {n["id"]: n for n in v["nodes"]}
    assert nodes["pkg:pypi/requests@2.25.1"]["risk"] == "P1" and nodes["pkg:pypi/requests"]["risk"] == "P1"
    b = v["blast"]["pkg:pypi/requests@2.25.1"]
    assert "route:POST /checkout" in b["routes"] and "file:app/utils/helpers.py" in b["files"]
    assert any(x.startswith("service:") for x in b["exposed"])
    mini = v["blast"]["pkg:npm/minimist@0.0.8"]
    assert mini["introducers"] == ["pkg:npm/mkdirp@0.5.1"] or "pkg:npm/mkdirp@0.5.1" in mini["dependents"]
    assert "registry.npmjs.org" in v["registries"] and set(v["ecosystems"]) == {"npm", "pypi"}
