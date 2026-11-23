"""End-to-end LangGraph pipeline on the fixture (offline, no Docker, no LLM) + API contract."""
import json

from fastapi.testclient import TestClient

from guardian.api import create_app
from guardian.context import Settings
from guardian.orchestrator import run_pipeline
from guardian.report import verify_integrity


def test_full_pipeline_offline(fixture_repo, tmp_path):
    res = run_pipeline(str(fixture_repo), tmp_path / "out",
                       Settings(offline=True, use_llm=False, use_docker=False, cache_dir=tmp_path / "cache"))
    assert res.report_path and res.report_path.exists()
    expected_nodes = {"ingest", "cartographer", "resolver_sbom", "code_index", "graph", "dossier_agent", "supervisor",
                      "vuln_intel", "change_anomaly", "package_signals", "container_ci", "secrets", "discrepancies",
                      "correlator", "evidence_agent", "report"}
    assert expected_nodes <= set(res.node_status)
    assert "failed" not in res.node_status.values()
    rep = json.loads(res.report_path.read_text(encoding="utf-8"))
    assert rep["schema_version"] == "1.0" and {"remediation", "validation", "vex"} <= set(rep)
    for name in ("facts.json", "sbom.cdx.json", "code_index.json", "graph.json", "report.html"):
        assert (res.run_dir / name).exists()
    sbom = json.loads((res.run_dir / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    signals = {f["signals"].get("signal") or f["signals"].get("rule") for f in rep["findings"]}
    planted = {"integrity_changed_same_version", "resolved_host_changed", "non_registry_source", "install_script",
               "new_dependency", "large_version_jump", "declared_not_imported", "DF001", "DF003", "DF004", "DC001",
               "CI001", "CI002", "CI003", "CI004", "SEC001"}
    assert planted <= signals, planted - signals
    # offline OSV -> degraded node + coverage entry, never a crash
    assert res.node_status["vuln_intel"] == "degraded" and "vuln_intel" in rep["coverage"]["degraded"]
    # every cited evidence id is embedded/resolvable
    for f in rep["findings"]:
        for c in (f["explanation"] or {}).get("claims", []):
            assert all(e in rep["evidence"] for e in c["evidence_ids"])
    assert verify_integrity(rep, res.run_dir)
    (res.run_dir / "sbom.cdx.json").write_text("{}")
    assert not verify_integrity(rep, res.run_dir)


def test_ingest_failure_gives_failure_report(tmp_path):
    res = run_pipeline("https://gitlab.com/o/r", tmp_path / "out", Settings(offline=True, use_llm=False))
    assert res.node_status["ingest"] == "failed"
    assert json.loads(res.report_path.read_text())["status"] == "failed"


def test_api_rejects_bad_url(tmp_path):
    client = TestClient(create_app(tmp_path))
    assert client.post("/runs", json={"repo_url": "https://example.com/x"}).status_code == 422
    assert client.get("/runs/nope/report").status_code == 404
