"""Stage 6 API on stored demo snapshots (built offline by `guardian demo`)."""
import json
import shutil

import pytest
from typer.testing import CliRunner

from guardian.cli import app


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    if not shutil.which("git"):
        pytest.skip("git is needed")
    base = tmp_path_factory.mktemp("stage6")
    res = CliRunner().invoke(app, ["demo", "--root", str(base / "scans"), "--workdir", str(base / "fx")])
    assert res.exit_code == 0, res.output
    from fastapi.testclient import TestClient
    from guardian.webapp import create_web_app
    return TestClient(create_web_app(base / "scans"))


def test_scans_and_overview(client):
    ids = {s["scan_id"] for s in client.get("/api/scans").json()}
    assert {"demo-minishop-head", "demo-minishop-baseline"} <= ids
    o = client.get("/api/scans/demo-minishop-head/overview").json()
    assert o["whats_in_it"]["modules"] and o["what_looks_risky"]["by_risk"]["critical"] >= 1


def test_unified_findings_and_detail(client):
    rows = client.get("/api/scans/demo-minishop-head/findings").json()
    assert {r["type"] for r in rows} == {"vulnerability", "anomaly"}
    f = client.get(f"/api/scans/demo-minishop-head/findings/{rows[0]['finding_id']}").json()
    assert f["card"] and f["trace"]
    pyyaml = next(r for r in rows if (r["component_name"] or "").lower() == "pyyaml")
    assert pyyaml["review_status"] == "confirmed"          # demo includes a recorded decision


def test_review_endpoint(client):
    pend = client.get("/api/scans/demo-minishop-head/review").json()
    assert pend
    fid = pend[0]["finding_id"]
    bad = client.post(f"/api/scans/demo-minishop-head/review/{fid}", json={"action": "dismiss"})
    assert bad.status_code == 422
    ok = client.post(f"/api/scans/demo-minishop-head/review/{fid}", json={"action": "dismiss", "reason": "accepted_risk", "by": "t"})
    assert ok.status_code == 200 and ok.json()["review"]["status"] == "dismissed"


def test_graph_entity_compare_and_exports(client):
    g = client.get("/api/scans/demo-minishop-head/graph").json()
    assert any(n["type"] == "Module" for n in g["nodes"])
    e = client.get("/api/scans/demo-minishop-head/entity/pkg:pypi/pyyaml@5.3.1").json()
    assert e["entity"]["type"] == "Package" and e["findings"]
    c = client.get("/api/compare", params={"from": "demo-minishop-baseline", "to": "demo-minishop-head"}).json()
    labels = [i["label"] for i in c["items"]]
    assert any("colorama" in l for l in labels) and any("reqeusts" in l for l in labels)
    sarif = client.get("/api/scans/demo-minishop-head/report", params={"format": "sarif"}).json()
    assert sarif["runs"][0]["results"]
    assert client.get("/api/scans/demo-minishop-head/search", params={"q": "yaml"}).json()
    assert client.get("/api/scans/demo-minishop-head/files/app/config/load.py").json()["markers"]
    assert client.get("/api/scans/demo-minishop-head/supply-chain").json()["workflows"]
    assert client.get("/api/scans/nope/overview").status_code == 404


def test_start_scan_validates_path(client):
    assert client.post("/api/scans", json={"path": "Z:/does/not/exist"}).status_code == 422
