import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from guardian.api import create_app, resolve_use_llm


def _disk_run(out: Path, repo: str, run_id: str, generated_at: str, commit="abc1234", viz=None):
    d = out / repo / run_id
    d.mkdir(parents=True)
    (d / "report.json").write_text(json.dumps(
        {"run_id": run_id, "generated_at": generated_at, "summary": {}, "repo": {"name": repo, "url": f"https://github.com/o/{repo}", "commit": commit}}))
    if viz is not None:
        (d / "viz.json").write_text(json.dumps(viz))
    return d


def test_list_runs_reads_finished_runs_from_disk_newest_first(tmp_path):
    _disk_run(tmp_path, "mini-shop", "20261123-100000-a", "2026-11-23T10:00:00Z")
    _disk_run(tmp_path, "mini-shop", "20261123-120000-b", "2026-11-23T12:00:00Z")
    ids = [r["run_id"] for r in TestClient(create_app(tmp_path)).get("/runs").json()]
    assert ids == ["20261123-120000-b", "20261123-100000-a"]


def test_disk_run_summary_has_repo_commit_and_done_status(tmp_path):
    _disk_run(tmp_path, "mini-shop", "r1", "2026-11-23T10:00:00Z")
    r = TestClient(create_app(tmp_path)).get("/runs").json()[0]
    assert (r["repo_name"], r["commit"], r["status"]) == ("mini-shop", "abc1234", "done")


def _fake_pipeline(monkeypatch, fn):
    import guardian.orchestrator as orch
    monkeypatch.setattr(orch, "run_pipeline", fn)


def test_list_runs_includes_a_failed_in_memory_run_with_its_error(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")
    _fake_pipeline(monkeypatch, boom)
    client = TestClient(create_app(tmp_path))
    rid = client.post("/runs", json={"repo_url": str(tmp_path)}).json()["run_id"]
    import time
    for _ in range(50):
        if client.get(f"/runs/{rid}").json()["status"] != "running":
            break
        time.sleep(0.05)
    got = [(r["status"], r["error"]) for r in client.get("/runs").json() if r["run_id"] == rid]
    assert got == [("failed", "RuntimeError: boom")]


def test_list_runs_includes_a_running_run(tmp_path, monkeypatch):
    import threading
    gate = threading.Event()
    _fake_pipeline(monkeypatch, lambda *a, **k: gate.wait(5))
    client = TestClient(create_app(tmp_path))
    rid = client.post("/runs", json={"repo_url": str(tmp_path)}).json()["run_id"]
    try:
        assert client.get("/runs").json()[0]["status"] == "running"
        assert client.get(f"/runs/{rid}").json()["run_id"] == rid
    finally:
        gate.set()


def test_get_run_returns_summary_for_disk_runs(tmp_path):
    _disk_run(tmp_path, "mini-shop", "r1", "2026-11-23T10:00:00Z")
    body = TestClient(create_app(tmp_path)).get("/runs/r1").json()
    assert body["status"] == "done" and body["repo_name"] == "mini-shop"


def test_get_run_unknown_is_404(tmp_path):
    assert TestClient(create_app(tmp_path)).get("/runs/nope").status_code == 404


def test_viz_endpoint_serves_viz_json_or_404(tmp_path):
    _disk_run(tmp_path, "a", "r1", "2026-11-23T10:00:00Z", viz={"nodes": []})
    _disk_run(tmp_path, "b", "r2", "2026-11-23T11:00:00Z")
    c = TestClient(create_app(tmp_path))
    assert c.get("/runs/r1/viz").json() == {"nodes": []}
    assert c.get("/runs/r2/viz").status_code == 404


def test_use_llm_defaults_to_whether_a_groq_key_exists(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert resolve_use_llm(None) is False
    monkeypatch.setenv("GROQ_API_KEY", "k")
    assert resolve_use_llm(None) is True and resolve_use_llm(False) is False


def test_cors_allows_the_vite_dev_origin(tmp_path):
    r = TestClient(create_app(tmp_path)).options(
        "/runs", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_a_corrupt_report_json_does_not_break_the_list(tmp_path):
    _disk_run(tmp_path, "a", "r1", "2026-11-23T10:00:00Z")
    bad = tmp_path / "b" / "r2"
    bad.mkdir(parents=True)
    (bad / "report.json").write_text("{")
    assert len(TestClient(create_app(tmp_path)).get("/runs").json()) == 1


# --- Task 2: static site -------------------------------------------------
def _web(tmp_path):
    web = tmp_path / "dist"
    web.mkdir()
    (web / "index.html").write_text("<html>app</html>")
    return web


def test_root_serves_index_html_when_a_build_exists(tmp_path):
    assert "app" in TestClient(create_app(tmp_path / "out", _web(tmp_path))).get("/").text


def test_client_side_routes_fall_back_to_index_html(tmp_path):
    assert "app" in TestClient(create_app(tmp_path / "out", _web(tmp_path))).get("/vulnerabilities").text


def test_api_routes_still_win_over_the_site(tmp_path):
    assert TestClient(create_app(tmp_path / "out", _web(tmp_path))).get("/runs").json() == []


def test_no_web_dir_leaves_the_api_unchanged(tmp_path):
    assert TestClient(create_app(tmp_path / "out")).get("/").status_code == 404


def test_static_assets_are_served(tmp_path):
    web = _web(tmp_path)
    (web / "assets").mkdir()
    (web / "assets" / "a.js").write_text("x")
    assert TestClient(create_app(tmp_path / "out", web)).get("/assets/a.js").text == "x"


def test_unknown_run_path_is_not_swallowed_by_the_site(tmp_path):
    assert TestClient(create_app(tmp_path / "out", _web(tmp_path))).get("/runs/nope/report").status_code == 404


# --- review fixes -----------------------------------------------------------
def test_a_failed_clone_stub_is_a_failed_run_not_a_done_one(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import time

    def stub(target, out_dir, settings, emit=None, run_id=None):
        d = out_dir / "_failed" / run_id
        d.mkdir(parents=True)
        (d / "report.json").write_text(json.dumps({"schema_version": "1.0", "status": "failed", "errors": ["clone failed"]}))
        return SimpleNamespace(run_dir=d, report_path=d / "report.json", node_status={"ingest": "failed"})
    _fake_pipeline(monkeypatch, stub)
    client = TestClient(create_app(tmp_path))
    rid = client.post("/runs", json={"repo_url": str(tmp_path)}).json()["run_id"]
    for _ in range(50):
        if client.get(f"/runs/{rid}").json()["status"] != "running":
            break
        time.sleep(0.05)
    body = client.get(f"/runs/{rid}").json()
    assert body["status"] == "failed" and body["error"]


def test_failed_stubs_and_non_report_json_are_not_listed_as_runs(tmp_path):
    stub = tmp_path / "_failed" / "r9"
    stub.mkdir(parents=True)
    (stub / "report.json").write_text(json.dumps({"schema_version": "1.0", "status": "failed"}))
    clone = tmp_path / "clones" / "owner__repo"
    clone.mkdir(parents=True)
    (clone / "report.json").write_text(json.dumps({"hello": "world"}))
    _disk_run(tmp_path, "real", "r1", "2026-11-23T10:00:00Z")
    ids = [r["run_id"] for r in TestClient(create_app(tmp_path)).get("/runs").json()]
    assert ids == ["r1"]


def test_missing_static_file_is_404_but_client_routes_still_work(tmp_path):
    c = TestClient(create_app(tmp_path / "out", _web(tmp_path)))
    assert c.get("/favicon.ico").status_code == 404
    assert c.get("/missing.js").status_code == 404
    assert "app" in c.get("/runsx").text          # only /runs and /runs/... belong to the API
    assert "app" in c.get("/vulnerabilities").text
