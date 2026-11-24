"""HTTP API for the UI. Runs execute in a background thread; events are polled or streamed (SSE)."""
from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel

from .context import Settings
from .ingest import InvalidRepoUrl, parse_repo_url


class RunRequest(BaseModel):
    repo_url: str
    offline: bool = False
    use_llm: bool = True
    remediate: bool = True             # one pipeline: detection -> Day 2 up to the approval gate
    sandbox: str = "docker"
    fixture_snapshots: bool = False


class RemediateRequest(BaseModel):
    sandbox: str = "docker"
    offline: bool = False
    use_llm: bool = True
    only: list[str] = []
    replan: bool = False
    max_queue: int = 5
    fixture_snapshots: bool = False


class DecisionRequest(BaseModel):
    plan: str
    decision: Literal["approve", "reject", "accept_risk"]
    reviewer: str
    plan_hash: str
    reason: str = ""
    candidate: list[str] = []
    expires: str | None = None


class PatchRequest(BaseModel):
    plan: str
    reviewer: str
    reason: str = ""


def _fixture(name: str) -> Path:
    from importlib import resources
    return Path(str(resources.files("guardian.data").joinpath(name)))


def create_app(out_dir: Path = Path("output")) -> FastAPI:
    app = FastAPI(title="Guardian API", version="0.1.0")
    runs: dict[str, dict] = {}

    def _run(run_id: str, req: RunRequest) -> None:
        from .orchestrator import run_pipeline
        st = runs[run_id]
        try:
            s = Settings(offline=req.offline, use_llm=req.use_llm, remediate=req.remediate, sandbox=req.sandbox,
                         advisory_db=_fixture("fixture_advisories.json") if req.fixture_snapshots else None,
                         registry_snapshot=_fixture("fixture_registry.json") if req.fixture_snapshots else None)
            res = run_pipeline(req.repo_url, out_dir, s, emit=lambda e: st["events"].append(e), run_id=run_id)
            st.update(status="done", run_dir=str(res.run_dir), report=str(res.report_path) if res.report_path else None,
                      node_status=res.node_status, day2=res.day2.status if res.day2 else None)
        except Exception as e:  # never crash the server
            st.update(status="failed", error=f"{type(e).__name__}: {e}")

    def _dir(run_id: str) -> Path:
        st = runs.get(run_id)
        if st and st.get("run_dir"):
            return Path(st["run_dir"])
        hits = list(out_dir.glob(f"*/{run_id}/report.json"))
        if hits:
            return hits[0].parent
        raise HTTPException(404, "run not found or not finished")

    @app.post("/runs", status_code=202)
    def create_run(req: RunRequest):
        if not Path(req.repo_url).exists():
            try:
                parse_repo_url(req.repo_url)
            except InvalidRepoUrl as e:
                raise HTTPException(422, str(e))
        run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        runs[run_id] = {"status": "running", "events": [], "target": req.repo_url}
        threading.Thread(target=_run, args=(run_id, req), daemon=True).start()
        return {"run_id": run_id}

    @app.get("/runs/{run_id}")
    def get_run(run_id: str):
        if run_id not in runs:
            _dir(run_id)
            return {"status": "done"}
        return {k: v for k, v in runs[run_id].items() if k != "events"} | {"events": len(runs[run_id]["events"])}

    @app.get("/runs/{run_id}/events")
    async def events(run_id: str):
        if run_id not in runs:
            raise HTTPException(404, "unknown run")

        async def gen():
            i = 0
            while True:
                evs = runs[run_id]["events"]
                while i < len(evs):
                    yield f"data: {json.dumps(evs[i])}\n\n"
                    i += 1
                if runs[run_id]["status"] != "running":
                    yield f"data: {json.dumps({'node': 'run', 'status': runs[run_id]['status']})}\n\n"
                    return
                await asyncio.sleep(0.5)
        return StreamingResponse(gen(), media_type="text/event-stream")

    def _json(run_id: str, name: str):
        p = _dir(run_id) / name
        if not p.exists():
            raise HTTPException(404, f"{name} not available")
        return json.loads(p.read_text(encoding="utf-8"))

    @app.get("/runs/{run_id}/report")
    def report(run_id: str):
        return _json(run_id, "report.json")

    @app.get("/runs/{run_id}/report.html", response_class=HTMLResponse)
    def report_html(run_id: str):
        return FileResponse(_dir(run_id) / "report.html")

    @app.get("/runs/{run_id}/graph")
    def graph(run_id: str):
        return _json(run_id, "graph.json")

    @app.get("/runs/{run_id}/sbom")
    def sbom(run_id: str):
        return _json(run_id, "sbom.cdx.json")

    @app.get("/runs/{run_id}/facts")
    def facts(run_id: str):
        return _json(run_id, "facts.json")

    @app.get("/runs/{run_id}/code-index")
    def code_index(run_id: str):
        return _json(run_id, "code_index.json")

    # ------------------------------------------------------------------- Day 2
    def _d2(run_id: str, req: "RemediateRequest") -> None:
        from .day2.pipeline import run_day2
        st = runs.setdefault(run_id, {"status": "done", "events": []})
        st["day2"] = "running"
        try:
            s = Settings(offline=req.offline, use_llm=req.use_llm, sandbox=req.sandbox, max_queue=req.max_queue,
                         advisory_db=_fixture("fixture_advisories.json") if req.fixture_snapshots else None,
                         registry_snapshot=_fixture("fixture_registry.json") if req.fixture_snapshots else None)
            res = run_day2(_dir(run_id), s, only=req.only or None, replan=req.replan,
                           emit=lambda e: st["events"].append({**e, "phase": "day2"}))
            st["day2"] = res.status
        except Exception as e:
            st["day2"] = f"failed: {type(e).__name__}: {e}"

    @app.post("/runs/{run_id}/remediate", status_code=202)
    def remediate(run_id: str, req: RemediateRequest):
        _dir(run_id)
        if (runs.get(run_id) or {}).get("day2") == "running":
            raise HTTPException(409, "Day 2 already running for this run")
        threading.Thread(target=_d2, args=(run_id, req), daemon=True).start()
        return {"run_id": run_id, "day2": "running"}

    @app.get("/runs/{run_id}/remediation")
    def remediation(run_id: str):
        return _json(run_id, "day2/report.json")

    @app.get("/runs/{run_id}/day2/remediation.html", response_class=HTMLResponse)   # iframe path inside report.html
    @app.get("/runs/{run_id}/remediation.html", response_class=HTMLResponse)
    def remediation_html(run_id: str):
        p = _dir(run_id) / "day2" / "remediation.html"
        if not p.exists():
            raise HTTPException(404, "Day 2 report not available")
        return FileResponse(p)

    @app.get("/runs/{run_id}/plans")
    def list_plans(run_id: str):
        from .day2.decisions import open_d2
        st, d2 = open_d2(_dir(run_id))
        try:
            return [p.model_dump(exclude={"candidates": {"__all__": {"diff"}}}) for p in d2.plans()]
        finally:
            st.close()

    @app.post("/runs/{run_id}/decisions")
    def decision(run_id: str, req: DecisionRequest):
        from .day2.decisions import PlanNotFound, record
        try:
            p = record(_dir(run_id), req.plan, req.decision, req.reviewer, req.plan_hash, req.reason, req.candidate or None, req.expires)
        except PlanNotFound as e:
            raise HTTPException(404, str(e))
        except (ValueError, PermissionError) as e:
            raise HTTPException(409, str(e))
        return {"plan_key": p.plan_key, "revision": p.revision, "plan_hash": p.plan_hash, "status": p.status}

    @app.post("/runs/{run_id}/patches")
    def patch(run_id: str, req: PatchRequest):
        from .day2.decisions import PlanNotFound, export_patch
        try:
            path = export_patch(_dir(run_id), req.plan, req.reviewer, req.reason)
        except PlanNotFound as e:
            raise HTTPException(404, str(e))
        except ValueError as e:
            raise HTTPException(409, str(e))
        return {"patch": path.read_text(encoding="utf-8")}

    @app.get("/runs/{run_id}/evidence/{evidence_id}")
    def evidence(run_id: str, evidence_id: str):
        from .store import RunStore
        st = RunStore(_dir(run_id), run_id)
        try:
            e = st.get_evidence(evidence_id)
        finally:
            st.close()
        if not e:
            raise HTTPException(404, "unknown evidence id")
        return e.model_dump()

    return app
