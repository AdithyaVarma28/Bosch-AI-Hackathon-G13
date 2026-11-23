"""HTTP API for the UI. Runs execute in a background thread; events are polled or streamed (SSE)."""
from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel

from .context import Settings
from .ingest import InvalidRepoUrl, parse_repo_url


class RunRequest(BaseModel):
    repo_url: str
    offline: bool = False
    use_llm: bool = True


def create_app(out_dir: Path = Path("output")) -> FastAPI:
    app = FastAPI(title="Guardian API", version="0.1.0")
    runs: dict[str, dict] = {}

    def _run(run_id: str, req: RunRequest) -> None:
        from .orchestrator import run_pipeline
        st = runs[run_id]
        try:
            res = run_pipeline(req.repo_url, out_dir, Settings(offline=req.offline, use_llm=req.use_llm),
                               emit=lambda e: st["events"].append(e), run_id=run_id)
            st.update(status="done", run_dir=str(res.run_dir), report=str(res.report_path) if res.report_path else None,
                      node_status=res.node_status)
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
