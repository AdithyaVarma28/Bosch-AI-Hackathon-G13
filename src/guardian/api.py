"""HTTP API for the UI. Runs execute in a background thread; events are polled or streamed (SSE)."""
from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .context import Settings
from .ingest import InvalidRepoUrl, parse_repo_url


# Run ids look like 20261124-064853-6143a3. Letters, digits, "_" and "-" only: no glob characters, no dots, no slashes.
_RUN_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


class RunRequest(BaseModel):
    repo_url: str
    offline: bool = False
    use_llm: bool | None = None


def resolve_use_llm(value: bool | None) -> bool:
    """None means: use the LLM only when a Groq key is configured."""
    return bool(os.environ.get("GROQ_API_KEY")) if value is None else value


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def create_app(out_dir: Path = Path("output"), web_dir: Path | None = None) -> FastAPI:
    app = FastAPI(title="Guardian API", version="0.1.0")
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                       allow_methods=["*"], allow_headers=["*"])
    runs: dict[str, dict] = {}

    def _run(run_id: str, req: RunRequest) -> None:
        from .orchestrator import run_pipeline
        st = runs[run_id]
        try:
            res = run_pipeline(req.repo_url, out_dir, Settings(offline=req.offline, use_llm=resolve_use_llm(req.use_llm)),
                               emit=lambda e: st["events"].append(e), run_id=run_id)
            ok = False
            if res.report_path:
                try:
                    ok = isinstance(json.loads(Path(res.report_path).read_text(encoding="utf-8")).get("summary"), dict)
                except (OSError, ValueError, AttributeError):
                    ok = False
            if not ok:  # e.g. the clone failed: the pipeline only wrote a stub report
                bad = [n for n, v in (res.node_status or {}).items() if v == "failed"]
                st.update(finished_at=_iso(time.time()), status="failed",
                          error=f"Scan did not produce a report ({', '.join(bad) or 'unknown step'} failed)")
                return
            st.update(finished_at=_iso(time.time()), status="done", run_dir=str(res.run_dir), report=str(res.report_path),
                      node_status=res.node_status)
        except Exception as e:  # never crash the server
            st.update(status="failed", finished_at=_iso(time.time()), error=f"{type(e).__name__}: {e}")

    def _dir(run_id: str) -> Path:
        st = runs.get(run_id)
        if st and st.get("run_dir"):
            return Path(st["run_dir"])
        if not _RUN_ID.fullmatch(run_id):  # never let a URL segment act as a glob pattern ("*", "[a-z]*", "..")
            raise HTTPException(404, "run not found or not finished")
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
        runs[run_id] = {"status": "running", "events": [], "target": req.repo_url, "started_at": _iso(time.time())}
        threading.Thread(target=_run, args=(run_id, req), daemon=True).start()
        return {"run_id": run_id}

    def _disk_summary(report_path: Path) -> dict | None:
        try:
            rep = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(rep.get("summary"), dict):
                return None  # not a finished Guardian report (failure stub, or an unrelated report.json)
            repo = rep.get("repo") or {}
            return {"run_id": rep.get("run_id") or report_path.parent.name, "repo_name": repo.get("name") or report_path.parent.parent.name,
                    "target": repo.get("url") or "", "status": "done", "commit": repo.get("commit"),
                    "finished_at": rep.get("generated_at"), "error": None}
        except (OSError, ValueError, AttributeError):
            return None

    def _mem_summary(run_id: str, st: dict) -> dict:
        disk = None
        if st.get("report"):
            disk = _disk_summary(Path(st["report"]))
        target = st.get("target", "")
        return {"run_id": run_id, "repo_name": (disk or {}).get("repo_name") or target.rstrip("/\\").split("/")[-1].split("\\")[-1] or run_id,
                "target": target, "status": st["status"], "commit": (disk or {}).get("commit"),
                "finished_at": st.get("finished_at") or st.get("started_at"), "error": st.get("error")}

    @app.get("/runs")
    def list_runs():
        found: dict[str, dict] = {}
        for rp in out_dir.glob("*/*/report.json"):
            d = _disk_summary(rp)
            if d:
                found[d["run_id"]] = d
        for rid, st in runs.items():
            found[rid] = _mem_summary(rid, st)
        return sorted(found.values(), key=lambda r: r["finished_at"] or "", reverse=True)

    @app.get("/runs/{run_id}")
    def get_run(run_id: str):
        if run_id in runs:
            return _mem_summary(run_id, runs[run_id]) | {"events": len(runs[run_id]["events"])}
        d = _disk_summary(_dir(run_id) / "report.json")
        if not d:
            raise HTTPException(404, "run not found or not finished")
        return d

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

    @app.get("/runs/{run_id}/viz")
    def viz(run_id: str):
        return _json(run_id, "viz.json")

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

    if web_dir and (web_dir / "index.html").exists():
        if (web_dir / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=web_dir / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def site(path: str):
            if path == "runs" or path.startswith("runs/"):
                raise HTTPException(404, "not found")
            f = (web_dir / path).resolve()
            if path and f.is_file() and web_dir.resolve() in f.parents:
                return FileResponse(f)
            if Path(path).suffix:  # a missing asset (favicon.ico, x.js) is a 404, not the app page
                raise HTTPException(404, "not found")
            return FileResponse(web_dir / "index.html")

    return app
