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
    max_queue: int = 5


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


class HealRequest(BaseModel):
    repo: str                                   # clone name under output/clones, path, or GitHub URL
    max_iterations: int = 3
    max_retries: int = 2
    bands: list[str] = ["P0", "P1"]
    max_remaining: int = 0
    count_signals: bool = False
    require_verified: bool = False
    sandbox: str = "docker"
    offline: bool = False
    use_llm: bool = True
    fixture_snapshots: bool = False
    skip_pending: bool = False                  # continue without deciding the plans waiting in this iteration
    reviewer: str | None = None                 # recorded in the journal for skip decisions
    force: bool = False                         # start even if a previous run left the state 'running'


class ChaosRequest(BaseModel):
    target: str                                 # local repository path
    monkey: int = 0                             # extra random multi-fault experiments
    seed: int | None = None
    only: list[str] = []
    online: bool = False


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
                         max_queue=req.max_queue, advisory_db=_fixture("fixture_advisories.json") if req.fixture_snapshots else None,
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

    # ------------------------------------------------------------------- UI (single page app)
    @app.get("/", response_class=HTMLResponse)
    @app.get("/app", response_class=HTMLResponse)
    def ui():
        from .ui_app import APP_HTML
        return HTMLResponse(APP_HTML)

    def _summary(rd: Path) -> dict:
        try:
            r = json.loads((rd / "report.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        rem = r.get("remediation") or {}
        return {"run_id": rd.name, "repo": (r.get("repo") or {}).get("name") or rd.parent.name,
                "target": (r.get("repo") or {}).get("url"), "commit": (r.get("repo") or {}).get("commit"),
                "generated_at": r.get("generated_at"), "status": r.get("status", "done"),
                "bands": (r.get("summary") or {}).get("bands", {}), "findings": (r.get("summary") or {}).get("findings"),
                "components": (r.get("summary") or {}).get("components"),
                "plan_status": rem.get("plan_status", {}), "verdicts": rem.get("verdicts", {}), "day2": bool(rem)}

    @app.get("/runs")
    def list_runs(limit: int = 100):
        out = []
        for rid, st in runs.items():
            if st.get("status") == "running":
                out.append({"run_id": rid, "repo": Path(st.get("target", "")).name or st.get("target"), "target": st.get("target"),
                            "status": "running", "generated_at": None})
        seen = {x["run_id"] for x in out}
        dirs = sorted((p.parent for p in out_dir.glob("*/*/report.json") if p.parent.parent.name not in ("heal", "_failed")),
                      key=lambda d: d.name, reverse=True)
        for d in dirs[:limit]:
            if d.name not in seen:
                x = _summary(d)
                if x:
                    if d.name in runs and runs[d.name].get("day2") == "running":
                        x["status"] = "day2 running"
                    out.append(x)
        return out

    @app.get("/clones")
    def list_clones():
        from .runner import ToolFailed, git
        out = []
        for d in sorted((out_dir / "clones").glob("*")):
            if not (d / ".git").exists():
                continue
            try:
                branch = git(d, "rev-parse", "--abbrev-ref", "HEAD").strip()
            except ToolFailed:
                branch = None
            hp = out_dir / "heal" / d.name / "heal_state.json"
            h = json.loads(hp.read_text(encoding="utf-8")) if hp.exists() else None
            out.append({"name": d.name, "path": str(d), "branch": branch,
                        "heal": None if not h else {"status": heals.get(d.name) or h.get("status"), "stop_reason": h.get("stop_reason"),
                                                    "iterations": len(h.get("iterations") or []),
                                                    "remaining": (h.get("iterations") or [{}])[-1].get("remaining"),
                                                    "fixes": sum(1 for f in h.get("fixes") or [] if f.get("status") == "applied")}})
        return out

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
        d = _dir(run_id)
        try:   # re-render with the current template so every run gets the current UI (graph, SBOM, remediation, embed)
            from .report import render_html
            rep = json.loads((d / "report.json").read_text(encoding="utf-8"))
            viz = json.loads((d / "viz.json").read_text(encoding="utf-8"))
            sbom = json.loads((d / "sbom.cdx.json").read_text(encoding="utf-8")) if (d / "sbom.cdx.json").exists() else None
            return HTMLResponse(render_html(rep, viz, sbom))
        except (OSError, ValueError):
            return FileResponse(d / "report.html")

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
        d = _dir(run_id) / "day2"
        if (d / "report.json").exists():
            from .day2.report import render_html as render_d2
            return HTMLResponse(render_d2(json.loads((d / "report.json").read_text(encoding="utf-8"))))
        if not (d / "remediation.html").exists():
            raise HTTPException(404, "Day 2 report not available")
        return FileResponse(d / "remediation.html")

    @app.get("/runs/{run_id}/plans")
    def list_plans(run_id: str):
        from .day2.decisions import open_d2
        st, d2 = open_d2(_dir(run_id))
        try:
            return [p.model_dump(exclude={"candidates": {"__all__": {"diff"}}}) for p in d2.plans()]
        finally:
            st.close()

    @app.get("/runs/{run_id}/approvals")
    def approvals_view(run_id: str):
        """Everything the approval screen needs, read live from run.db (plans with diffs, analyst answers, ledger)."""
        from .day2.decisions import open_d2
        st, d2 = open_d2(_dir(run_id))
        try:
            fmap = {f.id: {"title": f.title, "band": f.band, "cls": f.cls, "subject": f.subject} for f in st.list_findings()}
            return {"plans": [p.model_dump() for p in d2.plans()], "advisories": d2.get("advisories") or {},
                    "investigations": d2.get("investigations") or {}, "findings": fmap,
                    "reports": {k.split(":", 1)[1]: d2.get(k) for k in d2.keys("report:")},
                    "approvals": [a.model_dump() for a in d2.approvals()], "policy": (d2.get("policy") or {}).get("sha256")}
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

    # ------------------------------------------------------------------- heal agent (applies to output/clones/*)
    heals: dict[str, str] = {}
    heal_events: dict[str, list[dict]] = {}

    @app.post("/heal", status_code=202)
    def start_heal(req: HealRequest):
        from .day2.heal import HealConfig, HealError, heal, resolve_clone
        cfg = HealConfig(max_iterations=req.max_iterations, max_retries=req.max_retries, bands=tuple(req.bands),
                         max_remaining=req.max_remaining, count_signals=req.count_signals, out_dir=out_dir,
                         accept=("Verified",) if req.require_verified else ("Verified", "Partially verified"),
                         allowed_root=out_dir / "clones")
        try:
            name = resolve_clone(req.repo, cfg).name
        except HealError as e:
            raise HTTPException(422, str(e))
        if heals.get(name) == "running":
            raise HTTPException(409, "heal already running for this clone")
        sp = out_dir / "heal" / name / "heal_state.json"
        if sp.exists() and not req.force and json.loads(sp.read_text(encoding="utf-8")).get("status") == "running" and name not in heals:
            raise HTTPException(409, "the heal state says another process is running it (CLI?); pass force=true if it crashed")
        s = Settings(offline=req.offline, use_llm=req.use_llm, sandbox=req.sandbox,
                     advisory_db=_fixture("fixture_advisories.json") if req.fixture_snapshots else None,
                     registry_snapshot=_fixture("fixture_registry.json") if req.fixture_snapshots else None)

        def go():
            heals[name] = "running"
            heal_events[name] = []
            try:   # no in-process approver: the agent pauses at the human gate; approvals come from the UI
                heals[name] = heal(req.repo, s, cfg, reviewer=req.reviewer, skip_pending=req.skip_pending,
                                   emit=lambda e: heal_events[name].append({**e, "t": time.time()})).status
            except Exception as e:
                heals[name] = f"failed: {type(e).__name__}: {e}"
        threading.Thread(target=go, daemon=True).start()
        return {"repo": name, "status": "running"}

    @app.get("/heal/{repo}")
    def heal_state(repo: str):
        p = out_dir / "heal" / repo / "heal_state.json"
        if not p.exists():
            raise HTTPException(404, "no heal state for this clone")
        return {"process": heals.get(repo), **json.loads(p.read_text(encoding="utf-8"))}

    @app.get("/heal/{repo}/events")
    def heal_events_view(repo: str, since: int = 0):
        evs = heal_events.get(repo, [])
        return {"process": heals.get(repo), "events": evs[since:], "next": len(evs)}

    @app.get("/heal/{repo}/report.html", response_class=HTMLResponse)
    def heal_html(repo: str):
        from .day2.heal import HealState
        from .day2.heal_report import render_heal_html
        p = out_dir / "heal" / repo / "heal_state.json"
        if not p.exists():
            raise HTTPException(404, "no heal report")
        # rendered from the live state on every request, so the page is current while the agent runs
        return HTMLResponse(render_heal_html(HealState.model_validate_json(p.read_text(encoding="utf-8"))))

    # ------------------------------------------------------------------- chaos engineering
    chaos_jobs: dict[str, dict] = {}

    @app.get("/chaos")
    def chaos_list():
        out = [{"id": k, **v} for k, v in chaos_jobs.items() if v.get("status") == "running"]
        for p in sorted((out_dir / "chaos").glob("*/chaos_report.json"), reverse=True)[:50]:
            try:
                s = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            out.append({"id": p.parent.name, "status": "done", "target": s.get("target"), "generated_at": s.get("generated_at"),
                        "resilience_score": s.get("resilience_score"), "passed": s.get("passed"), "experiments": s.get("experiments")})
        return out

    @app.get("/chaos/experiments")
    def chaos_experiments():
        from .chaos import EXPERIMENTS
        return [{"id": e.id, "category": e.category, "name": e.name} for e in EXPERIMENTS]

    @app.post("/chaos", status_code=202)
    def chaos_run(req: ChaosRequest):
        if not Path(req.target).is_dir():
            raise HTTPException(422, "chaos experiments need a local repository path (they run on a throwaway copy)")
        job = time.strftime("%Y%m%d-%H%M%S")
        chaos_jobs[job] = {"status": "running", "target": req.target, "results": []}

        def go():
            from .chaos import run_chaos
            try:
                s = run_chaos(req.target, out_dir / "chaos", req.only or None, req.monkey, req.seed, offline=not req.online,
                              emit=lambda r: chaos_jobs[job]["results"].append(r))
                chaos_jobs[job].update(status="done", report=Path(s["path"]).parent.name, resilience_score=s.get("resilience_score"))
            except Exception as e:
                chaos_jobs[job].update(status=f"failed: {type(e).__name__}: {e}")
        threading.Thread(target=go, daemon=True).start()
        return {"job": job}

    @app.get("/chaos/jobs/{job}")
    def chaos_job(job: str):
        if job not in chaos_jobs:
            raise HTTPException(404, "unknown chaos job")
        return chaos_jobs[job]

    @app.get("/chaos/{cid}/report.html", response_class=HTMLResponse)
    def chaos_html(cid: str):
        p = out_dir / "chaos" / cid / "chaos_report.html"
        if not p.exists() or ".." in cid:
            raise HTTPException(404, "no chaos report")
        return FileResponse(p)

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
