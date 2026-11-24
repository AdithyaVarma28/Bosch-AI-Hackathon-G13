"""Immutable scan snapshots (docs/stage6.md section 3): ``<root>/<scan_id>/`` holds every Stage 1-5 file
for one scan and is never overwritten. A scan runs in a background thread; its progress events go to
``events.jsonl`` (replayable) and to live SSE subscribers."""
from __future__ import annotations

import json
import queue
import os
import re
import shutil
import subprocess
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

STAGES = [("1", "Facts"), ("2", "Code index"), ("3", "Knowledge graph"), ("4", "Vulnerabilities"), ("5", "Anomalies"),
          ("6", "Prioritize & remediate")]


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


GITHUB_URL = re.compile(r"^(?:(?:https?://)?(?:www\.)?github\.com/|git@github\.com:)([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)"
                        r"(?:\.git)?(?:/(?:tree|blob|pulls?|issues|commits?|releases|actions|wiki)(?:/[^\s]*)?)?/?"
                        r"(?:[?#][^\s]*)?$", re.IGNORECASE)
CLONE_DEPTH = 300      # enough history for the dependency time-travel without downloading everything
CLONE_TIMEOUT_S = 600


def parse_github_url(text: str) -> Optional[tuple[str, str]]:
    """(owner, repo) for a GitHub repository link, else None. Accepts https://github.com/owner/repo with or without
    the scheme, ``www.``, ``.git``, a trailing ``/tree/<branch>/...`` or ``?query``, and git@github.com:owner/repo.
    Owner and repo stay restricted to [A-Za-z0-9_.-]: the clone URL is rebuilt from them, never passed through."""
    m = GITHUB_URL.match((text or "").strip().strip("<>\"'"))
    if not m or m.group(1).startswith((".", "-")) or m.group(2) in (".", "..") or m.group(2).startswith("-"):
        return None
    return m.group(1), m.group(2)


def _read(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


class NotPythonRepo(RuntimeError):
    """The cloned repository is not a Python project, so the scan stops before Stage 1."""


class ScanStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.subscribers: dict[str, list[queue.Queue]] = {}
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ listing
    def dir(self, scan_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", scan_id or ""):
            raise KeyError(scan_id)
        d = self.root / scan_id
        if not d.is_dir():
            raise KeyError(scan_id)
        return d

    def meta(self, scan_id: str) -> dict:
        d = self.dir(scan_id)
        m = _read(d / "scan.json", {}) or {}
        if not m:  # a plain output folder (guardian scan --out): describe it from its files
            facts = _read(d / "facts.json", {}) or {}
            repo = facts.get("repo") or {}
            m = {"scan_id": scan_id, "repo": repo.get("name") or scan_id, "commit": repo.get("commit"),
                 "created_at": repo.get("scanned_at"), "status": "done" if (d / "graph.json").exists() else "unknown"}
        m["scan_id"] = scan_id
        vf, af = _read(d / "vuln_findings.json", []) or [], _read(d / "anomaly_findings.json", []) or []
        cards = vf + af
        m["findings"] = {r: sum(1 for c in cards if c.get("project_risk") == r) for r in ("critical", "high", "medium", "low")}
        m["pending_reviews"] = sum(1 for c in cards if (c.get("review") or {}).get("status") == "pending")
        return m

    def list(self) -> list[dict]:
        out = []
        for d in sorted(self.root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if d.is_dir() and ((d / "scan.json").exists() or (d / "graph.json").exists()):
                try:
                    out.append(self.meta(d.name))
                except KeyError:
                    continue
        return out

    # ------------------------------------------------------------------ events
    def emit(self, scan_id: str, event: dict) -> None:
        event = {"at": now(), **event}
        try:
            d = self.root / scan_id
            with self.lock:
                with open(d / "events.jsonl", "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, default=str) + "\n")
        except OSError:
            pass
        for q in list(self.subscribers.get(scan_id, [])):
            q.put(event)

    def events(self, scan_id: str) -> list[dict]:
        p = self.dir(scan_id) / "events.jsonl"
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

    def subscribe(self, scan_id: str) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        self.subscribers.setdefault(scan_id, []).append(q)
        return q

    def unsubscribe(self, scan_id: str, q: queue.Queue) -> None:
        if q in self.subscribers.get(scan_id, []):
            self.subscribers[scan_id].remove(q)

    # ------------------------------------------------------------------ run
    def start(self, repo_path: str, offline: bool = False, llm: str = "auto", label: Optional[str] = None,
              osv_dump: Optional[str] = None) -> str:
        """``repo_path`` is a local folder or a https://github.com/owner/repo link (cloned inside the scan thread)."""
        gh = parse_github_url(repo_path)
        if gh:
            repo, name, url = None, gh[1], f"https://github.com/{gh[0]}/{gh[1]}.git"
        else:
            low = repo_path.strip().lower()
            if low.startswith(("http://", "https://", "git@", "ssh://", "www.")) or "github.com" in low:
                raise ValueError("Use a GitHub repository link such as https://github.com/<owner>/<repo> "
                                 "(other hosts are not supported yet)")
            repo = Path(repo_path.strip().strip('"')).resolve()
            if not repo.is_dir():
                raise ValueError(f"{repo_path} is not a folder on this machine or a GitHub link")
            from .dashboard import not_python_reason
            reason = not_python_reason(repo)
            if reason:
                raise ValueError(reason)
            name, url = repo.name, None
        scan_id = f"{re.sub(r'[^A-Za-z0-9_-]', '-', label or name)}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        d = self.root / scan_id
        d.mkdir(parents=True)
        meta = {"scan_id": scan_id, "repo": name, "repo_path": str(repo) if repo else None, "repo_url": url,
                "created_at": now(), "status": "running", "offline": offline,
                "stages": {k: {"name": n, "status": "pending"} for k, n in STAGES}}
        (d / "scan.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        threading.Thread(target=self._run, args=(scan_id, repo, url, offline, llm, osv_dump), daemon=True).start()
        return scan_id

    def _clone(self, scan_id: str, url: str, log) -> Path:
        name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        dest = self.root / ".clones" / scan_id / name      # the folder name becomes the repo name in the scan
        dest.parent.mkdir(parents=True, exist_ok=True)
        log(f"cloning {url} (depth {CLONE_DEPTH})")
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        try:
            r = subprocess.run(["git", "-c", "core.longpaths=true", "-c", "core.symlinks=false", "clone", "--quiet",
                                "--depth", str(CLONE_DEPTH), "--", url, str(dest)],
                               capture_output=True, text=True, timeout=CLONE_TIMEOUT_S, env=env)
        except subprocess.TimeoutExpired:
            shutil.rmtree(dest, ignore_errors=True)
            raise RuntimeError(f"git clone timed out after {CLONE_TIMEOUT_S}s")
        if r.returncode != 0 and not dest.is_dir():
            raise RuntimeError(f"git clone failed: {(r.stderr or r.stdout).strip()[-400:]}")
        if r.returncode != 0:  # e.g. a few paths Windows cannot create: the checkout is still usable
            log(f"git clone warning: {(r.stderr or '').strip()[-300:]}")
        log("clone finished")
        return dest

    def _stage(self, scan_id: str, key: str, status: str, **extra) -> None:
        d = self.root / scan_id
        m = _read(d / "scan.json", {})
        st = m.setdefault("stages", {}).setdefault(key, {})
        st.update({"status": status, **extra})
        if status == "running":
            st["started_at"] = time.time()
        if status in ("done", "failed") and st.get("started_at"):
            st["duration_s"] = round(time.time() - st["started_at"], 1)
        (d / "scan.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
        self.emit(scan_id, {"type": "stage", "stage": key, "status": status, **extra})

    def _run(self, scan_id: str, repo: Optional[Path], url: Optional[str], offline: bool, llm: str,
             osv_dump: Optional[str]) -> None:
        d = self.root / scan_id
        log = lambda msg: self.emit(scan_id, {"type": "log", "message": msg})
        try:
            if url:
                repo = self._clone(scan_id, url, log)
                from .dashboard import not_python_reason
                reason = not_python_reason(repo)
                if reason:
                    raise NotPythonRepo(reason)
            run_pipeline(repo, d, offline=offline, llm=llm, osv_dump=osv_dump, log=log,
                         stage=lambda k, s, **x: self._stage(scan_id, k, s, **x),
                         emit=lambda e: self.emit(scan_id, e), scan_id=scan_id)
            status = "done"
        except Exception as exc:
            msg = str(exc) if isinstance(exc, (NotPythonRepo, RuntimeError)) else f"{type(exc).__name__}: {exc}"
            self.emit(scan_id, {"type": "error", "message": msg, "trace": traceback.format_exc()[-1500:]})
            status, error = "failed", msg
        else:
            error = None
        m = _read(d / "scan.json", {})
        m["status"] = status
        if error:
            m["error"] = error
            for st in (m.get("stages") or {}).values():   # stages that never started
                if st.get("status") == "running":
                    st["status"] = "failed"
        m["finished_at"] = now()
        facts = _read(d / "facts.json", {}) or {}
        m["commit"] = (facts.get("repo") or {}).get("commit")
        (d / "scan.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
        self.emit(scan_id, {"type": "done", "status": status})


def run_pipeline(repo: Path, dest: Path, offline: bool = False, llm: str = "auto", osv_dump: Optional[str] = None,
                 log=print, stage=lambda *a, **k: None, emit=lambda e: None, scan_id: Optional[str] = None,
                 skip_sbom: bool = True, day2: bool = True) -> None:
    """Stages 1-5 (+ Day 2 prioritize & remediate) into ``dest`` (the snapshot folder)."""
    from guardian.adapters import declared_vs_used
    from guardian.stage1_facts.collector import run_stage1_collection
    from guardian.stage2_code.parser import index_repo
    from guardian.stage3_knowledge import run_stage3
    from guardian.stage4_vulns import run_stage4
    from guardian.stage5_anomalies import run_stage5

    stage("1", "running")
    facts = run_stage1_collection(repo_path=repo, output_dir=dest, use_docker=False, offline=offline, skip_sbom=skip_sbom)
    stage("1", "done", summary=f"{len(facts.declared_dependencies)} declared, {len(facts.resolved_packages)} resolved packages")
    stage("2", "running")
    idx = index_repo(repo, cache_dir=dest.parent / ".cache", resolved=facts.resolved_packages)
    (dest / "code_index.json").write_text(idx.model_dump_json(indent=2), encoding="utf-8")
    (dest / "summary.json").write_text(declared_vs_used(facts, idx).model_dump_json(indent=2), encoding="utf-8")
    stage("2", "done", summary=f"parsed {len(idx.files)} files, {sum(len(f.routes) for f in idx.files)} routes")
    stage("3", "running")
    # offline = no OSV/PyPI network; an explicitly named LLM (groq, gemini, ...) is still used
    s3 = run_stage3(dest, repo_path=repo, llm_provider="offline" if offline and llm == "auto" else llm, log=log)
    stage("3", "done", summary=f"{s3.G.number_of_nodes()} nodes, {len(s3.paths)} paths, {len(s3.findings)} findings")
    stage("4", "running")
    s4 = run_stage4(s3, offline=offline, osv_dump=osv_dump, log=log, emit=emit, scan_id=scan_id)
    cards = s4.state.get("cards", [])
    stage("4", "done", summary=f"{len(cards)} vulnerability findings, {len(s4.state.get('deep', []))} investigated")
    stage("5", "running")
    s5 = run_stage5(s4, offline=offline, log=log)
    stage("5", "done", summary=f"{len(s5.state.get('cards', []))} anomaly findings from {len(s5.state.get('signals', []))} signals")
    if day2:
        from guardian.day2 import run_day2
        stage("6", "running")
        d2 = run_day2(dest, repo=repo, llm=s3.llm, offline=offline, osv_dump=osv_dump, log=log)
        rems = d2["remediations"]
        stage("6", "done", summary=f"{len(d2['register'])} findings prioritized, {len(rems)} remediations, "
                                   f"{sum(1 for r in rems if r.get('tab') == 'decide')} need a decision")
