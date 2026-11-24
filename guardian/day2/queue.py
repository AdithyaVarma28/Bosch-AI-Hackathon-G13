"""Auto-validate queue (docs/DAY_2_COMPLETION_PLAN.md section 4).

After a scan, and after every new proposal, remediations with a patch and priority Critical/High are validated in
the sandbox BEFORE anyone approves them (install -> tests -> security tests -> proof-of-fix -> rescan). One
background worker per scan runs them one at a time. When the reviewer approves a proposal whose current version is
already validated, the workflow goes straight to patch review (no second run).

GUARDIAN_AUTO_VALIDATE = high (default) | all | off. The first job of a scan is the build-health check
(does the project install on its target Python?), which may add a "build health" remediation.
"""
from __future__ import annotations

import os
import threading
import traceback
from pathlib import Path
from typing import Optional

from .common import band_idx, get_rem, load_remediations, now, put_rem, scan_lock
from .history import audit


def policy() -> str:
    p = (os.environ.get("GUARDIAN_AUTO_VALIDATE") or "high").strip().lower()
    return p if p in ("high", "all", "off") else "high"


def validated(unit: dict) -> bool:
    v, p = unit.get("validation") or {}, (unit.get("proposals") or [{}])[unit.get("current") or 0] if unit.get("proposals") else {}
    return bool(v.get("finished_at")) and v.get("proposal_version") == p.get("version")


def eligible(unit: dict, everything: bool = False) -> bool:
    if not unit.get("proposals") or unit.get("status") != "awaiting_proposal_review" or unit.get("working"):
        return False
    p = unit["proposals"][unit["current"]]
    if not p.get("edits") or validated(unit):
        return False
    return everything or band_idx(unit.get("priority")) >= band_idx("high")


class AutoValidator:
    _by_dir: dict[str, "AutoValidator"] = {}
    _guard = threading.Lock()

    @classmethod
    def for_dir(cls, out: Path, create: bool = True) -> Optional["AutoValidator"]:
        key = str(Path(out).resolve())
        with cls._guard:
            if key not in cls._by_dir and create:
                cls._by_dir[key] = cls(Path(out))
            return cls._by_dir.get(key)

    def __init__(self, out: Path):
        self.out = out
        self.pending: list[str] = []
        self.current: Optional[str] = None
        self.done: list[dict] = []
        self.started = False
        self.lock = threading.Lock()
        self.thread: Optional[threading.Thread] = None
        self.note: Optional[str] = None

    # ---- public
    def ensure(self) -> None:
        """Start once per scan per server: build health first, then the Critical/High items."""
        with self.lock:
            if self.started:
                return
            self.started = True
        if policy() == "off":
            self.note = "auto-validation is off (GUARDIAN_AUTO_VALIDATE=off)"
            return
        cfg_offline = False
        try:
            from .common import load_config
            from .sandbox import effective_offline
            cfg = load_config(self.out)
            cfg_offline = effective_offline(self.out, cfg)
        except Exception:
            pass
        jobs = [] if cfg_offline or os.environ.get("GUARDIAN_BUILD_HEALTH", "1") == "0" else ["@build_health"]
        jobs += [u["rid"] for u in sorted(load_remediations(self.out), key=lambda u: min(u.get("ranks") or [0]))
                 if eligible(u, policy() == "all")]
        self.enqueue(jobs)

    def enqueue(self, rids: list[str]) -> int:
        with self.lock:
            new = [r for r in rids if r not in self.pending and r != self.current]
            self.pending += new
            if new and (self.thread is None or not self.thread.is_alive()):
                self.thread = threading.Thread(target=self._work, daemon=True, name=f"guardian-autovalidate-{self.out.name}")
                self.thread.start()
            return len(new)

    def state(self) -> dict:
        with self.lock:
            total = len(self.done) + len(self.pending) + (1 if self.current else 0)
            return {"policy": policy(), "running": self.current, "pending": list(self.pending), "done": self.done[-30:],
                    "position": len(self.done) + (1 if self.current else 0), "total": total, "note": self.note}

    # ---- worker
    def _work(self) -> None:
        while True:
            with self.lock:
                if not self.pending:
                    self.current = None
                    return
                rid = self.current = self.pending.pop(0)
            res = "done"
            try:
                if rid == "@build_health":
                    from .candidates import add_build_health
                    bh = add_build_health(self.out)
                    res = bh.get("status", "done")
                    u = get_rem(self.out, "B-001")
                    if u is not None and eligible(u, True):     # it blocks deployment: always validated
                        with self.lock:
                            self.pending.insert(0, "B-001")
                else:
                    res = self._validate(rid)
            except Exception as exc:
                res = f"error: {type(exc).__name__}: {exc}"
                audit(self.out, "auto_validation_error", None if rid.startswith("@") else rid, error=res,
                      trace=traceback.format_exc()[-1200:])
            with self.lock:
                self.done.append({"rid": rid, "result": res, "at": now()})

    def _validate(self, rid: str) -> str:
        from .workflow import _refresh, do_validate
        with scan_lock(self.out):
            u = get_rem(self.out, rid)
            if u is None or not eligible(u, True):
                return "skipped (already decided, validated or being worked on)"
            u["working"] = {"what": "auto-validating in the sandbox before your review", "since": now()}
            put_rem(self.out, u)
        try:
            do_validate(self.out, rid, auto=True)
        finally:
            u = get_rem(self.out, rid)
            u.pop("working", None)
            put_rem(self.out, _refresh(u))
        return (u.get("validation") or {}).get("status") or "done"


def on_new_proposal(out: Path, rid: str) -> None:
    """Called after every new proposal: queue it when this scan's queue is active (web server)."""
    q = AutoValidator.for_dir(out, create=False)
    if q is None or not q.started or policy() == "off":
        return
    u = get_rem(out, rid)
    if u is not None and eligible(u, policy() == "all"):
        q.enqueue([rid])
