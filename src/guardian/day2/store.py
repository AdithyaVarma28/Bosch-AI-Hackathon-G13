"""Day 2 persistence in the same run.db as Day 1.

* approvals and audit are append-only (SQLite triggers refuse UPDATE/DELETE), like Day 1 evidence.
* plans keep every revision (plan_key, revision); a superseded revision is never overwritten.
* JSON artifacts go to <run_dir>/day2/.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ..store import RunStore, _jsonable, now_iso
from .models import ApprovalRecord, RemediationPlan, TimelineEntry

_SCHEMA = """
CREATE TABLE IF NOT EXISTS d2_approvals(seq INTEGER PRIMARY KEY AUTOINCREMENT, plan_key TEXT NOT NULL,
  plan_hash TEXT NOT NULL, kind TEXT NOT NULL, decision TEXT NOT NULL, body TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS d2_approvals_no_update BEFORE UPDATE ON d2_approvals
  BEGIN SELECT RAISE(ABORT, 'approvals are immutable'); END;
CREATE TRIGGER IF NOT EXISTS d2_approvals_no_delete BEFORE DELETE ON d2_approvals
  BEGIN SELECT RAISE(ABORT, 'approvals are append-only'); END;
CREATE TABLE IF NOT EXISTS d2_audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS d2_audit_no_update BEFORE UPDATE ON d2_audit
  BEGIN SELECT RAISE(ABORT, 'audit trail is immutable'); END;
CREATE TRIGGER IF NOT EXISTS d2_audit_no_delete BEFORE DELETE ON d2_audit
  BEGIN SELECT RAISE(ABORT, 'audit trail is append-only'); END;
CREATE TABLE IF NOT EXISTS d2_plans(plan_key TEXT NOT NULL, revision INTEGER NOT NULL, plan_hash TEXT NOT NULL,
  status TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(plan_key, revision));
CREATE TABLE IF NOT EXISTS d2_kv(name TEXT PRIMARY KEY, body TEXT NOT NULL);
"""


class Day2Store:
    def __init__(self, store: RunStore):
        self.base = store
        self.dir = store.run_dir / "day2"
        self.dir.mkdir(parents=True, exist_ok=True)
        with store._lock:
            store.conn.executescript(_SCHEMA)
            store.conn.commit()

    @property
    def conn(self):
        return self.base.conn

    @property
    def lock(self):
        return self.base._lock

    # ----------------------------------------------------------------- audit
    def audit(self, stage: str, event: str, detail: str = "", actor: str = "guardian", plan_key: str | None = None,
              evidence_ids: list[str] | None = None) -> TimelineEntry:
        e = TimelineEntry(at=now_iso(), stage=stage, event=event, detail=detail[:1000], actor=actor, plan_key=plan_key,
                          evidence_ids=evidence_ids or [])
        with self.lock:
            self.conn.execute("INSERT INTO d2_audit(body) VALUES (?)", (e.model_dump_json(),))
            self.conn.commit()
        return e

    def timeline(self, plan_key: str | None = None) -> list[TimelineEntry]:
        with self.lock:
            rows = self.conn.execute("SELECT body FROM d2_audit ORDER BY seq").fetchall()
        out = [TimelineEntry.model_validate_json(r[0]) for r in rows]
        return [e for e in out if plan_key is None or e.plan_key in (None, plan_key)]

    # ----------------------------------------------------------------- approvals
    def add_approval(self, a: ApprovalRecord) -> ApprovalRecord:
        a = a.model_copy(update={"timestamp": a.timestamp or now_iso()})
        with self.lock:
            self.conn.execute("INSERT INTO d2_approvals(plan_key, plan_hash, kind, decision, body) VALUES (?,?,?,?,?)",
                              (a.plan_key, a.plan_hash, a.kind, a.decision, a.model_dump_json()))
            self.conn.commit()
        return a

    def approvals(self, plan_key: str | None = None) -> list[ApprovalRecord]:
        with self.lock:
            rows = self.conn.execute("SELECT body FROM d2_approvals ORDER BY seq").fetchall()
        out = [ApprovalRecord.model_validate_json(r[0]) for r in rows]
        return [a for a in out if plan_key is None or a.plan_key == plan_key]

    # ----------------------------------------------------------------- plans
    def save_plan(self, p: RemediationPlan) -> None:
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO d2_plans VALUES (?,?,?,?,?)",
                              (p.plan_key, p.revision, p.plan_hash, p.status, p.model_dump_json()))
            self.conn.commit()

    def plan(self, plan_key: str, revision: int | None = None) -> RemediationPlan | None:
        with self.lock:
            if revision is None:
                row = self.conn.execute("SELECT body FROM d2_plans WHERE plan_key=? ORDER BY revision DESC LIMIT 1",
                                        (plan_key,)).fetchone()
            else:
                row = self.conn.execute("SELECT body FROM d2_plans WHERE plan_key=? AND revision=?", (plan_key, revision)).fetchone()
        return RemediationPlan.model_validate_json(row[0]) if row else None

    def plan_by_hash(self, plan_hash: str) -> RemediationPlan | None:
        with self.lock:
            row = self.conn.execute("SELECT body FROM d2_plans WHERE plan_hash=?", (plan_hash,)).fetchone()
        return RemediationPlan.model_validate_json(row[0]) if row else None

    def plans(self, latest_only: bool = True) -> list[RemediationPlan]:
        with self.lock:
            rows = self.conn.execute("SELECT plan_key, revision, body FROM d2_plans ORDER BY plan_key, revision").fetchall()
        out: dict[str, RemediationPlan] = {}
        allp = []
        for key, _, body in rows:
            p = RemediationPlan.model_validate_json(body)
            out[key] = p
            allp.append(p)
        return list(out.values()) if latest_only else allp

    # ----------------------------------------------------------------- kv + artifacts
    def put(self, name: str, obj: Any) -> None:
        body = obj.model_dump_json() if isinstance(obj, BaseModel) else json.dumps(_jsonable(obj), default=str)
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO d2_kv VALUES (?,?)", (name, body))
            self.conn.commit()

    def get(self, name: str, default: Any = None) -> Any:
        with self.lock:
            row = self.conn.execute("SELECT body FROM d2_kv WHERE name=?", (name,)).fetchone()
        return json.loads(row[0]) if row else default

    def keys(self, prefix: str) -> list[str]:
        with self.lock:
            rows = self.conn.execute("SELECT name FROM d2_kv WHERE name LIKE ? ORDER BY name", (prefix + "%",)).fetchall()
        return [r[0] for r in rows]

    def save_artifact(self, name: str, obj: Any) -> Path:
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        text = obj.model_dump_json(indent=2) if isinstance(obj, BaseModel) else json.dumps(_jsonable(obj), indent=2, default=str)
        path.write_text(text, encoding="utf-8")
        return path
