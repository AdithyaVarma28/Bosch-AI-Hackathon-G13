"""Run store: immutable, content-addressed evidence in SQLite plus JSON artifacts on disk."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .models import Evidence, Explanation, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence(
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, locator TEXT NOT NULL,
  excerpt TEXT NOT NULL, sha256 TEXT NOT NULL, captured_at TEXT NOT NULL, run_id TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence
  BEGIN SELECT RAISE(ABORT, 'evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence
  BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS explanations(finding_id TEXT PRIMARY KEY, body TEXT NOT NULL);
"""

MAX_EXCERPT = 4000


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class RunStore:
    def __init__(self, run_dir: Path, run_id: str):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.run_dir / "run.db", check_same_thread=False)
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # ----------------------------------------------------------------- evidence
    def add_evidence(self, kind: str, source: str, locator: str, excerpt: str) -> Evidence:
        excerpt = (excerpt or "")[:MAX_EXCERPT]
        digest = hashlib.sha256(excerpt.encode("utf-8", "replace")).hexdigest()
        eid = "ev_" + hashlib.sha256(f"{kind}|{source}|{locator}|{digest}".encode()).hexdigest()[:10]
        with self._lock:
            row = self.conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
            if row:
                return self._row(row)
            ev = Evidence(id=eid, kind=kind, source=source, locator=locator, excerpt=excerpt,
                          sha256=digest, captured_at=now_iso(), run_id=self.run_id)
            self.conn.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?)",
                              (ev.id, ev.kind, ev.source, ev.locator, ev.excerpt, ev.sha256,
                               ev.captured_at, ev.run_id))
            self.conn.commit()
            return ev

    def get_evidence(self, eid: str) -> Evidence | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
        return self._row(row) if row else None

    def all_evidence(self) -> list[Evidence]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM evidence").fetchall()
        return [self._row(r) for r in rows]

    @staticmethod
    def _row(r: tuple) -> Evidence:
        return Evidence(id=r[0], kind=r[1], source=r[2], locator=r[3], excerpt=r[4], sha256=r[5],
                        captured_at=r[6], run_id=r[7])

    # ----------------------------------------------------------------- artifacts
    def save_artifact(self, name: str, obj: Any) -> Path:
        path = self.run_dir / name
        if isinstance(obj, BaseModel):
            text = obj.model_dump_json(indent=2, by_alias=True)
        else:
            text = json.dumps(_jsonable(obj), indent=2, default=str)
        path.write_text(text, encoding="utf-8")
        return path

    def load_artifact(self, name: str) -> Any:
        path = self.run_dir / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    # ----------------------------------------------------------------- findings
    def add_finding(self, f: Finding) -> None:
        with self._lock:
            self.conn.execute("INSERT OR REPLACE INTO findings VALUES (?,?)", (f.id, f.model_dump_json()))
            self.conn.commit()

    def list_findings(self) -> list[Finding]:
        with self._lock:
            rows = self.conn.execute("SELECT body FROM findings").fetchall()
        return [Finding.model_validate_json(r[0]) for r in rows]

    def save_explanation(self, e: Explanation) -> None:
        with self._lock:
            self.conn.execute("INSERT OR REPLACE INTO explanations VALUES (?,?)", (e.finding_id, e.model_dump_json()))
            self.conn.commit()

    def get_explanations(self) -> list[Explanation]:
        with self._lock:
            rows = self.conn.execute("SELECT body FROM explanations").fetchall()
        return [Explanation.model_validate_json(r[0]) for r in rows]

    def close(self) -> None:
        with self._lock:
            self.conn.close()


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json", by_alias=True)
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    return obj
