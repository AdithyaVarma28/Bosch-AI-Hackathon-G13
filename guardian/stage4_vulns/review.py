"""Step 7 Human review (shared by Stages 4 and 5).

* A small LangGraph graph per finding: ``await_decision`` calls ``interrupt(card)``; the API resumes it
  with ``Command(resume=decision)``; ``apply_decision`` updates the card. Checkpoints live in
  ``output/<repo>/review.sqlite`` (``SqliteSaver``), so a pending review survives restarts. One thread
  per finding means each review is resumed on its own and the report is written without waiting.
* ``triage.json`` stores decisions keyed by ``(finding kind, subject id, component, sha256 of the
  evidence files)``. A re-scan reuses a decision only when that key is unchanged; otherwise the review
  is re-opened (and says so).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional, TypedDict

from .schema import DISMISS_REASONS, RISKS, ReviewDecision, now_iso

TRIAGE_FILE = "triage.json"
REVIEW_DB = "review.sqlite"
STATUS = {"confirm": "confirmed", "dismiss": "dismissed", "override": "overridden"}

try:  # LangGraph is the review engine; without it decisions are applied directly (same store)
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import Command, interrupt
    HAVE_LANGGRAPH = True
except ImportError:  # pragma: no cover - depends on environment
    HAVE_LANGGRAPH = False


class ReviewError(ValueError):
    pass


def files_hash(code_index: dict, files: list[str]) -> str:
    by_path = {f.get("path"): f.get("sha256") or "" for f in code_index.get("files", []) or []}
    blob = "|".join(f"{p}:{by_path.get(p, '?')}" for p in sorted(set(f for f in files if f)))
    return hashlib.sha256(blob.encode()).hexdigest()[:16] if blob else "none"


def triage_key(kind: str, subject: str, component: str, fhash: str) -> str:
    return hashlib.sha256(f"{kind}|{subject}|{component}|{fhash}".encode()).hexdigest()[:20]


def validate_decision(d: ReviewDecision) -> ReviewDecision:
    if d.action == "dismiss" and d.reason not in DISMISS_REASONS:
        raise ReviewError(f"dismiss needs a reason: one of {', '.join(DISMISS_REASONS)}")
    if d.action == "override":
        if d.new_risk not in RISKS:
            raise ReviewError(f"override needs new_risk: one of {', '.join(RISKS)}")
        if not (d.reason or d.note):
            raise ReviewError("override needs a reason")
    return d


def apply_decision(card: dict, d: dict) -> dict:
    card = dict(card)
    review = dict(card.get("review") or {})
    review.update({"status": STATUS[d["action"]], "action": d["action"], "by": d.get("by"), "reason": d.get("reason"),
                   "note": d.get("note"), "decided_at": d.get("decided_at") or now_iso()})
    if d["action"] == "override":
        card.setdefault("project_risk_by_rules", card.get("project_risk"))
        card["project_risk"] = d["new_risk"]
        review["new_risk"] = d["new_risk"]
    card["review"] = review
    return card


class TriageStore:
    def __init__(self, output_dir: Path):
        self.path = Path(output_dir) / TRIAGE_FILE
        self.data = {"decisions": {}, "history": []}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        self.data.setdefault("decisions", {})
        self.data.setdefault("history", [])

    def get(self, key: str) -> Optional[dict]:
        return self.data["decisions"].get(key)

    def previous(self, kind: str, subject: str) -> Optional[dict]:
        """An older decision for the same finding subject whose key no longer matches (changed code/version)."""
        for d in self.data["decisions"].values():
            if d.get("kind") == kind and d.get("subject") == subject:
                return d
        return None

    def record(self, key: str, card: dict, decision: dict) -> None:
        entry = {**decision, "kind": card.get("type"), "subject": card.get("subject_id"),
                 "component": card.get("component"), "finding_id": card.get("finding_id"),
                 "files_hash": card.get("evidence_files_hash"), "key": key}
        self.data["decisions"][key] = entry
        self.data["history"].append(entry)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")


class ReviewState(TypedDict, total=False):
    card: dict
    decision: dict


def _await_decision(state: ReviewState) -> dict:
    payload = {k: state["card"].get(k) for k in ("finding_id", "type", "title", "component", "project_risk",
                                                 "confidence", "review")}
    decision = interrupt(payload)
    return {"decision": decision}


def _apply(state: ReviewState) -> dict:
    return {"card": apply_decision(state["card"], state["decision"])}


class ReviewManager:
    """Opens and resumes review threads for the finding cards of one output folder."""

    _locks: dict[str, threading.Lock] = {}

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.triage = TriageStore(self.output_dir)
        self.lock = self._locks.setdefault(str(self.output_dir.resolve()), threading.Lock())
        self.graph = None
        self.conn = None
        if HAVE_LANGGRAPH:
            from langgraph.checkpoint.sqlite import SqliteSaver
            self.conn = sqlite3.connect(str(self.output_dir / REVIEW_DB), check_same_thread=False)
            b = StateGraph(ReviewState)
            b.add_node("await_decision", _await_decision)
            b.add_node("apply_decision", _apply)
            b.add_edge(START, "await_decision")
            b.add_edge("await_decision", "apply_decision")
            b.add_edge("apply_decision", END)
            self.graph = b.compile(checkpointer=SqliteSaver(self.conn))

    @property
    def engine(self) -> str:
        return "langgraph" if self.graph is not None else "direct"

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def prepare(self, card: dict, scan_id: str) -> dict:
        """Card needs review: reuse a stored decision for an unchanged key, otherwise open a thread."""
        review = dict(card.get("review") or {})
        key = card["triage_key"]
        stored = self.triage.get(key)
        if stored:
            card = apply_decision(card, stored)
            card["review"].update({"reused": True, "reasons": review.get("reasons", []),
                                   "note_reused": "decision reused: package version and evidence files unchanged"})
            return card
        prev = self.triage.previous(card.get("type"), card.get("subject_id"))
        if prev:
            review["reopened"] = (f"an earlier decision ({prev.get('action')}) was made for "
                                  f"{prev.get('component')}; the version or evidence files changed, so it was re-opened")
        thread_id = f"{scan_id}:{card['finding_id']}:{key[:8]}"
        review.update({"status": "pending", "thread_id": thread_id, "engine": self.engine})
        card = {**card, "review": review}
        if self.graph is not None:
            with self.lock:
                self.graph.invoke({"card": card}, config={"configurable": {"thread_id": thread_id}})
        return card

    def is_pending(self, thread_id: Optional[str]) -> bool:
        if not thread_id or self.graph is None:
            return False
        st = self.graph.get_state({"configurable": {"thread_id": thread_id}})
        return bool(st.next)

    def submit(self, card: dict, decision: ReviewDecision) -> dict:
        d = validate_decision(decision).model_dump()
        d["decided_at"] = now_iso()
        thread_id = (card.get("review") or {}).get("thread_id")
        with self.lock:
            if self.graph is not None and thread_id and self.is_pending(thread_id):
                out = self.graph.invoke(Command(resume=d), config={"configurable": {"thread_id": thread_id}})
                new = out["card"]
            else:
                new = apply_decision(card, d)       # no paused thread (e.g. re-review of a reused decision)
            self.triage.record(card["triage_key"], new, d)
            self.triage.save()
        return new


def load_cards(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def save_cards(path: Path, cards: list[dict]) -> None:
    path.write_text(json.dumps(cards, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def submit_review(output_dir: Path, findings_file: str, finding_id: str, decision: ReviewDecision) -> dict:
    """Apply a human decision to one card of ``findings_file`` and persist everything."""
    output_dir = Path(output_dir)
    path = output_dir / findings_file
    cards = load_cards(path)
    idx = next((i for i, c in enumerate(cards) if c.get("finding_id") == finding_id), None)
    if idx is None:
        raise KeyError(finding_id)
    mgr = ReviewManager(output_dir)
    try:
        cards[idx] = mgr.submit(cards[idx], decision)
    finally:
        mgr.close()
    save_cards(path, cards)
    return cards[idx]


def review_summary(cards: list[dict]) -> dict[str, Any]:
    by = {}
    for c in cards:
        s = (c.get("review") or {}).get("status", "not_required")
        by[s] = by.get(s, 0) + 1
    return by
