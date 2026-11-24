"""Append-only records: the audit trail of one scan (audit.jsonl) and the risk history of a repository across
scans (never overwritten: each scan appends an entry with the reason the priority changed)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .common import AUDIT_FILE, now, read_json, scan_lock, write_json


def audit(out: Path, event: str, rid: Optional[str] = None, **data: Any) -> dict:
    e = {"at": now(), "event": event, "rid": rid, **{k: v for k, v in data.items() if v is not None}}
    with scan_lock(out):
        with open(Path(out) / AUDIT_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(e, ensure_ascii=False, default=str) + "\n")
    return e


def read_audit(out: Path, rid: Optional[str] = None) -> list[dict]:
    p = Path(out) / AUDIT_FILE
    if not p.exists():
        return []
    evs = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return [e for e in evs if rid is None or e.get("rid") == rid]


def history_path(out: Path, repo: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in (repo or "repo"))
    return Path(out).resolve().parent / ".guardian_history" / f"{safe}.json"


INPUT_LABELS = {"exploitation": "exploitation", "automatable": "automatable", "technical_impact": "technical impact",
                "mission": "mission & well-being", "suspicion": "suspicion", "exposure": "exposure",
                "epss_percentile": "EPSS percentile", "kev": "KEV", "cvss": "CVSS", "stage_risk": "rule-based risk"}


def change_reason(prev: dict, cur: dict) -> str:
    diffs = []
    for k, label in INPUT_LABELS.items():
        a, b = (prev.get("inputs") or {}).get(k), (cur.get("inputs") or {}).get(k)
        if a != b and not (a is None and b is None):
            diffs.append(f"{label} {a} → {b}")
    if prev.get("evidence_hash") != cur.get("evidence_hash"):
        diffs.append("evidence changed")
    return "; ".join(diffs) or "re-scan, inputs unchanged"


def record_history(out: Path, repo: str, scan_id: str, entries: list[dict]) -> dict[str, list[dict]]:
    """Append one history entry per register entry (only when this scan has not been recorded yet).
    Returns {history_key: [entries...]} for the register to show."""
    path = history_path(out, repo)
    with scan_lock(path.parent):
        hist: dict[str, list[dict]] = read_json(path, {}) or {}
        for e in entries:
            key = e["history_key"]
            items = hist.setdefault(key, [])
            cur = {"scan_id": scan_id, "at": now(), "priority": e["priority"], "decision": e["decision"],
                   "finding_id": e["finding_id"], "inputs": e["decision_inputs"], "evidence_hash": e["evidence_hash"],
                   "human_decision": (e.get("review") or {}).get("status")}
            same = [i for i, h in enumerate(items) if h.get("scan_id") == scan_id]
            prev = next((h for h in reversed(items) if h.get("scan_id") != scan_id), None)
            if prev:
                cur["previous_priority"] = prev["priority"]
                cur["change_reason"] = ("priority " + prev["priority"] + " → " + cur["priority"] + ": " + change_reason(prev, cur)
                                        if prev["priority"] != cur["priority"] else change_reason(prev, cur))
            if same:      # the same scan re-prioritised (e.g. AI answers arrived): replace, keep the first timestamp
                cur["at"] = items[same[0]]["at"]
                items[same[0]] = cur
            else:
                items.append(cur)
        write_json(path, hist)
    return {e["history_key"]: hist.get(e["history_key"], []) for e in entries}
