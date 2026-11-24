"""Shared helpers for Day 2 (prioritize, remediate, approve, verify). See docs/DAY_2_PLAN.md."""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

REGISTER_FILE = "register.json"
REMEDIATIONS_FILE = "remediations.json"
CONFIG_FILE = "day2_config.json"
AUDIT_FILE = "audit.jsonl"
WORKFLOW_DB = "remediation.sqlite"

BANDS = ["low", "medium", "high", "critical"]          # project priority / stage risk, lowest first
CONF = ["low", "medium", "high"]
DECISIONS = ["Track", "Track*", "Attend", "Act"]


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def write_json(path: Path, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    os.replace(tmp, path)


def band_idx(b: Optional[str]) -> int:
    return BANDS.index(b) if b in BANDS else 0


def conf_idx(c: Optional[str]) -> int:
    return CONF.index(c) if c in CONF else 0


def lower_conf(c: str, steps: int = 1) -> str:
    return CONF[max(0, conf_idx(c) - steps)]


def norm_name(name: str) -> str:
    """PEP 503 normalised package name."""
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def purl_name_version(purl: str) -> tuple[str, str]:
    m = re.match(r"pkg:pypi/([^@]+)@(.+)$", purl or "")
    return (m.group(1), m.group(2)) if m else ("", "")


_locks: dict[str, threading.RLock] = {}


def scan_lock(out: Path) -> threading.RLock:
    """One lock per scan folder: workflow threads and API calls never write remediations.json together."""
    return _locks.setdefault(str(Path(out).resolve()), threading.RLock())


def load_config(out: Path) -> dict:
    cfg = read_json(Path(out) / CONFIG_FILE, {}) or {}
    if not cfg.get("repo_path"):
        meta = read_json(Path(out) / "scan.json", {}) or {}
        g = read_json(Path(out) / "graph.json", {}) or {}
        cfg["repo_path"] = meta.get("repo_path") or (g.get("graph") or {}).get("repo_path")
    return cfg


def repo_path(out: Path) -> Optional[Path]:
    p = load_config(out).get("repo_path")
    return Path(p) if p and Path(p).exists() else None


def load_remediations(out: Path) -> list[dict]:
    return read_json(Path(out) / REMEDIATIONS_FILE, []) or []


def save_remediations(out: Path, rems: list[dict]) -> None:
    write_json(Path(out) / REMEDIATIONS_FILE, rems)


def get_rem(out: Path, rid: str) -> Optional[dict]:
    return next((r for r in load_remediations(out) if r["rid"] == rid), None)


def put_rem(out: Path, rem: dict) -> None:
    with scan_lock(out):
        rems = load_remediations(out)
        for i, r in enumerate(rems):
            if r["rid"] == rem["rid"]:
                rems[i] = rem
                break
        else:
            rems.append(rem)
        save_remediations(out, rems)
