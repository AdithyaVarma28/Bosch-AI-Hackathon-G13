"""Unified findings register: Stage 4 vulnerability cards + Stage 5 suspicious cards in one model.
Fields that do not apply stay null (a typosquat gets no CVSS, EPSS or KEV)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional

from .common import read_json

SENS = {"low": 0, "medium": 1, "high": 2}


class GraphView:
    """Just what Day 2 needs from graph.json: module sensitivity per file, package nodes."""

    def __init__(self, out: Path):
        g = read_json(Path(out) / "graph.json", {}) or {}
        nodes = g.get("nodes", [])
        self.repo_path = (g.get("graph") or {}).get("repo_path")
        self.modules = [n for n in nodes if n.get("type") == "Module"]
        self.packages = {n["id"]: n for n in nodes if n.get("type") == "Package"}
        self.file_module: dict[str, dict] = {}
        for m in self.modules:
            for f in m.get("files") or []:
                self.file_module[f] = m

    def module_of(self, file: str) -> Optional[dict]:
        if file in self.file_module:
            return self.file_module[file]
        best = None
        for m in self.modules:
            p = (m.get("path") or "").rstrip("/")
            if p and (file == p or file.startswith(p + "/")) and (best is None or len(p) > len(best.get("path") or "")):
                best = m
        return best

    def sensitivity(self, files: list[str]) -> dict:
        level, reasons, mods = "low", [], []
        for f in files:
            m = self.module_of(f)
            if not m or m["id"] in mods:
                continue
            mods.append(m["id"])
            card = m.get("card") or {}
            s = card.get("sensitivity") or "low"
            if SENS.get(s, 0) > SENS[level]:
                level = s
            if SENS.get(s, 0) >= 1:
                reasons += [f"{m.get('name') or m['id']}: {r}" for r in (card.get("sensitivity_reasons") or [])[:2]]
        return {"level": level, "reasons": reasons[:4], "modules": mods}

    def package_files(self, purl: str) -> list[str]:
        return list((self.packages.get(purl) or {}).get("used_by_files") or [])


def _files_of_card(c: dict) -> list[str]:
    files = [s.get("file") for s in c.get("usage_sites") or [] if s.get("file")]
    files += [e.get("file") for e in c.get("evidence") or [] if e.get("file")]
    files += list(c.get("evidence_files") or [])
    out = []
    for f in files:
        if f and f not in out and not f.endswith((".lock", ".txt", ".toml")):
            out.append(f)
    return out


def evidence_ids(c: dict) -> list[dict]:
    """Stable evidence ids (E-<finding>-<n>) that the AI classifier, the agent and the critic must cite."""
    out = []
    for i, e in enumerate(c.get("evidence") or [], 1):
        where = e.get("file") and f"{e['file']}:{e.get('lines') or e.get('line') or ''}".rstrip(":")
        out.append({"id": f"E-{c['finding_id']}-{i}", "type": e.get("type"),
                    "where": where or e.get("url") or e.get("commit") or " → ".join(e.get("labels") or []) or "",
                    "text": e.get("snippet") or e.get("detail") or e.get("claim") or e.get("ref_type") or ""})
    return out


def _subtype(c: dict) -> str:
    if c.get("type") == "vulnerability":
        return "cve"
    checks = {s.get("check", "") for s in c.get("signals") or []}
    comp = c.get("component", "")
    if comp.startswith("workflow:"):
        return "ci_workflow"
    if comp.startswith("image:"):
        return "base_image"
    if any(k.startswith("typosquat") for k in checks):
        return "typosquat"
    if checks & {"hash_mismatch", "lockfile_only_change"}:
        return "lockfile_integrity"
    if any("install_hook" in k for k in checks):
        return "install_hook"
    if comp.startswith("file:"):
        return "unexpected_change"
    if checks & {"new_behaviour_in_update", "recent_release", "wheel_to_sdist_only"}:
        return "suspicious_update"
    return "unexpected_change"


def _epss(c: dict) -> Optional[dict]:
    e = c.get("epss")
    if e is None and c.get("epss_percentile") is None:
        return None
    if isinstance(e, dict):
        return {"probability": e.get("probability", e.get("epss")), "percentile": e.get("percentile", c.get("epss_percentile")),
                "date": e.get("date")}
    return {"probability": e, "percentile": c.get("epss_percentile"), "date": None}


def build_register(out: Path) -> list[dict]:
    out = Path(out)
    gv = GraphView(out)
    vulns = read_json(out / "vuln_findings.json", []) or []
    anoms = read_json(out / "anomaly_findings.json", []) or []
    entries = []
    for c in vulns + anoms:
        vuln = c.get("type") == "vulnerability"
        files = _files_of_card(c)
        if not files and str(c.get("component", "")).startswith("pkg:"):
            files = gv.package_files(c["component"])
        sens = gv.sensitivity(files)
        if c.get("component", "").startswith("workflow:"):
            secrets = [s for s in c.get("signals") or [] if s.get("check") == "secrets_in_pr_workflow"]
            if secrets:
                sens = {"level": "high", "reasons": ["CI workflow exposes repository secrets"], "modules": []}
        sev = c.get("severity") or {}
        ev = evidence_ids(c)
        ehash = hashlib.sha256(json.dumps([c.get("component"), c.get("evidence_files_hash"),
                                           [e["where"] for e in ev]], sort_keys=True).encode()).hexdigest()[:16]
        scope = c.get("scope") or ("runtime" if not c.get("component", "").startswith(("workflow:", "image:")) else "build")
        entries.append({
            "finding_id": c["finding_id"], "kind": "vulnerability" if vuln else "suspicious", "subtype": _subtype(c),
            "component": c.get("component"), "component_name": c.get("component_name"),
            "component_version": c.get("component_version"), "title": c.get("title"),
            "vuln_id": c.get("vuln_id"), "aliases": c.get("aliases") or [],
            "cvss": {"score": sev.get("cvss"), "vector": sev.get("vector")} if vuln and sev.get("cvss") is not None else None,
            "epss": _epss(c) if vuln else None,
            "kev": bool(c.get("kev")) if vuln else None,
            "stage_risk": c.get("project_risk"), "stage_confidence": c.get("confidence"),
            "stage_confidence_reasons": c.get("confidence_reasons") or [],
            "usage": c.get("usage"), "reachability": c.get("reachability"), "exposure": c.get("exposure"),
            "suspicion": c.get("suspicion"), "scope": scope,
            "sensitivity": sens, "files": files, "evidence": ev, "evidence_hash": ehash,
            "references": c.get("references") or [], "conditions": c.get("conditions") or [],
            "usage_sites": c.get("usage_sites") or [], "signals": c.get("signals") or [],
            "summary": c.get("summary") or c.get("capability") or c.get("title"),
            "explanation": c.get("explanation"), "recommendation": c.get("recommendation"),
            "fix": c.get("fix"), "fixed_versions": c.get("fixed_versions") or [],
            "review": c.get("review") or {},
            "history_key": f"{'vuln' if vuln else 'anomaly'}|{c.get('vuln_id') or c.get('subject_id')}|"
                           f"{(c.get('component') or '').split('@')[0]}",
        })
    return entries
