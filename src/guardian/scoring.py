"""S7 Correlate + score: dedupe, attack class, axes and P0-P3 priority bands (first matching rule wins).

The thresholds below are UNVALIDATED starting values; the report labels them as such.
"""
from __future__ import annotations

import re
from importlib import resources

import yaml
from pydantic import BaseModel

from .models import Dossier, Finding
from .purl import parse_purl

THRESHOLDS_NOTE = "Priority bands use unvalidated starting thresholds (hackathon Day 1); treat as triage order, not risk scores."


class Axes(BaseModel):
    severity_band: str | None
    exploitability: str          # kev | epss-high | unknown
    trust_alerts: int            # strong signals on the same package
    context: str                 # High | Medium | Low | Unknown
    confidence: str              # high | medium | low


def _attack_map() -> dict:
    try:
        return yaml.safe_load(resources.files("guardian.data").joinpath("attack_map.yaml").read_text(encoding="utf-8")) or {}
    except (FileNotFoundError, ModuleNotFoundError):
        return {}


def package_name(subject: str) -> str:
    if subject.startswith("pkg:"):
        try:
            return parse_purl(subject)[1].lower()
        except ValueError:
            return subject
    return subject.lower()


def _is_malicious_advisory(s: dict) -> bool:
    ids = [s.get("advisory_id") or ""] + list(s.get("aliases") or [])
    summary = (s.get("summary") or "").lower()
    return any(i.startswith("MAL-") for i in ids) or bool(re.search(r"\b(is malware|malicious code in|malicious package)\b", summary))


def correlate(findings: list[Finding]) -> list[Finding]:
    amap = _attack_map()
    merged: dict[str, Finding] = {}
    for f in findings:
        if f.id in merged:
            m = merged[f.id]
            m.raw_evidence_ids = list(dict.fromkeys(m.raw_evidence_ids + f.raw_evidence_ids))
            m.signals = {**f.signals, **m.signals}
            continue
        merged[f.id] = f.model_copy(deep=True)
    for f in merged.values():
        s = f.signals
        if f.cls == "vuln":
            f.attack_class = "Known malicious package" if _is_malicious_advisory(s) else "Known vulnerability"
        elif s.get("pattern") and s["pattern"] in (amap.get("patterns") or {}):
            f.attack_class = amap["patterns"][s["pattern"]]
        elif s.get("rule") in (amap.get("rules") or {}):
            f.attack_class = amap["rules"][s["rule"]]
        elif s.get("signal") in (amap.get("signals") or {}):
            f.attack_class = amap["signals"][s["signal"]]
    return list(merged.values())


def _context(f: Finding, dossier: Dossier | None) -> str:
    scope = f.signals.get("scope")
    exposure = dossier.exposure if dossier else "unknown"
    if f.cls in ("ci", "secret"):
        return "High" if f.classification == "S" else "Medium"
    if f.cls == "container":
        return "Medium" if exposure == "network_facing" else "Low"
    if scope in ("dev", "test", "optional", "build"):
        return "Low"
    if scope == "prod" or scope is None:
        return "High" if exposure == "network_facing" else "Medium" if scope == "prod" else "Unknown"
    return "Unknown"


def axes_for(f: Finding, dossier: Dossier | None, sbom_confidence: str, trust: dict[str, int]) -> Axes:
    s = f.signals
    expl = "kev" if s.get("kev") else "epss-high" if (s.get("epss") or 0) >= 0.5 else "unknown"
    conf = sbom_confidence if f.cls == "vuln" else {"C": "high", "S": "medium", "W": "low"}[f.classification]
    return Axes(severity_band=s.get("severity_band"), exploitability=expl,
                trust_alerts=trust.get(package_name(f.subject), 0), context=_context(f, dossier), confidence=conf)


def priority_band(ax: Axes, f: Finding) -> tuple[str, str]:
    s = f.signals
    if f.cls == "sbom_quality":
        return "Unprioritized", "coverage gap, not a finding about the application"
    if f.cls == "vuln":
        sev = ax.severity_band
        prod = s.get("scope") in ("prod", None, "unknown")
        exposed = bool(s.get("exposed_routes"))
        if ax.exploitability == "kev":
            return "P0", "known exploited vulnerability (CISA KEV)"
        if _is_malicious_advisory(s):
            return "P0", "OSV lists this package version in a malicious-package advisory"
        if sev is None:
            return "Unprioritized", "advisory has no severity data; review manually"
        if sev == "Critical" and prod and exposed:
            return "P0", "critical, runtime scope, package statically referenced from an exposed route (reachability not proven)"
        if sev in ("Critical", "High") and prod and ax.exploitability == "epss-high":
            return "P1", f"{sev.lower()} with high EPSS ({s.get('epss')}) in runtime scope"
        if sev in ("Critical", "High") and prod:
            return "P1", f"{sev.lower()} in runtime scope; reachability unknown (not downgraded)"
        if sev in ("Critical", "High"):
            return "P2", f"{sev.lower()} but only in {s.get('scope')} scope"
        if sev == "Medium" and prod:
            return "P2", "medium severity in runtime scope"
        return "P3", f"{sev.lower()} severity" + (f" in {s.get('scope')} scope" if s.get("scope") else "")
    # non-CVE signals
    if f.classification == "S" and ax.trust_alerts >= 2:
        return "P0", f"{ax.trust_alerts} independent strong supply-chain signals on the same package"
    if f.classification == "S":
        return "P1", f"strong {f.attack_class or f.cls} signal"
    if f.attack_class == "Typosquatting" and s.get("direct"):
        return "P2", "possible typosquat declared directly (weak signal)"
    if f.cls == "discrepancy":
        return "P3", "cross-layer discrepancy (informational)"
    return "P3", f"weak {f.attack_class or f.cls} signal"


def score(findings: list[Finding], dossier: Dossier | None, sbom_confidence: str) -> list[Finding]:
    trust: dict[str, int] = {}
    for f in findings:
        if f.classification == "S" and f.cls == "anomaly":
            trust[package_name(f.subject)] = trust.get(package_name(f.subject), 0) + 1
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "Unprioritized": 4}
    for f in findings:
        ax = axes_for(f, dossier, sbom_confidence, trust)
        f.band, f.band_reason = priority_band(ax, f)
        f.signals["axes"] = ax.model_dump()
    return sorted(findings, key=lambda f: (order.get(f.band or "", 9), {"C": 0, "S": 1, "W": 2}[f.classification], f.title))
