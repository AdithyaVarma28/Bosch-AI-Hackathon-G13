"""Policy-as-code engine (section 9 of docs/day2_plan.md).

Three phases use the same policy:
  triage     S10: which rules does a single finding violate? (raises it to Fix now)
  candidate  S12: would the simulated dependency set violate a block rule? (candidate discarded)
  verify     S15/S16: the regression gate and the verdict, per plan, with evidence ids per rule
Floor rules (approval hash, target resolved, no new high, build, tests, risk acceptance) cannot be disabled
or weakened by a repository policy file: repository text is untrusted.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from ..models import Component, Finding
from ..scoring import package_name
from .models import ApprovalRecord, Investigation, PolicyResult, RescanDiff, ValidationResult

REPO_POLICY_FILES = ("guardian-policy.yaml", "guardian-policy.yml", ".guardian/policy.yaml")


@dataclass
class Policy:
    rules: list[dict]
    blocked: list[dict]
    sha256: str
    sources: list[str]
    notes: list[str] = field(default_factory=list)

    def rule(self, rid: str) -> dict | None:
        return next((r for r in self.rules if r["id"] == rid), None)


def _load_yaml(text: str) -> dict:
    data = yaml.safe_load(text) or {}
    return data if isinstance(data, dict) else {}


def load_policy(repo_root: Path | None = None, extra: Path | None = None) -> Policy:
    base = _load_yaml(resources.files("guardian.data").joinpath("default_policy.yaml").read_text(encoding="utf-8"))
    rules = {r["id"]: dict(r) for r in base.get("rules", [])}
    blocked = list(base.get("blocked_packages") or [])
    sources, notes = ["guardian:default_policy.yaml"], []
    paths = []
    if repo_root:
        paths += [Path(repo_root) / p for p in REPO_POLICY_FILES if (Path(repo_root) / p).is_file()][:1]
    if extra:
        paths.append(Path(extra))
    for p in paths:
        try:
            doc = _load_yaml(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as e:
            notes.append(f"policy file {p.name} ignored: {type(e).__name__}")
            continue
        sources.append(str(p.name))
        for b in doc.get("blocked_packages") or []:
            if isinstance(b, dict) and b.get("name"):
                blocked.append({"ecosystem": b.get("ecosystem"), "name": str(b["name"]), "reason": str(b.get("reason", ""))})
        for r in doc.get("rules") or []:
            if not isinstance(r, dict) or not r.get("id"):
                continue
            cur = rules.get(r["id"])
            if cur and cur.get("floor"):
                if r.get("severity") == "warn" or r.get("enabled") is False:
                    notes.append(f"{p.name}: cannot weaken floor rule {r['id']} (ignored)")
                continue
            if r.get("enabled") is False:
                rules.pop(r["id"], None)
                notes.append(f"{p.name}: disabled rule {r['id']}")
                continue
            merged = {**(cur or {}), **{k: v for k, v in r.items() if k != "floor"}}
            if merged.get("severity") not in ("block", "warn"):
                merged["severity"] = "warn"
            if not merged.get("type"):
                notes.append(f"{p.name}: rule {r['id']} has no type (ignored)")
                continue
            rules[r["id"]] = merged
    eff = {"rules": sorted(rules.values(), key=lambda r: r["id"]), "blocked_packages": blocked}
    sha = hashlib.sha256(json.dumps(eff, sort_keys=True, default=str).encode()).hexdigest()
    return Policy(rules=eff["rules"], blocked=blocked, sha256=sha, sources=sources, notes=notes)


# ----------------------------------------------------------------------------- matching
def _field(f: Finding, key: str, investigations: dict[str, Investigation]) -> Any:
    if key == "cls":
        return f.cls
    if key == "attack_class":
        return f.attack_class
    if key == "band":
        return f.band
    if key == "classification":
        return f.classification
    if key == "investigation_verdict":
        inv = investigations.get(f.id)
        return inv.verdict if inv else None
    return f.signals.get(key)


def finding_matches(f: Finding, match: dict, investigations: dict[str, Investigation] | None = None) -> bool:
    inv = investigations or {}
    for k, want in match.items():
        got = _field(f, k, inv)
        if isinstance(want, list):
            if got not in want:
                return False
        elif got != want:
            return False
    return True


def rule_matches(rule: dict, f: Finding, investigations: dict[str, Investigation] | None = None) -> bool:
    if rule.get("type") != "max_findings":
        return False
    if rule.get("match_any"):
        return any(finding_matches(f, m, investigations) for m in rule["match_any"])
    return finding_matches(f, rule.get("match") or {}, investigations)


def is_blocked(policy: Policy, ecosystem: str | None, name: str) -> dict | None:
    n = name.lower()
    for b in policy.blocked:
        if b["name"].lower() == n and (not b.get("ecosystem") or b.get("ecosystem") == ecosystem):
            return b
    return None


# ----------------------------------------------------------------------------- phases
def triage_violations(policy: Policy, f: Finding, investigations: dict[str, Investigation] | None = None) -> list[str]:
    """Rule ids a single open finding violates (block rules first)."""
    out = [r["id"] for r in policy.rules if r.get("type") == "max_findings" and int(r.get("max", 0)) == 0
           and rule_matches(r, f, investigations)]
    return sorted(out, key=lambda rid: (policy.rule(rid) or {}).get("severity") != "block")


def candidate_violations(policy: Policy, components: list[Component], new_advisory_findings: list[Finding]) -> list[str]:
    """Block-rule violations of a simulated dependency set (used to discard candidates before the tournament)."""
    out = []
    for c in components:
        if is_blocked(policy, c.ecosystem, c.name):
            out.append(f"no-blocked-packages: {c.name}")
    for r in policy.rules:
        if r.get("severity") != "block" or r.get("type") != "max_findings":
            continue
        hits = [f for f in new_advisory_findings if rule_matches(r, f)]
        if len(hits) > int(r.get("max", 0)):
            out.append(f"{r['id']}: {', '.join(sorted({f.subject for f in hits}))[:200]}")
    return out


@dataclass
class VerifyInput:
    plan_key: str
    plan_hash: str | None
    applied_hash: str | None
    approvals: list[ApprovalRecord]
    target_ids: list[str]
    after_findings: list[Finding]                    # rescan findings
    new_finding_ids: set[str]
    after_components: list[Component]
    rescan: RescanDiff | None
    validation: ValidationResult | None
    investigations: dict[str, Investigation] = field(default_factory=dict)
    today: date | None = None


def evaluate_verify(policy: Policy, vi: VerifyInput) -> list[PolicyResult]:
    """Per-plan verification gate. Finding-count rules consider the plan's target findings that are still open
    plus findings the fix introduced; the rest of the repository's posture is reported separately."""
    res: list[PolicyResult] = []
    today = vi.today or date.today()
    target_pkgs = {package_name(f.subject) for f in vi.after_findings if f.id in vi.target_ids}
    from .simulate import is_historical   # past-commit events never "resolve"; they are reported as remaining risk
    relevant = [f for f in vi.after_findings if (f.id in vi.target_ids or f.id in vi.new_finding_ids) and not is_historical(f)]
    ev = [vi.rescan.evidence_id] if vi.rescan and vi.rescan.evidence_id else []

    def add(r: dict, passed: bool, detail: str, evidence: list[str] | None = None) -> None:
        res.append(PolicyResult(policy_sha256=policy.sha256, rule_id=r["id"], severity=r.get("severity", "warn"), passed=passed,
                                detail=detail[:500], evidence_ids=evidence if evidence is not None else ev,
                                floor=bool(r.get("floor"))))

    for r in policy.rules:
        t = r.get("type")
        if t == "max_findings":
            hits = [f for f in relevant if rule_matches(r, f, vi.investigations)]
            add(r, len(hits) <= int(r.get("max", 0)),
                "no matching open target/new findings" if not hits else
                f"{len(hits)} matching: " + "; ".join(f"{f.title} [{f.band}]" for f in hits[:4]))
        elif t == "blocked_packages":
            bad = [c.purl for c in vi.after_components if is_blocked(policy, c.ecosystem, c.name)]
            add(r, not bad, "no blocked components" if not bad else f"blocked: {', '.join(bad[:5])}")
        elif t == "resolved_versions":
            scopes = r.get("scope") or ["prod"]
            missing = [c.name for c in vi.after_components if c.scope in scopes and not c.version
                       and (not target_pkgs or package_name(c.purl) in target_pkgs or not vi.target_ids)]
            add(r, not missing, "all resolved" if not missing else f"unresolved: {', '.join(missing[:8])}")
        elif t == "approval_hash_match":
            ok_hashes = {a.plan_hash for a in vi.approvals if a.decision == "approve" and a.kind == "plan"}
            ok = bool(vi.applied_hash) and vi.applied_hash in ok_hashes
            add(r, ok, f"applied {str(vi.applied_hash)[:12]} " + ("matches an approval" if ok else
                "has no matching approval" if vi.applied_hash else "nothing was applied"), [])
        elif t == "target_resolved":
            ok = bool(vi.rescan and vi.rescan.target_resolved)
            detail = "target findings gone in rescan" if ok else (
                "no rescan" if not vi.rescan else f"still open: {', '.join(x['title'] for x in vi.rescan.findings_open[:3])}"
                + (f"; vulnerable versions left: {', '.join(vi.rescan.vulnerable_versions_left[:3])}" if vi.rescan.vulnerable_versions_left else ""))
            add(r, ok, detail)
        elif t == "no_new_findings":
            bands = set(r.get("bands") or ["P0", "P1"])
            new = [x for x in (vi.rescan.findings_new if vi.rescan else []) if x.get("band") in bands]
            add(r, bool(vi.rescan) and not new, "no rescan" if not vi.rescan else
                "none" if not new else "; ".join(f"[{x['band']}] {x['title']}" for x in new[:4]))
        elif t == "build_passes":
            v = vi.validation
            if v is None or v.sandbox == "none" or v.build_ok is None:
                add(r, True, "not run (no sandbox); verdict capped at Partially verified", [])
            else:
                add(r, bool(v.build_ok), "build ok" if v.build_ok else "build failed",
                    [s.evidence_id for s in v.steps if s.evidence_id][:3])
        elif t == "tests_not_regressed":
            v = vi.validation
            if v is None or not v.tests_after.ran:
                add(r, True, "tests not run; verdict capped at Partially verified", [])
            else:
                add(r, not v.regressions, "no regressions" if not v.regressions else f"regressed: {', '.join(v.regressions[:5])}",
                    [x for x in (v.tests_before.evidence_id, v.tests_after.evidence_id) if x])
        elif t == "risk_acceptance_valid":
            bad = []
            for a in vi.approvals:
                if a.decision != "accept_risk":
                    continue
                try:
                    exp = date.fromisoformat(str(a.expires))
                except ValueError:
                    bad.append(f"{a.plan_key}: invalid expiry {a.expires}")
                    continue
                if exp < today:
                    bad.append(f"{a.plan_key}: expired {a.expires}")
            add(r, not bad, "valid" if not bad else "; ".join(bad), [])
    return res


def posture(policy: Policy, findings: list[Finding], investigations: dict[str, Investigation] | None = None) -> list[dict]:
    """Whole-repository release gate (informational, per rule): how many open findings violate each rule."""
    out = []
    for r in policy.rules:
        if r.get("type") != "max_findings":
            continue
        hits = [f for f in findings if f.status == "open" and rule_matches(r, f, investigations)]
        out.append({"rule_id": r["id"], "severity": r.get("severity"), "description": r.get("description", ""),
                    "violations": len(hits), "passed": len(hits) <= int(r.get("max", 0)),
                    "examples": [f.title for f in hits[:3]]})
    return out
