"""Grouping, priority bands, exposure, and the suspicion x exposure -> project risk rules (docs/stage5.md 4, 6)."""
from __future__ import annotations

from typing import Optional

from guardian.purl import normalize_name
from guardian.stage4_vulns.graphfacts import classify, files_using, package_functions, reach, used_requirers
from guardian.stage3_knowledge.graph_builder import succ

from .context import Stage5Context
from .schema import STRENGTH_RANK, AnomalyInvestigation, Signal

INSTALL_FILES = ("setup.py", "build_backend.py", "_build.py")
CONTEXT_ONLY = ("commit_message_silent",)
RISK = {  # suspicion -> {exposure column -> risk}
    "high": {"hot": "critical", "internal": "high", "cold": "medium"},
    "medium": {"hot": "high", "internal": "medium", "cold": "low"},
    "low": {"hot": "medium", "internal": "low", "cold": "low"},
}
COLUMN = {"install_path": "hot", "runtime_public": "hot", "build_env": "hot", "runtime_internal": "internal",
          "installed_unused": "cold", "not_in_install_set": "cold", "unknown": "cold"}


def group(signals: list[Signal]) -> dict[str, list[Signal]]:
    groups: dict[str, list[Signal]] = {}
    for s in signals:
        groups.setdefault(s.subject, []).append(s)
    # context-only signals (weak, e.g. a silent commit message) never make a finding on their own
    groups = {k: v for k, v in groups.items() if any(s.check not in CONTEXT_ONLY for s in v)}
    for subj, sigs in groups.items():   # D1 + D4 behaviour in the same package -> the name match becomes strong
        if any(s.detector == "D4" and s.behaviour for s in sigs):
            for s in sigs:
                if s.detector == "D1":
                    s.strength = "strong"
                    s.metadata_only = False          # now backed by install behaviour, not metadata alone
                    s.data["escalated_by"] = "D4 install behaviour in the same package"
    return groups


def exposure(ctx: Stage5Context, subject: str, sigs: list[Signal]) -> tuple[str, str]:
    G = ctx.G
    if subject.startswith(("image:", "workflow:")):
        return "build_env", "used to build or run the application (CI workflow / container image)"
    if subject.startswith("file:"):
        path = subject[5:]
        if subject not in G:
            return "unknown", f"{path} is not a code file in the graph"
        fns = [c for c in succ(G, subject, "CONTAINS") if G.nodes[c].get("type") == "Function"]
        ents = [e for fn in fns for e in reach(G, fn)["entries"]]
        r = classify(ents)
        if r == "public_path":
            return "runtime_public", f"code in {path} is reachable from {', '.join(sorted({e['label'] for e in ents if e['public']})[:2])}"
        if r == "internal_only":
            return "runtime_internal", f"code in {path} runs from {', '.join(sorted({e['label'] for e in ents})[:2])}"
        return "unknown", f"no entry point reaches code in {path}"
    if subject not in G or G.nodes[subject].get("type") != "Package":
        return "not_in_install_set", "present in files or history but not in the resolved install set"
    d = G.nodes[subject]
    name, ver = d.get("name"), ctx.pkg_version(subject)
    files = ctx.pypi.files(name, ver) if ver else []
    sdist_only = bool(files) and all(f.get("packagetype") == "sdist" for f in files)
    pkg_files = [e.get("package_file", "") for s in sigs for e in s.evidence if e.get("package_file")]
    install_beh = any(p.rsplit("/", 1)[-1] in INSTALL_FILES for p in pkg_files)
    pth = any(s.check == "pth_code" for s in sigs)
    if pth:
        return "install_path", "in the install set; a .pth file runs on every Python start (not executed during our scan)"
    if install_beh and sdist_only:
        return "install_path", ("in the resolved install set and sdist-only, so its setup.py runs whenever this project "
                                "is installed (e.g. in CI). Not executed during our scan.")
    runtime, _ = files_using(G, subject)
    users = runtime or [f for r in used_requirers(G, subject) for f in files_using(G, r)[0]]
    if users:
        fns = package_functions(G, subject) or [f for r in used_requirers(G, subject) for f in package_functions(G, r)]
        ents = [e for fn in fns[:6] for e in reach(G, fn)["entries"]]
        r = classify(ents)
        via = "" if runtime else " (through the packages that require it)"
        if r == "public_path":
            return "runtime_public", f"imported{via} by code reachable from {', '.join(sorted({e['label'] for e in ents if e['public']})[:2])}"
        return "runtime_internal", f"imported{via} by {', '.join(sorted(G.nodes[f]['path'] for f in users)[:2])}; no public path found"
    if sdist_only:
        return "install_path", "in the install set and sdist-only: its build code runs on install (not executed during our scan)"
    return "installed_unused", "in the install set, never imported, and no install-time code was found"


def band(sigs: list[Signal], exp: str, radius: Optional[str]) -> str:
    strengths = [s.strength for s in sigs]
    med = strengths.count("medium")
    if "strong" in strengths or (med and exp in ("install_path", "runtime_public")):
        return "P1"
    if med >= 2 or (med and (radius in ("public", "large") or exp == "build_env")):
        return "P2"
    return "P3"


def sort_key(sigs: list[Signal]) -> tuple:
    return (-max(STRENGTH_RANK[s.strength] for s in sigs), -len(sigs))


def suspicion(sigs: list[Signal], inv: AnomalyInvestigation) -> tuple[str, str]:
    strong = [s for s in sigs if s.strength == "strong"]
    medium = [s for s in sigs if s.strength == "medium"]
    verified_ids = {c.text.split(":", 1)[0] for c in inv.claims if c.verified}
    if inv.normal_explanation and inv.normal_explanation_verified:
        return "low", f"verified normal explanation: {inv.normal_explanation}"
    if any(s.check == "hash_mismatch" for s in strong):
        return "high", "lockfile hash does not match the hash PyPI publishes"
    if any(s.signal_id in verified_ids and s.behaviour for s in strong):
        return "high", "strong signal whose behaviour is verified in the cited lines"
    if strong:
        return "medium", "strong signal without verified behaviour"
    if len(medium) >= 2:
        return "medium", f"{len(medium)} medium signals"
    return "low", "single medium/weak or metadata-only signal"


def project_risk(susp: str, exp: str) -> str:
    return RISK[susp][COLUMN.get(exp, "cold")]


def confidence(inv: AnomalyInvestigation, sigs: list[Signal], ver_ok: bool) -> tuple[str, list[str]]:
    if inv.light_pass:
        return "low", ["light pass: rules only, no investigation"]
    if inv.budget_exhausted:
        return "low", ["tool budget exhausted"]
    if not ver_ok:
        return "low", ["verifier rejected a claim"]
    if any(s.behaviour for s in sigs) and any(c.verified for c in inv.claims):
        return "high", ["behaviour and exposure backed by verified lines and graph edges"]
    if inv.normal_explanation_verified:
        return "high", ["normal explanation verified against package metadata and code"]
    return "medium", ["based on metadata or partly inferred exposure"]


def review_reasons(sigs: list[Signal], risk: str, conf: str, ver_ok: bool, light: bool) -> tuple[list[str], bool]:
    reasons = []
    guard = any(s.strength == "strong" for s in sigs) and risk == "low"
    if guard:
        reasons.append("downgrade guard: a strong signal ended at Low")
    if conf == "low" and not light:
        reasons.append("low confidence")
    if not ver_ok:
        reasons.append("the verifier rejected a claim")
    if risk == "critical":
        reasons.append("critical project risk must be confirmed before it is reported")
    return reasons, guard


def subject_name(ctx: Stage5Context, subject: str) -> str:
    if subject in ctx.G and ctx.G.nodes[subject].get("type") == "Package":
        d = ctx.G.nodes[subject]
        return f"{d.get('name')} {ctx.pkg_version(subject) or ''}".strip()
    return subject.split(":", 1)[-1]


def norm(name: str) -> str:
    return normalize_name(name)
