"""Step 6 Risk assessment: rules decide, AI only explains (docs/stage4.md section 9).

Project risk comes from the first matching rule; confidence from evidence quality; the LLM writes
the explanation from verified claims only and cannot change either value.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from guardian.stage3_knowledge.schema import short_label

from .context import Stage4Context
from .schema import Fingerprint, Fix, Investigation, Verdict, Verification, VulnMatch, band_as_risk, risk_rank

PROMPTS = Path(__file__).resolve().parent / "prompts"
BAND_MIN = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1, "none": 0.0}

RULES = {
    1: "KEV-listed, used, runtime",
    2: "CVSS >= 9, vulnerable symbol called on a public path, no trigger condition ruled out",
    3: "CVSS >= 7, vulnerable symbol called, public or unknown reachability",
    4: "CVSS >= 9, vulnerable symbol called (any reachability)",
    5: "CVSS >= 9, package used at runtime but vulnerable symbol not found or unknown",
    6: "CVSS >= 7, runtime package in use",
    7: "CVSS 4-7, vulnerable symbol called",
    8: "container OS package: CVSS band, capped at High unless KEV",
    9: "runtime package that nothing imports (still ships)",
    10: "test-only, dev or build dependency",
    11: "anything else",
}

EXPLAIN_SCHEMA = {
    "type": "object",
    "properties": {"explanation": {"type": "string"}, "recommendation": {"type": "string"}},
    "required": ["explanation", "recommendation"], "additionalProperties": False,
}


def cvss_number(m: VulnMatch) -> Optional[float]:
    if m.cvss.score is not None:
        return m.cvss.score
    return BAND_MIN.get(m.cvss.band)


def project_risk(m: VulnMatch, inv: Investigation) -> tuple[str, int]:
    s = cvss_number(m)
    s = -1.0 if s is None else s
    runtime = m.scope == "runtime"
    u, r = inv.usage, inv.reachability
    ruled_out = any(c.status == "not_shown" for c in inv.conditions)
    if m.kev and u != "package_not_imported" and runtime:
        return "critical", 1
    if s >= 9 and u == "symbol_called" and r == "public_path" and not ruled_out:
        return "critical", 2
    if s >= 7 and u == "symbol_called" and r in ("public_path", "unknown"):
        return "high", 3
    if s >= 9 and u == "symbol_called":
        return "high", 4
    if s >= 9 and u in ("package_used_symbol_unknown", "package_used_symbol_not_found") and runtime:
        return ("high" if r == "public_path" else "medium"), 5
    if s >= 7 and runtime and u != "package_not_imported":
        return "medium", 6
    if 4 <= s < 7 and u == "symbol_called":
        return "medium", 7
    if m.scope == "container_os":
        band = band_as_risk(m.cvss.band)
        if not m.kev and band == "critical":
            band = "high"
        return band, 8
    if u == "package_not_imported" and runtime:
        return "low", 9
    if m.scope in ("test_only", "dev", "build"):
        return "low", 10
    return "low", 11


def confidence(m: VulnMatch, inv: Investigation, fp: Fingerprint, ver: Optional[Verification]) -> tuple[str, list[str]]:
    low: list[str] = []
    if inv.light_pass:
        if inv.usage in ("package_not_imported",):
            return "high" if not inv.dynamic_imports else "medium", ["no import of the package in the code graph (fact)"]
        if inv.usage == "not_applicable":
            return "medium", ["container package reported by Grype; usage in the image was not analysed"]
        low.append("not investigated (light pass)")
    if m.scope != "container_os" and not fp.vulnerable_symbols and inv.usage != "package_not_imported":
        low.append("vulnerable symbol unknown")
    if inv.budget_exhausted:
        low.append("tool budget exhausted")
    if ver and ver.ran and not ver.verified:
        low.append("verifier rejected a claim")
    if inv.reachability == "no_path_found" and inv.dynamic_imports:
        low.append("no path found, but dynamic imports exist near the affected code")
    if low:
        return "low", low
    reasons: list[str] = []
    usage_backed = inv.usage == "package_not_imported" or any(
        c.kind == "usage" and (c.graph_backed or c.verified) for c in inv.claims)
    reach_backed = inv.reachability in ("no_path_found",) or (bool(inv.paths) and any(
        c.kind == "reachability" and c.graph_backed for c in inv.claims))
    cond_ok = all(c.status in ("met", "not_shown") and c.evidence for c in inv.conditions)
    if not usage_backed:
        reasons.append("usage is not backed by a graph edge or verified line")
    if not reach_backed:
        reasons.append("reachability is not backed by a graph path")
    if not cond_ok:
        reasons.append("some trigger condition is unknown")
    if ver and ver.ran and ver.dropped_claims:
        reasons.append("the verifier corrected the investigation")
    if inv.usage in ("package_used_symbol_unknown",):
        reasons.append("only package-level use was checked")
    if inv.discovered_by == "algorithm" and fp.discovered_by == "algorithm" and fp.confidence < 0.5 and fp.vulnerable_symbols:
        reasons.append("vulnerable symbols were extracted from the advisory text by rules")
    if reasons:
        return "medium", reasons
    return "high", ["usage and reachability backed by graph edges and verified lines; conditions checked"]


def review_reasons(m: VulnMatch, risk: str, conf: str, ver: Optional[Verification]) -> tuple[list[str], bool]:
    reasons = []
    s = cvss_number(m) or 0
    guard = s >= 9 and m.scope == "runtime" and risk in ("medium", "low")
    if guard:
        reasons.append(f"downgrade guard: CVSS {m.cvss.score or m.cvss.band} runtime vulnerability rated {risk}")
    if conf == "low":
        reasons.append("low confidence")
    if ver and ver.ran and not ver.verified:
        reasons.append("the verifier rejected a claim")
    if risk == "critical":
        reasons.append("critical project risk must be confirmed before it is reported")
    return reasons, guard


def fix_of(m: VulnMatch, fp: Fingerprint) -> Fix:
    code = None
    if fp.safe_alternatives:
        code = f"use {' / '.join(fp.safe_alternatives[:2])} instead of {' / '.join(fp.vulnerable_symbols[:2]) or 'the vulnerable API'}"
    return Fix(upgrade_to=m.fixed_versions[0] if m.fixed_versions else None, code_change=code)


def verdict(m: VulnMatch, inv: Investigation, fp: Fingerprint, ver: Optional[Verification]) -> Verdict:
    risk, rule = project_risk(m, inv)
    conf, conf_reasons = confidence(m, inv, fp, ver)
    reasons, guard = review_reasons(m, risk, conf, ver)
    if inv.light_pass and "low confidence" in reasons and not guard and risk != "critical":
        reasons.remove("low confidence")       # light-pass items are marked "not investigated", not queued
    return Verdict(project_risk=risk, rule=rule, rule_text=RULES[rule], confidence=conf, confidence_reasons=conf_reasons,
                   needs_human_review=bool(reasons), review_reasons=reasons, downgrade_guard=guard, fix=fix_of(m, fp))


# --------------------------------------------------------------------------- explanation

USAGE_TEXT = {
    "symbol_called": "the vulnerable code is called",
    "package_used_symbol_not_found": "the package is used, but no call to the vulnerable function was found",
    "package_used_symbol_unknown": "the package is used; which function is vulnerable is not known",
    "package_not_imported": "no code imports the package",
    "not_applicable": "it is an operating-system package in the container image",
}


def template_explanation(m: VulnMatch, inv: Investigation, fp: Fingerprint, v: Verdict) -> tuple[str, str]:
    parts = []
    site = next((s for s in inv.usage_sites if not s.in_test), None)
    if inv.usage == "symbol_called" and site:
        parts.append(f"{site.symbol or 'The vulnerable symbol'} is used in {short_label(site.function)} "
                     f"({site.file}:{site.lines})" + (f": `{site.code.strip()[:90]}`" if site.code else "") + ".")
    elif inv.usage == "package_used_symbol_not_found":
        parts.append(f"{m.package_name} is used, but no call to {', '.join(fp.vulnerable_symbols[:3])} was found.")
    elif inv.usage == "package_used_symbol_unknown":
        note = next((n for n in inv.notes if "not imported directly" in n), "")
        parts.append(note or f"{m.package_name} is used; the advisory does not name the vulnerable function, so only package-level use was checked.")
    elif inv.usage == "package_not_imported":
        parts.append(f"No code imports {m.package_name}; it is still installed" +
                     (f" as a {m.scope} dependency." if m.scope != "runtime" else "."))
    else:
        parts.append(f"{m.package_name} {m.version} is an OS package in {m.image or 'the container image'}.")
    ents = inv.entries
    if inv.reachability == "public_path":
        pub = [e["label"] for e in ents if e.get("public")]
        parts.append(f"It is reachable from {', '.join(pub[:2]) or 'a public entry point'}.")
    elif inv.reachability == "internal_only":
        parts.append(f"It runs from {', '.join(e['label'] for e in ents[:2])}; no path from a public route was found.")
    elif inv.reachability == "no_path_found" and inv.usage != "package_not_imported":
        parts.append("No path from a route, CLI or startup code was found (this is not proof that it cannot run).")
    unknown = [c for c in inv.conditions if c.status == "unknown"]
    shown = [c for c in inv.conditions if c.status == "not_shown"]
    met = [c for c in inv.conditions if c.status == "met"]
    if met:
        parts.append("Trigger condition met: " + "; ".join(c.note or c.text for c in met[:2]) + ".")
    if shown:
        parts.append("Not shown: " + "; ".join(c.note or c.text for c in shown[:2]) + ".")
    if unknown and not shown:
        parts.append("Not verified: " + "; ".join(c.text for c in unknown[:2]) + ".")
    rec = []
    if v.fix.upgrade_to:
        rec.append(f"Upgrade {m.package_name} to {v.fix.upgrade_to} or later")
    elif m.scope == "container_os":
        rec.append(f"Rebuild on a base image with a fixed {m.package_name}")
    if fp.safe_alternatives and inv.usage == "symbol_called":
        rec.append(f"switch to {' / '.join(f'`{s}`' for s in fp.safe_alternatives[:2])}")
    if inv.usage == "package_not_imported" and m.scope == "runtime":
        rec.append(f"or remove the unused dependency")
    recommendation = (rec[0] + "".join(f", {r}" if r.startswith("or ") else f", or {r}" for r in rec[1:]) + ".") if rec \
        else "No fixed version is published yet; limit exposure of the affected code."
    return " ".join(parts), recommendation


ID_RE = re.compile(r"\b(CVE-\d{4}-\d+|GHSA-[\w-]{14}|PYSEC-\d{4}-\d+)\b")
VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)*\b")
FORBIDDEN = re.compile(r"not exploitable|cannot be exploited|is safe\b|no risk", re.I)


def explanation_ok(text: str, m: VulnMatch, allowed_versions: set[str]) -> bool:
    ids = set(ID_RE.findall(text))
    if ids - {m.vuln_id, *m.aliases}:
        return False
    if {v for v in VERSION_RE.findall(text)} - allowed_versions:
        return False
    return not FORBIDDEN.search(text)


def explain(ctx: Stage4Context, m: VulnMatch, inv: Investigation, fp: Fingerprint, v: Verdict,
            use_llm: bool = True) -> Verdict:
    text, rec = template_explanation(m, inv, fp, v)
    v.explanation, v.recommendation, v.explanation_by = text, rec, "template"
    llm = ctx.llm
    if not use_llm or inv.light_pass or not (llm.available or llm.cache_dir.exists()):
        return v
    verified = [{"claim": c.text, "evidence": [e.label() for e in c.evidence]} for c in inv.claims if c.verified is not False]
    allowed = {x for x in [m.version or "", *m.fixed_versions, *(r.introduced or "" for r in m.affected_ranges),
                           *(r.fixed or "" for r in m.affected_ranges), str(m.cvss.score or "")] if x}
    allowed |= {v2 for c in inv.claims for v2 in VERSION_RE.findall(c.text)}
    system = (PROMPTS / "explain_system.md").read_text(encoding="utf-8")
    prompt = (f"Vulnerability {m.vuln_id} in {m.package_name} {m.version}; CVSS {m.cvss.score} ({m.cvss.band}).\n"
              f"Project risk (decided by rules, do not change): {v.project_risk}. Confidence: {v.confidence}.\n"
              f"Usage: {inv.usage}. Reachability: {inv.reachability}.\n"
              f"Conditions: {[c.model_dump(include={'text', 'status', 'note'}) for c in inv.conditions]}\n"
              f"Unknowns: {inv.unknowns}\nVerified claims: {verified}\n"
              f"Fixed versions: {m.fixed_versions or 'none published'}; safe alternatives: {fp.safe_alternatives or 'none'}")
    raw = llm.complete_json("explain", system, prompt, EXPLAIN_SCHEMA)
    if raw and raw.get("explanation") and explanation_ok(raw["explanation"] + " " + raw.get("recommendation", ""), m, allowed):
        v.explanation = raw["explanation"].strip()[:900]
        v.recommendation = (raw.get("recommendation") or rec).strip()[:300]
        v.explanation_by = "ai"
    return v
