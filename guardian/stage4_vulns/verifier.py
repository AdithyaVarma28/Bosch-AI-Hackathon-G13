"""Step 5 Verifier (conditional): re-fetch every cited line and check it shows the claim.

Runs only when a cheaper pass is not enough (section 8 triggers). Each claim is checked twice when an
LLM is available: a deterministic token check (the code names in the claim appear in the cited lines)
and an LLM judgement on the same lines. A failed claim goes back to the investigator once with the
objection; if it fails again it is dropped and confidence drops.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from guardian.stage3_knowledge.schema import Evidence

from .context import Stage4Context
from .schema import ClaimCheck, Investigation, Verdict, Verification, VulnMatch, band_as_risk, risk_rank
from .tools import VulnToolbox

PROMPTS = Path(__file__).resolve().parent / "prompts"
ABSENCE = re.compile(r"^\s*(no |none |not |nothing )", re.I)
VERIFY_SCHEMA = {
    "type": "object",
    "properties": {"results": {"type": "array", "items": {
        "type": "object", "properties": {"index": {"type": "integer"}, "supported": {"type": "boolean"},
                                         "objection": {"type": "string"}},
        "required": ["index", "supported", "objection"], "additionalProperties": False}}},
    "required": ["results"], "additionalProperties": False,
}
NOISE = {"self", "cls", "None", "True", "False", "return", "from", "import"}


def triggers(m: VulnMatch, inv: Investigation, prelim: Verdict) -> list[str]:
    out = []
    if risk_rank(prelim.project_risk) < risk_rank(band_as_risk(m.cvss.band)):
        out.append(f"project risk {prelim.project_risk} is below the CVSS band {m.cvss.band}")
    if prelim.project_risk == "critical":
        out.append("project risk is critical")
    if prelim.confidence in ("medium", "low"):
        out.append(f"confidence would be {prelim.confidence}")
    if inv.claims and not any(c.graph_backed for c in inv.claims):
        out.append("claims rest on read_code only (no graph edge backs them)")
    if (inv.reachability == "public_path" and inv.usage == "package_used_symbol_not_found") or \
            (inv.usage == "package_not_imported" and inv.reachability in ("public_path", "internal_only")):
        out.append(f"usage ({inv.usage}) and reachability ({inv.reachability}) disagree")
    return out


def claim_tokens(text: str) -> list[str]:
    toks: list[str] = []
    quoted: list[str] = []
    for code in re.findall(r"`([^`]+)`", text):
        found = re.findall(r"[A-Za-z0-9_]\w*(?:\.[A-Za-z_]\w*)*", code)
        toks += found
        quoted += [t.split(".")[-1] for t in found if len(t.split(".")[-1]) >= 3]
    toks += re.findall(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\b", re.sub(r"`[^`]*`", " ", text))
    toks += re.findall(r"\b([A-Za-z_]\w*)\(\)", text)
    tails = []
    for t in toks:
        tail = t.split(".")[-1]
        if len(tail) >= 3 and tail not in NOISE and (tail in quoted or "_" in tail or "." in t
                                                     or re.search(r"[a-z][A-Z]", tail) or t + "()" in text):
            tails.append(tail)
    return list(dict.fromkeys(tails))


def deterministic_check(G, claim_text: str, evidence: list[Evidence], texts: list[str]) -> tuple[bool, str]:
    joined = "\n".join(texts)
    files = [e for e in evidence if e.file]
    nodes = [e for e in evidence if e.node and not e.file]
    if files and not texts:
        return False, "the cited lines could not be read"
    if nodes and not files:
        missing = [e.node for e in nodes if e.node not in G]
        return (not missing, "cited graph node(s) exist" if not missing else f"unknown node(s) {missing}")
    if ABSENCE.match(claim_text):
        return True, "absence claim: the cited lines are where the search looked"
    toks = claim_tokens(claim_text)
    if not toks:
        return True, "lines exist (no code names to match)"
    hit = [t for t in toks if re.search(rf"\b{re.escape(t)}\b", joined)]
    if hit:
        return True, f"cited lines contain {', '.join(hit[:3])}"
    return False, f"cited lines do not contain {', '.join(toks[:3])}"


def verify(ctx: Stage4Context, m: VulnMatch, inv: Investigation, trig: list[str], emit=lambda e: None,
           retried: bool = False) -> tuple[Verification, list[dict]]:
    tb = VulnToolbox(ctx, m, budget=max(4, 2 * len(inv.claims) + 2), stage="verifier", emit=emit)
    checks: list[ClaimCheck] = []
    fetched: list[list[str]] = []
    for c in inv.claims:
        texts: list[str] = []
        for e in [x for x in c.evidence if x.file][:2]:
            rng = e.line_range()
            if not rng:
                continue
            out = tb.call("verify_evidence", {"file": e.file, "lines": f"{rng[0]}-{rng[1]}", "claim": c.text})
            texts += out.get("text") or []
        ok, why = deterministic_check(ctx.G, c.text, c.evidence, texts)
        checks.append(ClaimCheck(text=c.text, ok=ok, reason=why, lines=texts[:6]))
        fetched.append(texts)
    discovered_by = "algorithm"
    llm = ctx.llm
    if checks and (llm.available or llm.cache_dir.exists()):
        system = (PROMPTS / "verifier_system.md").read_text(encoding="utf-8")
        items = "\n\n".join(f"[{i}] Claim: {c.text}\nCited lines:\n" + ("\n".join(t) or "(none: graph evidence only)")
                            for i, (c, t) in enumerate(zip(inv.claims, fetched)))
        raw = llm.complete_json("verifier", system, items, VERIFY_SCHEMA)
        if raw:
            discovered_by = "ai"
            for r in raw.get("results") or []:
                i = r.get("index")
                if isinstance(i, int) and 0 <= i < len(checks) and not r.get("supported") and checks[i].ok:
                    checks[i].ok = False
                    checks[i].reason = f"verifier: {r.get('objection') or 'the lines do not show the claim'}"
    for c, chk in zip(inv.claims, checks):
        c.verified = chk.ok
    failed = [f"'{c.text[:120]}': {c.reason}" for c in checks if not c.ok]
    ver = Verification(ran=True, triggers=trig, verified=not failed, checks=checks, retried=retried,
                       objections=failed, discovered_by=discovered_by)
    return ver, tb.activity


def apply_verification(inv: Investigation, ver: Verification) -> Investigation:
    """Drop claims that failed (after the one retry) and weaken verdicts that lost all support."""
    keep = [c for c in inv.claims if c.verified is not False]
    dropped = [c for c in inv.claims if c.verified is False]
    if not dropped:
        return inv
    inv.claims = keep
    ver.dropped_claims = [c.text for c in dropped]
    inv.dropped += [f"verifier dropped: {c.text[:120]}" for c in dropped]
    if inv.usage == "symbol_called" and not any(c.kind == "usage" for c in keep) and \
            not any(s.via == "graph" for s in inv.usage_sites):
        inv.usage = "package_used_symbol_unknown"
        inv.notes.append("the usage claim failed verification; usage lowered to package_used_symbol_unknown")
    if inv.reachability in ("public_path", "internal_only") and not any(c.kind == "reachability" for c in keep):
        inv.notes.append(f"the {inv.reachability} claim failed verification; reachability set to unknown")
        inv.reachability = "unknown"
    return inv
