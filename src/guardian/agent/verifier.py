"""Deterministic Verifier: no LLM claim reaches the report unless it is backed by stored evidence.

Rules (in order):
 1. every cited evidence id must exist, else REJECTED
 2. every `backtick-quoted` token in the claim must appear in the cited excerpts, else REJECTED
 3. a `fact` must cite at least one RAW evidence item, else DOWNGRADED to inference
 4. an `inference` with no evidence is DOWNGRADED to unknown
"""
from __future__ import annotations

import re

from ..models import Claim
from ..store import RunStore

TOKEN = re.compile(r"`([^`]{1,200})`")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def verify_claims(claims: list[Claim], store: RunStore) -> list[Claim]:
    out = []
    for c in claims:
        c = c.model_copy()
        evs = [store.get_evidence(e) for e in c.evidence_ids]
        if any(e is None for e in evs):
            missing = [i for i, e in zip(c.evidence_ids, evs) if e is None]
            c.verifier_status, c.reason = "rejected", f"unknown evidence id(s): {', '.join(missing)}"
            out.append(c)
            continue
        corpus = _norm(" ".join(f"{e.locator} {e.excerpt}" for e in evs if e))
        bad = [t for t in TOKEN.findall(c.text) if _norm(t) not in corpus]
        if bad:
            c.verifier_status, c.reason = "rejected", f"quoted token(s) not found in cited evidence: {', '.join(bad[:3])}"
            out.append(c)
            continue
        if c.type == "fact" and not any(e and e.kind == "raw" for e in evs):
            c.type, c.verifier_status, c.reason = "inference", "downgraded", "fact cited only derived evidence"
        elif c.type == "inference" and not evs:
            c.type, c.verifier_status, c.reason = "unknown", "downgraded", "inference without evidence"
        else:
            c.verifier_status = "verified"
        out.append(c)
    return out


def safe_claim(text: str, type_: str, evidence_ids: list[str], confidence: str = "medium") -> Claim | None:
    """Build a Claim from untrusted LLM output; returns None if it cannot be a valid claim."""
    if type_ not in ("fact", "inference", "unknown"):
        type_ = "inference"
    if confidence not in ("low", "medium", "high"):
        confidence = "medium"
    ids = [str(e) for e in (evidence_ids or []) if isinstance(e, (str, int))][:10]
    if type_ == "fact" and not ids:
        type_ = "inference"
    try:
        return Claim(text=str(text)[:600], type=type_, evidence_ids=ids, confidence=confidence)
    except ValueError:
        return None
