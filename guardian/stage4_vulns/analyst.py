"""Step 3 Advisory analyst: advisory text (+ fix-commit function names) -> Fingerprint.

With an LLM: one structured-output call per vulnerability, validated afterwards. Without one (or when
the call fails): deterministic extraction from the advisory text. Both are held to the same checks:

* every symbol must start with an import name of the affected package (others are dropped),
* every quoted evidence span must appear in the advisory text,
* no symbols -> ``symbols_source: none`` (the investigator then checks package-level usage only).
"""
from __future__ import annotations

import builtins
import json
import keyword
import re
from pathlib import Path
from typing import Optional

from .context import Stage4Context
from .graphfacts import import_names
from .schema import Fingerprint, QuoteEvidence, Trigger, VulnMatch
from .sources import fix_commit_functions

PROMPTS = Path(__file__).resolve().parent / "prompts"
MAX_ADVISORY_CHARS = 8000

FINGERPRINT_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerable_symbols": {"type": "array", "items": {"type": "string"}},
        "safe_alternatives": {"type": "array", "items": {"type": "string"}},
        "trigger_conditions": {"type": "array", "items": {
            "type": "object",
            "properties": {"type": {"type": "string", "enum": ["untrusted_input", "argument", "config", "other"]},
                           "text": {"type": "string"}},
            "required": ["type", "text"], "additionalProperties": False}},
        "impact": {"type": "string"},
        "attack_vector": {"type": "string", "enum": ["network", "adjacent", "local", "physical", "unknown"]},
        "symbols_source": {"type": "string", "enum": ["advisory_text", "fix_commit", "none"]},
        "confidence": {"type": "number"},
        "evidence": {"type": "array", "items": {
            "type": "object", "properties": {"quote_span": {"type": "string"}},
            "required": ["quote_span"], "additionalProperties": False}},
    },
    "required": ["vulnerable_symbols", "safe_alternatives", "trigger_conditions", "impact", "attack_vector",
                 "symbols_source", "confidence", "evidence"],
    "additionalProperties": False,
}

AV = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
IMPACTS = [
    (r"(remote )?(arbitrary )?code execution|execute arbitrary code|\bRCE\b", "code execution"),
    (r"sql injection", "SQL injection"),
    (r"command injection|os command", "command injection"),
    (r"path traversal|directory traversal|zip slip", "path traversal"),
    (r"server[- ]side request forgery|\bSSRF\b", "server-side request forgery"),
    (r"cross[- ]site scripting|\bXSS\b", "cross-site scripting"),
    (r"denial of service|\bReDoS\b|\bDoS\b|resource consumption|infinite loop", "denial of service"),
    (r"credential|password|token|leak|disclos|exposure of sensitive", "information disclosure"),
    (r"certificate|tls|ssl|verif", "certificate validation bypass"),
    (r"deserializ|pickle", "unsafe deserialization"),
]
CODE_WORDS = r"(?:method|function|class|loader|constructor|object|module|api|utility|helper|decorator|call|endpoint)s?"
ARG_WORDS = r"(?:flag|parameter|argument|option|kwarg|keyword|attribute|setting)s?"
UNTRUSTED = re.compile(r"untrusted|attacker|malicious|crafted|user[- ]supplied|user[- ]controlled|arbitrary input|remote", re.I)
BUILTIN_NAMES = set(dir(builtins))
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


def norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


def advisory_text(m: VulnMatch) -> str:
    return f"{m.summary}\n\n{m.details}".strip()[:MAX_ADVISORY_CHARS]


def attack_vector(m: VulnMatch) -> str:
    mm = re.search(r"/AV:([NALP])", m.cvss.vector or "")
    return AV[mm.group(1)] if mm else "unknown"


def impact_of(text: str) -> str:
    for rx, label in IMPACTS:
        if re.search(rx, text, re.I):
            return label
    return ""


def _code_shaped(tok: str) -> bool:
    return "_" in tok or "." in tok or bool(re.search(r"[a-z][A-Z]", tok)) or bool(re.match(r"^[A-Z][a-z]+[A-Z]", tok))


def _sentence(text: str, token: str) -> str:
    for s in re.split(r"(?<=[.!?])\s+", text):
        if token in s:
            return s.strip()[:240]
    return token


def validate_symbols(symbols: list[str], imports: list[str]) -> tuple[list[str], list[str]]:
    keep, dropped = [], []
    for s in symbols:
        s = (s or "").strip().strip("`").removesuffix("()").strip()
        if not s:
            continue
        if any(s == i or s.startswith(i + ".") for i in imports) and re.fullmatch(rf"{IDENT}(\.{IDENT})*", s):
            if s not in keep:
                keep.append(s)
        else:
            dropped.append(s)
    return keep, dropped


def extract_offline(m: VulnMatch, imports: list[str], fix_fns: list[str]) -> Fingerprint:
    """Deterministic fingerprint from the advisory text (no AI)."""
    text = advisory_text(m)
    # URLs and markdown link targets carry dotted names that are hosts or anchors, not APIs
    scan = re.sub(r"\]\([^)]*\)", "]", text)
    scan = re.sub(r"https?://\S+", " ", scan)
    cands: list[tuple[str, str]] = []           # (token, how)
    triggers: list[Trigger] = []
    quotes: list[str] = []
    arg_tokens: set[str] = set()

    for mm in re.finditer(r"`([^`\n]{1,80})`", scan):
        tok = mm.group(1).strip()
        after = scan[mm.end():mm.end() + 24]
        if "=" in tok and re.match(rf"^{IDENT}\s*=", tok):
            triggers.append(Trigger(type="argument", text=f"called with {tok}"))
            quotes.append(_sentence(text, tok))
        elif re.fullmatch(IDENT, tok) and re.match(rf"\s+{ARG_WORDS}\b", after, re.I):
            arg_tokens.add(tok)                 # "`pre_dispatch` flag": an argument, not a symbol
            triggers.append(Trigger(type="argument", text=f"the {tok} argument is attacker-controlled or set unsafely"))
            quotes.append(_sentence(text, tok))
        elif re.fullmatch(rf"{IDENT}(\.{IDENT})*(\(\))?", tok):
            cands.append((tok, "backtick"))
    for imp in imports:
        for mm in re.finditer(rf"\b{re.escape(imp)}(?:\.{IDENT})+", scan):
            cands.append((mm.group(0), "dotted"))
    for mm in re.finditer(rf"\b({IDENT}(?:\.{IDENT})*)\(\)", scan):
        cands.append((mm.group(1), "call"))
    for mm in re.finditer(rf"\b({IDENT})`?\s+{CODE_WORDS}\b", scan, re.I):
        if _code_shaped(mm.group(1)):
            cands.append((mm.group(1), "word"))
    for mm in re.finditer(rf"\b({IDENT})`?\s+{ARG_WORDS}\b", scan, re.I):
        tok = mm.group(1)
        if _code_shaped(tok) and tok not in arg_tokens and tok not in [c for c, _ in cands]:
            arg_tokens.add(tok)
            triggers.append(Trigger(type="argument", text=f"the {tok} argument is attacker-controlled or set unsafely"))
            quotes.append(_sentence(text, tok))

    pkg_names = {m.package_name.lower(), *[i.lower() for i in imports]}
    symbols: list[str] = []
    dropped: list[str] = []
    strong = False
    for tok, how in cands:
        tok = tok.removesuffix("()")
        root = tok.split(".")[0]
        tail = tok.split(".")[-1]
        if tok.lower() in pkg_names or re.match(r"^(CVE|GHSA|PYSEC)", tok, re.I) or tok.isdigit():
            continue
        if keyword.iskeyword(tail) or len(tail) < 3 or (tail.isupper() and "." not in tok) or tok in arg_tokens:
            dropped.append(tok)                 # operators, placeholders, constants/env vars, arguments
            continue
        if "." not in tok and tok in BUILTIN_NAMES:
            dropped.append(tok)
            continue
        if "." in tok and root not in imports:
            dropped.append(tok)                 # another module's API (e.g. os.system): not this package
            continue
        full = tok if root in imports else f"{imports[0]}.{tok}"
        if full not in symbols:
            symbols.append(full)
            quotes.append(_sentence(text, tok))
            strong = strong or how in ("backtick", "dotted", "call")
    source = "advisory_text" if symbols else "none"
    if not symbols and fix_fns:
        public = [f for f in fix_fns if not f.startswith("_")]
        symbols = [f"{imports[0]}.{f}" for f in public[:6]]
        source = "fix_commit" if symbols else "none"
    safe: list[str] = []
    for mm in re.finditer(rf"\buse\s+`?({IDENT}(?:\.{IDENT})*)`?(?:\(\))?\s+instead", text, re.I):
        safe.append(mm.group(1))
    for mm in re.finditer(r"\b((?:safe_|Safe)[A-Za-z_]+)\b", text):
        safe.append(mm.group(1))
    safe = [s if s.split(".")[0] in imports else f"{imports[0]}.{s}" for s in dict.fromkeys(safe)]
    if UNTRUSTED.search(text):
        triggers.insert(0, Trigger(type="untrusted_input", text="attacker-controlled input reaches the vulnerable code"))
        quotes.append(_sentence(text, UNTRUSTED.search(text).group(0)))
    seen_t = set()
    triggers = [t for t in triggers if not (t.text in seen_t or seen_t.add(t.text))]
    conf = 0.0 if not symbols else (0.6 if strong else 0.45)
    if source == "fix_commit":
        conf = 0.35
    return Fingerprint(
        vuln_id=m.vuln_id, vulnerable_symbols=symbols, safe_alternatives=safe[:4], trigger_conditions=triggers[:4],
        impact=impact_of(text), attack_vector=attack_vector(m), symbols_source=source, confidence=conf,
        evidence=[QuoteEvidence(advisory=m.vuln_id, quote_span=q) for q in dict.fromkeys(quotes) if q][:4],
        dropped_symbols=sorted(set(dropped)), fix_functions=fix_fns, discovered_by="algorithm",
    )


def validate_llm(m: VulnMatch, raw: dict, imports: list[str], fix_fns: list[str]) -> Fingerprint:
    text = norm_text(advisory_text(m))
    symbols, dropped = validate_symbols(raw.get("vulnerable_symbols") or [], imports)
    safe, _ = validate_symbols(raw.get("safe_alternatives") or [], imports)
    quotes = []
    bad_quotes = 0
    for e in raw.get("evidence") or []:
        q = (e or {}).get("quote_span", "")
        if q and norm_text(q) in text:
            quotes.append(QuoteEvidence(advisory=m.vuln_id, quote_span=q.strip()[:300]))
        else:
            bad_quotes += 1
    source = raw.get("symbols_source") if raw.get("symbols_source") in ("advisory_text", "fix_commit") else "advisory_text"
    if source == "fix_commit" and not fix_fns:
        source = "advisory_text"
    if not symbols:
        source = "none"
    try:
        conf = min(1.0, max(0.0, float(raw.get("confidence", 0.5))))
    except (TypeError, ValueError):
        conf = 0.5
    if dropped or bad_quotes:
        conf = round(conf * 0.85, 2)
    triggers = []
    for t in raw.get("trigger_conditions") or []:
        try:
            triggers.append(Trigger(**t))
        except Exception:
            continue
    av = raw.get("attack_vector") if raw.get("attack_vector") in ("network", "adjacent", "local", "physical") else attack_vector(m)
    return Fingerprint(vuln_id=m.vuln_id, vulnerable_symbols=symbols, safe_alternatives=safe,
                       trigger_conditions=triggers[:6], impact=str(raw.get("impact") or "")[:80], attack_vector=av,
                       symbols_source=source, confidence=conf if symbols else min(conf, 0.3), evidence=quotes[:6],
                       dropped_symbols=dropped, fix_functions=fix_fns, discovered_by="ai")


def analyze(ctx: Stage4Context, m: VulnMatch) -> Fingerprint:
    imports = import_names(ctx.s3, m.package) if m.package in ctx.G else [m.package_name.lower().replace("-", "_")]
    if m.scope == "container_os":
        return Fingerprint(vuln_id=m.vuln_id, symbols_source="none", confidence=0.0, impact=impact_of(advisory_text(m)),
                           attack_vector=attack_vector(m))
    llm = ctx.llm
    use_llm = llm.available or llm.cache_dir.exists()
    fix_fns = fix_commit_functions(m.references, ctx.cache) if use_llm and not ctx.cache.offline else []
    if use_llm:
        system = (PROMPTS / "analyst_system.md").read_text(encoding="utf-8")
        prompt = (f"Package: {m.package_name} {m.version}\nImport names: {', '.join(imports)}\n"
                  f"Advisory: {m.vuln_id} (aliases: {', '.join(m.aliases) or 'none'})\n"
                  f"CVSS vector: {m.cvss.vector or 'not given'}\n"
                  f"Fix-commit functions: {', '.join(fix_fns) or 'not available'}\n\n"
                  f"Advisory text:\n\"\"\"\n{advisory_text(m)}\n\"\"\"")
        raw = llm.complete_json("analyst", system, prompt, FINGERPRINT_SCHEMA)
        if raw:
            return validate_llm(m, raw, imports, fix_fns)
    return extract_offline(m, imports, fix_fns)


def fingerprint_summary(fp: Fingerprint) -> str:
    return json.dumps({"symbols": fp.vulnerable_symbols, "source": fp.symbols_source,
                       "conditions": [t.text for t in fp.trigger_conditions]}, ensure_ascii=False)
