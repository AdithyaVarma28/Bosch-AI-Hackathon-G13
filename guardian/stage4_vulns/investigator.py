"""Step 4 Repository investigator: usage, reachability and trigger conditions, with evidence.

Two ways to the same ``Investigation``:

* **playbook** (no LLM, or the LLM failed): a fixed sequence of tool calls through the same toolbox, so
  the activity timeline and the evidence ledger look exactly like an agent's.
* **agent** (LLM): a bounded tool-calling loop; its submission is validated against the ledger and the
  graph (usage sites must have been read, paths must be real CALLS chains, enum values enforced).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from guardian.stage3_knowledge.graph_builder import in_edges, out_edges
from guardian.stage3_knowledge.schema import Evidence, short_label

from .agent import run_tool_agent
from .context import Stage4Context
from .graphfacts import (api_of, classify, dynamic_import_files, enclosing_function, files_using, import_names,
                         inputs_on_paths, package_functions, used_requirers)
from .schema import (CONDITION_STATUS, REACHABILITY, USAGES, Claim, ConditionResult, Fingerprint, Investigation,
                     UsageSite, VulnMatch, activity)
from .tools import TOOL_SPECS, VulnToolbox, dumps, evidence_ok

PROMPTS = Path(__file__).resolve().parent / "prompts"
IMPORT_LINE = re.compile(r"^\s*(from|import)\s")

SUBMIT_SPEC: dict = {
    "name": "submit_investigation",
    "description": "Record the investigation result. Call exactly once.",
    "strict": True,
    "input_schema": {"type": "object", "properties": {
        "usage": {"type": "string", "enum": [u for u in USAGES if u != "not_applicable"]},
        "usage_sites": {"type": "array", "items": {"type": "object", "properties": {
            "function": {"type": "string"}, "file": {"type": "string"}, "lines": {"type": "string"},
            "code": {"type": "string"}, "symbol": {"type": "string"},
            "unsafe_argument": {"type": "string", "enum": ["yes", "no", "unknown"]}},
            "required": ["function", "file", "lines", "code", "symbol", "unsafe_argument"], "additionalProperties": False}},
        "reachability": {"type": "string", "enum": list(REACHABILITY)},
        "paths": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}},
        "conditions": {"type": "array", "items": {"type": "object", "properties": {
            "condition": {"type": "string", "enum": ["untrusted_input", "argument", "config", "other"]},
            "text": {"type": "string"}, "status": {"type": "string", "enum": list(CONDITION_STATUS)},
            "note": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "object", "properties": {
                "file": {"type": "string"}, "lines": {"type": "string"}},
                "required": ["file", "lines"], "additionalProperties": False}}},
            "required": ["condition", "text", "status", "note", "evidence"], "additionalProperties": False}},
        "unknowns": {"type": "array", "items": {"type": "string"}},
        "claims": {"type": "array", "items": {"type": "object", "properties": {
            "text": {"type": "string"}, "kind": {"type": "string", "enum": ["usage", "reachability", "condition", "other"]},
            "evidence": {"type": "array", "items": {"type": "object", "properties": {
                "file": {"type": "string"}, "lines": {"type": "string"}},
                "required": ["file", "lines"], "additionalProperties": False}}},
            "required": ["text", "kind", "evidence"], "additionalProperties": False}}},
        "required": ["usage", "usage_sites", "reachability", "paths", "conditions", "unknowns", "claims"],
        "additionalProperties": False},
}


# --------------------------------------------------------------------------- symbol matching

def symbol_matches(api: str, symbol: str) -> bool:
    if not api or not symbol:
        return False
    if api == symbol or api.startswith(symbol + "."):
        return True
    a, s = api.split("."), symbol.split(".")
    return a[0] == s[0] and a[-1] == s[-1]


def search_pattern(symbols: list[str], imports: list[str]) -> Optional[str]:
    parts = []
    for s in symbols:
        tail = s.split(".")[-1]
        if not re.fullmatch(r"[A-Za-z_]\w*", tail):
            continue
        shaped = "_" in tail or re.search(r"[a-z][A-Z]", tail) or len(tail) >= 8
        if shaped:
            parts.append(rf"\b{re.escape(tail)}\b")
        else:
            alt = "|".join(re.escape(i) for i in imports)
            parts.append(rf"\b(?:{alt})\.{re.escape(tail)}\b")
    return "|".join(dict.fromkeys(parts)) or None


def _site_line_text(read: dict, line: int) -> str:
    for l in read.get("lines", []) or []:
        num, _, text = l.partition(": ")
        if num.strip().isdigit() and int(num) == line:
            return text
    return ""


def _short_path(path: list[str]) -> str:
    return " → ".join(short_label(p) if not p.startswith(("route:", "cli:")) else p.split(":", 1)[1] for p in path)


def _call_evidence(G, path: list[str]) -> list[Evidence]:
    """File:line evidence of each CALLS / HANDLES step along a path."""
    out: list[Evidence] = []
    for a, b in zip(path, path[1:]):
        for _, v, d in out_edges(G, a, "CALLS", "HANDLES"):
            if v == b:
                for e in d.get("evidence", [])[:1]:
                    out.append(Evidence(**e))
                break
    return out


# --------------------------------------------------------------------------- playbook

def playbook(ctx: Stage4Context, m: VulnMatch, fp: Fingerprint, tb: VulnToolbox) -> Investigation:
    G = ctx.G
    pid = m.package
    name = m.package_name
    inv = Investigation(vuln_id=m.vuln_id, package=pid, discovered_by="algorithm")
    tb.call("advisory", {"vuln_id": m.vuln_id})
    tb.call("query_graph", {"node_id": pid, "edge_types": ["USES_PACKAGE", "CALLS_API", "REQUIRES"], "direction": "in"})
    runtime_files, test_files = files_using(G, pid)

    # ---- usage
    if not runtime_files and not test_files:
        req = used_requirers(G, pid)
        if not req:
            inv.usage, inv.reachability = "package_not_imported", "no_path_found"
            inv.claims.append(Claim(text=f"No file imports {name} and no imported package requires it.", kind="usage",
                                    evidence=[Evidence(node=pid)], graph_backed=True))
            return _finish(ctx, m, fp, tb, inv, [])
        inv.usage = "package_used_symbol_unknown"
        names = ", ".join(G.nodes[r].get("name", r) for r in req)
        inv.notes.append(f"{name} is not imported directly; it is installed because {names} require(s) it.")
        inv.unknowns.append(f"whether {names} call(s) the vulnerable part of {name}")
        req_ev = [Evidence(node=r) for r in req[:2]]
        tb.ledger.nodes.update(req)
        inv.claims.append(Claim(text=f"{name} is not imported by the repository; it is pulled in by {names}, which the code imports.",
                                kind="usage", evidence=req_ev, graph_backed=True))
        fns = [f for r in req for f in package_functions(G, r)]
        return _finish(ctx, m, fp, tb, inv, fns[:3], package_level=True)

    imports = import_names(ctx.s3, pid)
    symbols = fp.vulnerable_symbols
    sites: dict[tuple[str, int], UsageSite] = {}
    graph_lines: dict[tuple[str, int], str] = {}
    for fn, _, d in in_edges(G, pid, "CALLS_API"):
        for e in d.get("evidence", [])[:3]:
            if e.get("file") and e.get("line"):
                graph_lines[(e["file"], int(e["line"]))] = api_of(d) or _api_at(G, fn, int(e["line"]))
    for (file, line), api in graph_lines.items():
        sym = next((s for s in symbols if symbol_matches(api, s)), None)
        if sym:
            fn = enclosing_function(G, file, line)
            sites[(file, line)] = UsageSite(function=fn or f"file:{file}", file=file, lines=str(line), symbol=sym, via="graph",
                                            in_test=bool(G.nodes.get(f"file:{file}", {}).get("is_test")))
    pattern = search_pattern(symbols, imports) if symbols else None
    if pattern:
        res = tb.call("search_code", {"pattern": pattern, "glob": "**/*.py"})
        allowed = {G.nodes[f]["path"] for f in runtime_files + test_files}
        for hit in res.get("matches", []) or []:
            if hit["file"] not in allowed or IMPORT_LINE.match(hit.get("text", "")) or hit.get("text", "").lstrip().startswith("#"):
                continue
            key = (hit["file"], int(hit["line"]))
            if key in sites:
                continue
            fn = enclosing_function(G, hit["file"], int(hit["line"]))
            sym = next((s for s in symbols if re.search(rf"\b{re.escape(s.split('.')[-1])}\b", hit.get("text", ""))), symbols[0])
            sites[key] = UsageSite(function=fn or f"file:{hit['file']}", file=hit["file"], lines=str(hit["line"]),
                                   symbol=sym, via="graph" if key in graph_lines else "search",
                                   in_test=bool(G.nodes.get(f"file:{hit['file']}", {}).get("is_test")))
    ordered = sorted(sites.values(), key=lambda s: (s.in_test, s.via != "graph", s.file, int(s.lines)))
    for s in ordered[:2]:
        ln = int(s.lines)
        read = tb.call("read_code", {"file": s.file, "start": max(1, ln - 1), "end": ln + 1})
        s.code = _site_line_text(read, ln).strip()
        s.unsafe_argument = _unsafe_argument(s.code, s.symbol, fp)
    for s in ordered[2:]:
        s.code = ""
    runtime_sites = [s for s in ordered if not s.in_test]
    inv.usage_sites = ordered[:6]
    if not symbols:
        inv.usage = "package_used_symbol_unknown"
        inv.unknowns.append("the advisory names no vulnerable function, so only package-level use was checked")
        inv.claims.append(Claim(text=f"{name} is imported by {', '.join(G.nodes[f]['path'] for f in runtime_files[:3])}.",
                                kind="usage", evidence=_import_evidence(G, pid, runtime_files), graph_backed=True))
        tb.ledger.nodes.update(runtime_files)
        for e in _import_evidence(G, pid, runtime_files):
            tb.ledger.add(e.model_dump(exclude_none=True))
        return _finish(ctx, m, fp, tb, inv, package_functions(G, pid)[:3], package_level=True)
    if runtime_sites:
        inv.usage = "symbol_called"
        for s in runtime_sites[:2]:
            inv.claims.append(Claim(
                text=f"`{s.code or s.symbol}` uses {s.symbol} in {short_label(s.function)}" if s.code else
                     f"{s.symbol} is referenced in {short_label(s.function)}",
                kind="usage", evidence=[Evidence(file=s.file, lines=s.lines)], graph_backed=s.via == "graph"))
        return _finish(ctx, m, fp, tb, inv, list(dict.fromkeys(s.function for s in runtime_sites[:2])))
    inv.usage = "package_used_symbol_not_found"
    if ordered:
        inv.notes.append("the vulnerable symbol is only used in test files")
    files_txt = ", ".join(G.nodes[f]["path"] for f in runtime_files[:4])
    ev = _import_evidence(G, pid, runtime_files)
    for e in ev:
        tb.ledger.add(e.model_dump(exclude_none=True))
    inv.claims.append(Claim(text=f"No call to {', '.join(f'`{s}`' for s in symbols)} was found in {files_txt}, "
                                 f"the file(s) that import {name}.", kind="usage", evidence=ev, graph_backed=True))
    return _finish(ctx, m, fp, tb, inv, package_functions(G, pid)[:3], package_level=True)


def _api_at(G, fn: str, line: int) -> str:
    for c in G.nodes[fn].get("external_calls", []) or []:
        if c.get("line") == line:
            return c.get("target") or ""
    return ""


def _import_evidence(G, pid: str, files: list[str]) -> list[Evidence]:
    out = []
    for f, _, d in in_edges(G, pid, "USES_PACKAGE"):
        if f in files:
            out += [Evidence(**e) for e in d.get("evidence", [])[:1]]
    return out[:3]


def _unsafe_argument(code: str, symbol: Optional[str], fp: Fingerprint) -> Optional[bool]:
    if not code:
        return None
    if any(re.search(rf"\b{re.escape(a.split('.')[-1])}\b", code) for a in fp.safe_alternatives):
        return False
    tails = [s.split(".")[-1] for s in fp.vulnerable_symbols]
    # a vulnerable symbol passed as an argument value (Loader=yaml.FullLoader)
    if any(re.search(rf"=\s*[\w.]*\b{re.escape(t)}\b", code) for t in tails):
        return True
    others = [s.split(".")[-1] for s in fp.vulnerable_symbols if s != symbol]
    if any(re.search(rf"\b{re.escape(t)}\b", code) for t in others):
        return True
    return None


def _argument_text(code: str, fp: Fingerprint) -> str:
    for s in fp.vulnerable_symbols:
        mm = re.search(rf"\w+\s*=\s*[\w.]*\b{re.escape(s.split('.')[-1])}\b", code)
        if mm:
            return mm.group(0)
    return code.strip()[:80]


def _finish(ctx: Stage4Context, m: VulnMatch, fp: Fingerprint, tb: VulnToolbox, inv: Investigation,
            functions: list[str], package_level: bool = False) -> Investigation:
    """Reachability + conditions + unknowns for the given functions (usage sites or package users)."""
    G = ctx.G
    entries: dict[str, dict] = {}
    for fn in functions[:2]:
        if fn not in G:
            continue
        r = tb.call("trace_callers", {"function_id": fn, "max_depth": 8})
        for e in r.get("entries", []) or []:
            entries.setdefault(e["id"], {**e, "target": fn})
    ents = sorted(entries.values(), key=lambda e: (not e["public"], len(e["path"])))
    inv.entries = [{k: e[k] for k in ("id", "kind", "public", "label")} for e in ents]
    if inv.usage != "package_not_imported":
        inv.reachability = classify(ents) if functions else "unknown"
    inv.paths = [e["path"] for e in ents[:3]]
    for e in ents[:2]:
        ev = _call_evidence(G, e["path"])
        for x in ev:
            tb.ledger.add(x.model_dump(exclude_none=True))
        kind = "public" if e["public"] else "internal"
        inv.claims.append(Claim(text=f"{e['label']} ({e['kind']}, {kind}) reaches {short_label(e['target'])}: {_short_path(e['path'])}.",
                                kind="reachability", evidence=ev or [Evidence(node=e["target"])], graph_backed=True))
    if functions and not ents and inv.usage != "package_not_imported":
        inv.claims.append(Claim(text=f"No route, CLI or startup code was found that calls {', '.join(short_label(f) for f in functions[:2])}.",
                                kind="reachability", evidence=[Evidence(node=f) for f in functions[:2] if f in G],
                                graph_backed=True))
    if package_level and inv.usage != "package_not_imported":
        inv.notes.append("reachability is for the code that uses the package, not for a specific vulnerable call")

    # ---- trigger conditions
    site = next((s for s in inv.usage_sites if not s.in_test), None)
    for t in fp.trigger_conditions:
        cr = ConditionResult(condition=t.type, text=t.text)
        if t.type == "untrusted_input":
            target = site.function if site else (functions[0] if functions else None)
            if target and target in G and not tb.exhausted:
                src = tb.call("input_sources", {"function_id": target})
                own = [i for i in src.get("inputs", []) if i.get("function") == target]
                path_inputs = [i for i in src.get("inputs", []) if i.get("function") != target]
                if own:
                    cr.status = "met"
                    cr.note = f"{short_label(target)} itself reads {', '.join(sorted({i['source'] for i in own}))}"
                    cr.evidence = [Evidence(file=i["file"], lines=str(i["line"])) for i in own if i.get("file") and i.get("line")][:2]
                elif path_inputs and inv.reachability == "public_path":
                    cr.status = "unknown"
                    srcs = sorted({i["source"] for i in path_inputs})
                    cr.note = (f"user input ({', '.join(srcs)}) enters the path at "
                               f"{', '.join(sorted({short_label(i['function']) for i in path_inputs if i.get('function')}))}; "
                               f"whether it reaches the vulnerable call was not traced")
                    cr.evidence = [Evidence(file=i["file"], lines=str(i["line"])) for i in path_inputs if i.get("file") and i.get("line")][:2]
                elif inv.reachability in ("internal_only", "no_path_found"):
                    cr.status = "not_shown"
                    cr.note = ("no route or CLI input reaches " + short_label(target) +
                               (f"; it runs from {', '.join(e['label'] for e in ents[:2])}" if ents else "; no caller found"))
                    cr.evidence = (_call_evidence(G, ents[0]["path"]) if ents else []) or [Evidence(node=target)]
                else:
                    cr.note = "no input source was recorded on the path"
            else:
                cr.note = "no usage site to check"
        elif t.type == "argument" and site and site.code:
            if site.unsafe_argument is True:
                cr.status, cr.note = "met", f"the call passes {_argument_text(site.code, fp)}"
                cr.evidence = [Evidence(file=site.file, lines=site.lines)]
            elif site.unsafe_argument is False:
                cr.status, cr.note = "not_shown", "the call uses a safe alternative"
                cr.evidence = [Evidence(file=site.file, lines=site.lines)]
            else:
                cr.note = "argument values could not be confirmed from the call line"
        else:
            cr.note = "not checked by static analysis"
        if cr.status == "unknown":
            inv.unknowns.append(f"whether {t.text}")
        inv.conditions.append(cr)
        if cr.status in ("met", "not_shown") and cr.evidence:
            inv.claims.append(Claim(text=f"Condition '{t.text}': {cr.status.replace('_', ' ')} ({cr.note}).",
                                    kind="condition", evidence=cr.evidence,
                                    graph_backed=t.type == "untrusted_input" and cr.status == "not_shown"))
    # argument-type usage evidence: Loader=yaml.FullLoader style
    if site and site.unsafe_argument and not any(c.condition == "argument" for c in inv.conditions):
        inv.conditions.append(ConditionResult(condition="argument", text="the call passes a vulnerable option",
                                              status="met", note=f"the call passes {_argument_text(site.code, fp)}",
                                              evidence=[Evidence(file=site.file, lines=site.lines)]))
    files = [s.file for s in inv.usage_sites] or [G.nodes[f].get("path") for f in files_using(G, m.package)[0]]
    inv.dynamic_imports = dynamic_import_files(G, [f"file:{f}" for f in files if f])
    if inv.dynamic_imports:
        inv.unknowns.append(f"dynamic imports in {', '.join(inv.dynamic_imports[:3])} may add callers static analysis cannot see")
    inv.unknowns = list(dict.fromkeys(inv.unknowns))
    inv.tool_calls_used = tb.steps
    inv.budget_exhausted = tb.exhausted and inv.reachability == "unknown"
    return inv


# --------------------------------------------------------------------------- LLM agent

def _baseline_hints(base: Investigation) -> dict:
    return {"usage": base.usage, "usage_sites": [s.model_dump(include={"function", "file", "lines", "code", "symbol"}) for s in base.usage_sites[:4]],
            "reachability": base.reachability, "entry_points": base.entries[:4], "paths": base.paths[:2]}


def agent_investigate(ctx: Stage4Context, m: VulnMatch, fp: Fingerprint, tb: VulnToolbox, base: Investigation,
                      objections: list[str]) -> Optional[Investigation]:
    system = (PROMPTS / "investigator_system.md").read_text(encoding="utf-8").replace("{max_steps}", str(tb.budget))
    user = (f"Vulnerability: {m.vuln_id} ({', '.join(m.aliases[:4]) or 'no aliases'})\n"
            f"Package: {m.package} (scope {m.scope}; dependency path {' -> '.join(m.dependency_path)})\n"
            f"Severity (CVSS, for context only): {m.cvss.score} {m.cvss.band}\n"
            f"Summary: {m.summary}\n"
            f"Fingerprint: {dumps(fp.model_dump(include={'vulnerable_symbols', 'safe_alternatives', 'trigger_conditions', 'impact', 'symbols_source'}))}\n"
            f"Pre-computed graph facts (hints, confirm with tools): {dumps(_baseline_hints(base))}\n")
    if objections:
        user += "\nThe verifier rejected these claims from your previous attempt; fix or drop them:\n- " + "\n- ".join(objections)
    raw = run_tool_agent(ctx.llm, "vuln_investigator", system, user, tb, TOOL_SPECS, SUBMIT_SPEC)
    if raw is None:
        return None
    if raw.get("__budget_exhausted"):
        inv = base.model_copy(deep=True)
        inv.discovered_by = "ai"
        inv.budget_exhausted = True
        inv.notes.append("the agent did not submit within its tool budget; the static result is kept")
        inv.tool_calls_used = tb.steps
        return inv
    return validate_agent(ctx, m, fp, raw, tb, base)


def _path_ok(G, path: list[str]) -> bool:
    if len(path) < 2 or any(p not in G for p in path if not p.startswith("startup:")):
        return False
    for a, b in zip(path, path[1:]):
        if not any(v == b for _, v, _ in out_edges(G, a, "CALLS", "HANDLES")):
            return False
    return True


def validate_agent(ctx: Stage4Context, m: VulnMatch, fp: Fingerprint, raw: dict, tb: VulnToolbox,
                   base: Investigation) -> Investigation:
    G = ctx.G
    inv = Investigation(vuln_id=m.vuln_id, package=m.package, discovered_by="ai", tool_calls_used=tb.steps)
    usage = raw.get("usage") if raw.get("usage") in USAGES else base.usage
    sites = []
    for s in raw.get("usage_sites") or []:
        e = Evidence(file=s.get("file"), lines=s.get("lines"))
        if not evidence_ok(tb.ledger, e):
            inv.dropped.append(f"usage site {s.get('file')}:{s.get('lines')} (not read by a tool)")
            continue
        rng = e.line_range() or (0, 0)
        fn = s.get("function") if s.get("function") in G else enclosing_function(G, s.get("file"), rng[0]) or s.get("function")
        sites.append(UsageSite(function=fn, file=s["file"], lines=s["lines"], code=s.get("code", "")[:200],
                               symbol=s.get("symbol") or None,
                               unsafe_argument={"yes": True, "no": False}.get(s.get("unsafe_argument")),
                               via="graph" if any(k == (s["file"], rng[0]) for k in _graph_site_keys(G, m.package)) else "search",
                               in_test=bool(G.nodes.get(f"file:{s['file']}", {}).get("is_test"))))
    if usage == "symbol_called" and not sites:
        inv.dropped.append("usage 'symbol_called' had no verified usage site; the static result is used")
        usage, sites = base.usage, base.usage_sites
    if usage == "symbol_called" and not fp.vulnerable_symbols:
        usage = "package_used_symbol_unknown"
        inv.notes.append("no vulnerable symbol is known, so usage is capped at package_used_symbol_unknown")
    if usage == "package_not_imported" and base.usage != "package_not_imported":
        inv.dropped.append("usage 'package_not_imported' contradicts USES_PACKAGE edges in the graph")
        usage = base.usage
    inv.usage, inv.usage_sites = usage, sites

    reachability = raw.get("reachability") if raw.get("reachability") in REACHABILITY else "unknown"
    paths = [p for p in raw.get("paths") or [] if isinstance(p, list) and _path_ok(G, p)]
    if reachability in ("public_path", "internal_only") and not paths:
        inv.dropped.append(f"reachability '{reachability}' had no valid call path; the static result is used")
        reachability, paths = base.reachability, base.paths
    inv.reachability, inv.paths = reachability, paths[:3]
    inv.entries = base.entries if reachability == base.reachability else \
        [e for e in (_entry_of(G, p[0]) for p in paths) if e]

    for c in raw.get("conditions") or []:
        ev = [Evidence(**x) for x in c.get("evidence") or [] if x.get("file")]
        good = [e for e in ev if evidence_ok(tb.ledger, e)]
        status = c.get("status") if c.get("status") in CONDITION_STATUS else "unknown"
        if status == "met" and not good:
            inv.dropped.append(f"condition '{c.get('text')}' marked met without verified evidence -> unknown")
            status = "unknown"
        inv.conditions.append(ConditionResult(condition=c.get("condition", "other"), text=c.get("text", ""),
                                              status=status, note=c.get("note", ""), evidence=good))
    for c in raw.get("claims") or []:
        ev = [Evidence(**x) for x in c.get("evidence") or [] if x.get("file")]
        good = [e for e in ev if evidence_ok(tb.ledger, e)]
        bad = [e.label() for e in ev if e not in good]
        if bad:
            inv.dropped.append(f"evidence {', '.join(bad)} for '{c.get('text', '')[:80]}' was not returned by a tool")
        if not good:
            continue
        inv.claims.append(Claim(text=c.get("text", "")[:400], kind=c.get("kind", "other"), evidence=good,
                                graph_backed=any(_graph_backed(G, e) for e in good)))
    inv.unknowns = [u for u in raw.get("unknowns") or [] if u][:6]
    files = [s.file for s in inv.usage_sites] or [G.nodes[f].get("path") for f in files_using(G, m.package)[0]]
    inv.dynamic_imports = dynamic_import_files(G, [f"file:{f}" for f in files if f])
    return inv


def _graph_site_keys(G, pid: str) -> set[tuple[str, int]]:
    keys = set()
    for _, _, d in in_edges(G, pid, "CALLS_API"):
        for e in d.get("evidence", []):
            if e.get("file") and e.get("line"):
                keys.add((e["file"], int(e["line"])))
    return keys


def _graph_backed(G, e: Evidence) -> bool:
    rng = e.line_range()
    if not e.file or not rng:
        return False
    for _, _, d in G.edges(data=True):
        if d.get("type") in ("CALLS", "CALLS_API", "HANDLES", "USES_PACKAGE", "READS_ENV", "CONTACTS"):
            for x in d.get("evidence", [])[:2]:
                if x.get("file") == e.file and x.get("line") and rng[0] <= int(x["line"]) <= rng[1]:
                    return True
    return False


def _entry_of(G, node: str) -> Optional[dict]:
    from .graphfacts import entry_kind
    e = entry_kind(G, node)
    if e:
        return {k: e[k] for k in ("id", "kind", "public", "label")}
    if G.nodes.get(node, {}).get("module_level"):
        return {"id": node, "kind": "startup", "public": False, "label": f"module code of {G.nodes[node].get('file')}"}
    return None


# --------------------------------------------------------------------------- entry points

def investigate(ctx: Stage4Context, m: VulnMatch, fp: Fingerprint, objections: Optional[list[str]] = None,
                emit=lambda e: None) -> tuple[Investigation, list[dict]]:
    """Returns the investigation and its activity steps."""
    budget = ctx.budgets.tool_calls
    use_llm = ctx.llm.available or ctx.llm.cache_dir.exists()
    if use_llm:
        base = playbook(ctx, m, fp, VulnToolbox(ctx, m, fp, budget=budget))      # hints only, not shown
        tb = VulnToolbox(ctx, m, fp, budget=budget, emit=emit)
        inv = agent_investigate(ctx, m, fp, tb, base, objections or [])
        if inv is not None:
            return inv, tb.activity
        ctx.coverage.setdefault("llm_fallbacks", []).append(m.match_id)
    tb = VulnToolbox(ctx, m, fp, budget=budget, emit=emit)
    inv = playbook(ctx, m, fp, tb)
    if objections:
        inv.notes.append("the verifier's objections were applied by dropping the failed claims")
    return inv, tb.activity


def light_investigation(ctx: Stage4Context, m: VulnMatch, usage_hint: Optional[str], reason: str) -> Investigation:
    """Light pass: no agent, rules only. Usage comes from graph facts; reachability stays unknown."""
    G = ctx.G
    inv = Investigation(vuln_id=m.vuln_id, package=m.package, light_pass=True, discovered_by="algorithm")
    inv.notes.append(f"light pass: {reason}")
    if usage_hint == "not_applicable":
        inv.usage, inv.reachability = "not_applicable", "unknown"
        return inv
    if usage_hint == "package_not_imported":
        inv.usage, inv.reachability = "package_not_imported", "no_path_found"
        inv.claims.append(Claim(text=f"No file imports {m.package_name} and no imported package requires it.",
                                kind="usage", evidence=[Evidence(node=m.package)], graph_backed=True, verified=True))
        return inv
    runtime, tests = files_using(G, m.package) if m.package in G else ([], [])
    if runtime or used_requirers(G, m.package):
        inv.usage = "package_used_symbol_unknown"
    elif tests:
        inv.usage = "package_used_symbol_unknown"
        inv.notes.append("imported only by tests")
    else:
        inv.usage = "package_not_imported"
    br = ctx.s3.blast.get(m.package) or {}
    if br.get("routes_reaching"):
        inv.reachability = "public_path"
        inv.entries = [{"id": r, "kind": "route", "public": True, "label": r.split(":", 1)[1]} for r in br["routes_reaching"][:3]]
    else:
        inv.reachability = "unknown"
    inv.unknowns.append("not investigated (light pass)")
    return inv
