"""Investigator tools: Stage 3's toolbox (query_graph, get_path, read_code, git_history, grep as
``search_code``) plus the Stage 4 tools trace_callers, input_sources, advisory and verify_evidence.

Every tool result goes into the evidence ledger; a claim may only cite what a tool returned. Every call
is also recorded as an activity step (tool, input, short result) for the investigation timeline.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Optional

from guardian.stage3_knowledge.investigator.tools import TOOL_SPECS as S3_SPECS
from guardian.stage3_knowledge.investigator.tools import EvidenceLedger, Toolbox, tool_result_text
from guardian.stage3_knowledge.schema import Evidence

from .graphfacts import inputs_on_paths, reach
from .schema import Fingerprint, VulnMatch, activity

MAX_VERIFY_LINES = 40


class Ledger(EvidenceLedger):
    def __init__(self) -> None:
        super().__init__()
        self.urls: set[str] = set()
        self.package_files: dict[str, list[tuple[int, int]]] = {}   # Stage 5: "<name>@<ver>:<path>" spans


def _spec(name: str) -> dict:
    return next(s for s in S3_SPECS if s["name"] == name)


TOOL_SPECS: list[dict] = [
    _spec("query_graph"),
    {"name": "trace_callers",
     "description": "Callers of a function up to entry points (reverse CALLS): routes and argument-parsing CLIs are public; "
                    "__main__ scripts and module-level startup code are internal. Returns each entry with its call path.",
     "input_schema": {"type": "object", "properties": {
         "function_id": {"type": "string", "description": "e.g. fn:app/config/load.py::load_settings"},
         "max_depth": {"type": "integer", "minimum": 1, "maximum": 10}}, "required": ["function_id"]}},
    _spec("get_path"),
    {"name": "input_sources",
     "description": "Input sources (request.*, CLI arguments) recorded on a function and on the functions of every entry "
                    "path that reaches it. Function-level, not variable-level dataflow.",
     "input_schema": {"type": "object", "properties": {"function_id": {"type": "string"}}, "required": ["function_id"]}},
    _spec("read_code"),
    {"name": "search_code",
     "description": "Regex search over repository files (symbols, aliases, config flags), at most 50 file:line matches.",
     "input_schema": {"type": "object", "properties": {
         "pattern": {"type": "string"}, "glob": {"type": "string", "description": "Default **/*.py"}},
         "required": ["pattern"]}},
    _spec("git_history"),
    {"name": "advisory",
     "description": "The full vulnerability record being investigated (ids, versions, CVSS, references) and its fingerprint.",
     "input_schema": {"type": "object", "properties": {"vuln_id": {"type": "string"}}, "required": ["vuln_id"]}},
    {"name": "verify_evidence",
     "description": "Re-read cited lines to check they exist and show the claim. Returns the lines.",
     "input_schema": {"type": "object", "properties": {
         "file": {"type": "string"}, "lines": {"type": "string", "description": "\"12\" or \"12-14\""},
         "claim": {"type": "string"}}, "required": ["file", "lines"]}},
]


def summarize(name: str, args: dict, out: dict) -> str:
    if "error" in out:
        return f"error: {out['error']}"[:160]
    if name == "query_graph":
        n = out.get("neighbours", [])
        kinds = sorted({x.get("edge") for x in n if x.get("edge")})
        return f"{len(n)} related node(s) via {', '.join(kinds) or 'no edges'}"
    if name == "trace_callers":
        ents = out.get("entries", [])
        return (f"{len(out.get('callers', []))} caller(s); entry points: "
                + (", ".join(f"{e['label']} ({'public' if e['public'] else 'internal'})" for e in ents[:3]) or "none found"))
    if name == "input_sources":
        srcs = sorted({i.get("source") for i in out.get("inputs", []) if i.get("source")})
        return f"inputs: {', '.join(srcs) or 'none recorded'}"
    if name == "read_code":
        lines = out.get("lines") or []
        return f"read {out.get('file')} lines {out.get('start')}-{out.get('end')} ({len(lines)} lines)"
    if name in ("search_code", "grep"):
        return f"{len(out.get('matches', []))} match(es) in {out.get('files_searched', 0)} file(s)"
    if name == "advisory":
        return f"{out.get('vuln_id')}: {len(out.get('fingerprint', {}).get('vulnerable_symbols', []))} vulnerable symbol(s)"
    if name == "verify_evidence":
        return f"{out.get('file')}:{out.get('lines')} {'found' if out.get('exists') else 'not found'}"
    if name == "get_path":
        return f"{len(out.get('paths', []))} execution path(s)"
    if name == "git_history":
        return f"{len(out.get('commits', []))} commit(s)"
    if name == "exposure":
        return f"exposure {out.get('exposure')}: {out.get('note', '')}"[:160]
    if name == "pypi_info":
        return f"{out.get('name')} {out.get('version') or ''}: {len(out.get('files', []))} file(s), author {out.get('author')}"
    if name == "compare_names":
        c = out.get("closest") or []
        return f"closest popular name: {c[0]['looks_like']} ({c[0]['check']})" if c else "no close popular name"
    if name == "package_diff":
        return f"{len(out.get('changed_files', []))} changed file(s), {len(out.get('new_behaviour', []))} new behaviour item(s)"
    if name == "read_package_file":
        return f"read {out.get('package')}/{out.get('path')} ({len(out.get('lines', []))} lines)"
    if name == "scan_install_hooks":
        return f"{len(out.get('install_files', {}))} install file(s) scanned"
    return "ok"


TOOL_ACTIONS = {
    "query_graph": "Graph queried", "trace_callers": "Callers traced", "input_sources": "Input sources checked",
    "read_code": "Code read", "search_code": "Code searched", "grep": "Code searched", "git_history": "History read",
    "advisory": "Advisory read", "verify_evidence": "Evidence re-read", "get_path": "Execution paths read",
    "exposure": "Exposure checked", "pypi_info": "Package metadata read", "compare_names": "Names compared",
    "package_diff": "Releases diffed in sandbox", "read_package_file": "Package file read", "scan_install_hooks": "Install hooks scanned",
}


class VulnToolbox(Toolbox):
    """Stage 3 toolbox with the Stage 4 tools, a hard call budget and an activity log."""

    def __init__(self, ctx4, match: Optional[VulnMatch] = None, fingerprint: Optional[Fingerprint] = None,
                 budget: int = 10, stage: str = "investigator", emit: Callable[[dict], None] = lambda e: None):
        super().__init__(ctx4.s3)
        self.ctx4 = ctx4
        self.ledger = Ledger()
        self.match = match
        self.fingerprint = fingerprint
        self.budget = budget
        self.stage = stage
        self.activity: list[dict] = []
        self.emit = emit

    @property
    def exhausted(self) -> bool:
        return self.steps >= self.budget

    def call(self, name: str, args: dict[str, Any]) -> dict:
        if self.exhausted:
            return {"error": "tool budget exhausted"}
        if name == "search_code":
            name_impl = "grep"
        else:
            name_impl = name
        self.steps += 1
        fn = getattr(self, f"t_{name_impl}", None)
        try:
            out = fn(**(args or {})) if fn else {"error": f"unknown tool {name}"}
        except TypeError as exc:
            out = {"error": f"bad arguments: {exc}"}
        except Exception as exc:  # tools fail soft
            out = {"error": f"{type(exc).__name__}: {exc}"}
        step = activity(self.stage, TOOL_ACTIONS.get(name, name), summarize(name, args or {}, out), tool=name,
                        input={k: v for k, v in (args or {}).items() if k != "claim"}, ok="error" not in out)
        self.activity.append(step)
        self.trace.append({"tool": name, "args": args, "ok": "error" not in out})
        try:
            self.emit(step)
        except Exception:
            pass
        return out

    # ------------------------------------------------------------------ new tools
    def t_trace_callers(self, function_id: str, max_depth: int = 8) -> dict:
        fid = self.resolve_node(function_id)
        if not fid:
            return {"error": f"no function matches {function_id!r}"}
        r = reach(self.G, fid, max(1, min(10, int(max_depth or 8))))
        self.ledger.nodes.add(fid)
        for c in r["callers"]:
            self.ledger.nodes.add(c["id"])
            for _, _, d in self.G.out_edges(c["id"], data=True):
                if d.get("type") == "CALLS":
                    for e in d.get("evidence", [])[:1]:
                        self.ledger.add(e)
        entries = []
        for e in r["entries"]:
            for n in e["path"]:
                self.ledger.nodes.add(n)
                for ev in self.G.nodes.get(n, {}).get("evidence", [])[:1]:
                    self.ledger.add(ev)
            entries.append({k: e[k] for k in ("id", "kind", "public", "label", "path")})
        callers = [{**c, "file": self.G.nodes[c["id"]].get("file"), "line": self.G.nodes[c["id"]].get("line")}
                   for c in r["callers"][:40]]
        return {"function": fid, "callers": callers, "entries": entries}

    def t_input_sources(self, function_id: str) -> dict:
        fid = self.resolve_node(function_id)
        if not fid:
            return {"error": f"no function matches {function_id!r}"}
        r = reach(self.G, fid)
        own = [{"function": fid, "source": i.get("source"), "line": i.get("line"), "file": self.G.nodes[fid].get("file")}
               for i in self.G.nodes[fid].get("inputs", []) or []]
        path_inputs = inputs_on_paths(self.G, r["entries"])
        for i in own + path_inputs:
            if i.get("file") and i.get("line"):
                self.ledger.add_file(i["file"], i["line"])
            if i.get("function"):
                self.ledger.nodes.add(i["function"])
        return {"function": fid, "inputs": own + [i for i in path_inputs if i not in own],
                "note": "function-level: an input on a path does not prove it reaches the vulnerable argument"}

    def t_advisory(self, vuln_id: str = "") -> dict:
        m = self.match
        if not m:
            return {"error": "no advisory loaded"}
        for r in m.references:
            self.ledger.urls.add(r.url)
        fp = self.fingerprint.model_dump() if self.fingerprint else {}
        return {"vuln_id": m.vuln_id, "aliases": m.aliases, "package": m.package, "version": m.version,
                "summary": m.summary, "details": m.details[:3000], "cvss": m.cvss.model_dump(),
                "fixed_versions": m.fixed_versions, "scope": m.scope, "dependency_path": m.dependency_path,
                "references": [r.model_dump() for r in m.references[:8]], "fingerprint": fp}

    def t_verify_evidence(self, file: str, lines: str, claim: str = "") -> dict:
        rng = Evidence(file=file, lines=str(lines)).line_range()
        if not rng:
            return {"error": f"bad line range {lines!r}"}
        a, b = rng
        b = min(b, a + MAX_VERIFY_LINES - 1)
        src = self.ctx.source
        if not src.available:
            return {"file": file, "lines": f"{a}-{b}", "exists": False, "error": "repository source unavailable"}
        got = src.read_lines(file, a, b)
        if got:
            self.ledger.add_file(file, got[0][0], got[-1][0])
        return {"file": file, "lines": f"{a}-{b}", "exists": bool(got), "text": [f"{i}: {t}" for i, t in got]}


def result_text(out: dict) -> str:
    return tool_result_text(out)


def evidence_ok(ledger: Ledger, e: dict | Evidence) -> bool:
    e = e if isinstance(e, Evidence) else Evidence(**{k: v for k, v in (e or {}).items() if v not in (None, "")})
    if not (e.file or e.commit or e.node):
        return False
    return ledger.covers(e)


def dumps(o: Any) -> str:
    return json.dumps(o, default=str, ensure_ascii=False)
