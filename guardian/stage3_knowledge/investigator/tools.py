"""3D agent tools. Every tool result is recorded in an evidence ledger: a finding may only cite
files, line ranges, commits and nodes that a tool returned during the same investigation."""
from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from typing import Any, Optional

from ..context import Stage3Context
from ..flow import get_paths
from ..graph_builder import nodes_of
from ..schema import Evidence, normalize_name
from ..semantic import ensure_card
from ..structural import FALLBACK_DIST

MAX_READ_LINES = 120
MAX_GREP = 50
MAX_NEIGHBOURS = 60

TOOL_SPECS: list[dict] = [
    {"name": "query_graph",
     "description": "Neighbours of a knowledge-graph node (callers, callees, files, packages, tables, services, env vars). "
                    "Node ids look like fn:app/x.py::name, file:app/x.py, module:app/x, pkg:pypi/name@1.0, route:POST /p, "
                    "svc:Name, env:NAME, table:name. A bare name is matched against node ids.",
     "input_schema": {"type": "object", "properties": {
         "node_id": {"type": "string"},
         "edge_types": {"type": "array", "items": {"type": "string"},
                        "description": "Filter, e.g. CALLS, CONTACTS, READS_ENV, WRITES, USES_PACKAGE, CALLS_API, HANDLES, DEPENDS_ON, CONTAINS, CHANGED_IN"},
         "direction": {"type": "string", "enum": ["out", "in", "both"]},
         "depth": {"type": "integer", "minimum": 1, "maximum": 3}},
         "required": ["node_id"]}},
    {"name": "get_card",
     "description": "The semantic card (purpose, inputs, outputs, sensitivity, evidence) of a module, file or repo node.",
     "input_schema": {"type": "object", "properties": {"node_id": {"type": "string"}}, "required": ["node_id"]}},
    {"name": "read_code",
     "description": f"Source lines of a repository file, at most {MAX_READ_LINES} lines per call. Secret files (.env, keys) are refused.",
     "input_schema": {"type": "object", "properties": {
         "file": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}},
         "required": ["file", "start", "end"]}},
    {"name": "grep",
     "description": f"Regex search over repository files, at most {MAX_GREP} file:line matches.",
     "input_schema": {"type": "object", "properties": {
         "pattern": {"type": "string"}, "glob": {"type": "string", "description": "Default **/*.py; use **/* for all files"}},
         "required": ["pattern"]}},
    {"name": "git_history",
     "description": "Commits (hash, date, author, message) and a trimmed diff for a file path, or the dependency history of a package name.",
     "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
    {"name": "pypi_info",
     "description": "Stage 1 metadata of a package: version, direct/dev, declaration lines, requirers, origin metadata, blast radius.",
     "input_schema": {"type": "object", "properties": {"package": {"type": "string"}}, "required": ["package"]}},
    {"name": "get_path",
     "description": "Execution paths from an entry point (route/CLI) to sinks (tables, services, env vars, package APIs).",
     "input_schema": {"type": "object", "properties": {"entry": {"type": "string"}, "sink": {"type": "string"}}}},
]

SUBMIT_SPEC: dict = {
    "name": "submit_finding",
    "description": "Record the answer to the question. Call exactly once, when the evidence is enough or the step budget is spent.",
    "strict": True,
    "input_schema": {"type": "object", "properties": {
        "answer": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "object", "properties": {
            "file": {"type": "string"}, "lines": {"type": "string"}, "commit": {"type": "string"}},
            "required": ["file", "lines", "commit"], "additionalProperties": False}},
        "confidence": {"type": "number"},
        "status": {"type": "string", "enum": ["resolved", "unresolved"]},
        "notable": {"type": "boolean"},
        "notable_reason": {"type": "string"},
        "new_questions": {"type": "array", "items": {"type": "string"}}},
        "required": ["answer", "evidence", "confidence", "status", "notable", "notable_reason", "new_questions"],
        "additionalProperties": False},
}


class EvidenceLedger:
    def __init__(self) -> None:
        self.files: dict[str, list[tuple[int, int]]] = defaultdict(list)
        self.commits: set[str] = set()
        self.nodes: set[str] = set()

    def add_file(self, path: Optional[str], a: Optional[int] = None, b: Optional[int] = None) -> None:
        if not path:
            return
        if a is None:
            self.files[path].append((0, 10**9))
        else:
            self.files[path].append((int(a), int(b if b is not None else a)))

    def add(self, e: dict | Evidence | None) -> None:
        if not e:
            return
        e = e if isinstance(e, Evidence) else Evidence(**e)
        if e.file:
            rng = e.line_range()
            self.add_file(e.file, *(rng or (None, None)))
        if e.commit:
            self.commits.add(e.commit)
        if e.node:
            self.nodes.add(e.node)

    def covers(self, e: Evidence) -> bool:
        if e.commit:
            c = e.commit.removeprefix("commit:")
            return any(x.startswith(c[:7]) or c.startswith(x[:7]) for x in self.commits if len(c) >= 7)
        if e.file:
            spans = self.files.get(e.file.removeprefix("./"))
            if not spans:
                return False
            rng = e.line_range()
            if rng is None:
                return True
            return any(a <= rng[1] and rng[0] <= b for a, b in spans)
        if e.node:
            return e.node in self.nodes
        return False


class Toolbox:
    def __init__(self, ctx: Stage3Context):
        self.ctx = ctx
        self.G = ctx.G
        self.ledger = EvidenceLedger()
        self.steps = 0
        self.trace: list[dict] = []

    # ------------------------------------------------------------------ dispatch
    def call(self, name: str, args: dict[str, Any]) -> dict:
        self.steps += 1
        fn = getattr(self, f"t_{name}", None)
        try:
            out = fn(**(args or {})) if fn else {"error": f"unknown tool {name}"}
        except TypeError as exc:
            out = {"error": f"bad arguments: {exc}"}
        except Exception as exc:  # tools fail soft
            out = {"error": f"{type(exc).__name__}: {exc}"}
        self.trace.append({"tool": name, "args": args, "ok": "error" not in out})
        return out

    # ------------------------------------------------------------------ helpers
    def resolve_node(self, node_id: str) -> Optional[str]:
        if node_id in self.G:
            return node_id
        cands = [n for n in self.G.nodes if n.endswith(node_id) or n.endswith(f"::{node_id}") or
                 self.G.nodes[n].get("name") == node_id]
        return sorted(cands, key=len)[0] if cands else None

    def summary(self, nid: str) -> dict:
        d = self.G.nodes[nid]
        for e in d.get("evidence", [])[:3]:
            self.ledger.add(e)
        self.ledger.nodes.add(nid)
        keep = ("type", "name", "qualname", "path", "file", "line", "end_line", "version", "direct", "dev", "tags",
                "docstring", "params", "inputs", "via", "secret_like", "method", "framework", "new_in_diff",
                "external_calls", "sensitive", "blast_radius", "tightly_coupled_with", "date", "message", "sha")
        out = {"id": nid, **{k: d[k] for k in keep if d.get(k) not in (None, "", [], {})}}
        out["evidence"] = d.get("evidence", [])[:3]
        card = d.get("card")
        if card:
            out["card_purpose"] = card.get("purpose")
        return out

    # ------------------------------------------------------------------ tools
    def t_query_graph(self, node_id: str, edge_types: Optional[list[str]] = None, direction: str = "both",
                      depth: int = 1) -> dict:
        nid = self.resolve_node(node_id)
        if not nid:
            return {"error": f"no node matches {node_id!r}"}
        depth = max(1, min(3, int(depth or 1)))
        types = set(edge_types or [])
        out, seen, q = [], {nid}, deque([(nid, 0)])
        while q and len(out) < MAX_NEIGHBOURS:
            cur, dep = q.popleft()
            if dep >= depth:
                continue
            edges = []
            if direction in ("out", "both"):
                edges += [(v, d, "out") for _, v, d in self.G.out_edges(cur, data=True)]
            if direction in ("in", "both"):
                edges += [(u, d, "in") for u, _, d in self.G.in_edges(cur, data=True)]
            for other, d, dirn in edges:
                if types and d.get("type") not in types:
                    continue
                for e in d.get("evidence", [])[:2]:
                    self.ledger.add(e)
                od = self.G.nodes[other]
                for e in od.get("evidence", [])[:1]:
                    self.ledger.add(e)
                self.ledger.nodes.add(other)
                out.append({"from": cur, "edge": d.get("type"), "direction": dirn, "node": other,
                            "node_type": od.get("type"), "attrs": {k: d[k] for k in ("target", "via", "source", "change", "from", "to", "weight") if k in d},
                            "evidence": d.get("evidence", [])[:2], "depth": dep + 1})
                if other not in seen:
                    seen.add(other)
                    q.append((other, dep + 1))
        return {"node": self.summary(nid), "neighbours": out[:MAX_NEIGHBOURS]}

    def t_get_card(self, node_id: str) -> dict:
        nid = self.resolve_node(node_id)
        if not nid:
            return {"error": f"no node matches {node_id!r}"}
        card = ensure_card(self.ctx, nid)
        if not card:
            return {"error": f"{nid} has no card (cards exist for modules, files and the repo)", "node": self.summary(nid)}
        for e in card.get("evidence", []):
            self.ledger.add(e)
        return {"card": card}

    def t_read_code(self, file: str, start: int, end: int) -> dict:
        start, end = int(start), int(end)
        if end < start:
            start, end = end, start
        end = min(end, start + MAX_READ_LINES - 1)
        src = self.ctx.source
        if src.available:
            lines = src.read_lines(file, start, end)
            if lines:
                self.ledger.add_file(file, lines[0][0], lines[-1][0])
            return {"file": file, "start": start, "end": lines[-1][0] if lines else start,
                    "lines": [f"{i}: {t}" for i, t in lines]}
        # source not available: return the indexed facts for the range instead
        f = self.ctx.files_by_path.get(file)
        if not f:
            return {"error": f"{file} is not in the code index and the source is unavailable"}
        defs = [d for d in f.get("definitions", []) if d.get("line", 0) <= end and (d.get("end_line") or 0) >= start]
        for d in defs:
            self.ledger.add_file(file, d.get("line"), d.get("end_line"))
        return {"file": file, "note": "repository source unavailable; returning indexed definitions",
                "definitions": defs}

    def t_grep(self, pattern: str, glob: str = "**/*.py") -> dict:
        src = self.ctx.source
        if src.available:
            hits = src.grep(pattern, glob or "**/*.py", MAX_GREP)
            files_searched = sum(1 for _ in src.iter_files(glob or "**/*.py"))
        else:  # search the code index (imports + call targets) instead
            rx = re.compile(pattern)
            hits = []
            for f in self.ctx.code_index.get("files", []):
                for imp in f.get("imports", []):
                    text = f"import {imp.get('name')}"
                    if rx.search(text) or rx.search(f"from {imp.get('name')} import"):
                        hits.append({"file": f["path"], "line": imp.get("line"), "text": text})
                for c in f.get("calls", []):
                    if rx.search(str(c.get("target", ""))):
                        hits.append({"file": f["path"], "line": c.get("line"), "text": c.get("target")})
            hits = hits[:MAX_GREP]
            files_searched = len(self.ctx.code_index.get("files", []))
        for h in hits:
            self.ledger.add_file(h["file"], h["line"])
        return {"pattern": pattern, "glob": glob, "files_searched": files_searched, "matches": hits,
                "source": "repository" if src.available else "code_index"}

    def t_git_history(self, target: str) -> dict:
        src = self.ctx.source
        facts_hist = self.ctx.facts.get("dependency_history", []) or []
        is_path = "/" in target or bool(re.search(r"\.(py|txt|toml|cfg|ya?ml|lock|ini|json)$", target))
        commits: list[dict] = []
        diff = None
        if is_path and src.is_git:
            out = src.git("log", "-n", "10", "--format=%H%x1f%aI%x1f%an%x1f%s", "--follow", "--", target) or ""
            for line in out.splitlines():
                p = line.split("\x1f")
                if len(p) == 4:
                    commits.append({"commit": p[0], "date": p[1], "author": p[2], "message": p[3]})
            if commits:
                d = src.git("show", "--format=", "--unified=1", commits[0]["commit"], "--", target) or ""
                diff = "\n".join(d.splitlines()[:60])
        elif is_path:
            commits = [{"commit": h.get("commit"), "date": h.get("date"), "author": h.get("author"),
                        "message": h.get("message")} for h in facts_hist if target in (h.get("files_changed") or [])]
        else:
            n = normalize_name(target)
            for h in facts_hist:
                changes = []
                if any(normalize_name(re.split(r"[<>=!~ ]", str(a))[0]) == n for a in h.get("added", []) or []):
                    changes.append("added")
                if any(normalize_name(re.split(r"[<>=!~ ]", str(a))[0]) == n for a in h.get("removed", []) or []):
                    changes.append("removed")
                for c in h.get("changed", []) or []:
                    if normalize_name(c.get("name", "")) == n:
                        changes.append(f"version {c.get('from')} → {c.get('to')}")
                if changes:
                    commits.append({"commit": h.get("commit"), "date": h.get("date"), "author": h.get("author"),
                                    "message": h.get("message"), "changes": changes,
                                    "files_changed": h.get("files_changed", [])})
        for c in commits:
            if c.get("commit"):
                self.ledger.commits.add(c["commit"])
        return {"target": target, "commits": commits, "diff": diff}

    def t_pypi_info(self, package: str) -> dict:
        n = normalize_name(package.split("/", 1)[-1].split("@")[0] if package.startswith("pkg:") else package)
        pid = next((p for p in nodes_of(self.G, "Package") if normalize_name(self.G.nodes[p].get("name", "")) == n
                    and self.G.nodes[p].get("version")), None) or \
            next((p for p in nodes_of(self.G, "Package") if normalize_name(self.G.nodes[p].get("name", "")) == n), None)
        if not pid:
            return {"error": f"package {package!r} is not declared, resolved or in the SBOM"}
        d = self.G.nodes[pid]
        for e in d.get("evidence", []):
            self.ledger.add(e)
        self.ledger.nodes.add(pid)
        import_names = sorted({k for k, v in {**FALLBACK_DIST, **(self.ctx.code_index.get("import_name_to_distribution") or {})}.items()
                               if normalize_name(v) == n} | {d.get("name", "").replace("-", "_").lower()})
        return {"purl": pid, "name": d.get("name"), "version": d.get("version"), "direct": d.get("direct"),
                "dev": d.get("dev"), "declared_spec": d.get("declared_spec"), "declared_at": d.get("evidence", []),
                "required_by": d.get("required_by"), "requires": d.get("requires"), "origin": d.get("origin"),
                "tags": d.get("tags"), "used_by_files": d.get("used_by_files"), "import_names": import_names,
                "blast_radius": self.ctx.blast.get(pid, {}).get("radius"), "new_in_diff": d.get("new_in_diff", False)}

    def t_get_path(self, entry: Optional[str] = None, sink: Optional[str] = None) -> dict:
        paths = get_paths(self.ctx.paths, entry, sink)[:10]
        for p in paths:
            for e in p.get("evidence", []):
                self.ledger.add(e)
        return {"paths": paths}


def tool_result_text(out: dict, limit: int = 12000) -> str:
    text = json.dumps(out, default=str, ensure_ascii=False)
    return text if len(text) <= limit else text[:limit] + "…(truncated)"
