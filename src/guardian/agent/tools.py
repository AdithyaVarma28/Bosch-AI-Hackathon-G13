"""Read-only, path-confined evidence tools for the agents. No shell, no writes, no free-form graph queries.

Every tool result is stored as RAW evidence first, so whatever the agent cites can be re-checked.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from ..cartographer.history import file_at
from ..context import RunContext
from ..detectors.infra import SECRET_PATTERNS, redact
from ..fsutil import read_text, rel, walk_files
from ..runner import ToolFailed, git
from ..purl import package_key


class PathEscape(PermissionError):
    pass


class ToolRefused(PermissionError):
    pass


def scrub(text: str) -> str:
    for rx in SECRET_PATTERNS.values():
        text = rx.sub(lambda m: redact(m.group(0)), text)
    return text


class EvidenceTools:
    def __init__(self, ctx: RunContext):
        self.ctx = ctx
        self.root = Path(ctx.repo.clone_path).resolve()
        self.registry: dict[str, Callable[..., dict]] = {
            "read_file": self.read_file, "grep_repo": self.grep_repo, "get_dep_path": self.get_dep_path,
            "get_lockfile_entry": self.get_lockfile_entry, "git_log": self.git_log, "get_advisory": self.get_advisory,
            "get_scope": self.get_scope, "get_code_usage": self.get_code_usage, "get_blast_radius": self.get_blast_radius,
            "get_commit_diff": self.get_commit_diff,
        }

    TOOL_SPECS = {
        "read_file": "read_file(path:str, start:int, end:int) - lines of a repo file (max 80 lines)",
        "grep_repo": "grep_repo(pattern:str, max_hits:int=20) - regex search over repo text files",
        "get_dep_path": "get_dep_path(purl:str) - dependency paths from direct dependencies to this package",
        "get_lockfile_entry": "get_lockfile_entry(purl:str) - resolved url, integrity, scope, install-script flag",
        "git_log": "git_log(path:str, n:int=10) - recent commits touching a file",
        "get_commit_diff": "get_commit_diff(commit:str, path:str) - the file before/after a commit (first 60 lines each)",
        "get_advisory": "get_advisory(id:str) - stored OSV advisory record",
        "get_scope": "get_scope(purl:str) - prod/dev scope and whether it is a direct dependency",
        "get_code_usage": "get_code_usage(purl:str) - source files/functions that import or call this package",
        "get_blast_radius": "get_blast_radius(purl:str) - dependents, importing code and exposed routes",
    }

    @property
    def allowlist(self) -> frozenset[str]:
        return frozenset(self.registry)

    def call(self, name: str, args: dict[str, Any]) -> dict:
        if name not in self.registry:
            raise ToolRefused(f"tool '{name}' is not allowlisted")
        if not isinstance(args, dict):
            args = {}
        return self.registry[name](**{k: v for k, v in args.items() if isinstance(k, str)})

    def _ev(self, source: str, locator: str, excerpt: str) -> dict:
        excerpt = scrub(excerpt)
        e = self.ctx.store.add_evidence("raw", f"tool:{source}", locator, excerpt)
        return {"evidence_id": e.id, "locator": locator, "excerpt": excerpt[:2500]}

    def _confine(self, path: str) -> Path:
        p = (self.root / str(path)).resolve()
        if not p.is_relative_to(self.root) or ".git" in p.relative_to(self.root).parts:
            raise PathEscape(f"path escapes repository: {path}")
        return p

    # ----------------------------------------------------------------- tools
    def read_file(self, path: str, start: int = 1, end: int = 40, **_) -> dict:
        p = self._confine(path)
        text = read_text(p)
        if text is None:
            return {"error": f"cannot read {path}"}
        start, end = max(1, int(start)), int(end)
        end = min(max(end, start), start + 79)
        lines = text.splitlines()[start - 1:end]
        body = "\n".join(f"{start + i}: {l}" for i, l in enumerate(lines))
        return self._ev("read_file", f"{rel(self.root, p)}:{start}-{start + len(lines) - 1}", body)

    def grep_repo(self, pattern: str, max_hits: int = 20, **_) -> dict:
        try:
            rx = re.compile(str(pattern)[:200])
        except re.error as e:
            return {"error": f"bad regex: {e}"}
        hits = []
        for p in walk_files(self.root):
            if p.suffix.lower() in (".png", ".jpg", ".gif", ".zip", ".gz", ".pdf", ".woff", ".woff2", ".ico"):
                continue
            t = read_text(p, limit=500_000)
            if not t:
                continue
            for i, line in enumerate(t.splitlines(), 1):
                if rx.search(line):
                    hits.append(f"{rel(self.root, p)}:{i}: {line.strip()[:200]}")
                    if len(hits) >= min(int(max_hits), 50):
                        break
            if len(hits) >= min(int(max_hits), 50):
                break
        return self._ev("grep", f"grep:{pattern}", "\n".join(hits) or "(no matches)")

    def get_dep_path(self, purl: str, **_) -> dict:
        paths = self.ctx.graph.paths_to(purl) if self.ctx.graph else []
        body = "\n".join(" -> ".join(p) for p in paths) or f"no path from a direct dependency to {purl}"
        return self._ev("dep_path", f"graph:paths:{purl}", body)

    def get_lockfile_entry(self, purl: str, **_) -> dict:
        c = next((c for c in self.ctx.components if c.purl == purl), None)
        if not c:
            return {"error": f"{purl} not in SBOM"}
        body = json.dumps({"purl": c.purl, "version": c.version, "scope": c.scope, "direct": c.direct,
                           "resolved": c.origin.resolved_url, "integrity": c.origin.integrity,
                           "has_install_script": c.origin.has_install_script, "seen_by": c.seen_by, "source": c.source})
        return self._ev("lockfile_entry", f"sbom:{purl}", body)

    def git_log(self, path: str, n: int = 10, **_) -> dict:
        self._confine(path)
        try:
            out = git(self.root, "log", f"-n{min(int(n), 20)}", "--format=%h %aI %an: %s", "--", str(path), runner=self.ctx.runner)
        except ToolFailed as e:
            return {"error": str(e)}
        return self._ev("git_log", f"git:log:{path}", out or "(no commits)")

    def get_commit_diff(self, commit: str, path: str, **_) -> dict:
        self._confine(path)
        if not re.fullmatch(r"[0-9a-f]{7,40}", str(commit)):
            return {"error": "commit must be a hex hash"}
        after = file_at(self.root, commit, path, self.ctx.runner) or ""
        before = file_at(self.root, f"{commit}^", path, self.ctx.runner) or ""
        a, b = before.splitlines(), after.splitlines()
        changed = [f"- {x}" for x in a if x not in b][:40] + [f"+ {x}" for x in b if x not in a][:40]
        return self._ev("commit_diff", f"{path}@{commit}", "\n".join(changed) or "(no line changes)")

    def get_advisory(self, id: str, **_) -> dict:
        for e in self.ctx.store.all_evidence():
            if e.source == "osv" and e.locator == f"osv:{id}":
                return {"evidence_id": e.id, "locator": e.locator, "excerpt": e.excerpt[:2500]}
        return {"error": f"advisory {id} not stored for this run"}

    def get_scope(self, purl: str, **_) -> dict:
        c = next((c for c in self.ctx.components if c.purl == purl), None)
        if not c:
            return {"error": f"{purl} not in SBOM"}
        return self._ev("scope", f"sbom:scope:{purl}", f"{purl}: scope={c.scope}, direct={c.direct}")

    def get_code_usage(self, purl: str, **_) -> dict:
        from ..purl import parse_purl
        try:
            eco, name, _v = parse_purl(purl)
        except ValueError:
            return {"error": "invalid purl"}
        uses = self.ctx.graph.importers(package_key(eco, name)) if self.ctx.graph else []
        body = "\n".join(f"{u['rel']} {u['from']} at {u['locator']}" + (f" ({u['target']})" if u.get("target") else "") for u in uses)
        return self._ev("code_usage", f"graph:usage:{purl}", body or f"no static import/use of {name} found")

    def get_blast_radius(self, purl: str, **_) -> dict:
        br = self.ctx.graph.blast_radius(purl) if self.ctx.graph else {}
        return self._ev("blast_radius", f"graph:blast:{purl}", json.dumps(br) if br else f"{purl} not in graph")
