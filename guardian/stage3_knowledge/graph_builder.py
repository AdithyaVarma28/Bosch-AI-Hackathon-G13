"""Load Stage 1–2 JSON (facts.json, code_index.json, sbom.cdx.json) into one NetworkX graph.

The builder only records facts. It never judges, and it tolerates missing or extra
fields so a slightly different Stage 1–2 output does not crash the scan.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Optional

import networkx as nx

from .schema import (
    action_id, class_id, cli_id, commit_id, env_id, file_id, fn_id, image_id, normalize_name,
    now_iso, purl, repo_id, route_id, svc_id, table_id, workflow_id,
)

SECRET_NAME_RE = re.compile(
    r"(KEY|SECRET|TOKEN|PASSW|PWD|CRED|PRIVATE|AUTH|DSN|DATABASE_URL|CONN(ECTION)?_STR)", re.I
)


# --------------------------------------------------------------------------- graph helpers

def add_node(G: nx.MultiDiGraph, nid: str, type: str, discovered_by: str,
             evidence: Optional[Iterable[dict]] = None, confidence: float = 1.0, **attrs: Any) -> str:
    """Add or merge a node. Lists merge, tags union, scalars only fill blanks."""
    ev = [e for e in (evidence or []) if e]
    if nid in G:
        data = G.nodes[nid]
        for e in ev:
            if e not in data["evidence"]:
                data["evidence"].append(e)
        for k, v in attrs.items():
            if k == "tags":
                for t in v or []:
                    if t not in data["tags"]:
                        data["tags"].append(t)
            elif data.get(k) in (None, "", [], {}):
                data[k] = v
        return nid
    tags = list(dict.fromkeys(attrs.pop("tags", []) or []))
    G.add_node(nid, id=nid, type=type, discovered_by=discovered_by, evidence=ev,
               confidence=confidence, commit=G.graph.get("commit"), analyzed_at=G.graph.get("analyzed_at"),
               tags=tags, **attrs)
    return nid


def add_edge(G: nx.MultiDiGraph, u: str, v: str, type: str, discovered_by: str,
             evidence: Optional[Iterable[dict]] = None, key: Optional[str] = None,
             confidence: float = 1.0, **attrs: Any) -> None:
    """Add or merge an edge. Repeated edges increase ``weight`` and collect evidence."""
    key = key or type
    ev = [e for e in (evidence or []) if e]
    if G.has_edge(u, v, key):
        data = G.edges[u, v, key]
        data["weight"] = data.get("weight", 1) + attrs.pop("weight", 1)
        for e in ev:
            if e not in data["evidence"]:
                data["evidence"].append(e)
        for k, val in attrs.items():
            data.setdefault(k, val)
        return
    weight = attrs.pop("weight", 1)
    G.add_edge(u, v, key=key, type=type, discovered_by=discovered_by, evidence=ev,
               confidence=confidence, weight=weight, commit=G.graph.get("commit"),
               analyzed_at=G.graph.get("analyzed_at"), **attrs)


def tag(G: nx.MultiDiGraph, nid: str, *tags: str) -> None:
    if nid not in G:
        return
    cur = G.nodes[nid].setdefault("tags", [])
    for t in tags:
        if t and t not in cur:
            cur.append(t)


def nodes_of(G: nx.MultiDiGraph, *types: str) -> list[str]:
    return [n for n, d in G.nodes(data=True) if d.get("type") in types]


def succ(G: nx.MultiDiGraph, nid: str, *etypes: str) -> list[str]:
    if nid not in G:
        return []
    return list(dict.fromkeys(v for _, v, d in G.out_edges(nid, data=True) if not etypes or d.get("type") in etypes))


def pred(G: nx.MultiDiGraph, nid: str, *etypes: str) -> list[str]:
    if nid not in G:
        return []
    return list(dict.fromkeys(u for u, _, d in G.in_edges(nid, data=True) if not etypes or d.get("type") in etypes))


def out_edges(G: nx.MultiDiGraph, nid: str, *etypes: str) -> list[tuple[str, str, dict]]:
    if nid not in G:
        return []
    return [(u, v, d) for u, v, d in G.out_edges(nid, data=True) if not etypes or d.get("type") in etypes]


def in_edges(G: nx.MultiDiGraph, nid: str, *etypes: str) -> list[tuple[str, str, dict]]:
    if nid not in G:
        return []
    return [(u, v, d) for u, v, d in G.in_edges(nid, data=True) if not etypes or d.get("type") in etypes]


def ev(file: Optional[str] = None, line: Optional[int] = None, lines: Optional[str] = None,
       commit: Optional[str] = None) -> dict:
    out: dict[str, Any] = {}
    if file:
        out["file"] = file
    if line is not None:
        out["line"] = int(line)
    if lines:
        out["lines"] = str(lines)
    if commit:
        out["commit"] = commit
    return out


def is_secret_name(name: str) -> bool:
    return bool(SECRET_NAME_RE.search(name or ""))


def strip_spec(req: str) -> str:
    """'PyYAML>=5.4 ; python_version>"3"' -> 'PyYAML'."""
    return re.split(r"[\s<>=!~;\[@(]", (req or "").strip(), maxsplit=1)[0]


# --------------------------------------------------------------------------- loading

def load_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def load_stage12(input_dir: str | Path) -> dict:
    """Read the Stage 1–2 output folder (``output/<repo>/``)."""
    d = Path(input_dir)
    facts = load_json(d / "facts.json")
    code_index = load_json(d / "code_index.json")
    if facts is None or code_index is None:
        missing = [n for n, v in (("facts.json", facts), ("code_index.json", code_index)) if v is None]
        raise FileNotFoundError(f"Stage 1–2 output missing in {d}: {', '.join(missing)}")
    sbom = load_json(d / "sbom.cdx.json")
    if sbom is None and facts.get("sbom_path"):
        sbom = load_json(Path(facts["sbom_path"]))
    return {"facts": facts, "code_index": code_index, "sbom": sbom}


# --------------------------------------------------------------------------- builder

class GraphBuilder:
    def __init__(self, facts: dict, code_index: dict, sbom: Optional[dict] = None, source=None):
        self.facts = facts or {}
        self.ci = code_index or {}
        self.sbom = sbom
        self.source = source                          # RepoSource or None (used by enrich only)
        repo = self.facts.get("repo", {}) or {}
        self.repo_name = repo.get("name") or "repo"
        self.G = nx.MultiDiGraph()
        self.G.graph.update({
            "repo": self.repo_name, "commit": repo.get("commit"), "analyzed_at": now_iso(),
            "errors": [], "unresolved_calls": [], "unresolved_imports": [], "known_unknowns": [],
            "calls_internal_total": 0, "calls_internal_resolved": 0,
        })
        self.pkg_by_name: dict[str, str] = {}
        self.def_index: dict[str, str] = {}          # "path::qual" -> node id
        self.def_ranges: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
        self.model_tables: dict[str, str] = {}       # class name / id -> table name
        self.module_files: dict[str, str] = {}       # dotted module path -> file path
        self.module_by_last: dict[str, Optional[str]] = {}

    def error(self, where: str, exc: Exception | str) -> None:
        self.G.graph["errors"].append({"where": where, "error": str(exc)})

    # ------------------------------------------------------------------ public
    def build(self) -> nx.MultiDiGraph:
        self._repo()
        for step in (self._packages, self._scopes, self._sbom, self._ci, self._containers, self._config):
            try:
                step()
            except Exception as exc:  # fail soft
                self.error(step.__name__, exc)
        self._code()
        try:
            from .enrich import enrich
            enrich(self)
        except Exception as exc:
            self.error("enrich", exc)
        try:
            self._history()
        except Exception as exc:
            self.error("_history", exc)
        return self.G

    def resolve_internal(self, target: Optional[str]) -> Optional[str]:
        """Dotted internal call target ('app.payments.service.charge') -> definition node.

        Stage 2 records internal calls alias-resolved but without a function id, so the
        longest module prefix is mapped to its file and the rest to a definition. A class
        call (constructor) resolves to its ``__init__`` when there is one.
        """
        if not target:
            return None
        if "::" in target:
            return self.def_index.get(target)
        parts = target.split(".")
        for i in range(len(parts), 0, -1):
            mod = ".".join(parts[:i])
            path = self.module_files.get(mod)
            if path is None and i == 1:
                path = self.module_by_last.get(mod)   # script-style sibling import
            if not path:
                continue
            rest = parts[i:]
            for j in range(len(rest), 0, -1):
                ref = f"{path}::{'.'.join(rest[:j])}"
                nid = self.def_index.get(ref)
                if nid:
                    if nid.startswith("class:"):
                        return self.def_index.get(f"{ref}.__init__") or nid
                    return nid
            return None
        return None

    def _scopes(self) -> None:
        """prod/dev/unknown scope per package, using the team's Stage 1 adapter."""
        from guardian.adapters import components_from_facts
        from guardian.models.facts import ScanFacts
        comps, _ = components_from_facts(ScanFacts.model_validate(self.facts))
        for c in comps:
            pid = self.pkg_by_name.get(normalize_name(c.name))
            if pid:
                self.G.nodes[pid]["scope"] = c.scope

    # ------------------------------------------------------------------ facts
    def _repo(self) -> None:
        repo = self.facts.get("repo", {}) or {}
        docs = self.facts.get("docs", {}) or {}
        previews = docs.get("previews") or {}
        add_node(self.G, repo_id(self.repo_name), "Repo", "git", [ev(commit=repo.get("commit"))],
                 name=self.repo_name, branch=repo.get("branch"), scanned_at=repo.get("scanned_at"),
                 path=repo.get("path"), readme=docs.get("readme"),
                 readme_excerpt=previews.get(docs.get("readme") or "") or docs.get("readme_excerpt"),
                 package_indexes=self.facts.get("package_indexes", []),
                 stage12_errors=(self.facts.get("errors", []) or [])[:20])

    def _packages(self) -> None:
        G = self.G
        declared: dict[str, list[dict]] = defaultdict(list)
        for d in self.facts.get("declared_dependencies", []) or []:
            declared[normalize_name(d.get("name", ""))].append(d)

        for p in self.facts.get("resolved_packages", []) or []:
            name = p.get("name") or ""
            pid = p.get("purl") or purl(name, p.get("version"))
            decl = declared.get(normalize_name(name), [])
            dev = bool(decl) and all(d.get("dev") for d in decl)
            evidence = [ev(d.get("source_file"), d.get("line")) for d in decl]
            add_node(G, pid, "Package", p.get("source") or "manifest", evidence,
                     name=name, version=p.get("version"), purl=pid, direct=bool(p.get("direct")),
                     dev=dev, declared=bool(decl), declared_spec=[d.get("spec") for d in decl],
                     dep_kind=(decl[0].get("kind") if decl else None), required_by=p.get("required_by", []),
                     requires=p.get("requires", []), hashes=p.get("hashes", []),
                     origin=(self.facts.get("package_metadata", {}) or {}).get(pid, {}))
            self.pkg_by_name[normalize_name(name)] = pid

        # declared but not resolved (e.g. resolver failed): still a node, without a version
        for norm, decls in declared.items():
            if norm in self.pkg_by_name:
                continue
            d = decls[0]
            pid = purl(d.get("name", norm))
            add_node(G, pid, "Package", "manifest", [ev(x.get("source_file"), x.get("line")) for x in decls],
                     name=d.get("name", norm), version=None, purl=pid, direct=True,
                     dev=all(x.get("dev") for x in decls), declared=True,
                     declared_spec=[x.get("spec") for x in decls], dep_kind=d.get("kind"),
                     tags=["unresolved_version"])
            self.pkg_by_name[norm] = pid

        for p in self.facts.get("resolved_packages", []) or []:
            src = p.get("purl") or purl(p.get("name", ""), p.get("version"))
            for r in p.get("requires", []) or []:
                tgt = r if str(r).startswith("pkg:") else self.pkg_by_name.get(normalize_name(strip_spec(str(r))))
                if tgt and tgt in G and tgt != src:
                    add_edge(G, src, tgt, "REQUIRES", p.get("source") or "manifest")

    def _sbom(self) -> None:
        if not self.sbom:
            return
        for comp in self.sbom.get("components", []) or []:
            p = comp.get("purl") or ""
            if not p.startswith("pkg:pypi/"):
                continue
            name = comp.get("name") or p.split("/", 1)[1].split("@")[0]
            existing = self.pkg_by_name.get(normalize_name(name))
            if existing:
                self.G.nodes[existing]["in_sbom"] = True
                sbom_ver = comp.get("version")
                if sbom_ver and self.G.nodes[existing].get("version") not in (None, sbom_ver):
                    self.G.nodes[existing]["sbom_version_mismatch"] = sbom_ver
                continue
            add_node(self.G, p, "Package", "syft", [], name=name, version=comp.get("version"), purl=p,
                     direct=False, dev=False, declared=False, in_sbom=True, tags=["sbom_only"])
            self.pkg_by_name[normalize_name(name)] = p

    def _ci(self) -> None:
        rid = repo_id(self.repo_name)
        for wf in self.facts.get("ci_workflows", []) or []:
            wid = workflow_id(wf.get("file", "workflow"))
            add_node(self.G, wid, "Workflow", "yaml", [ev(wf.get("file"))], file=wf.get("file"),
                     triggers=wf.get("triggers", []), permissions=wf.get("permissions"),
                     secrets_used=wf.get("secrets_used", []), run_steps=wf.get("run_steps", []))
            add_edge(self.G, rid, wid, "CONTAINS", "yaml")
            for a in wf.get("actions", []) or []:
                aid = action_id(a.get("uses", "?"), a.get("ref"))
                add_node(self.G, aid, "Action", "yaml", [ev(wf.get("file"), a.get("line"))],
                         uses=a.get("uses"), ref=a.get("ref"), pinned_to_sha=bool(a.get("pinned_to_sha")),
                         tags=[] if a.get("pinned_to_sha") else ["pinned_to_tag"])
                add_edge(self.G, wid, aid, "USES_ACTION", "yaml", [ev(wf.get("file"), a.get("line"))])

    def _containers(self) -> None:
        rid = repo_id(self.repo_name)
        for c in self.facts.get("containers", []) or []:
            for img in c.get("base_images", []) or []:
                iid = image_id(img.get("ref", "?"))
                add_node(self.G, iid, "Image", "dockerfile", [ev(c.get("file"), img.get("line"))],
                         ref=img.get("ref"), image_tag=img.get("tag"), digest=img.get("digest"),
                         tags=[] if img.get("digest") else ["pinned_to_tag"])
                add_edge(self.G, rid, iid, "USES_IMAGE", "dockerfile", [ev(c.get("file"), img.get("line"))],
                         source="Dockerfile")
        for s in ((self.facts.get("config", {}) or {}).get("compose_services", []) or []):
            if not s.get("image"):
                continue
            iid = image_id(s["image"])
            add_node(self.G, iid, "Image", "yaml", [ev(s.get("file"), s.get("line"))], ref=s["image"],
                     digest=s.get("digest"), compose_service=s.get("name"),
                     tags=[] if s.get("digest") else ["pinned_to_tag"])
            add_edge(self.G, rid, iid, "USES_IMAGE", "yaml", [ev(s.get("file"), s.get("line"))],
                     source="compose", service=s.get("name"))

    def _config(self) -> None:
        cfg = self.facts.get("config", {}) or {}
        for envf in cfg.get("env_files", []) or []:
            for name in envf.get("var_names", []) or []:
                add_node(self.G, env_id(name), "EnvVar", "manifest", [ev(envf.get("file"))], name=name,
                         secret_like=is_secret_name(name), declared_in=[envf.get("file")])

    def _history(self) -> None:
        for h in self.facts.get("dependency_history", []) or []:
            sha = h.get("commit")
            if not sha:
                continue
            cid = commit_id(sha)
            add_node(self.G, cid, "Commit", "git", [ev(commit=sha)], sha=sha, date=h.get("date"),
                     author=h.get("author"), message=h.get("message"), files_changed=h.get("files_changed", []),
                     added=h.get("added", []), removed=h.get("removed", []), changed=h.get("changed", []))
            for a in h.get("added", []) or []:
                pid = self.pkg_by_name.get(normalize_name(strip_spec(str(a))))
                if pid:
                    add_edge(self.G, pid, cid, "CHANGED_IN", "git", [ev(commit=sha)], key=f"CHANGED_IN:{cid}",
                             change="added")
            for c in h.get("changed", []) or []:
                pid = self.pkg_by_name.get(normalize_name(c.get("name", "")))
                if pid:
                    add_edge(self.G, pid, cid, "CHANGED_IN", "git", [ev(commit=sha)], key=f"CHANGED_IN:{cid}",
                             change="version", **{"from": c.get("from"), "to": c.get("to")})

    # ------------------------------------------------------------------ code index
    def enclosing(self, path: str, line: Optional[int]) -> Optional[str]:
        """Innermost definition containing ``line`` in ``path``."""
        if line is None:
            return None
        best = None
        for start, end, nid in self.def_ranges.get(path, []):
            if start <= line <= end and (best is None or start >= best[0]):
                best = (start, end, nid)
        return best[2] if best else None

    def _fn(self, def_ref: Optional[str], path: str, line: Optional[int] = None) -> Optional[str]:
        """Resolve a Stage 2 definition id (``path::qual``) to a node, creating module-level pseudo functions."""
        if def_ref:
            if def_ref in self.def_index:
                return self.def_index[def_ref]
            if def_ref.startswith(("fn:", "class:")) and def_ref in self.G:
                return def_ref
        enc = self.enclosing(path, line)
        if enc:
            return enc
        ref = def_ref if def_ref and "::" in def_ref else f"{path}::<module>"
        if not ref.endswith("<module>") and ref not in self.def_index:
            ref = f"{path}::<module>"
        nid = fn_id(ref)
        if nid not in self.G:
            add_node(self.G, nid, "Function", "ast", [ev(path, 1)], name="<module>", qualname="<module>",
                     file=path, line=1, end_line=1, module_level=True, params=[], external_calls=[],
                     inputs=[], sensitive=[])
            add_edge(self.G, file_id(path), nid, "CONTAINS", "ast")
        return nid

    def _code(self) -> None:
        G = self.G
        files = self.ci.get("files", []) or []
        last_seen: dict[str, list[str]] = defaultdict(list)
        for f in files:
            if f.get("path") and f.get("module_path"):
                self.module_files[f["module_path"]] = f["path"]
                last_seen[f["module_path"].split(".")[-1]].append(f["path"])
        self.module_by_last = {k: v[0] for k, v in last_seen.items() if len(v) == 1}
        # pass 1: files + definitions
        for f in files:
            path = f.get("path")
            if not path:
                continue
            fid = file_id(path)
            add_node(G, fid, "File", "ast", [ev(path)], path=path, module_path=f.get("module_path"),
                     package_dir=f.get("package_dir"), sha256=f.get("sha256"), loc=f.get("loc") or 0,
                     is_test=bool(f.get("is_test")), docstring=f.get("docstring"),
                     parse_error=f.get("parse_error"), dynamic_imports=f.get("dynamic_imports", []) or [],
                     string_urls=f.get("string_urls", []) or [], external_imports=[], services=[],
                     tags=["parse_error"] if f.get("parse_error") else [])
            for d in f.get("definitions", []) or []:
                ref = d.get("id") or f"{path}::{d.get('name')}"
                dtype = (d.get("type") or "function").lower()
                nid = class_id(ref) if dtype == "class" else fn_id(ref)
                qual = ref.split("::", 1)[-1]
                start, end = d.get("line") or 0, d.get("end_line") or d.get("line") or 0
                add_node(G, nid, "Class" if dtype == "class" else "Function", "ast",
                         [ev(path, lines=f"{start}-{end}")], name=d.get("name") or qual.split(".")[-1],
                         qualname=qual, file=path, line=start, end_line=end, kind=dtype,
                         decorators=d.get("decorators", []) or [], params=d.get("params", []) or [],
                         returns=d.get("returns"), docstring=d.get("docstring"), external_calls=[],
                         inputs=[], sensitive=[])
                add_edge(G, fid, nid, "CONTAINS", "ast")
                self.def_index[ref] = nid
                self.def_ranges[path].append((start, end, nid))

        # pass 2: relations
        for f in files:
            path = f.get("path")
            if not path:
                continue
            try:
                self._file_relations(f, path)
            except Exception as exc:  # one bad file must not crash the scan
                self.error(f"code:{path}", exc)

        # pass 3: things that need every file loaded
        for f in files:
            path = f.get("path")
            if not path:
                continue
            for acc in f.get("db_access", []) or []:
                try:
                    self._db_access(acc, path)
                except Exception as exc:
                    self.error(f"db_access:{path}", exc)
            for src in f.get("input_sources", []) or []:
                fn = self._fn(src.get("function") or src.get("function_id"), path, src.get("line"))
                if not fn:
                    continue
                G.nodes[fn]["inputs"].append({"source": src.get("source"), "line": src.get("line")})
                for rid in pred(G, fn, "HANDLES"):
                    add_edge(G, fn, rid, "RECEIVES_INPUT", "ast", [ev(path, src.get("line"))],
                             key=f"RECEIVES_INPUT:{src.get('source')}", source=src.get("source"))

    def _file_relations(self, f: dict, path: str) -> None:
        G = self.G
        fid = file_id(path)
        fdata = G.nodes[fid]
        for imp in f.get("imports", []) or []:
            kind = imp.get("kind")
            if kind == "internal" and imp.get("resolved_file"):
                tgt = file_id(imp["resolved_file"])
                if tgt not in G:
                    add_node(G, tgt, "File", "ast", [ev(imp["resolved_file"])], path=imp["resolved_file"],
                             loc=0, is_test=False, external_imports=[], services=[], dynamic_imports=[],
                             string_urls=[], tags=["not_indexed"])
                if tgt != fid:
                    add_edge(G, fid, tgt, "IMPORTS", "ast", [ev(path, imp.get("line"))], names=[imp.get("name")])
            elif kind == "external":
                fdata["external_imports"].append({k: imp.get(k) for k in ("name", "alias", "line", "in_try_except", "conditional")})

        for c in f.get("calls", []) or []:
            caller = self._fn(c.get("caller"), path, c.get("line"))
            if not caller:
                continue
            if c.get("kind") == "internal":
                G.graph["calls_internal_total"] += 1
                tgt = self.resolve_internal(c.get("resolved_target") or c.get("target"))
                if tgt:
                    G.graph["calls_internal_resolved"] += 1
                    if tgt != caller:
                        add_edge(G, caller, tgt, "CALLS", "ast", [ev(path, c.get("line"))])
                else:
                    G.graph["unresolved_calls"].append({"file": path, "line": c.get("line"), "target": c.get("target")})
            else:  # external + stdlib: kept for package linking, DB and service detection
                G.nodes[caller]["external_calls"].append(
                    {"target": c.get("target"), "import_name": c.get("import_name"), "line": c.get("line"),
                     "kind": c.get("kind")})

        for r in f.get("routes", []) or []:
            methods = r.get("methods") or [r.get("method") or "ANY"]
            href = r.get("handler") or r.get("handler_id") or ""
            if href.startswith("include:"):      # Django include(): routes live in another urls module
                G.graph["known_unknowns"].append(f"Django include {href[8:]} at {path}:{r.get('line')} not expanded")
                continue
            handler = self.def_index.get(href) or self.resolve_internal(href) or self._fn(None, path, r.get("line"))
            for m in methods if isinstance(methods, list) else [methods]:
                rid = route_id(m, r.get("path", "/"))
                add_node(G, rid, "Route", "ast", [ev(path, r.get("line"))], method=str(m).upper(),
                         path=r.get("path"), framework=r.get("framework"), handler=handler, file=path,
                         line=r.get("line"))
                if handler:
                    add_edge(G, rid, handler, "HANDLES", "ast", [ev(path, r.get("line"))])

        for cli in f.get("cli_entrypoints", []) or []:
            kind, line, name = cli.get("kind"), cli.get("line"), cli.get("name") or ""
            if cli.get("function"):
                fn = self._fn(cli["function"], path, line)
            elif kind in ("click", "typer"):
                fn = self.def_index.get(f"{path}::{name}") or self.enclosing(path, (line or 0) + 1)
            elif kind == "argparse":
                fn = self.enclosing(path, line) or self._fn(None, path, line)
            else:                                   # main_guard: module-level code runs
                fn = self._fn(None, path, line)
            cid = cli_id(f"{path}::{name}" if kind in ("click", "typer") else path)
            add_node(G, cid, "CLIEntry", "ast", [ev(path, line)], kind=kind, file=path, line=line,
                     handler=fn, name=name)
            if fn:
                add_edge(G, cid, fn, "HANDLES", "ast", [ev(path, line)])

        for r in f.get("env_reads", []) or []:
            name = r.get("var") or r.get("name")
            if not name:
                continue
            fn = self._fn(r.get("function"), path, r.get("line"))
            eid = add_node(G, env_id(name), "EnvVar", "ast", [ev(path, r.get("line"))], name=name,
                           secret_like=is_secret_name(name), declared_in=[])
            if fn:
                add_edge(G, fn, eid, "READS_ENV", "ast", [ev(path, r.get("line"))], how=r.get("how"))

        for m in f.get("db_models", []) or []:
            table = m.get("table") or m.get("table_name") or (m.get("name") or "").lower()
            if not table:
                continue
            tid = add_node(G, table_id(table), "Table", "ast", [ev(path, m.get("line"))], name=table,
                           fields=m.get("fields", []), model=m.get("name"))
            ref = m.get("class") or m.get("id") or f"{path}::{m.get('name')}"
            cls = self.def_index.get(ref)
            if cls:
                add_edge(G, cls, tid, "MAPS_TO", "ast", [ev(path, m.get("line"))])
            if m.get("name"):
                self.model_tables[m["name"]] = table
            self.model_tables[ref] = table

        for s in f.get("external_services", []) or []:
            name = s.get("name")
            if not name:
                continue
            sid = add_node(G, svc_id(name), "ExternalService", "ast", [ev(path, s.get("line"))], name=name,
                           via=s.get("via"), url=s.get("url"))
            fdata["services"].append({"service": sid, "via": s.get("via"), "line": s.get("line")})
            fns: list[str] = []
            if s.get("function"):
                fns = [self._fn(s["function"], path, s.get("line"))]
            elif s.get("via") == "sdk" and s.get("import_name"):
                imp = s["import_name"].split(".")[0]
                for _, fn in self.def_ranges_nodes(path):
                    calls = G.nodes[fn].get("external_calls", [])
                    if any((c.get("import_name") or str(c.get("target", "")).split(".")[0]) == imp for c in calls):
                        fns.append(fn)
            else:
                enc = self.enclosing(path, s.get("line"))
                if enc:
                    fns = [enc]
            for fn in fns:
                if fn:
                    line = s.get("line")
                    if s.get("via") == "sdk":  # cite the API call line, not the import line
                        imp = (s.get("import_name") or "").split(".")[0]
                        lines = [c.get("line") for c in G.nodes[fn].get("external_calls", [])
                                 if (c.get("import_name") or str(c.get("target", "")).split(".")[0]) == imp]
                        line = lines[0] if lines else line
                    add_edge(G, fn, sid, "CONTACTS", "ast", [ev(path, line)], via=s.get("via"))

        for sc in f.get("sensitive_calls", []) or []:
            fn = self._fn(sc.get("function"), path, sc.get("line"))
            if fn:
                G.nodes[fn]["sensitive"].append({"category": sc.get("category"), "target": sc.get("target"),
                                                 "line": sc.get("line")})

    def def_ranges_nodes(self, path: str) -> list[tuple[int, str]]:
        return [(s, nid) for s, _, nid in self.def_ranges.get(path, [])]

    def _db_access(self, acc: dict, path: str) -> None:
        G = self.G
        fn = self._fn(acc.get("function") or acc.get("function_id"), path, acc.get("line"))
        if not fn:
            return
        op = (acc.get("operation") or "").lower()
        table = acc.get("table") or self.model_tables.get(acc.get("model") or "") or None
        G.nodes[fn].setdefault("db_ops", []).append({"operation": op, "table": table, "line": acc.get("line")})
        etype = "WRITES" if op in ("write", "insert", "update", "delete") else "READS" if op == "read" else None
        if op == "raw_sql":
            etype = "WRITES" if re.search(r"\b(insert|update|delete|drop|create|alter)\b",
                                          str(acc.get("sql", "")), re.I) else "READS"
        if not etype:
            return
        if not table:
            G.graph.setdefault("db_unknown_tables", []).append({"file": path, "line": acc.get("line"), "function": fn})
            tag(G, fn, "writes_db" if etype == "WRITES" else "reads_db")
            return
        tid = add_node(G, table_id(table), "Table", "ast", [ev(path, acc.get("line"))], name=table)
        add_edge(G, fn, tid, etype, "ast", [ev(path, acc.get("line"))], operation=op)


def build_graph(facts: dict, code_index: dict, sbom: Optional[dict] = None) -> nx.MultiDiGraph:
    return GraphBuilder(facts, code_index, sbom).build()
