"""S4 Unified multi-layer graph (NetworkX).

Layers in ONE graph:
  declared : Project -DECLARES-> Package
  resolved : Package -HAS_ARTIFACT-> Artifact, Artifact -DEPENDS_ON-> Artifact
  usage    : SourceModule -IMPORTS-> Package, Function -CALLS-> Function, Function -USES-> Package
  context  : Route, DB table, env var, external service, Dockerfile, base image, workflow, action

Every edge carries `evidence_status` (verified | declared | registry-derived | statically-observed | unknown),
`discovered_by` and, where available, `evidence_id` + `locator`.
"""
from __future__ import annotations

from collections import deque
from typing import Any

import networkx as nx

from .models import CodeIndex, Component, DepEdge, RepoFacts
from .purl import LANGUAGE_ECOSYSTEM, is_valid_purl, normalize_name, package_key

VERIFIED_SOURCES = {"lockfile", "pip-report", "npm-resolve", "syft", "trivy"}


class UnifiedGraph:
    def __init__(self, project: str):
        self.g = nx.MultiDiGraph()
        self.project = f"project:{project}"
        self.g.add_node(self.project, type="project", label=project, layer="all")
        self.validation: dict[str, Any] = {}

    # ------------------------------------------------------------------ construction
    def node(self, nid: str, **attrs) -> str:
        if nid in self.g:
            self.g.nodes[nid].update({k: v for k, v in attrs.items() if v is not None})
        else:
            self.g.add_node(nid, **attrs)
        return nid

    def edge(self, s: str, t: str, rel: str, **attrs) -> None:
        if not self.g.has_edge(s, t, key=rel):
            self.g.add_edge(s, t, key=rel, rel=rel, **attrs)

    @classmethod
    def build(cls, project: str, facts: RepoFacts | None, components: list[Component], edges: list[DepEdge],
              code: CodeIndex | None) -> "UnifiedGraph":
        ug = cls(project)
        P = ug.project
        # -- declared layer
        for d in (facts.declared_dependencies if facts else []):
            if d.kind == "path":
                continue
            pk = ug.node(package_key(d.ecosystem, d.name), type="package", label=d.name, ecosystem=d.ecosystem,
                         declared=True)
            ug.edge(P, pk, "DECLARES", spec=d.spec, scope=d.scope, kind=d.kind, source_file=d.source_file,
                    line=d.line, evidence_status="declared", discovered_by="manifest", evidence_id=d.evidence_id,
                    locator=f"{d.source_file}:{d.line or 1}")
        # -- resolved layer
        purls = {c.purl for c in components}
        for c in components:
            pk = ug.node(package_key(c.ecosystem, c.name), type="package", label=c.name, ecosystem=c.ecosystem)
            ug.g.nodes[pk]["resolved"] = True
            ug.node(c.purl, type="artifact", label=f"{c.name}@{c.version or '?'}", ecosystem=c.ecosystem,
                    version=c.version, scope=c.scope, direct=c.direct, seen_by=c.seen_by, source=c.source,
                    registry=c.origin.registry, resolved_url=c.origin.resolved_url, integrity=c.origin.integrity,
                    has_install_script=c.origin.has_install_script, source_repo=c.origin.source_repo,
                    evidence_ids=c.evidence_ids)
            status = "verified" if c.source in VERIFIED_SOURCES and c.version else "declared" if c.source == "manifest" else "unknown"
            ug.edge(pk, c.purl, "HAS_ARTIFACT", evidence_status=status, discovered_by=c.source,
                    evidence_id=c.evidence_ids[0] if c.evidence_ids else None)
        dangling = []
        for e in edges:
            if e.src in purls and e.dst in purls:
                ug.edge(e.src, e.dst, "DEPENDS_ON", evidence_status="verified" if e.source in VERIFIED_SOURCES else "unknown",
                        discovered_by=e.source)
            else:
                dangling.append(f"{e.src} -> {e.dst}")
        ug.validation["dangling_edges"] = dangling
        # -- usage layer (code index)
        if code:
            dist_map = code.import_name_to_distribution
            func_nodes: set[str] = set()
            for cf in code.files:
                mod = ug.node(f"file:{cf.path}", type="source_module", label=cf.path, language=cf.language,
                              is_test=cf.is_test, loc=cf.loc, parse_error=cf.parse_error)
                ug.edge(P, mod, "CONTAINS", evidence_status="statically-observed", discovered_by=cf.discovered_by)
                for imp in cf.imports:
                    if imp.kind == "external":
                        eco = LANGUAGE_ECOSYSTEM.get(cf.language, "other")
                        dist = imp.distribution or (dist_map.get(imp.name.split(".")[0]) if eco == "pypi" else
                                                    imp.name if eco == "npm" else None)
                        if not dist:
                            continue
                        pk = package_key(eco, dist)
                        mapping = "mapped" if pk in ug.g else "guessed"
                        ug.node(pk, type="package", label=dist, ecosystem=eco)
                        ug.g.nodes[pk]["imported"] = True
                        ug.edge(mod, pk, "IMPORTS", line=imp.line, source_file=cf.path, parser=cf.discovered_by,
                                mapping_status=mapping, evidence_status="statically-observed", discovered_by=cf.discovered_by,
                                locator=f"{cf.path}:{imp.line}", import_name=imp.name)
                    elif imp.kind == "internal" and imp.resolved_file:
                        ug.edge(mod, f"file:{imp.resolved_file}", "IMPORTS_MODULE", line=imp.line,
                                evidence_status="statically-observed", discovered_by=cf.discovered_by)
                py = cf.language == "python"   # call graph + definitions are Python-only on Day 1
                for d in (cf.definitions if py else []):
                    if d.type in ("function", "async_function", "method"):
                        fn = ug.node(f"func:{d.id}", type="function", label=d.id.split("::")[1], file=cf.path,
                                     line=d.line, end_line=d.end_line)
                        func_nodes.add(fn)
                        ug.edge(mod, fn, "DEFINES", evidence_status="statically-observed", discovered_by="ast", line=d.line)
                for c in (cf.calls if py else []):
                    src = ug._fn(c.caller, cf.path)
                    if c.kind == "internal" and c.resolved_target:
                        tgt = f"func:{c.resolved_target}"
                        if tgt not in ug.g:  # class constructor or module-level target
                            ug.node(tgt, type="function", label=c.resolved_target.split("::")[1], file=c.resolved_target.split("::")[0])
                        ug.edge(src, tgt, "CALLS", line=c.line, evidence_status="statically-observed", discovered_by="ast",
                                locator=f"{cf.path}:{c.line}")
                    elif c.kind == "external" and c.import_name:
                        dist = dist_map.get(c.import_name)
                        if dist:
                            pk = ug.node(package_key("pypi", dist), type="package", label=dist, ecosystem="pypi")
                            ug.edge(src, pk, "USES", line=c.line, call_target=c.target, evidence_status="statically-observed",
                                    discovered_by="ast", locator=f"{cf.path}:{c.line}")
                ext_imports = {i.name.split(".")[0] for i in cf.imports if i.kind == "external"}
                for ref in cf.name_refs:
                    top = ref.name.split(".")[0]
                    dist = dist_map.get(top) if top in ext_imports else None
                    if dist:
                        pk = ug.node(package_key("pypi", dist), type="package", label=dist, ecosystem="pypi")
                        ug.edge(ug._fn(ref.function, cf.path), pk, "USES", line=ref.line, call_target=ref.name,
                                evidence_status="statically-observed", discovered_by="ast", locator=f"{cf.path}:{ref.line}")
                for r in cf.routes:
                    rn = ug.node(f"route:{r.method} {r.path}", type="route", label=f"{r.method} {r.path}", framework=r.framework)
                    ug.edge(P, rn, "EXPOSES", evidence_status="statically-observed", discovered_by="ast",
                            locator=f"{cf.path}:{r.line}")
                    ug.edge(rn, ug._fn(r.handler, cf.path), "HANDLED_BY", line=r.line, evidence_status="statically-observed",
                            discovered_by="ast", locator=f"{cf.path}:{r.line}")
                for s in cf.input_sources:
                    n = ug.node(f"input:{s.name}", type="input", label=s.name)
                    ug.edge(n, ug._fn(s.function, cf.path), "INPUT_TO", line=s.line, evidence_status="statically-observed",
                            discovered_by="ast", locator=f"{cf.path}:{s.line}")
                for e in cf.env_reads:
                    n = ug.node(f"env:{e.name}", type="secret", label=e.name)
                    ug.edge(ug._fn(e.function, cf.path), n, "READS_ENV", line=e.line, evidence_status="statically-observed",
                            discovered_by="ast", locator=f"{cf.path}:{e.line}")
                for m in cf.db_models:
                    n = ug.node(f"table:{m.table or m.class_id}", type="db_table", label=m.table or m.class_id, model=m.class_id)
                    ug.edge(ug.node(f"func:{m.class_id}", type="model", label=m.class_id.split("::")[1], file=cf.path),
                            n, "MAPS_TO", evidence_status="statically-observed", discovered_by="ast", line=m.line)
                for a in cf.db_access:
                    table = ug._table_for(code, a.model) if a.model else None
                    n = ug.node(f"table:{table}", type="db_table", label=table) if table else ug.node(
                        "table:<unknown>", type="db_table", label="database (unknown table)")
                    rel = {"read": "READS_DB", "write": "WRITES_DB", "raw_sql": "RAW_SQL"}[a.operation]
                    ug.edge(ug._fn(a.function, cf.path), n, rel, line=a.line, evidence_status="statically-observed",
                            discovered_by="ast", locator=f"{cf.path}:{a.line}", call_target=a.target)
                for s in cf.external_services:
                    n = ug.node(f"service:{s.name}", type="external_service", label=s.name, via=s.via)
                    # attribute to the functions that use the SDK / call the URL
                    users = {c.caller for c in cf.calls if s.import_name and c.import_name == s.import_name} | \
                            {r.function for r in cf.name_refs if s.import_name and r.name.split(".")[0] == s.import_name} | \
                            {u.function for u in cf.string_urls if s.domain and u.detail == s.domain}
                    users = users or {f"{cf.path}::<module>"}
                    for u in users:
                        ug.edge(ug._fn(u, cf.path), n, "CONTACTS", line=s.line, via=s.via, evidence_status="statically-observed",
                                discovered_by="ast", locator=f"{cf.path}:{s.line}")
                for s in cf.sensitive_calls:
                    n = ug.node(f"sink:{s.category}:{s.target}", type="sensitive_call", label=s.target, category=s.category)
                    ug.edge(ug._fn(s.function, cf.path), n, "SENSITIVE_CALL", line=s.line, evidence_status="statically-observed",
                            discovered_by=cf.discovered_by, locator=f"{cf.path}:{s.line}")
        # -- supply-chain context
        if facts:
            for df in facts.dockerfiles:
                dn = ug.node(f"dockerfile:{df.file}", type="dockerfile", label=df.file, user=df.user)
                ug.edge(P, dn, "BUILT_BY", evidence_status="verified", discovered_by="dockerfile", evidence_id=df.evidence_id)
                for st in df.stages:
                    ref = st.base_image + (f":{st.tag}" if st.tag else "") + (f"@{st.digest}" if st.digest else "")
                    im = ug.node(f"image:{ref}", type="image", label=ref, tag=st.tag, digest=st.digest)
                    ug.edge(dn, im, "BASED_ON", line=st.line, evidence_status="verified", discovered_by="dockerfile",
                            locator=f"{df.file}:{st.line}")
            for wf in facts.ci_workflows:
                wn = ug.node(f"workflow:{wf.file}", type="workflow", label=wf.file, triggers=wf.triggers)
                ug.edge(P, wn, "CI", evidence_status="verified", discovered_by="yaml", evidence_id=wf.evidence_id)
                for a in wf.actions:
                    an = ug.node(f"action:{a.uses}", type="action", label=a.uses, pinned_to_sha=a.pinned_to_sha)
                    ug.edge(wn, an, "USES_ACTION", line=a.line, evidence_status="verified", discovered_by="yaml",
                            locator=f"{wf.file}:{a.line}")
            for s in facts.config.compose_services:
                sn = ug.node(f"compose:{s.name}", type="compose_service", label=s.name)
                ug.edge(P, sn, "RUNS_SERVICE", evidence_status="verified", discovered_by="yaml", locator=f"{s.file}:{s.line}")
                if s.image:
                    im = ug.node(f"image:{s.image}", type="image", label=s.image, tag=s.tag, digest=s.digest)
                    ug.edge(sn, im, "BASED_ON", evidence_status="verified", discovered_by="yaml", locator=f"{s.file}:{s.line}")
        ug._validate(components)
        return ug

    def _fn(self, func_id: str | None, path: str) -> str:
        fid = func_id or f"{path}::<module>"
        nid = f"func:{fid}"
        if nid not in self.g:
            self.node(nid, type="function", label=fid.split("::")[1], file=fid.split("::")[0])
            if f"file:{path}" in self.g:
                self.edge(f"file:{path}", nid, "DEFINES", evidence_status="statically-observed", discovered_by="ast")
        return nid

    @staticmethod
    def _table_for(code: CodeIndex, model: str) -> str | None:
        short = model.split(".")[-1].split("::")[-1]
        for cf in code.files:
            for m in cf.db_models:
                if m.class_id.endswith("::" + short) or m.class_id.endswith("." + short):
                    return m.table
        return None

    # ------------------------------------------------------------------ queries
    def artifacts(self) -> list[str]:
        return [n for n, d in self.g.nodes(data=True) if d.get("type") == "artifact"]

    def dep_view(self) -> nx.DiGraph:
        dg = nx.DiGraph()
        dg.add_nodes_from(self.artifacts())
        dg.add_edges_from((s, t) for s, t, k in self.g.edges(keys=True) if k == "DEPENDS_ON")
        return dg

    def direct_artifacts(self) -> list[str]:
        return [n for n in self.artifacts() if self.g.nodes[n].get("direct")]

    def metrics(self) -> dict[str, dict]:
        dg = self.dep_view()
        direct = set(self.direct_artifacts())
        depth: dict[str, int] = {}
        q = deque((d, 0) for d in direct)
        while q:
            n, dpt = q.popleft()
            if n in depth:
                continue
            depth[n] = dpt
            q.extend((s, dpt + 1) for s in dg.successors(n))
        return {n: {"depth": depth.get(n), "fan_in": dg.in_degree(n), "fan_out": dg.out_degree(n)} for n in dg.nodes}

    def paths_to(self, purl: str, max_paths: int = 5, cutoff: int = 12) -> list[list[str]]:
        dg = self.dep_view()
        if purl not in dg:
            return []
        out: list[list[str]] = []
        for d in self.direct_artifacts():
            if d == purl:
                out.append([purl])
                continue
            try:
                for p in nx.all_simple_paths(dg, d, purl, cutoff=cutoff):
                    out.append(p)
                    if len(out) >= max_paths:
                        return out
            except nx.NetworkXError:
                continue
        return sorted(out, key=len)[:max_paths]

    def importers(self, package: str) -> list[dict]:
        out = []
        for s, _, k, d in self.g.in_edges(package, keys=True, data=True):
            if k in ("IMPORTS", "USES"):
                out.append({"from": s, "rel": k, "locator": d.get("locator"), "target": d.get("call_target")})
        return out

    def blast_radius(self, purl: str) -> dict:
        """Reverse walk: which direct deps pull it in, which code imports/uses it, which routes reach that code."""
        dg = self.dep_view()
        if purl not in dg:
            return {}
        dependents = nx.ancestors(dg, purl)
        affected = dependents | {purl}
        pkgs = {self._package_of(a) for a in affected}
        code_users = [u for p in pkgs if p for u in self.importers(p)]
        funcs = {u["from"] for u in code_users if u["from"].startswith("func:")}
        files = {u["from"] for u in code_users if u["from"].startswith("file:")}
        funcs |= {t for f in files for _, t, k in self.g.out_edges(f, keys=True) if k == "DEFINES"}
        callers = set(funcs)
        stack = list(funcs)
        while stack:  # reverse CALLS closure
            f = stack.pop()
            for s, _, k in self.g.in_edges(f, keys=True):
                if k == "CALLS" and s not in callers:
                    callers.add(s)
                    stack.append(s)
        routes = sorted({s for f in callers for s, _, k in self.g.in_edges(f, keys=True) if k == "HANDLED_BY"})
        return {"package": purl, "dependent_artifacts": sorted(dependents),
                "direct_introducers": sorted(a for a in affected if self.g.nodes[a].get("direct")),
                "importing_modules": sorted({f.removeprefix("file:") for f in files} | {self.g.nodes[f].get("file", "") for f in funcs}),
                "reaching_functions": sorted(callers), "exposed_routes": routes,
                "scope": self.g.nodes[purl].get("scope")}

    def _package_of(self, artifact: str) -> str | None:
        for s, _, k in self.g.in_edges(artifact, keys=True):
            if k == "HAS_ARTIFACT":
                return s
        return None

    def execution_paths(self, max_depth: int = 8) -> list[dict]:
        """route -> handler -> ... -> {db table, env var, external service, sensitive call, package}."""
        sinks_rel = {"WRITES_DB", "READS_DB", "RAW_SQL", "READS_ENV", "CONTACTS", "SENSITIVE_CALL", "USES"}
        out = []
        for r, d in self.g.nodes(data=True):
            if d.get("type") != "route":
                continue
            inputs = [s for f in self.g.successors(r) for s, _, k in self.g.in_edges(f, keys=True) if k == "INPUT_TO"]
            for _, h, k in self.g.out_edges(r, keys=True):
                if k != "HANDLED_BY":
                    continue
                stack = [(h, [h])]
                seen = set()
                while stack:
                    f, path = stack.pop()
                    if f in seen or len(path) > max_depth:
                        continue
                    seen.add(f)
                    for _, t, k2, ed in self.g.out_edges(f, keys=True, data=True):
                        if k2 == "CALLS":
                            stack.append((t, path + [t]))
                        elif k2 in sinks_rel:
                            out.append({"route": d["label"], "inputs": [self.g.nodes[i]["label"] for i in inputs],
                                        "chain": [self.g.nodes[p].get("label", p) for p in path],
                                        "sink": self.g.nodes[t].get("label", t), "sink_type": self.g.nodes[t].get("type"),
                                        "rel": k2, "locator": ed.get("locator")})
        return out

    def discrepancies(self) -> list[dict]:
        rows = []
        for n, d in self.g.nodes(data=True):
            if d.get("type") != "package":
                continue
            declared = any(k == "DECLARES" for _, _, k in self.g.in_edges(n, keys=True))
            resolved = any(k == "HAS_ARTIFACT" for _, _, k in self.g.out_edges(n, keys=True))
            imported = any(k in ("IMPORTS", "USES") for _, _, k in self.g.in_edges(n, keys=True))
            if declared and resolved and imported:
                status = "declared+resolved+imported"
            elif declared and resolved and not imported:
                status = "declared-not-imported"
            elif declared and not resolved:
                status = "declared-not-resolved"
            elif not declared and resolved and imported:
                status = "imported-transitive-not-declared"
            elif not declared and resolved:
                status = "transitive-only"
            elif imported and not declared and not resolved:
                status = "imported-not-declared"
            else:
                status = "other"
            scopes = {ed.get("scope") for _, _, k, ed in self.g.in_edges(n, keys=True, data=True) if k == "DECLARES"}
            rows.append({"package": n, "name": d.get("label"), "ecosystem": d.get("ecosystem"), "declared": declared,
                         "resolved": resolved, "imported": imported, "status": status, "declared_scopes": sorted(s for s in scopes if s)})
        return sorted(rows, key=lambda r: (r["status"], r["package"]))

    # ------------------------------------------------------------------ validation
    def _validate(self, components: list[Component]) -> None:
        purls = [c.purl for c in components]
        v = self.validation
        v["duplicate_identities"] = sorted({p for p in purls if purls.count(p) > 1})
        v["invalid_purls"] = [p for p in purls if not is_valid_purl(p)]
        dg = self.dep_view()
        reach = set()
        for d in self.direct_artifacts():
            reach |= {d} | nx.descendants(dg, d)
        v["orphans"] = sorted(a for a in self.artifacts() if a not in reach)
        try:
            cycles = []
            for c in nx.simple_cycles(dg):
                cycles.append(c)
                if len(cycles) >= 20:
                    break
            v["cycles"] = cycles
        except nx.NetworkXError:
            v["cycles"] = []
        versions: dict[str, set[str]] = {}
        for c in components:
            versions.setdefault(f"{c.ecosystem}:{normalize_name(c.ecosystem, c.name)}", set()).add(c.version or "?")
        v["multiple_versions"] = {k: sorted(x) for k, x in versions.items() if len(x) > 1}
        v["unversioned"] = sorted(c.purl for c in components if not c.version)
        no_rel = [a for a in self.artifacts() if dg.out_degree(a) == 0 and dg.in_degree(a) == 0 and not self.g.nodes[a].get("direct")]
        v["missing_relationships"] = sorted(no_rel)

    # ------------------------------------------------------------------ export
    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for _, d in self.g.nodes(data=True):
            c[d.get("type", "?")] = c.get(d.get("type", "?"), 0) + 1
        for _, _, k in self.g.edges(keys=True):
            c[f"edge:{k}"] = c.get(f"edge:{k}", 0) + 1
        return c

    def to_json(self) -> dict:
        def clean(d: dict) -> dict:
            return {k: v for k, v in d.items() if v is not None and v != [] and v != {}}
        metrics = self.metrics()
        nodes = []
        for n, d in self.g.nodes(data=True):
            item = {"id": n, **clean(d)}
            if n in metrics:
                item.update(metrics[n])
            nodes.append(item)
        edges = [{**clean(d), "source": s, "target": t} for s, t, d in self.g.edges(data=True)]
        return {"nodes": nodes, "edges": edges, "counts": self.counts(), "validation": self.validation}
