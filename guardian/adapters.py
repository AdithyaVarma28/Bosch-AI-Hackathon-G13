"""Turn Stage 1 facts and the Stage 2 code index into the Stage 3 graph inputs (no new analysis)."""
import re
from collections import deque

from pydantic import BaseModel

from guardian.models.code_index import CodeIndex
from guardian.models.common import Component, DepEdge, Declaration, Origin, UsageRef
from guardian.models.facts import Facts
from guardian.purl import normalize_name

_REQ_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def _req_name(requirement: str) -> str:
    m = _REQ_NAME.match(requirement.strip())
    return normalize_name(m.group(0)) if m else ""


def components_from_facts(facts: Facts) -> tuple[list[Component], list[DepEdge]]:
    """Components with prod/dev scope, and DEPENDS_ON edges that point dependent -> dependency."""
    packages = facts.resolved_packages
    by_norm = {normalize_name(p.name): p for p in packages}
    declared = {normalize_name(d.name): d for d in facts.declared_dependencies}

    children: dict[str, list[str]] = {p.purl: [] for p in packages}
    edges: list[DepEdge] = []
    for p in packages:
        for req in p.requires:
            q = by_norm.get(_req_name(req))
            if q is not None and q.purl != p.purl:  # never invent an edge to an unresolved package
                children[p.purl].append(q.purl)
                edges.append(DepEdge(src=p.purl, dst=q.purl))

    def reach(roots: list[str]) -> set[str]:
        seen, queue = set(roots), deque(roots)
        while queue:
            for nxt in children[queue.popleft()]:
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return seen

    prod_roots = [p.purl for p in packages if p.direct and normalize_name(p.name) in declared
                  and not declared[normalize_name(p.name)].dev]
    dev_roots = [p.purl for p in packages if p.direct and normalize_name(p.name) in declared
                 and declared[normalize_name(p.name)].dev]
    prod, dev = reach(prod_roots), reach(dev_roots)

    components = []
    for p in packages:
        scope = "prod" if p.purl in prod else "dev" if p.purl in dev else "unknown"
        meta = facts.package_metadata.get(p.purl)
        components.append(Component(
            purl=p.purl, name=p.name, version=p.version, scope=scope, direct=p.direct,
            origin=Origin(sdist_only=bool(meta and meta.sdist_only))))
    return components, edges


def declarations_from_facts(facts: Facts, project: str = ".") -> list[Declaration]:
    return [Declaration(project=project, package=normalize_name(d.name), requested_range=d.spec,
                        scope="dev" if d.dev else "prod", source_file=d.source_file, line=d.line)
            for d in facts.declared_dependencies]


def usage_from_index(index: CodeIndex, project: str = ".") -> list[UsageRef]:
    """Package references seen in source. Internal imports are not package usage, so they are skipped."""
    out: list[UsageRef] = []
    for f in index.files:
        for imp in f.imports:
            if imp.kind == "internal":
                continue
            if imp.kind == "stdlib":
                status, package = "stdlib", None
            elif imp.distribution:
                status, package = "mapped", normalize_name(imp.distribution)
            else:
                status, package = "unmapped", None  # never guessed
            out.append(UsageRef(project=project, source_file=f.path, line=imp.line, specifier=imp.name,
                                package=package, mapping_status=status))
        for dyn in f.dynamic_imports:
            out.append(UsageRef(project=project, source_file=f.path, line=dyn.line, specifier=dyn.expr,
                                package=None, mapping_status="dynamic_unresolved"))
    return out


class DeclaredVsUsed(BaseModel):
    """Where Stage 1 (what is declared/resolved) and Stage 2 (what the code imports) disagree."""

    declared_not_imported: list[str] = []
    imported_not_declared: list[str] = []
    dynamic_imports_present: bool = False


def declared_vs_used(facts: Facts, index: CodeIndex) -> DeclaredVsUsed:
    """Informational only: a missing import may mean plugin/dynamic loading, not an unused dependency."""
    usage = usage_from_index(index)
    used = {u.package for u in usage if u.mapping_status == "mapped" and u.package}
    declared_all = {normalize_name(d.name) for d in facts.declared_dependencies}
    declared_runtime = {normalize_name(d.name) for d in facts.declared_dependencies if not d.dev}
    resolved = {normalize_name(p.name) for p in facts.resolved_packages}
    # flat pin files also list transitive packages; one that another package requires is not "unused"
    provided = {_req_name(r) for p in facts.resolved_packages for r in p.requires}
    return DeclaredVsUsed(
        declared_not_imported=sorted(declared_runtime - used - provided),
        imported_not_declared=sorted(used - declared_all - resolved),
        dynamic_imports_present=any(u.mapping_status == "dynamic_unresolved" for u in usage),
    )
