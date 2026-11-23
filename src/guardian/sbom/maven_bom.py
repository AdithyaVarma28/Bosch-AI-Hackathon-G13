"""Resolve Maven versions managed by parent POMs and imported BOMs (e.g. spring-boot-starter-parent).

Fetches POM XML from Maven Central (cached, offline-capable). Only reads XML; nothing is built or executed.
This gives versions for DIRECT dependencies when Docker resolution is unavailable; transitive edges still
need `mvn dependency:tree` (sandboxed) or Syft/Trivy.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import httpx

from ..httpcache import CacheMiss, CachedHttp

CENTRAL = "https://repo.maven.apache.org/maven2"


def _strip(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _pom_url(g: str, a: str, v: str) -> str:
    return f"{CENTRAL}/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom"


class BomResolver:
    def __init__(self, http: CachedHttp, max_poms: int = 25):
        self.http = http
        self.max_poms = max_poms
        self.fetched = 0
        self.errors: list[str] = []

    def _fetch(self, g: str, a: str, v: str) -> ET.Element | None:
        if self.fetched >= self.max_poms:
            return None
        self.fetched += 1
        try:
            text, _ = self.http.get_text(_pom_url(g, a, v))
        except (CacheMiss, httpx.HTTPError) as e:
            self.errors.append(f"{g}:{a}:{v}: {type(e).__name__}")
            return None
        if not text:
            return None
        try:
            return _strip(ET.fromstring(text))
        except ET.ParseError:
            return None

    def managed(self, root: ET.Element, depth: int = 0) -> tuple[dict[str, str], dict[str, str]]:
        """Returns (properties, managed versions 'g:a' -> version) for a POM including its parents and BOM imports."""
        props: dict[str, str] = {}
        managed: dict[str, str] = {}
        parent = root.find("parent")
        if parent is not None and depth < 6:
            pg, pa, pv = parent.findtext("groupId"), parent.findtext("artifactId"), parent.findtext("version")
            proot = self._fetch(pg, pa, pv) if pg and pa and pv else None
            if proot is not None:
                pp, pm = self.managed(proot, depth + 1)
                props.update(pp)
                managed.update(pm)
            props.update({"project.parent.version": pv or "", "parent.version": pv or ""})
        for p in root.findall("./properties/*"):
            props[p.tag] = (p.text or "").strip()
        ver = root.findtext("version") or (parent.findtext("version") if parent is not None else "")
        props.update({"project.version": ver or "", "pom.version": ver or ""})

        def sub(v: str | None) -> str | None:
            for _ in range(6):
                if not v or "${" not in v:
                    break
                v = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
            return v

        for d in root.findall("./dependencyManagement/dependencies/dependency"):
            g, a, v = sub(d.findtext("groupId")), sub(d.findtext("artifactId")), sub(d.findtext("version"))
            if not g or not a or not v or "${" in v:
                continue
            if (d.findtext("scope") or "") == "import" and (d.findtext("type") or "") == "pom" and depth < 6:
                broot = self._fetch(g, a, v)
                if broot is not None:
                    _, bm = self.managed(broot, depth + 1)
                    for k, val in bm.items():
                        managed.setdefault(k, val)
                continue
            managed[f"{g}:{a}"] = v
        return props, managed


def resolve_pom_versions(pom_text: str, http: CachedHttp) -> tuple[dict[str, str], list[str]]:
    """'group:artifact' -> version for dependencies whose version comes from a parent POM or an imported BOM."""
    try:
        root = _strip(ET.fromstring(pom_text))
    except ET.ParseError as e:
        return {}, [f"pom parse error: {e}"]
    r = BomResolver(http)
    _, managed = r.managed(root)
    return managed, r.errors
