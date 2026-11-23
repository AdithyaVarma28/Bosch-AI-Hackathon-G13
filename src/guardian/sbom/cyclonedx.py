"""CycloneDX 1.5 JSON writer and reader."""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

from ..models import Component, DepEdge, Origin
from ..purl import ECOSYSTEMS, is_valid_purl, make_purl, parse_purl
from ..store import now_iso


def write_cyclonedx(components: list[Component], edges: list[DepEdge], path: Path, root_name: str,
                    root_version: str | None = None, tool: str = "guardian") -> dict:
    root_ref = f"project:{root_name}"
    comps = []
    for c in components:
        entry = {"type": "library", "bom-ref": c.purl, "name": c.name, "purl": c.purl,
                 "scope": "optional" if c.scope in ("dev", "optional", "test", "build") else "required"}
        if c.version:
            entry["version"] = c.version
        props = [{"name": "guardian:scope", "value": c.scope}, {"name": "guardian:direct", "value": str(c.direct).lower()},
                 {"name": "guardian:source", "value": c.source}]
        if c.origin.resolved_url:
            props.append({"name": "guardian:resolved", "value": c.origin.resolved_url})
            entry["externalReferences"] = [{"type": "distribution", "url": c.origin.resolved_url}]
        if c.origin.has_install_script:
            props.append({"name": "guardian:has_install_script", "value": "true"})
        entry["properties"] = props
        hashes = []
        for h in c.hashes[:4]:
            alg, sep, val = h.partition(":")
            if sep and alg.lower() in ("sha256", "sha512", "sha1") and re.fullmatch(r"[0-9a-fA-F]+", val):
                hashes.append({"alg": {"sha256": "SHA-256", "sha512": "SHA-512", "sha1": "SHA-1"}[alg.lower()], "content": val})
        if hashes:
            entry["hashes"] = hashes
        if c.origin.license:
            entry["licenses"] = [{"license": {"name": c.origin.license}}]
        comps.append(entry)
    deps: dict[str, list[str]] = {c.purl: [] for c in components}
    for e in edges:
        if e.src in deps and e.dst in deps:
            deps[e.src].append(e.dst)
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": now_iso(), "tools": {"components": [{"type": "application", "name": tool}]},
                     "component": {"type": "application", "bom-ref": root_ref, "name": root_name,
                                   **({"version": root_version} if root_version else {})}},
        "components": comps,
        "dependencies": [{"ref": root_ref, "dependsOn": sorted(c.purl for c in components if c.direct)}]
                        + [{"ref": k, "dependsOn": sorted(set(v))} for k, v in deps.items()],
    }
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return doc


def validate_cyclonedx(doc: dict) -> list[str]:
    """Structural validation (no network schema fetch): required fields, unique refs, no dangling edges."""
    problems = []
    if doc.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat must be CycloneDX")
    if doc.get("specVersion") not in ("1.4", "1.5", "1.6"):
        problems.append(f"unexpected specVersion {doc.get('specVersion')}")
    refs = [c.get("bom-ref") for c in doc.get("components", [])]
    if len(refs) != len(set(refs)):
        problems.append("duplicate bom-ref values")
    known = set(refs) | {((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")}
    for c in doc.get("components", []):
        if not c.get("name"):
            problems.append(f"component without name: {c.get('bom-ref')}")
        if c.get("purl") and not is_valid_purl(c["purl"]):
            problems.append(f"invalid purl {c['purl']}")
    for d in doc.get("dependencies", []):
        if d.get("ref") not in known:
            problems.append(f"dependency ref not a component: {d.get('ref')}")
        for t in d.get("dependsOn", []):
            if t not in known:
                problems.append(f"dangling dependsOn {d.get('ref')} -> {t}")
    return problems


def read_cyclonedx(doc: dict, tool: str) -> tuple[list[Component], list[DepEdge]]:
    comps, by_ref = [], {}
    for c in doc.get("components", []) or []:
        purl = c.get("purl")
        if not purl:
            continue
        purl = purl.split("?")[0].split("#")[0]
        try:
            eco, name, ver = parse_purl(purl)
        except ValueError:
            continue
        if eco not in ECOSYSTEMS:
            continue  # OS packages (deb/apk/rpm) etc. are reported by the image scan, not mixed into app deps
        purl = make_purl(eco, name, ver)  # canonical form so tool and lockfile purls match
        comp = Component(purl=purl, name=name, version=c.get("version") or ver,
                         ecosystem=eco, source=tool, seen_by=[tool],
                         origin=Origin(license=_license(c)))
        comps.append(comp)
        if c.get("bom-ref"):
            by_ref[c["bom-ref"]] = purl
    edges = []
    for d in doc.get("dependencies", []) or []:
        s = by_ref.get(d.get("ref"))
        for t in d.get("dependsOn", []) or []:
            if s and by_ref.get(t):
                edges.append(DepEdge(src=s, dst=by_ref[t], source=tool))
    return comps, edges


def _license(c: dict) -> str | None:
    for lic in c.get("licenses") or []:
        l = lic.get("license") or {}
        if l.get("id") or l.get("name"):
            return l.get("id") or l.get("name")
        if lic.get("expression"):
            return lic["expression"]
    return None
