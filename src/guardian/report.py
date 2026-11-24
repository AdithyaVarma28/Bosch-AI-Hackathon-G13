"""S9 Report: report.json (schema 1.0) + a self-contained interactive report.html."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .context import RunContext
from .report_html import HTML
from .viz import build_viz
from .scoring import THRESHOLDS_NOTE
from .store import now_iso

UNSUPPORTED = [
    "Malicious code inside a published package's contents (package tarballs are not unpacked or analysed on Day 1)",
    "Runtime reachability of vulnerable functions (static references only)",
    "Compromised maintainer accounts / registry account takeover",
    "Native/binary artifact analysis",
    "Call graphs and execution paths exist for Python only; other languages get file-level imports, routes, env reads and risky calls",
    "Java/Kotlin import-to-Maven mapping is heuristic (groupId prefix); unused-dependency checks are skipped for Maven, NuGet and Composer",
    "Ecosystems beyond npm, PyPI, Maven/Gradle, Go, Cargo, RubyGems, Composer and NuGet (e.g. Swift, CocoaPods, Conan) are inventoried by Syft/Trivy only",
    "Container image layer contents unless Syft/Trivy can run",
]


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build_report(ctx: RunContext, node_status: dict[str, str], plan: dict, errors: list[str]) -> Path:
    store = ctx.store
    findings = store.list_findings()
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "Unprioritized": 4}
    findings.sort(key=lambda f: (order.get(f.band or "", 9), {"C": 0, "S": 1, "W": 2}[f.classification], f.title))
    exps = {e.finding_id: e for e in store.get_explanations()}
    graph = ctx.graph
    f = ctx.facts
    cited: set[str] = set()
    fjson = []
    for x in findings:
        d = x.model_dump(mode="json")
        d["id"] = x.id
        e = exps.get(x.id)
        d["explanation"] = e.model_dump(mode="json") if e else None
        cited.update(x.raw_evidence_ids)
        if e:
            for c in e.claims:
                cited.update(c.evidence_ids)
        fjson.append(d)
    if ctx.dossier:
        for c in ctx.dossier.claims:
            cited.update(c.evidence_ids)
    evidence = {e.id: e.model_dump(mode="json") for e in store.all_evidence() if e.id in cited}

    bands: dict[str, int] = {}
    for x in findings:
        bands[x.band or "?"] = bands.get(x.band or "?", 0) + 1
    report = {
        "schema_version": "1.0",
        "generated_at": now_iso(),
        "run_id": store.run_id,
        "repo": ctx.repo.model_dump(mode="json"),
        "dossier": ctx.dossier.model_dump(mode="json") if ctx.dossier else None,
        "summary": {"components": len(ctx.components), "direct": sum(c.direct for c in ctx.components),
                    "transitive": sum(not c.direct for c in ctx.components), "findings": len(findings), "bands": bands,
                    "vulnerabilities": sum(x.cls == "vuln" for x in findings),
                    "supply_chain_signals": sum(x.cls in ("anomaly", "discrepancy") for x in findings),
                    "container_ci": sum(x.cls in ("container", "ci") for x in findings),
                    "secrets": sum(x.cls == "secret" for x in findings)},
        "inventory": {
            "ecosystems": f.ecosystems if f else [], "languages": f.languages if f else {},
            "manifests": [m.model_dump(mode="json") for m in (f.manifests if f else [])],
            "lockfiles": [h.model_dump(mode="json") for h in (f.lockfiles if f else [])],
            "package_indexes": [i.model_dump(mode="json") for i in (f.package_indexes if f else [])],
            "dockerfiles": [d.model_dump(mode="json", exclude={"instructions"}) for d in (f.dockerfiles if f else [])],
            "ci_workflows": [w.model_dump(mode="json") for w in (f.ci_workflows if f else [])],
            "compose_services": [s.model_dump(mode="json") for s in (f.config.compose_services if f else [])],
            "env_var_names": [e.model_dump(mode="json") for e in (f.config.env_files if f else [])],
        },
        "sbom": {"path": "sbom.cdx.json", "report": ctx.sbom_report.model_dump(mode="json") if ctx.sbom_report else None,
                 "components": [{**c.model_dump(mode="json", include={"purl", "name", "version", "ecosystem", "scope", "direct", "source", "seen_by"}),
                                 "origin": c.origin.model_dump(mode="json"),
                                 "metadata": (ctx.metadata.get(c.purl).model_dump(mode="json", include={"first_release", "version_uploaded", "release_count", "source_repo", "status"})
                                              if ctx.metadata.get(c.purl) else None)}
                                for c in ctx.components]},
        "graph": {"path": "graph.json", "counts": graph.counts() if graph else {},
                  "validation": graph.validation if graph else {},
                  "discrepancies": graph.discrepancies() if graph else [],
                  "execution_paths": graph.execution_paths() if graph else []},
        "history": [h.model_dump(mode="json", by_alias=True) for h in (f.dependency_history if f else [])],
        "findings": fjson,
        "evidence": evidence,
        "coverage": {
            "node_status": node_status,
            "degraded": sorted(k for k, v in node_status.items() if v == "degraded"),
            "skipped": {k: (plan.get("reasons") or {}).get(k, "") for k, v in node_status.items() if v == "skipped"},
            "failed": sorted(k for k, v in node_status.items() if v == "failed"),
            "code": ctx.code_index.coverage.model_dump() if ctx.code_index else None,
            "sbom_tools": ctx.sbom_report.tools if ctx.sbom_report else {},
            "notes": (ctx.sbom_report.notes if ctx.sbom_report else []) + (f.errors[:20] if f else []) +
                     (ctx.code_index.errors[:20] if ctx.code_index else []),
            "pipeline_errors": [e for e in errors if not e.startswith("Traceback")][:20],
            "llm": ctx.llm.name if ctx.llm else "not configured (set GROQ_API_KEY to enable the LLM agents)",
            "unsupported": UNSUPPORTED,
            "thresholds": THRESHOLDS_NOTE,
        },
        "remediation": None, "validation": None, "vex": None,   # Day 2
        # data sources of this scan: Day 2 (validation rescans, heal) must reuse them so before/after are comparable
        "settings": {"offline": ctx.settings.offline, "use_docker": ctx.settings.use_docker,
                     "advisory_db": str(ctx.settings.advisory_db) if ctx.settings.advisory_db else None,
                     "registry_snapshot": str(ctx.settings.registry_snapshot) if ctx.settings.registry_snapshot else None},
    }
    arts = {}
    for name in ("facts.json", "sbom.cdx.json", "code_index.json", "graph.json"):
        p = store.run_dir / name
        if p.exists():
            arts[name] = _sha(p)
    report["integrity"] = {"artifact_sha256": arts}
    out = store.run_dir / "report.json"
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    viz = build_viz(ctx, findings)
    (store.run_dir / "viz.json").write_text(json.dumps(viz, default=str), encoding="utf-8")
    sbom_path = store.run_dir / "sbom.cdx.json"
    sbom_doc = json.loads(sbom_path.read_text(encoding="utf-8")) if sbom_path.exists() else None
    (store.run_dir / "report.html").write_text(render_html(report, viz, sbom_doc), encoding="utf-8")
    return out


def verify_integrity(report: dict, run_dir: Path) -> bool:
    for name, digest in (report.get("integrity") or {}).get("artifact_sha256", {}).items():
        p = Path(run_dir) / name
        if not p.exists() or _sha(p) != digest:
            return False
    return True


def _js(obj) -> str:
    return json.dumps(obj, default=str).replace("</", "<\\/")


def render_html(report: dict, viz: dict, sbom: dict | None = None) -> str:
    return HTML.replace("__REPORT__", _js(report)).replace("__VIZ__", _js(viz)).replace("__SBOM__", _js(sbom)).replace(
        "__TITLE__", (report.get("repo") or {}).get("name", "report").replace("<", "").replace("&", ""))
