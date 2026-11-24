"""S12.2 Simulation: apply a candidate to a throwaway copy, re-run the Day 1 fact, SBOM and detector stages on it
(no build, no install scripts, nothing executed), and compare with the scanned state.

Answers, before anything is approved or built:
  * does the target finding disappear?
  * which components change, appear or disappear?
  * does the new dependency set match any advisory (new risk) or violate a block policy?
  * is it a major-version jump for a package the code calls (API compatibility risk)?
When Docker is available and the change is an npm manifest edit, the lockfile is regenerated in the sandbox
(`npm install --package-lock-only --ignore-scripts`) instead of trusting Guardian's own lockfile surgery.
"""
from __future__ import annotations

import dataclasses
import posixpath
from pathlib import Path

from ..cartographer.facts import build_repo_facts
from ..context import RunContext
from ..detectors.changes import detect_changes
from ..detectors.infra import detect_ci, detect_container, detect_secrets
from ..detectors.packages import detect_install_scripts, detect_name_confusion, detect_registry_signals
from ..detectors.vulns import detect_vulns
from ..ingest import open_local
from ..models import Finding
from ..purl import package_key
from ..runner import ToolFailed, docker_available
from ..sbom.stage import run_sbom_stage
from ..scoring import correlate, score
from ..store import RunStore
from .models import RemediationCandidate, SimulationResult
from .patcher import apply_edits, copy_tree, diff_sha, rmtree, unified_diff
from .versions import bump_kind

HISTORY_SIGNALS = {"new_dependency", "large_version_jump", "integrity_changed_same_version", "resolved_host_changed",
                   "install_script_added"}


def is_historical(f: Finding) -> bool:
    """Findings about past commits stay true after any fix; they are reported, not 'resolved'."""
    return f.cls == "anomaly" and f.signals.get("signal") in HISTORY_SIGNALS


def tree_context(root: Path, base: RunContext, work: Path, run_id: str, docker: bool = False) -> RunContext:
    settings = dataclasses.replace(base.settings, use_llm=False, use_docker=docker, history_depth=0)
    st = RunStore(work / "run", run_id)
    ctx = RunContext(repo=open_local(root, base.runner), store=st, settings=settings, runner=base.runner)
    ctx.facts = build_repo_facts(ctx)
    run_sbom_stage(ctx)
    return ctx


def detect_all(ctx: RunContext, dossier) -> list[Finding]:
    fs: list[Finding] = []
    for fn in (detect_vulns, detect_changes, detect_install_scripts, detect_name_confusion, detect_registry_signals,
               detect_container, detect_ci, detect_secrets):
        try:
            fs += fn(ctx)
        except Exception as e:  # fail soft: one detector never breaks a simulation
            fs.append(Finding(cls="sbom_quality", subject=fn.__name__, title=f"{fn.__name__} failed in simulation",
                              locator="simulation", detector="simulation", classification="W",
                              signals={"error": f"{type(e).__name__}: {str(e)[:200]}"}))
    return score(correlate(fs), dossier, ctx.sbom_report.confidence if ctx.sbom_report else "low")


def _regen_npm_lock(ctx: RunContext, root: Path, manifest_rel: str) -> str | None:
    """Real resolution in a throwaway container; returns an error string or None."""
    if not docker_available(ctx.runner):
        return "Docker unavailable"
    d = (root / manifest_rel).parent
    cmd = ["docker", "run", "--rm", "-v", f"{d.resolve()}:/w", "-w", "/w", "--security-opt", "no-new-privileges",
           "node:22-alpine", "npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
    try:
        r = ctx.runner(cmd, None, ctx.settings.sandbox_timeout)
    except ToolFailed as e:
        return str(e)
    return None if r.returncode == 0 else r.stderr.strip()[:300]


def call_sites(ctx: RunContext, ecosystem: str, name: str) -> list[str]:
    if not ctx.graph:
        return []
    users = ctx.graph.importers(package_key(ecosystem, name))
    return sorted({u.get("locator") or u["from"] for u in users})[:20]


def simulate(ctx: RunContext, cand: RemediationCandidate, baseline: list[Finding], dossier, work: Path,
             closes_check: list[str]) -> tuple[SimulationResult, str, list[Finding], list]:
    """Returns (result, unified diff, findings new in the simulated tree, simulated components)."""
    res = SimulationResult()
    tree = work / ctx.repo.name
    copy_tree(ctx.root, tree, with_git=False)
    try:
        changed = apply_edits(tree, cand.edits)
        diff = unified_diff(ctx.root, tree, changed)
        npm_manifests = [e.file for e in cand.edits if e.kind in ("npm_set_dep", "npm_override", "npm_remove_dep")]
        use_docker = ctx.settings.use_docker and ctx.settings.sandbox == "docker" and bool(npm_manifests)
        if use_docker:
            err = _regen_npm_lock(ctx, tree, npm_manifests[0])
            if err:
                res.notes.append(f"sandbox lockfile regeneration failed ({err}); using Guardian's lockfile edit")
            else:
                res.method = "sandbox-resolution"
                lock_rel = posixpath.join(posixpath.dirname(npm_manifests[0]), "package-lock.json")
                diff = unified_diff(ctx.root, tree, changed + [lock_rel])
        sim = tree_context(tree, ctx, work, f"sim-{cand.id}")
        try:
            before = {c.purl: c for c in ctx.components}
            after = {c.purl: c for c in sim.components}
            by_name_before = {(c.ecosystem, c.name): c for c in ctx.components}
            for p, c in after.items():
                if p not in before:
                    old = by_name_before.get((c.ecosystem, c.name))
                    if old:
                        res.resolved_changes.append({"name": c.name, "ecosystem": c.ecosystem, "from": old.version, "to": c.version,
                                                     "bump": bump_kind(c.ecosystem, old.version, c.version)})
                    else:
                        res.added.append(p)
            after_names = {(c.ecosystem, c.name) for c in sim.components}
            res.removed = sorted(p for p, c in before.items() if (c.ecosystem, c.name) not in after_names)
            fs = detect_all(sim, dossier)
            ids = {f.id for f in fs}
            if any(f.cls == "sbom_quality" and f.subject == "osv" for f in fs):
                res.notes.append("advisory source unavailable for the simulated set (offline without snapshot): new risks unknown")
            base_ids = {f.id for f in baseline}
            for f in fs:
                if f.cls == "vuln":
                    entry = {"purl": f.subject, "id": f.signals.get("advisory_id"), "severity_band": f.signals.get("severity_band"),
                             "band": f.band}
                    (res.remaining_advisories if f.id in base_ids else res.new_advisories).append(entry)
            res.target_resolved = bool(closes_check) and not (set(closes_check) & ids)
            if not closes_check:
                res.notes.append("nothing this candidate can resolve in the current tree (historical signals only)")
            new = [f for f in fs if f.id not in base_ids and f.cls != "sbom_quality" and not is_historical(f)]
            res.notes += [f"new finding in simulation: [{f.band}] {f.title}" for f in new[:6]]
            # API compatibility for the changed packages
            for ch in res.resolved_changes:
                if ch["bump"] == "major":
                    sites = call_sites(ctx, ch["ecosystem"], ch["name"])
                    if sites:
                        res.api_risk.append(f"{ch['name']} {ch['from']} -> {ch['to']} is a major change; code references: "
                                            + ", ".join(sites[:6]))
                    else:
                        res.notes.append(f"{ch['name']} {ch['from']} -> {ch['to']} is a major change, but no source file imports it "
                                         f"(only other packages use it)")
            for p in res.removed:
                c = before[p]
                sites = call_sites(ctx, c.ecosystem, c.name)
                if sites and c.direct:
                    res.api_risk.append(f"{c.name} is removed but referenced in: {', '.join(sites[:6])}")
            return res, diff, new, sim.components
        finally:
            sim.store.close()
    finally:
        rmtree(tree)


__all__ = ["simulate", "tree_context", "detect_all", "is_historical", "diff_sha"]
