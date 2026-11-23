"""Sandboxed dependency resolution for repos without a usable lockfile.

Runs ONLY inside a throwaway Docker container, with install scripts disabled:
  npm:  npm install --package-lock-only --ignore-scripts
  pip:  pip install --dry-run --ignore-installed --only-binary=:all: --report
Only manifest files are copied into the sandbox; repo code never runs.
"""
from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement

from ..models import Component, DepEdge, Origin
from ..purl import make_purl, normalize_pypi
from ..runner import Runner, ToolFailed, default_runner, docker_available
from .lockfiles import ParsedLock, parse_package_lock

NODE_IMAGE = "node:22-alpine"
PY_IMAGE = "python:3.12-slim"


def _sandbox(runner: Runner) -> None:
    if not docker_available(runner):
        raise ToolFailed("Docker daemon unavailable; sandboxed resolution skipped")


def resolve_npm(repo: Path, manifest_rel: str, runner: Runner = default_runner) -> ParsedLock:
    _sandbox(runner)
    with tempfile.TemporaryDirectory(prefix="guardian-npm-") as tmp:
        shutil.copy2(Path(repo) / manifest_rel, Path(tmp) / "package.json")
        cmd = ["docker", "run", "--rm", "-v", f"{tmp}:/w", "-w", "/w", NODE_IMAGE, "npm", "install",
               "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
        r = runner(cmd, None, 600)
        lock = Path(tmp) / "package-lock.json"
        if r.returncode != 0 or not lock.exists():
            raise ToolFailed(f"npm resolution failed: {r.stderr.strip()[:300]}")
        parsed = parse_package_lock(str(PurePosixPath(manifest_rel).parent / "package-lock.json"), lock.read_text(encoding="utf-8"))
    for c in parsed.components:
        c.source, c.seen_by = "npm-resolve", ["npm-resolve"]
    return parsed


def resolve_pip(repo: Path, manifest_rel: str, runner: Runner = default_runner) -> ParsedLock:
    _sandbox(runner)
    src_dir = (Path(repo) / manifest_rel).parent
    with tempfile.TemporaryDirectory(prefix="guardian-pip-") as tmp:
        name = PurePosixPath(manifest_rel).name
        for f in src_dir.glob("requirements*.txt"):
            shutil.copy2(f, Path(tmp) / f.name)
        if name == "pyproject.toml":
            shutil.copy2(src_dir / name, Path(tmp) / name)
            target = ["/w"]
        else:
            target = ["-r", f"/w/{name}"]
        cmd = ["docker", "run", "--rm", "-v", f"{tmp}:/w", PY_IMAGE, "pip", "install", "--quiet", "--dry-run",
               "--ignore-installed", "--only-binary=:all:", "--report", "/w/report.json", *target]
        r = runner(cmd, None, 900)
        rep = Path(tmp) / "report.json"
        if r.returncode != 0 or not rep.exists():
            raise ToolFailed(f"pip resolution failed: {r.stderr.strip()[:300]}")
        return parse_pip_report(manifest_rel, json.loads(rep.read_text(encoding="utf-8")))


def parse_pip_report(manifest_rel: str, report: dict) -> ParsedLock:
    out = ParsedLock(manifest_rel, "pypi")
    reqs: dict[str, list[str]] = {}
    for item in report.get("install", []):
        md = item.get("metadata") or {}
        name, ver = md.get("name"), md.get("version")
        if not name:
            continue
        dl = item.get("download_info") or {}
        hashes = [f"{k}:{v}" for k, v in ((dl.get("archive_info") or {}).get("hashes") or {}).items()]
        out.components.append(Component(purl=make_purl("pypi", name, ver), name=name, version=ver, ecosystem="pypi",
                                        direct=bool(item.get("requested")),
                                        origin=Origin(registry=re.sub(r"^https?://([^/]+)/.*$", r"\1", dl.get("url", "")) or None,
                                                      resolved_url=dl.get("url")),
                                        hashes=hashes, source="pip-report", seen_by=["pip-report"]))
        if item.get("requested"):
            out.direct_names.add(normalize_pypi(name))
        deps = []
        for rd in md.get("requires_dist") or []:
            try:
                r = Requirement(rd)
            except InvalidRequirement:
                continue
            if r.marker and "extra" in str(r.marker):
                continue
            deps.append(r.name)
        reqs[name] = deps
    by = {normalize_pypi(c.name): c.purl for c in out.components}
    for n, deps in reqs.items():
        for d in deps:
            if normalize_pypi(d) in by:
                out.edges.append(DepEdge(src=by[normalize_pypi(n)], dst=by[normalize_pypi(d)], source="pip-report"))
    out.has_integrity = any(c.hashes for c in out.components)
    return out


def resolve_without_lockfile(repo: Path, manifest_rel: str, ecosystem: str, runner: Runner = default_runner) -> ParsedLock:
    return resolve_npm(repo, manifest_rel, runner) if ecosystem == "npm" else resolve_pip(repo, manifest_rel, runner)
