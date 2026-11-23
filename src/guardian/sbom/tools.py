"""External SBOM tools (Syft, Trivy): local binary first, Docker image second, otherwise ToolFailed."""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Component, DepEdge
from ..runner import Runner, ToolFailed, default_runner, docker_available
from .cyclonedx import read_cyclonedx

SYFT_IMAGE = "anchore/syft:v1.18.1"
TRIVY_IMAGE = "aquasec/trivy:0.58.1"


@dataclass
class ToolSbom:
    tool: str
    components: list[Component] = field(default_factory=list)
    edges: list[DepEdge] = field(default_factory=list)
    raw_path: Path | None = None


def _run_json(cmd_local: list[str], cmd_docker: list[str], runner: Runner, use_docker: bool, timeout: int = 600) -> dict:
    errors = []
    if shutil.which(cmd_local[0]):
        r = runner(cmd_local, None, timeout)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout)
        errors.append(f"{cmd_local[0]} exit {r.returncode}: {r.stderr.strip()[:200]}")
    if use_docker and docker_available(runner):
        r = runner(cmd_docker, None, timeout)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout)
        errors.append(f"docker {cmd_docker[-3] if len(cmd_docker) > 3 else ''} exit {r.returncode}: {r.stderr.strip()[:200]}")
    raise ToolFailed("; ".join(errors) or f"{cmd_local[0]} not installed and Docker unavailable")


def run_syft(repo: Path, out_dir: Path, runner: Runner = default_runner, use_docker: bool = True) -> ToolSbom:
    repo = Path(repo).resolve()
    doc = _run_json(["syft", "scan", f"dir:{repo}", "-o", "cyclonedx-json", "-q"],
                    ["docker", "run", "--rm", "--network", "none", "-v", f"{repo}:/src:ro", SYFT_IMAGE, "scan", "dir:/src",
                     "-o", "cyclonedx-json", "-q"], runner, use_docker)
    raw = Path(out_dir) / "sbom.syft.cdx.json"
    raw.write_text(json.dumps(doc), encoding="utf-8")
    comps, edges = read_cyclonedx(doc, "syft")
    return ToolSbom("syft", comps, edges, raw)


def run_trivy_fs(repo: Path, out_dir: Path, runner: Runner = default_runner, use_docker: bool = True) -> ToolSbom:
    repo = Path(repo).resolve()
    doc = _run_json(["trivy", "fs", "--quiet", "--format", "cyclonedx", "--offline-scan", str(repo)],
                    ["docker", "run", "--rm", "-v", f"{repo}:/src:ro", TRIVY_IMAGE, "fs", "--quiet", "--format",
                     "cyclonedx", "--offline-scan", "/src"], runner, use_docker)
    raw = Path(out_dir) / "sbom.trivy.cdx.json"
    raw.write_text(json.dumps(doc), encoding="utf-8")
    comps, edges = read_cyclonedx(doc, "trivy")
    return ToolSbom("trivy", comps, edges, raw)


def scan_image(image: str, out_dir: Path, runner: Runner = default_runner, use_docker: bool = True) -> ToolSbom:
    """Satisfies 'inspect at least one container image' when a pullable base image is known."""
    doc = _run_json(["syft", "scan", image, "-o", "cyclonedx-json", "-q"],
                    ["docker", "run", "--rm", SYFT_IMAGE, "scan", f"registry:{image}", "-o", "cyclonedx-json", "-q"],
                    runner, use_docker, timeout=900)
    safe = image.replace("/", "_").replace(":", "_").replace("@", "_")
    raw = Path(out_dir) / f"sbom.image.{safe}.cdx.json"
    raw.write_text(json.dumps(doc), encoding="utf-8")
    return ToolSbom(f"syft-image:{image}", [], [], raw)
