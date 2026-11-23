from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from guardian.models.facts import ResolvedPackage


def generate_sbom(repo_path: Path, output_file: Path) -> Tuple[Optional[str], List[str]]:
    errors: List[str] = []
    syft_bin = shutil.which("syft")
    if not syft_bin:
        errors.append("Syft binary not found on PATH. SBOM generation skipped.")
        return None, errors

    output_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        cmd = [
            syft_bin,
            "scan",
            f"dir:{repo_path.resolve()}",
            "-o",
            f"cyclonedx-json={output_file.resolve()}"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if res.returncode != 0:
            errors.append(f"Syft SBOM scan failed (code {res.returncode}): {res.stderr.strip()[:300]}")
            return None, errors
        return str(output_file), errors
    except Exception as e:
        errors.append(f"Syft SBOM generation exception: {e}")
        return None, errors


def parse_and_cross_check_sbom(
    sbom_path: Path,
    resolved_packages: List[ResolvedPackage]
) -> Tuple[List[Dict], List[str]]:
    discrepancies: List[str] = []
    components: List[Dict] = []
    if not sbom_path.is_file():
        return components, discrepancies

    try:
        with open(sbom_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        components = data.get("components", [])

        sbom_purls: Set[str] = {c.get("purl") for c in components if c.get("purl")}
        resolved_purls: Set[str] = {p.purl for p in resolved_packages}

        for purl in resolved_purls:
            if purl not in sbom_purls:
                discrepancies.append(f"Package {purl} resolved by package manager but missing in Syft SBOM")

        for purl in sbom_purls:
            if purl.startswith("pkg:pypi/") and purl not in resolved_purls:
                discrepancies.append(f"Package {purl} detected by Syft SBOM but missing in resolved dependencies")

    except Exception as e:
        discrepancies.append(f"Error parsing SBOM {sbom_path}: {e}")

    return components, discrepancies
