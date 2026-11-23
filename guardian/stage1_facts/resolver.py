from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from guardian.models.facts import DeclaredDependency, ResolvedPackage


def make_purl(name: str, version: str) -> str:
    clean_name = re.sub(r"[-_.]+", "-", name).lower()
    return f"pkg:pypi/{clean_name}@{version}"


def parse_poetry_lock(lock_path: Path, direct_names: Set[str]) -> List[ResolvedPackage]:
    packages: List[ResolvedPackage] = []
    with open(lock_path, "rb") as fh:
        data = tomllib.load(fh)

    raw_packages = data.get("package", [])
    for pkg in raw_packages:
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if not name or not version:
            continue
        purl = make_purl(name, version)
        deps = list(pkg.get("dependencies", {}).keys())
        hashes = [f["hash"] for f in pkg.get("files", []) if "hash" in f]
        direct = name.lower() in direct_names

        packages.append(ResolvedPackage(
            purl=purl,
            name=name,
            version=version,
            direct=direct,
            requires=deps,
            hashes=hashes,
            source="lockfile",
            discovered_by="resolver"
        ))

    # Compute required_by
    name_to_pkg = {p.name.lower(): p for p in packages}
    for p in packages:
        for dep in p.requires:
            dep_lower = dep.lower()
            if dep_lower in name_to_pkg:
                name_to_pkg[dep_lower].required_by.append(p.name)

    return packages


def parse_pipfile_lock(lock_path: Path, direct_names: Set[str]) -> List[ResolvedPackage]:
    packages: List[ResolvedPackage] = []
    with open(lock_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    def extract_section(section_name: str) -> None:
        for name, info in data.get(section_name, {}).items():
            version = info.get("version", "").lstrip("=")
            hashes = info.get("hashes", [])
            direct = name.lower() in direct_names
            packages.append(ResolvedPackage(
                purl=make_purl(name, version),
                name=name,
                version=version,
                direct=direct,
                hashes=hashes,
                source="lockfile",
                discovered_by="resolver"
            ))

    extract_section("default")
    extract_section("develop")
    return packages


def resolve_via_pip_report(
    repo_path: Path,
    requirements_file: Path,
    direct_names: Set[str],
    use_docker: bool = False
) -> Tuple[List[ResolvedPackage], List[str]]:
    packages: List[ResolvedPackage] = []
    errors: List[str] = []
    report_data = None

    # Check if docker is available and requested
    docker_available = shutil.which("docker") is not None
    if use_docker and docker_available:
        try:
            rel_req = requirements_file.relative_to(repo_path).as_posix()
            cmd = [
                "docker", "run", "--rm",
                "--network", "host",
                "-v", f"{repo_path.resolve()}:/workspace:ro",
                "-w", "/workspace",
                "python:3.11-slim",
                "sh", "-c",
                f"pip install --quiet --dry-run --ignore-installed --only-binary=:all: --report /tmp/report.json -r '{rel_req}' >/dev/null 2>&1 && cat /tmp/report.json"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            if res.returncode == 0 and res.stdout.strip():
                report_data = json.loads(res.stdout)
            else:
                errors.append(f"Docker pip report resolution failed: {res.stderr.strip()[:300]}")
        except Exception as e:
            errors.append(f"Docker resolution exception: {e}")

    # Fallback to local python dry-run with --only-binary=:all:
    if report_data is None:
        tmp_report = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                tmp_report = Path(tmp.name)
            cmd = [
                sys.executable, "-m", "pip", "install", "--quiet", "--dry-run", "--ignore-installed",
                "--only-binary=:all:", "--report", str(tmp_report), "-r", str(requirements_file.resolve())
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0 and tmp_report.is_file() and tmp_report.stat().st_size > 0:
                with open(tmp_report, "r", encoding="utf-8") as fh:
                    report_data = json.load(fh)
            else:
                errors.append(f"Local pip report resolution failed: {res.stderr.strip()[:300]}")
        except Exception as e:
            errors.append(f"Local pip resolution exception: {e}")
        finally:
            if tmp_report and tmp_report.is_file():
                try:
                    tmp_report.unlink()
                except Exception:
                    pass

    if report_data and "install" in report_data:
        for item in report_data["install"]:
            metadata = item.get("metadata", {})
            name = metadata.get("name", "")
            version = metadata.get("version", "")
            if not name or not version:
                continue
            purl = make_purl(name, version)
            direct = name.lower() in direct_names
            reqs = [r.split()[0].split(";")[0] for r in metadata.get("requires_dist", [])]

            hashes = []
            if "download_info" in item and "archive_info" in item["download_info"]:
                archive_hashes = item["download_info"]["archive_info"].get("hashes", {})
                for k, v in archive_hashes.items():
                    hashes.append(f"{k}:{v}")

            packages.append(ResolvedPackage(
                purl=purl,
                name=name,
                version=version,
                direct=direct,
                requires=reqs,
                hashes=hashes,
                source="pip-report",
                discovered_by="resolver"
            ))

        # Compute required_by
        name_to_pkg = {p.name.lower(): p for p in packages}
        for p in packages:
            for dep in p.requires:
                dep_lower = dep.lower()
                if dep_lower in name_to_pkg:
                    name_to_pkg[dep_lower].required_by.append(p.name)

    return packages, errors


def resolve_packages(
    repo_path: Path,
    declared: List[DeclaredDependency],
    use_docker: bool = False
) -> Tuple[List[ResolvedPackage], List[str]]:
    direct_names = {d.name.lower() for d in declared if d.name and d.name != "unknown"}
    errors: List[str] = []

    # 1. Check for lockfiles
    poetry_lock = repo_path / "poetry.lock"
    if poetry_lock.is_file():
        try:
            return parse_poetry_lock(poetry_lock, direct_names), errors
        except Exception as e:
            errors.append(f"Error parsing poetry.lock: {e}")

    pipfile_lock = repo_path / "Pipfile.lock"
    if pipfile_lock.is_file():
        try:
            return parse_pipfile_lock(pipfile_lock, direct_names), errors
        except Exception as e:
            errors.append(f"Error parsing Pipfile.lock: {e}")

    # 2. Check for requirements.txt to run pip-report
    main_req = repo_path / "requirements.txt"
    if main_req.is_file():
        pkgs, res_errors = resolve_via_pip_report(repo_path, main_req, direct_names, use_docker=use_docker)
        errors.extend(res_errors)
        if pkgs:
            return pkgs, errors

    # 3. If pip-report failed or no requirements.txt, synthesize resolved packages from declared pins
    pinned_packages: List[ResolvedPackage] = []
    for dep in declared:
        if dep.name and dep.name != "unknown" and dep.spec:
            # Check if version is pinned e.g. ==1.2.3 or 1.2.3
            match = re.match(r"^==?\s*([0-9a-zA-Z._+-]+)", dep.spec)
            if match:
                ver = match.group(1)
                pinned_packages.append(ResolvedPackage(
                    purl=make_purl(dep.name, ver),
                    name=dep.name,
                    version=ver,
                    direct=True,
                    source="manifest-pin",
                    discovered_by="manifest"
                ))

    return pinned_packages, errors
