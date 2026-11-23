from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import List, Optional, Set, Tuple
from packaging.requirements import Requirement, InvalidRequirement

from guardian.models.facts import DeclaredDependency, PackageIndex

VCS_PREFIXES = ("git+", "svn+", "hg+", "bzr+")
DEV_FILE_PATTERNS = ("dev", "test")


def is_dev_filename(filepath: str | Path) -> bool:
    name = Path(filepath).stem.lower()
    return any(pat in name for pat in DEV_FILE_PATTERNS)


def parse_manifests(repo_path: Path) -> Tuple[List[DeclaredDependency], List[PackageIndex], List[str]]:
    declared: List[DeclaredDependency] = []
    indexes: List[PackageIndex] = []
    errors: List[str] = []

    # 1. Collect requirements*.txt files
    req_files: Set[Path] = set()
    for root, dirs, files in os.walk(repo_path):
        # Ignore common non-project directories
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "__pycache__", "build", "dist", "site-packages", "output"}]
        for f in files:
            p = Path(root) / f
            if f.startswith("requirements") and f.endswith(".txt") or f.endswith("-requirements.txt"):
                req_files.add(p)

    visited_reqs: Set[Path] = set()

    def parse_req_file(file_path: Path, is_dev_override: Optional[bool] = None) -> None:
        rel_path = file_path.relative_to(repo_path).as_posix()
        resolved_file = file_path.resolve()
        if resolved_file in visited_reqs:
            return
        visited_reqs.add(resolved_file)

        is_dev = is_dev_override if is_dev_override is not None else is_dev_filename(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                for line_idx, raw_line in enumerate(fh, start=1):
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Handle includes: -r or -c
                    if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
                        parts = line.split(maxsplit=1)
                        if len(parts) > 1:
                            target_file = (file_path.parent / parts[1].strip()).resolve()
                            if target_file.is_file():
                                parse_req_file(target_file, is_dev_override=is_dev)
                            else:
                                errors.append(f"Included requirement file not found: {parts[1].strip()} at {rel_path}:{line_idx}")
                        continue

                    # Handle package index configs
                    if line.startswith(("--index-url", "-i ")) or line.startswith("--extra-index-url"):
                        parts = line.split(maxsplit=1)
                        if len(parts) > 1:
                            idx_type = "index-url" if line.startswith(("--index-url", "-i ")) else "extra-index-url"
                            indexes.append(PackageIndex(
                                url=parts[1].strip(),
                                type=idx_type,
                                source_file=rel_path,
                                line=line_idx,
                                discovered_by="manifest"
                            ))
                        continue

                    # Ignore other pip options like -f, --find-links, --no-index, etc.
                    if line.startswith("-"):
                        continue

                    # Strip comments on the same line if not part of URL
                    clean_line = line.split(" #", 1)[0].split(" //", 1)[0].strip()

                    # Check for VCS requirement
                    if any(clean_line.startswith(pfx) for pfx in VCS_PREFIXES):
                        # Extract name from egg=name if present
                        name = "unknown"
                        if "#egg=" in clean_line:
                            name = clean_line.split("#egg=")[-1].split("&")[0]
                        declared.append(DeclaredDependency(
                            name=name,
                            spec=clean_line,
                            kind="vcs",
                            dev=is_dev,
                            source_file=rel_path,
                            line=line_idx,
                            discovered_by="manifest"
                        ))
                        continue

                    # Check for URL
                    if clean_line.startswith(("http://", "https://")):
                        name = "unknown"
                        if "#egg=" in clean_line:
                            name = clean_line.split("#egg=")[-1].split("&")[0]
                        declared.append(DeclaredDependency(
                            name=name,
                            spec=clean_line,
                            kind="url",
                            dev=is_dev,
                            source_file=rel_path,
                            line=line_idx,
                            discovered_by="manifest"
                        ))
                        continue

                    # Check for local path
                    if clean_line.startswith((".", "/", "file://")):
                        declared.append(DeclaredDependency(
                            name=Path(clean_line).name or "unknown",
                            spec=clean_line,
                            kind="local",
                            dev=is_dev,
                            source_file=rel_path,
                            line=line_idx,
                            discovered_by="manifest"
                        ))
                        continue

                    # Standard requirement
                    try:
                        req = Requirement(clean_line)
                        declared.append(DeclaredDependency(
                            name=req.name,
                            spec=str(req.specifier),
                            kind="registry",
                            dev=is_dev,
                            extras=list(req.extras),
                            markers=str(req.marker) if req.marker else None,
                            source_file=rel_path,
                            line=line_idx,
                            discovered_by="manifest"
                        ))
                    except InvalidRequirement as e:
                        errors.append(f"Invalid requirement '{clean_line}' at {rel_path}:{line_idx}: {e}")
        except Exception as e:
            errors.append(f"Failed to read requirements file {rel_path}: {e}")

    for req_f in sorted(req_files):
        parse_req_file(req_f)

    # 2. Check pyproject.toml
    pyproject_file = repo_path / "pyproject.toml"
    if pyproject_file.is_file():
        rel_pyproject = pyproject_file.relative_to(repo_path).as_posix()
        try:
            with open(pyproject_file, "rb") as fh:
                data = tomllib.load(fh)

            # [project.dependencies]
            project_deps = data.get("project", {}).get("dependencies", [])
            for dep_str in project_deps:
                try:
                    req = Requirement(dep_str)
                    declared.append(DeclaredDependency(
                        name=req.name,
                        spec=str(req.specifier),
                        kind="registry",
                        dev=False,
                        extras=list(req.extras),
                        markers=str(req.marker) if req.marker else None,
                        source_file=rel_pyproject,
                        line=1,
                        discovered_by="manifest"
                    ))
                except InvalidRequirement:
                    pass

            # [project.optional-dependencies]
            opt_deps = data.get("project", {}).get("optional-dependencies", {})
            for group, group_deps in opt_deps.items():
                is_dev = any(pat in group.lower() for pat in DEV_FILE_PATTERNS)
                for dep_str in group_deps:
                    try:
                        req = Requirement(dep_str)
                        declared.append(DeclaredDependency(
                            name=req.name,
                            spec=str(req.specifier),
                            kind="registry",
                            dev=is_dev,
                            extras=list(req.extras),
                            markers=str(req.marker) if req.marker else None,
                            source_file=rel_pyproject,
                            line=1,
                            discovered_by="manifest"
                        ))
                    except InvalidRequirement:
                        pass

            # [dependency-groups] (PEP 735)
            dep_groups = data.get("dependency-groups", {})
            for group, group_deps in dep_groups.items():
                is_dev = any(pat in group.lower() for pat in DEV_FILE_PATTERNS)
                for dep_item in group_deps:
                    dep_str = dep_item if isinstance(dep_item, str) else dep_item.get("include-group", "")
                    if dep_str and isinstance(dep_item, str):
                        try:
                            req = Requirement(dep_str)
                            declared.append(DeclaredDependency(
                                name=req.name,
                                spec=str(req.specifier),
                                kind="registry",
                                dev=is_dev,
                                extras=list(req.extras),
                                markers=str(req.marker) if req.marker else None,
                                source_file=rel_pyproject,
                                line=1,
                                discovered_by="manifest"
                            ))
                        except InvalidRequirement:
                            pass

            # [tool.poetry]
            poetry_data = data.get("tool", {}).get("poetry", {})
            poetry_deps = poetry_data.get("dependencies", {})
            for dep_name, dep_spec in poetry_deps.items():
                if dep_name.lower() == "python":
                    continue
                spec_str = dep_spec if isinstance(dep_spec, str) else str(dep_spec.get("version", ""))
                declared.append(DeclaredDependency(
                    name=dep_name,
                    spec=spec_str,
                    kind="registry",
                    dev=False,
                    source_file=rel_pyproject,
                    line=1,
                    discovered_by="manifest"
                ))

            # [tool.poetry.group.*]
            poetry_groups = poetry_data.get("group", {})
            for grp_name, grp_info in poetry_groups.items():
                is_dev = any(pat in grp_name.lower() for pat in DEV_FILE_PATTERNS)
                for dep_name, dep_spec in grp_info.get("dependencies", {}).items():
                    spec_str = dep_spec if isinstance(dep_spec, str) else str(dep_spec.get("version", ""))
                    declared.append(DeclaredDependency(
                        name=dep_name,
                        spec=spec_str,
                        kind="registry",
                        dev=is_dev,
                        source_file=rel_pyproject,
                        line=1,
                        discovered_by="manifest"
                    ))

            # Poetry / uv indexes
            for source in poetry_data.get("source", []):
                if "url" in source:
                    indexes.append(PackageIndex(
                        url=source["url"],
                        type="poetry-source",
                        source_file=rel_pyproject,
                        line=1,
                        discovered_by="manifest"
                    ))
            for uv_idx in data.get("tool", {}).get("uv", {}).get("index", []):
                if "url" in uv_idx:
                    indexes.append(PackageIndex(
                        url=uv_idx["url"],
                        type="uv-index",
                        source_file=rel_pyproject,
                        line=1,
                        discovered_by="manifest"
                    ))
        except Exception as e:
            errors.append(f"Error parsing pyproject.toml: {e}")

    # 3. Check Pipfile
    pipfile = repo_path / "Pipfile"
    if pipfile.is_file():
        rel_pipfile = pipfile.relative_to(repo_path).as_posix()
        try:
            with open(pipfile, "rb") as fh:
                data = tomllib.load(fh)
            for pkg_name, spec in data.get("packages", {}).items():
                declared.append(DeclaredDependency(
                    name=pkg_name,
                    spec=spec if isinstance(spec, str) else "*",
                    kind="registry",
                    dev=False,
                    source_file=rel_pipfile,
                    line=1,
                    discovered_by="manifest"
                ))
            for pkg_name, spec in data.get("dev-packages", {}).items():
                declared.append(DeclaredDependency(
                    name=pkg_name,
                    spec=spec if isinstance(spec, str) else "*",
                    kind="registry",
                    dev=True,
                    source_file=rel_pipfile,
                    line=1,
                    discovered_by="manifest"
                ))
            for source in data.get("source", []):
                if "url" in source:
                    indexes.append(PackageIndex(
                        url=source["url"],
                        type="pipfile-source",
                        source_file=rel_pipfile,
                        line=1,
                        discovered_by="manifest"
                    ))
        except Exception as e:
            errors.append(f"Error parsing Pipfile: {e}")

    return declared, indexes, errors
