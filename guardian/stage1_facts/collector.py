from __future__ import annotations

import datetime
import hashlib
import os
from pathlib import Path
from typing import Dict, Optional
import git

from guardian.models.facts import RepoInfo, ScanFacts
from guardian.stage1_facts.cicd import parse_workflows
from guardian.stage1_facts.config_inventory import parse_config_inventory
from guardian.stage1_facts.docker import parse_dockerfiles
from guardian.stage1_facts.docs import parse_docs_inventory
from guardian.stage1_facts.git_history import analyze_git_history
from guardian.stage1_facts.manifests import parse_manifests
from guardian.stage1_facts.pypi_meta import fetch_pypi_metadata
from guardian.stage1_facts.resolver import resolve_packages
from guardian.stage1_facts.sbom import generate_sbom, parse_and_cross_check_sbom


def compute_file_hashes(repo_path: Path) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "__pycache__", "output", ".guardian_cache"}]
        for f in files:
            file_p = Path(root) / f
            rel_p = file_p.relative_to(repo_path).as_posix()
            try:
                hasher = hashlib.sha256()
                with open(file_p, "rb") as fh:
                    while chunk := fh.read(65536):
                        hasher.update(chunk)
                hashes[rel_p] = hasher.hexdigest()
            except Exception:
                pass
    return hashes


def collect_repo_info(repo_path: Path) -> RepoInfo:
    repo_name = repo_path.resolve().name
    commit = "unknown"
    branch = None
    try:
        repo = git.Repo(repo_path)
        commit = repo.head.commit.hexsha[:7]
        try:
            branch = repo.active_branch.name
        except Exception:
            branch = "HEAD"
    except Exception:
        pass

    return RepoInfo(
        name=repo_name,
        commit=commit,
        branch=branch,
        scanned_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


def run_stage1_collection(
    repo_path: Path,
    output_dir: Path,
    use_docker: bool = False,
    offline: bool = False,
    skip_sbom: bool = False
) -> ScanFacts:
    all_errors = []
    repo_path = repo_path.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Repo info & File hashing
    repo_info = collect_repo_info(repo_path)
    file_hashes = compute_file_hashes(repo_path)

    # 2. Declared dependencies & package indexes
    declared, indexes, manifest_errors = parse_manifests(repo_path)
    all_errors.extend(manifest_errors)

    # 3. Resolved packages (direct + transitive)
    resolved, resolver_errors = resolve_packages(repo_path, declared, use_docker=use_docker)
    all_errors.extend(resolver_errors)

    # 4. SBOM generation with Syft
    sbom_path = None
    if not skip_sbom:
        sbom_target = output_dir / "sbom.cdx.json"
        sbom_path_str, sbom_errors = generate_sbom(repo_path, sbom_target)
        all_errors.extend(sbom_errors)
        if sbom_path_str:
            sbom_path = str(sbom_target)
            _, cross_check_errors = parse_and_cross_check_sbom(sbom_target, resolved)
            all_errors.extend(cross_check_errors)

    # 5. PyPI Metadata
    pypi_metadata = fetch_pypi_metadata(resolved, offline=offline)

    # 6. CI/CD Workflows
    ci_workflows, cicd_errors = parse_workflows(repo_path)
    all_errors.extend(cicd_errors)

    # 7. Containers
    containers, docker_errors = parse_dockerfiles(repo_path)
    all_errors.extend(docker_errors)

    # 8. Git history diffs & snapshots
    history, git_errors = analyze_git_history(repo_path)
    all_errors.extend(git_errors)

    # 9. Docs
    docs, docs_errors = parse_docs_inventory(repo_path)
    all_errors.extend(docs_errors)

    # 10. Config & Services
    config, config_errors = parse_config_inventory(repo_path)
    all_errors.extend(config_errors)

    facts = ScanFacts(
        repo=repo_info,
        declared_dependencies=declared,
        package_indexes=indexes,
        resolved_packages=resolved,
        sbom_path=sbom_path,
        package_metadata=pypi_metadata,
        ci_workflows=ci_workflows,
        containers=containers,
        dependency_history=history,
        docs=docs,
        config=config,
        file_hashes=file_hashes,
        errors=all_errors
    )

    # Save facts.json
    facts_file = output_dir / "facts.json"
    with open(facts_file, "w", encoding="utf-8") as fh:
        fh.write(facts.model_dump_json(indent=2))

    return facts
