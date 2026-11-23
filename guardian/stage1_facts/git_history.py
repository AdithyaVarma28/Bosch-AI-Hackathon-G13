from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import git

from guardian.models.facts import DependencyCommitDiff

DEP_FILE_PATTERNS = re.compile(
    r"(requirements.*\.txt|pyproject\.toml|poetry\.lock|Pipfile.*|uv\.lock|Dockerfile.*|\.github/workflows/.*\.ya?ml)",
    re.IGNORECASE
)


def extract_package_pins_from_text(content: str) -> Dict[str, str]:
    pins: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip().split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        # Check requirement pin e.g. foo==1.2.3 or foo>=1.2.3
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=><~^!]=?.*)?$", line)
        if m:
            pkg_name = m.group(1).lower()
            spec = m.group(2) or "*"
            pins[pkg_name] = spec.strip()
    return pins


def analyze_git_history(repo_path: Path, max_commits: int = 50) -> Tuple[List[DependencyCommitDiff], List[str]]:
    history: List[DependencyCommitDiff] = []
    errors: List[str] = []

    try:
        repo = git.Repo(repo_path)
    except Exception as e:
        errors.append(f"Git repo inspection failed: {e}")
        return history, errors

    try:
        commits = list(repo.iter_commits(max_count=max_commits))
    except Exception as e:
        errors.append(f"Failed to read git commits: {e}")
        return history, errors

    for i, commit in enumerate(commits):
        parent = commits[i + 1] if i + 1 < len(commits) else None
        changed_dep_files: List[str] = []

        if parent:
            diffs = parent.diff(commit)
            for d in diffs:
                target_path = d.b_path or d.a_path
                if target_path and DEP_FILE_PATTERNS.search(target_path):
                    changed_dep_files.append(target_path)
        else:
            # First commit in history: list all dependency files
            for item in commit.tree.traverse():
                if hasattr(item, "path") and DEP_FILE_PATTERNS.search(item.path):
                    changed_dep_files.append(item.path)

        if not changed_dep_files:
            continue

        added: List[str] = []
        removed: List[str] = []
        changed: List[Dict[str, Any]] = []

        # Compare package list between commit and parent for requirements.txt / manifests
        for f in changed_dep_files:
            if "requirements" in f or "pyproject" in f:
                content_now = ""
                content_prev = ""
                try:
                    content_now = (commit.tree / f).data_stream.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                if parent:
                    try:
                        content_prev = (parent.tree / f).data_stream.read().decode("utf-8", errors="replace")
                    except Exception:
                        pass

                pins_now = extract_package_pins_from_text(content_now)
                pins_prev = extract_package_pins_from_text(content_prev)

                for pkg, spec in pins_now.items():
                    if pkg not in pins_prev:
                        added.append(pkg)
                    elif pins_prev[pkg] != spec:
                        changed.append({"name": pkg, "from": pins_prev[pkg], "to": spec})

                for pkg in pins_prev:
                    if pkg not in pins_now:
                        removed.append(pkg)

        history.append(DependencyCommitDiff(
            commit=commit.hexsha[:7],
            date=commit.committed_datetime.isoformat(),
            author=f"{commit.author.name} <{commit.author.email}>",
            message=commit.message.strip().split("\n")[0],
            files_changed=sorted(set(changed_dep_files)),
            added=sorted(set(added)),
            removed=sorted(set(removed)),
            changed=changed
        ))

    return history, errors


def get_snapshot_file_content(repo_path: Path, commit_sha: str, rel_file_path: str) -> Optional[str]:
    """Time-travel snapshot: returns file content at commit_sha using git show."""
    try:
        repo = git.Repo(repo_path)
        target_commit = repo.commit(commit_sha)
        blob = target_commit.tree / rel_file_path
        return blob.data_stream.read().decode("utf-8", errors="replace")
    except Exception:
        return None
