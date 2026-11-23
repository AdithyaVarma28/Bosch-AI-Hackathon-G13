from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from guardian.models.facts import DocsInventory


def parse_docs_inventory(repo_path: Path) -> Tuple[DocsInventory, List[str]]:
    errors: List[str] = []
    readme_path: Optional[str] = None
    doc_files: List[str] = []
    previews: Dict[str, str] = {}

    # 1. Look for README
    for candidate in ["README.md", "README.rst", "README.txt", "README"]:
        cand_p = repo_path / candidate
        if cand_p.is_file():
            readme_path = candidate
            try:
                with open(cand_p, "r", encoding="utf-8", errors="replace") as fh:
                    previews[candidate] = fh.read(2000)
            except Exception as e:
                errors.append(f"Failed to read {candidate}: {e}")
            break

    # 2. Look for docs/ directory
    docs_dir = repo_path / "docs"
    if docs_dir.is_dir():
        for root, dirs, files in os.walk(docs_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in sorted(files):
                if f.endswith((".md", ".rst", ".txt")):
                    file_p = Path(root) / f
                    rel_p = file_p.relative_to(repo_path).as_posix()
                    doc_files.append(rel_p)
                    try:
                        with open(file_p, "r", encoding="utf-8", errors="replace") as fh:
                            previews[rel_p] = fh.read(2000)
                    except Exception as e:
                        errors.append(f"Failed to read {rel_p}: {e}")

    return DocsInventory(
        readme=readme_path,
        doc_files=doc_files,
        previews=previews
    ), errors
