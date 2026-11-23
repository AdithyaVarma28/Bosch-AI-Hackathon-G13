from pathlib import Path

import pytest


@pytest.fixture
def write_tree(tmp_path):
    """Create a repo-like tree from {relative_path: text} and return its root."""

    def _write(files: dict[str, str]) -> Path:
        for rel, text in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return tmp_path

    return _write
