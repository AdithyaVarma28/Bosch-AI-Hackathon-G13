"""Real-repo robustness runs. Set GUARDIAN_TEST_REPOS to a folder containing shallow clones of
pygoat, VAmPI, vulpy and shiftleft-python-demo (pinned commits); otherwise these tests skip."""
import os
from pathlib import Path

import pytest

from guardian.stage2_code.parser import index_repo

BASE = Path(os.environ["GUARDIAN_TEST_REPOS"]) if "GUARDIAN_TEST_REPOS" in os.environ else None
pytestmark = pytest.mark.slow


def repo(name: str) -> Path:
    if BASE is None or not (BASE / name).is_dir():
        pytest.skip(f"set GUARDIAN_TEST_REPOS with a clone of {name}")
    return BASE / name


@pytest.mark.parametrize("name", ["pygoat", "VAmPI", "vulpy", "shiftleft-python-demo"])
def test_real_repo_completes_with_problems_only_in_errors_list(name):
    idx = index_repo(repo(name))
    assert len(idx.files) >= 5
    assert all(f.parse_error or f.sha256 for f in idx.files)


def test_pygoat_has_django_routes_and_sensitive_calls():
    idx = index_repo(repo("pygoat"))
    assert any(r.framework == "django" for f in idx.files for r in f.routes)
    assert any(s.category in {"deserialize", "code_exec", "subprocess"} for f in idx.files for s in f.sensitive_calls)
    assert any(s.target == "yaml.load" for f in idx.files for s in f.sensitive_calls)
    assert idx.import_name_to_distribution.get("yaml") == "PyYAML"
