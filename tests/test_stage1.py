import json
import shutil
import subprocess
from pathlib import Path
import pytest

from guardian.models.facts import ScanFacts
from guardian.stage1_facts.collector import run_stage1_collection
from guardian.stage1_facts.git_history import get_snapshot_file_content


@pytest.fixture(scope="session")
def mini_shop_repo(tmp_path_factory):
    """Generates the mini-shop test repository fixture with 2 commits."""
    temp_dir = tmp_path_factory.mktemp("repos")
    mini_shop_path = temp_dir / "mini-shop"
    script_path = Path(__file__).parent / "fixtures" / "make_mini_shop.sh"

    res = subprocess.run(["bash", str(script_path), str(mini_shop_path)], capture_output=True, text=True)
    assert res.returncode == 0, f"make_mini_shop.sh failed: {res.stderr}"
    return mini_shop_path


def test_stage1_collection_mini_shop(mini_shop_repo, tmp_path):
    output_dir = tmp_path / "output"
    
    # Run Stage 1 collector
    facts = run_stage1_collection(
        repo_path=mini_shop_repo,
        output_dir=output_dir,
        use_docker=False,
        offline=True,  # offline mode for fast test execution
        skip_sbom=False
    )

    assert isinstance(facts, ScanFacts)
    facts_file = output_dir / "facts.json"
    assert facts_file.is_file()

    # Validate JSON parsing
    with open(facts_file, "r", encoding="utf-8") as fh:
        raw_facts = json.load(fh)
    loaded_facts = ScanFacts.model_validate(raw_facts)
    assert loaded_facts.repo.name == "mini-shop"

    # 1. Declared Dependencies
    declared_names = {d.name.lower() for d in facts.declared_dependencies}
    assert "flask" in declared_names
    assert "stripe" in declared_names
    assert "sqlalchemy" in declared_names
    assert "pyyaml" in declared_names
    assert "requests" in declared_names
    assert "colorama" in declared_names

    # Check dev dependency
    pytest_dep = next((d for d in facts.declared_dependencies if d.name.lower() == "pytest"), None)
    assert pytest_dep is not None
    assert pytest_dep.dev is True

    # 2. Resolved Packages
    resolved_map = {p.name.lower(): p for p in facts.resolved_packages}
    assert "pyyaml" in resolved_map
    assert resolved_map["pyyaml"].version == "6.0.1"
    assert resolved_map["pyyaml"].purl == "pkg:pypi/pyyaml@6.0.1"

    # 3. CI/CD Workflows
    assert len(facts.ci_workflows) == 1
    ci = facts.ci_workflows[0]
    assert ci.file == ".github/workflows/ci.yml"
    assert "push" in ci.triggers
    assert len(ci.actions) == 1
    action = ci.actions[0]
    assert action.uses == "actions/checkout"
    assert action.ref == "v4"
    assert action.pinned_to_sha is False  # Pinned to tag, not 40-char SHA!
    assert "SUPER_SECRET_KEY" in ci.secrets_used

    # 4. Containers / Dockerfile
    assert len(facts.containers) == 1
    df = facts.containers[0]
    assert df.file == "Dockerfile"
    assert len(df.base_images) == 1
    base_img = df.base_images[0]
    assert base_img.ref == "python:3.11-slim"
    assert base_img.tag == "3.11-slim"
    assert base_img.digest is None  # Tag only, no SHA digest
    assert len(df.pip_installs) >= 1

    # 5. Config & Services
    # .env files: strictly names only, NO secret values
    assert len(facts.config.env_files) == 1
    env_info = facts.config.env_files[0]
    assert env_info.file == ".env.example"
    assert "DATABASE_URL" in env_info.var_names
    assert "STRIPE_KEY" in env_info.var_names
    assert "your_stripe_key_here" not in str(raw_facts)

    # Compose services
    compose_services = {s.name: s for s in facts.config.compose_services}
    assert "db" in compose_services
    assert compose_services["db"].image == "postgres:16"
    assert compose_services["db"].digest is None
    assert "web" in compose_services
    assert "db" in compose_services["web"].depends_on

    # 6. Dependency History & Diffs
    assert len(facts.dependency_history) >= 2
    latest_commit = facts.dependency_history[0]
    assert "colorama" in latest_commit.added
    changed_packages = {c["name"]: c for c in latest_commit.changed}
    assert "pyyaml" in changed_packages
    assert "5.4.1" in changed_packages["pyyaml"]["from"]
    assert "6.0.1" in changed_packages["pyyaml"]["to"]

    # 7. Time-Travel Snapshot
    old_commit_sha = facts.dependency_history[1].commit
    old_reqs = get_snapshot_file_content(mini_shop_repo, old_commit_sha, "requirements.txt")
    assert old_reqs is not None
    assert "PyYAML==5.4.1" in old_reqs
    assert "colorama" not in old_reqs

    # 8. File hashes
    assert "requirements.txt" in facts.file_hashes
    assert len(facts.file_hashes["requirements.txt"]) == 64
