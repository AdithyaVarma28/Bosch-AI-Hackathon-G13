from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from guardian.cli import app
from guardian.models.code_index import CodeIndex
from guardian.models.common import Claim, DepEdge
from guardian.models.facts import Facts, ScanFacts

DATA = Path(__file__).parent / "data"

TEAM_SAMPLE_INDEX = {
    "source_roots": ["app"],
    "import_name_to_distribution": {"yaml": "PyYAML"},
    "files": [{
        "path": "app/payments/client.py", "module_path": "app.payments.client", "package_dir": "app/payments",
        "sha256": "0" * 64, "loc": 42, "is_test": False, "parse_error": None, "docstring": "Stripe client factory.",
        "imports": [
            {"name": "stripe", "alias": None, "kind": "external", "line": 1, "in_try_except": False, "conditional": False},
            {"name": "app.payments.config", "kind": "internal", "resolved_file": "app/payments/config.py", "line": 3},
        ],
        "definitions": [{"id": "app/payments/client.py::get_client", "type": "function", "name": "get_client",
                         "line": 6, "end_line": 14, "decorators": [], "params": [], "docstring": None}],
        "calls": [{"caller": "app/payments/client.py::get_client", "target": "stripe.Charge.create",
                   "kind": "external", "import_name": "stripe", "line": 11}],
        "routes": [], "cli_entrypoints": [],
        "env_reads": [{"var": "STRIPE_KEY", "how": "os.environ[]", "line": 8}],
        "sensitive_calls": [], "string_urls": [], "dynamic_imports": [],
    }],
    "errors": [],
}


def test_real_stage1_output_validates_against_the_contract():
    """tests/data/mini_shop_facts.json is real output of the teammate's Stage 1 collector."""
    raw = (DATA / "mini_shop_facts.json").read_text(encoding="utf-8")
    facts = ScanFacts.model_validate_json(raw)
    assert facts.repo.name == "mini-shop" and len(facts.resolved_packages) == 18
    assert ScanFacts.model_validate_json(facts.model_dump_json()) == facts
    assert Facts is ScanFacts


def test_real_stage1_facts_carry_a_file_and_line_for_every_declared_dependency():
    facts = ScanFacts.model_validate_json((DATA / "mini_shop_facts.json").read_text(encoding="utf-8"))
    assert facts.declared_dependencies and all(d.source_file and d.line > 0 for d in facts.declared_dependencies)


def test_history_diff_keeps_from_and_to_keys():
    facts = ScanFacts.model_validate_json((DATA / "mini_shop_facts.json").read_text(encoding="utf-8"))
    changed = [c for h in facts.dependency_history for c in h.changed]
    assert {"name": "pyyaml", "from": "==5.4.1", "to": "==6.0.1"} in changed


def test_code_index_roundtrip():
    c = CodeIndex.model_validate(TEAM_SAMPLE_INDEX)
    assert CodeIndex.model_validate_json(c.model_dump_json()) == c
    assert c.files[0].imports[1].resolved_file == "app/payments/config.py"


def test_fact_claim_requires_evidence():
    with pytest.raises(ValidationError):
        Claim(text="t", type="fact", evidence_ids=[], confidence="high", verifier_status="pending")


def test_inference_claim_may_have_no_evidence():
    assert Claim(text="t", type="inference", evidence_ids=[], confidence="low", verifier_status="pending")


def test_depedge_defaults_are_resolved_layer():
    e = DepEdge(src="a", dst="b")
    assert e.kind == "DEPENDS_ON" and e.evidence_status == "verified"


def test_cli_scan_help():
    assert CliRunner().invoke(app, ["scan", "--help"]).exit_code == 0
