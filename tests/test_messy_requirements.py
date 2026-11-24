"""Messy requirement lines must not become bogus SBOM components."""
from guardian.cartographer.facts import build_repo_facts
from guardian.context import RunContext, Settings
from guardian.ingest import open_local
from guardian.sbom.lockfiles import parse_requirements_pins
from guardian.sbom.stage import _exact_version, run_sbom_stage
from guardian.store import RunStore


def test_triple_equals_with_no_version_is_not_a_version():
    assert _exact_version("pypi", "===") is None
    assert _exact_version("pypi", "==") is None


def test_real_pins_still_count_as_exact_versions():
    assert _exact_version("pypi", "==1.2.3") == "1.2.3"
    assert _exact_version("pypi", "===1.0") == "1.0"
    assert _exact_version("pypi", "==2.0.0.post1") == "2.0.0.post1"


def test_wildcard_and_range_specs_are_not_exact_versions():
    assert _exact_version("pypi", "==1.*") is None
    assert _exact_version("pypi", ">=1.0,<3") is None
    assert _exact_version("pypi", "~=1.4") is None


def _components(tmp_path, requirements: str):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(requirements, encoding="utf-8")
    ctx = RunContext(repo=open_local(repo), store=RunStore(tmp_path / "run", "t"),
                     settings=Settings(offline=True, use_llm=False, use_docker=False, cache_dir=tmp_path / "cache"))
    ctx.facts = build_repo_facts(ctx)
    run_sbom_stage(ctx)
    return ctx, {c.purl for c in ctx.components}


MESSY = (
    "requests==2.25.1\n"
    "./local/pkg\n"
    "https://example.com/pkg_name-1.2.3-py3-none-any.whl\n"
    "https://example.com/blob.zip\n"
    "weird===\n"
    "git+https://github.com/psf/requests.git@main#egg=requests2\n"
    "flask>=1.0\n"  # an unpinned line stops the file acting as its own lock, so the declared-only fallback runs
)


def test_local_path_requirement_is_not_a_registry_component(tmp_path):
    ctx, purls = _components(tmp_path, MESSY)
    assert not any("local" in p for p in purls)
    assert any("local path dependency" in n for n in ctx.sbom_report.notes)


def test_wheel_url_gets_its_real_name_and_version(tmp_path):
    _, purls = _components(tmp_path, MESSY)
    assert "pkg:pypi/pkg-name@1.2.3" in purls
    assert not any(p.endswith("x-whl") or "whl" in p for p in purls)


def test_unnamed_url_dependency_is_left_out_with_a_note(tmp_path):
    ctx, purls = _components(tmp_path, MESSY)
    assert not any("blob" in p for p in purls)
    assert any("blob.zip" in n for n in ctx.sbom_report.notes)


def test_triple_equals_garbage_gives_an_unversioned_component_not_version_equals(tmp_path):
    _, purls = _components(tmp_path, MESSY)
    assert "pkg:pypi/weird" in purls
    assert not any(p.startswith("pkg:pypi/weird@") for p in purls)


def test_normal_and_vcs_requirements_are_untouched(tmp_path):
    _, purls = _components(tmp_path, MESSY)
    assert "pkg:pypi/requests@2.25.1" in purls
    assert "pkg:pypi/requests2" in purls


def test_pinned_requirements_parser_rejects_empty_wildcard_and_compound_pins():
    text = "weird===\nfoo==1.0,!=1.1\nbar==1.*\nok==2.0\nalso===3.1\n"
    parsed = parse_requirements_pins("requirements.txt", text)
    assert [(c.name, c.version) for c in parsed.components] == [("ok", "2.0"), ("also", "3.1")]
    assert sum(e.startswith("unpinned:") for e in parsed.errors) == 3
