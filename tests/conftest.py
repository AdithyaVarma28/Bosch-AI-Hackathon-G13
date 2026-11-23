from __future__ import annotations

from pathlib import Path

import pytest

from guardian.context import RunContext, Settings
from guardian.fixture import make_fixture
from guardian.ingest import open_local
from guardian.store import RunStore


@pytest.fixture(scope="session")
def fixture_repo(tmp_path_factory) -> Path:
    return make_fixture(tmp_path_factory.mktemp("fx"))


@pytest.fixture
def store(tmp_path) -> RunStore:
    s = RunStore(tmp_path / "run", "t1")
    yield s
    s.close()


@pytest.fixture
def make_ctx(tmp_path):
    def _make(repo: Path, **settings) -> RunContext:
        st = RunStore(tmp_path / "run", "t1")
        s = Settings(offline=True, use_llm=False, use_docker=False, cache_dir=tmp_path / "cache", **settings)
        return RunContext(repo=open_local(repo), store=st, settings=s)
    return _make


@pytest.fixture(scope="session")
def fixture_ctx(fixture_repo, tmp_path_factory):
    """Fully built context (facts, SBOM, code index, graph) for the fixture, offline, no Docker, no LLM."""
    from guardian.cartographer.facts import build_repo_facts
    from guardian.codeindex.parser import build_code_index, link_polyglot_imports
    from guardian.graph import UnifiedGraph
    from guardian.sbom.stage import run_sbom_stage
    d = tmp_path_factory.mktemp("ctx")
    ctx = RunContext(repo=open_local(fixture_repo), store=RunStore(d / "run", "fx"),
                     settings=Settings(offline=True, use_llm=False, use_docker=False, cache_dir=d / "cache"))
    ctx.facts = build_repo_facts(ctx)
    run_sbom_stage(ctx)
    ctx.code_index = build_code_index(ctx)
    link_polyglot_imports(ctx)
    ctx.graph = UnifiedGraph.build(ctx.repo.name, ctx.facts, ctx.components, ctx.edges, ctx.code_index)
    return ctx


@pytest.fixture(scope="session")
def polyglot_ctx(tmp_path_factory):
    """Context for the polyglot fixture (Maven, Gradle, Go, Cargo, Bundler, Composer, NuGet), offline."""
    from guardian.cartographer.facts import build_repo_facts
    from guardian.codeindex.parser import build_code_index, link_polyglot_imports
    from guardian.fixture_polyglot import make_polyglot_fixture
    from guardian.graph import UnifiedGraph
    from guardian.sbom.stage import run_sbom_stage
    d = tmp_path_factory.mktemp("poly")
    repo = make_polyglot_fixture(d)
    ctx = RunContext(repo=open_local(repo), store=RunStore(d / "run", "poly"),
                     settings=Settings(offline=True, use_llm=False, use_docker=False, cache_dir=d / "cache"))
    ctx.facts = build_repo_facts(ctx)
    run_sbom_stage(ctx)
    ctx.code_index = build_code_index(ctx)
    link_polyglot_imports(ctx)
    ctx.graph = UnifiedGraph.build(ctx.repo.name, ctx.facts, ctx.components, ctx.edges, ctx.code_index)
    return ctx
