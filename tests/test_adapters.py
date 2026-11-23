import json

from typer.testing import CliRunner

from guardian.adapters import components_from_facts, declarations_from_facts, usage_from_index
from guardian.cli import app
from guardian.models.code_index import CodeIndex, DynamicImport, FileIndex, ImportRef
from guardian.models.common import DepEdge
from guardian.models.facts import DeclaredDependency, Facts, PackageMetadata, RepoInfo, ResolvedPackage
from guardian.purl import make_purl


def RP(name, version, direct, requires=(), required_by=()):
    return ResolvedPackage(purl=make_purl("pypi", name, version), name=name, version=version, direct=direct,
                           requires=list(requires), required_by=list(required_by), source="pip-report")


def DD(name, spec, dev, line):
    return DeclaredDependency(name=name, spec=spec, kind="registry", dev=dev,
                              source_file="requirements.txt", line=line)


def repo_info(name="mini-shop"):
    return RepoInfo(name=name, commit="abc1234", scanned_at="2026-11-23T10:00:00Z")


FACTS = Facts(
    repo=repo_info(),
    declared_dependencies=[DD("Flask", "==3.0.0", False, 1), DD("pytest", ">=8", True, 2)],
    resolved_packages=[
        RP("Flask", "3.0.0", True, requires=["Werkzeug"]), RP("Werkzeug", "3.0.1", False, requires=["MarkupSafe"]),
        RP("MarkupSafe", "2.1.5", False), RP("pytest", "8.0.0", True, requires=["pluggy"]),
        RP("pluggy", "1.4.0", False), RP("Shared", "1", False),
    ],
    package_metadata={make_purl("pypi", "Werkzeug", "3.0.1"): PackageMetadata(sdist_only=True)},
)


def comps():
    c, e = components_from_facts(FACTS)
    return {x.name: x for x in c}, e


def test_dev_flag_becomes_dev_scope_and_prod_stays_prod():
    c, _ = comps()
    assert c["pytest"].scope == "dev" and c["Flask"].scope == "prod"


def test_transitive_scope_follows_its_roots():
    c, _ = comps()
    assert c["Werkzeug"].scope == "prod" and c["MarkupSafe"].scope == "prod" and c["pluggy"].scope == "dev"
    assert c["Shared"].scope == "unknown"


def test_direct_flag_and_purl_carried_over():
    c, _ = comps()
    assert c["Flask"].direct and not c["Werkzeug"].direct and c["Flask"].purl == "pkg:pypi/flask@3.0.0"


def test_edges_point_from_dependent_to_dependency():
    _, edges = comps()
    assert DepEdge(src="pkg:pypi/flask@3.0.0", dst="pkg:pypi/werkzeug@3.0.1") in edges
    assert not any(e.src == "pkg:pypi/werkzeug@3.0.1" and e.dst == "pkg:pypi/flask@3.0.0" for e in edges)


def test_edge_to_unresolved_package_is_not_invented():
    f = FACTS.model_copy(update={"resolved_packages": [RP("Flask", "3.0.0", True, requires=["Ghost"])]})
    _, edges = components_from_facts(f)
    assert edges == []


def test_sdist_only_flows_into_origin():
    c, _ = comps()
    assert c["Werkzeug"].origin.sdist_only is True and c["Flask"].origin.sdist_only is False


def test_declarations_carry_range_scope_and_line():
    d = {x.package: x for x in declarations_from_facts(FACTS)}
    assert d["flask"].requested_range == "==3.0.0" and d["flask"].scope == "prod" and d["flask"].line == 1
    assert d["pytest"].scope == "dev" and d["pytest"].source_file == "requirements.txt"


INDEX = CodeIndex(files=[FileIndex(
    path="app/a.py", module_path="app.a", package_dir="app", sha256="0" * 64, loc=5, is_test=False,
    imports=[
        ImportRef(name="yaml", kind="external", line=1, distribution="PyYAML"),
        ImportRef(name="notmapped", kind="external", line=2),
        ImportRef(name="os", kind="stdlib", line=3),
        ImportRef(name="app.b", kind="internal", line=4, resolved_file="app/b.py"),
    ],
    dynamic_imports=[DynamicImport(expr="<dynamic>", line=9)])])


def test_usage_maps_external_imports_to_normalised_packages():
    u = {(x.line, x.specifier): x for x in usage_from_index(INDEX)}
    assert u[(1, "yaml")].package == "pyyaml" and u[(1, "yaml")].mapping_status == "mapped"
    assert u[(2, "notmapped")].package is None and u[(2, "notmapped")].mapping_status == "unmapped"


def test_usage_keeps_stdlib_and_skips_internal_imports():
    u = usage_from_index(INDEX)
    assert any(x.mapping_status == "stdlib" for x in u) and not any(x.specifier == "app.b" for x in u)


def test_usage_records_dynamic_imports_as_unresolved():
    u = [x for x in usage_from_index(INDEX) if x.mapping_status == "dynamic_unresolved"]
    assert len(u) == 1 and u[0].line == 9 and u[0].source_file == "app/a.py"


def test_index_command_uses_resolved_packages_from_facts(write_tree, tmp_path):
    repo = write_tree({"m.py": "import django\nimport requests\n"})
    facts = Facts(repo=repo_info("x"), resolved_packages=[RP("Django", "4.2", True), RP("requests", "2.28.2", True)])
    fpath = tmp_path / "facts.json"
    fpath.write_text(facts.model_dump_json(), encoding="utf-8")
    out = tmp_path / "out"
    r = CliRunner().invoke(app, ["index", str(repo), "--out", str(out), "--facts", str(fpath)])
    assert r.exit_code == 0, r.output
    data = json.loads(next(out.rglob("code_index.json")).read_text(encoding="utf-8"))
    assert data["import_name_to_distribution"] == {"django": "Django", "requests": "requests"}
