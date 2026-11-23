"""Stage 1 (teammate) + Stage 2 (code index) wired together through `guardian scan`."""
import json

from typer.testing import CliRunner

from guardian.adapters import declared_vs_used
from guardian.cli import app
from guardian.models.code_index import CodeIndex, DynamicImport, FileIndex, ImportRef
from guardian.models.facts import DeclaredDependency, Facts, RepoInfo, ResolvedPackage
from guardian.purl import make_purl
from guardian.stage1_facts import resolver


def facts(declared, resolved=(), dev=()):
    deps = [DeclaredDependency(name=n, spec="==1", dev=False, source_file="requirements.txt", line=i + 1)
            for i, n in enumerate(declared)]
    deps += [DeclaredDependency(name=n, spec="==1", dev=True, source_file="requirements-dev.txt", line=1) for n in dev]
    res = [ResolvedPackage(purl=make_purl("pypi", n, "1"), name=n, version="1", direct=True) for n in resolved]
    return Facts(repo=RepoInfo(name="x", commit="abc", scanned_at="now"), declared_dependencies=deps,
                 resolved_packages=res)


def index(imports, dynamic=False):
    return CodeIndex(files=[FileIndex(
        path="a.py", module_path="a", package_dir="", sha256="0" * 64, loc=1, is_test=False,
        imports=[ImportRef(name=n, kind="external", line=i + 1, distribution=d) for i, (n, d) in enumerate(imports)],
        dynamic_imports=[DynamicImport(expr="<dynamic>", line=9)] if dynamic else [])])


def test_declared_but_never_imported_is_reported():
    r = declared_vs_used(facts(["Flask", "colorama"]), index([("flask", "Flask")]))
    assert r.declared_not_imported == ["colorama"]


def test_dev_dependencies_are_never_reported_unused():
    r = declared_vs_used(facts(["Flask"], dev=["pytest"]), index([("flask", "Flask")]))
    assert r.declared_not_imported == []


def test_imported_but_not_declared_or_resolved():
    r = declared_vs_used(facts(["Flask"]), index([("flask", "Flask"), ("yaml", "PyYAML")]))
    assert r.imported_not_declared == ["pyyaml"]


def test_imported_package_supplied_transitively_is_not_undeclared():
    r = declared_vs_used(facts(["Flask"], resolved=["Flask", "Werkzeug"]), index([("werkzeug", "Werkzeug")]))
    assert r.imported_not_declared == []


def test_unmapped_imports_are_never_guessed_as_undeclared():
    r = declared_vs_used(facts(["Flask"]), index([("mystery", None)]))
    assert r.imported_not_declared == []


def test_dynamic_imports_are_flagged_as_a_limit():
    assert declared_vs_used(facts(["a"]), index([], dynamic=True)).dynamic_imports_present is True


def test_scan_runs_both_stages_and_links_them(write_tree, tmp_path, monkeypatch):
    monkeypatch.setattr(resolver, "resolve_via_pip_report", lambda *a, **k: ([], ["pip blocked in test"]))
    repo = write_tree({"requirements.txt": "PyYAML==6.0.1\ncolorama==0.4.6\n", "app/__init__.py": "",
                       "app/cfg.py": "import yaml\nyaml.load(open('x'))\n"})
    out = tmp_path / "out"
    r = CliRunner().invoke(app, ["scan", str(repo), "--output", str(out), "--offline", "--skip-sbom"])
    assert r.exit_code == 0, r.output
    d = out / repo.name
    f = json.loads((d / "facts.json").read_text(encoding="utf-8"))
    c = json.loads((d / "code_index.json").read_text(encoding="utf-8"))
    s = json.loads((d / "summary.json").read_text(encoding="utf-8"))
    assert {x["name"] for x in f["declared_dependencies"]} == {"PyYAML", "colorama"}
    assert c["import_name_to_distribution"] == {"yaml": "PyYAML"}      # Stage 2 used Stage 1's resolved names
    assert s["declared_not_imported"] == ["colorama"]                  # the two stages agree on what is unused
    assert any(sc["target"] == "yaml.load" for fi in c["files"] for sc in fi["sensitive_calls"])


def test_scan_missing_target_fails_cleanly(tmp_path):
    r = CliRunner().invoke(app, ["scan", str(tmp_path / "nope"), "--output", str(tmp_path / "o")])
    assert r.exit_code != 0 and "not a directory" in r.output.lower()


def test_module_entrypoint_actually_runs():
    import os
    import subprocess
    import sys
    env = {**os.environ, "PYTHONPATH": str(__import__("pathlib").Path(__file__).parents[1] / "src")}
    r = subprocess.run([sys.executable, "-m", "guardian.cli", "--help"], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and "scan" in r.stdout and "index" in r.stdout


def test_declared_package_required_by_another_resolved_package_is_not_unused():
    f = facts(["Flask", "Werkzeug"])
    f.resolved_packages = [
        ResolvedPackage(purl=make_purl("pypi", "Flask", "1"), name="Flask", version="1", direct=True,
                        requires=["Werkzeug>=3.0", "Jinja2"]),
        ResolvedPackage(purl=make_purl("pypi", "Werkzeug", "1"), name="Werkzeug", version="1", direct=False)]
    r = declared_vs_used(f, index([("flask", "Flask")]))
    assert r.declared_not_imported == []


def test_declared_package_nobody_requires_is_still_reported():
    f = facts(["Flask", "colorama"])
    f.resolved_packages = [ResolvedPackage(purl=make_purl("pypi", "Flask", "1"), name="Flask", version="1",
                                           direct=True, requires=["Werkzeug"])]
    assert declared_vs_used(f, index([("flask", "Flask")])).declared_not_imported == ["colorama"]
