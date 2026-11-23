import json

from typer.testing import CliRunner

from guardian.cli import app
from guardian.models.facts import ResolvedPackage
from guardian.purl import make_purl
from guardian.stage2_code.dist_map import build_import_map, map_import
from guardian.stage2_code.parser import index_repo


def RP(name: str) -> ResolvedPackage:
    return ResolvedPackage(purl=make_purl("pypi", name, "1"), name=name, version="1", direct=True, source="pins")


def test_curated_table_mismatches():
    m = build_import_map([])
    assert m["yaml"] == "PyYAML" and m["PIL"] == "Pillow" and m["cv2"] == "opencv-python"
    assert m["sklearn"] == "scikit-learn" and m["bs4"] == "beautifulsoup4" and m["jwt"] == "PyJWT"


def test_normalised_name_guess_only_for_resolved_packages():
    m = build_import_map([RP("my-lib")])
    assert map_import("my_lib", m) == "my-lib" and map_import("other_lib", m) is None


def test_resolved_spelling_matches_case_insensitively():
    assert map_import("flask", build_import_map([RP("Flask")])) == "Flask"


def test_unknown_import_not_guessed():
    assert map_import("totally_unknown_mod", build_import_map([])) is None


def test_installed_dists_callable_is_preferred():
    m = build_import_map([RP("pyyaml")], lambda: {"yaml": ["PyYAML"], "_yaml": ["PyYAML"]})
    assert m["yaml"] == "PyYAML" and m["_yaml"] == "PyYAML"


def test_distribution_filled_on_imports_and_index(write_tree):
    repo = write_tree({"m.py": "import yaml\nimport notamodule\nimport os\n"})
    idx = index_repo(repo)
    imps = {i.name: i for i in idx.files[0].imports}
    assert idx.import_name_to_distribution == {"yaml": "PyYAML"}
    assert imps["yaml"].distribution == "PyYAML" and imps["notamodule"].distribution is None
    assert imps["os"].distribution is None


def test_resolved_packages_feed_the_map(write_tree):
    repo = write_tree({"m.py": "import mylib\n"})
    idx = index_repo(repo, resolved=[RP("MyLib")])
    assert idx.import_name_to_distribution == {"mylib": "MyLib"}


def test_string_urls_found_with_lines(write_tree):
    src = 'import requests\n\nBASE = "not a url"\nURL = "https://example.invalid/collect"\nf = f"http://x.invalid/{1}"\n'
    urls = {(u.url, u.line) for u in index_repo(write_tree({"m.py": src})).files[0].string_urls}
    assert ("https://example.invalid/collect", 4) in urls and all(u.startswith("http") for u, _ in urls)
    assert ("not a url", 3) not in urls


def test_dynamic_imports_recorded_as_known_unknowns(write_tree):
    src = "import importlib\nimportlib.import_module(name)\nimportlib.import_module('plugin_x')\n__import__('os')\n"
    d = {x.expr for x in index_repo(write_tree({"m.py": src})).files[0].dynamic_imports}
    assert d == {"<dynamic>", "plugin_x", "os"}


def test_index_command_writes_code_index_json(write_tree, tmp_path):
    repo = write_tree({"app/__init__.py": "", "app/a.py": "import yaml\n"})
    out = tmp_path / "out"
    r = CliRunner().invoke(app, ["index", str(repo), "--out", str(out)])
    assert r.exit_code == 0, r.output
    written = list(out.rglob("code_index.json"))
    assert len(written) == 1
    data = json.loads(written[0].read_text(encoding="utf-8"))
    assert data["source_roots"] == ["app"] and data["import_name_to_distribution"] == {"yaml": "PyYAML"}
