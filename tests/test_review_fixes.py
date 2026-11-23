"""Regression tests for the independent review of Stage 2 (each failed before its fix)."""
import os
import subprocess

import pytest
from typer.testing import CliRunner

from guardian.cli import app
from guardian.models.facts import ResolvedPackage
from guardian.purl import make_purl
from guardian.stage2_code import parser
from guardian.stage2_code.dist_map import build_import_map, map_import
from guardian.stage2_code.parser import detect_source_roots, index_repo


def by_path(idx):
    return {f.path: f for f in idx.files}


def RP(name):
    return ResolvedPackage(purl=make_purl("pypi", name, "1"), name=name, version="1", direct=True, source="pins")


def make_dir_link(link, target):
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        if r.returncode == 0:
            return
    pytest.skip("cannot create a directory link on this machine")


# ---- 1: deep expressions must not kill the run ----------------------------------
def test_deeply_nested_expression_is_recorded_not_fatal(write_tree):
    repo = write_tree({"big.py": "x = " + "+".join(["1"] * 700) + "\n", "ok.py": "x = 1\n"})
    f = by_path(index_repo(repo))
    assert f["big.py"].parse_error and "Recursion" in f["big.py"].parse_error
    assert f["ok.py"].parse_error is None


# ---- 2: never leave the repo, never loop ----------------------------------------
def test_linked_directories_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text('"""SECRET doc"""\nURL = "https://leak.invalid/x"\n')
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ok.py").write_text("x = 1\n")
    make_dir_link(repo / "ext", outside)
    make_dir_link(repo / "loop", repo)
    idx = index_repo(repo)
    assert [f.path for f in idx.files] == ["ok.py"]
    assert "SECRET" not in idx.model_dump_json()


def test_unreadable_file_is_recorded_not_fatal(write_tree, monkeypatch):
    repo = write_tree({"locked.py": "x = 1\n", "ok.py": "x = 1\n"})
    real = type(repo / "ok.py").read_bytes

    def fake(self):
        if self.name == "locked.py":
            raise PermissionError("denied")
        return real(self)

    monkeypatch.setattr(type(repo / "ok.py"), "read_bytes", fake)
    f = by_path(index_repo(repo))
    assert "unreadable" in f["locked.py"].parse_error and f["ok.py"].parse_error is None


# ---- 3: alias scoping -------------------------------------------------------------
def test_function_local_import_does_not_leak_to_other_functions(write_tree):
    src = ("from pickle import load\n"
           "def a():\n    return load(x)\n"
           "def b():\n    from json import load\n    return load(x)\n")
    f = by_path(index_repo(write_tree({"m.py": src})))["m.py"]
    assert [(s.target, s.line) for s in f.sensitive_calls] == [("pickle.load", 3)]
    assert {(c.target, c.line) for c in f.calls} >= {("pickle.load", 3), ("json.load", 6)}


def test_parameter_shadowing_an_import_is_not_a_call_to_it(write_tree):
    src = "import socket\ndef d(socket):\n    socket.send()\n"
    f = by_path(index_repo(write_tree({"m.py": src})))["m.py"]
    assert not f.sensitive_calls and not any(c.target == "socket.send" for c in f.calls)


def test_local_assignment_shadowing_an_import(write_tree):
    src = "import requests\ndef f():\n    requests = make()\n    requests.get('u')\n"
    assert not by_path(index_repo(write_tree({"m.py": src})))["m.py"].sensitive_calls


# ---- 4: resolved packages beat the curated table ----------------------------------
def test_resolved_distribution_wins_over_curated_default():
    m = build_import_map([RP("psycopg2"), RP("pycrypto"), RP("jwt")])
    assert map_import("psycopg2", m) == "psycopg2" and map_import("Crypto", m) == "pycrypto"
    assert map_import("jwt", m) == "jwt"


def test_curated_default_when_nothing_resolved():
    m = build_import_map([])
    assert map_import("Crypto", m) == "pycryptodome" and map_import("jwt", m) == "PyJWT"


# ---- 5: Django include from the legacy module -------------------------------------
def test_django_conf_urls_include_and_url(write_tree):
    files = {"proj/__init__.py": "", "proj/views.py": "def index(r): pass\n", "proj/urls.py": (
        "from django.conf.urls import url, include\nfrom django.urls import path\nfrom . import views\n"
        "urlpatterns = [url(r'^app/', include('app.urls')), path('y/', include('app2.urls')),"
        " path('x/', views.index)]\n")}
    r = {(x.path, x.handler) for x in by_path(index_repo(write_tree(files)))["proj/urls.py"].routes}
    assert r == {("^app/", "include:app.urls"), ("y/", "include:app2.urls"), ("x/", "proj/views.py::index")}


# ---- 6: a skipped name in the repo's own location must not change the result ------
def test_source_roots_ignore_skipped_names_above_the_repo(tmp_path):
    repo = tmp_path / "build" / "repo"
    (repo / "src" / "pkg").mkdir(parents=True)
    (repo / "src" / "pkg" / "__init__.py").write_text("")
    (repo / "src" / "pkg" / "a.py").write_text("")
    assert detect_source_roots(repo) == ["src"]
    assert {f.module_path for f in index_repo(repo).files} == {"pkg", "pkg.a"}


# ---- 7: cache robustness ----------------------------------------------------------
def test_corrupted_cache_entry_is_a_miss_not_a_crash(write_tree, tmp_path_factory):
    repo = write_tree({"app/__init__.py": "", "app/a.py": "import os\n"})
    cache = tmp_path_factory.mktemp("cache")
    first = index_repo(repo, cache)
    for p in cache.glob("*.json"):
        p.write_text(p.read_text()[:20])
    again = index_repo(repo, cache)
    assert [f.path for f in again.files] == [f.path for f in first.files]


def test_cache_key_carries_a_schema_version():
    assert parser.CACHE_VERSION


# ---- 8: .route is Flask only when Flask is plausible ------------------------------
def test_route_on_non_flask_object_is_not_a_route(write_tree):
    src = "from celery import Celery\nsched = Celery()\n@sched.route('tasks.add')\ndef add():\n    pass\n"
    assert by_path(index_repo(write_tree({"m.py": src})))["m.py"].routes == []


def test_blueprint_imported_from_repo_module_still_counts(write_tree):
    files = {"app/__init__.py": "", "app/bp.py": "x = 1\n",
             "app/views.py": "from app.bp import bp\n@bp.route('/p')\ndef p():\n    pass\n"}
    r = by_path(index_repo(write_tree(files)))["app/views.py"].routes
    assert [(x.framework, x.path) for x in r] == [("flask", "/p")]


# ---- 9: calls and imports agree on script-style siblings --------------------------
def test_sibling_script_module_calls_are_internal(write_tree):
    repo = write_tree({"bad/libuser.py": "def login(): pass\n", "bad/vulpy.py": "import libuser\nlibuser.login()\n"})
    c = [x for x in by_path(index_repo(repo))["bad/vulpy.py"].calls if x.target == "libuser.login"]
    assert c and c[0].kind == "internal" and c[0].import_name is None


# ---- 10: cheap minors ---------------------------------------------------------------
def test_relative_import_above_the_top_package_is_unresolved(write_tree):
    repo = write_tree({"utils.py": "", "pkg/__init__.py": "", "pkg/mod.py": "from ..utils import helper\n"})
    i = by_path(index_repo(repo))["pkg/mod.py"].imports[0]
    assert i.resolved_file is None


def test_yaml_load_with_safe_loader_is_not_flagged(write_tree):
    src = "import yaml\nyaml.load(a, Loader=yaml.SafeLoader)\nyaml.load(b, yaml.SafeLoader)\nyaml.load(c)\nyaml.load(d, Loader=yaml.Loader)\n"
    assert [s.line for s in by_path(index_repo(write_tree({"m.py": src})))["m.py"].sensitive_calls] == [4, 5]


def test_environ_assignment_is_not_a_read(write_tree):
    src = "import os\nos.environ['X'] = 'y'\nprint(os.environ['Z'])\n"
    assert [e.var for e in by_path(index_repo(write_tree({"m.py": src})))["m.py"].env_reads] == ["Z"]


def test_index_command_reports_missing_target_cleanly(tmp_path):
    r = CliRunner().invoke(app, ["index", str(tmp_path / "nope"), "--out", str(tmp_path / "out")])
    assert r.exit_code != 0 and "not a directory" in r.output.lower() and "Traceback" not in r.output
