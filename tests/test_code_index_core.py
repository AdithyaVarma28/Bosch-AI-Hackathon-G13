from guardian.stage2_code import parser
from guardian.stage2_code.parser import detect_source_roots, index_repo


def by_path(idx):
    return {f.path: f for f in idx.files}


def test_source_roots_src_layout(write_tree):
    repo = write_tree({"src/pkg/__init__.py": "", "src/pkg/a.py": ""})
    assert detect_source_roots(repo) == ["src"]


def test_source_roots_top_level_packages(write_tree):
    repo = write_tree({"app/__init__.py": "", "app/x.py": "", "manage.py": "", "docs/conf.py": ""})
    assert detect_source_roots(repo) == ["app"]


def test_walk_skips_vendored_and_build_dirs(write_tree):
    repo = write_tree({
        "app/ok.py": "x = 1\n",
        ".venv/lib/a.py": "x = 1\n", "venv/b.py": "x = 1\n", "build/c.py": "x = 1\n",
        "dist/d.py": "x = 1\n", "node_modules/e.py": "x = 1\n", "app/__pycache__/f.py": "x = 1\n",
        "x/site-packages/g.py": "x = 1\n", ".git/h.py": "x = 1\n",
    })
    assert [f.path for f in index_repo(repo).files] == ["app/ok.py"]


def test_identity_fields(write_tree):
    repo = write_tree({"app/__init__.py": "", "app/payments/__init__.py": "",
                       "app/payments/client.py": '"""Stripe client factory."""\nimport os\n'})
    f = by_path(index_repo(repo))["app/payments/client.py"]
    assert f.module_path == "app.payments.client" and f.package_dir == "app/payments"
    assert len(f.sha256) == 64 and f.loc == 2 and not f.is_test
    assert f.docstring == "Stripe client factory."


def test_module_paths_for_init_and_src_layout(write_tree):
    repo = write_tree({"src/pkg/__init__.py": "", "src/pkg/a.py": "", "src/pkg/sub/__init__.py": ""})
    m = {f.path: f.module_path for f in index_repo(repo).files}
    assert m == {"src/pkg/__init__.py": "pkg", "src/pkg/a.py": "pkg.a", "src/pkg/sub/__init__.py": "pkg.sub"}


def test_is_test_rules(write_tree):
    repo = write_tree({"tests/test_api.py": "", "pkg/foo_test.py": "", "conftest.py": "",
                       "pkg/foo.py": "", "tests/helpers.py": ""})
    f = by_path(index_repo(repo))
    assert f["tests/test_api.py"].is_test and f["pkg/foo_test.py"].is_test and f["conftest.py"].is_test
    assert f["tests/helpers.py"].is_test and not f["pkg/foo.py"].is_test


def test_import_kinds(write_tree):
    repo = write_tree({
        "app/__init__.py": "", "app/payments/__init__.py": "", "app/payments/config.py": "",
        "app/payments/client.py": "import stripe\nimport os\nimport app.payments.config\n",
    })
    imps = {i.name: i for i in by_path(index_repo(repo))["app/payments/client.py"].imports}
    assert imps["stripe"].kind == "external" and imps["stripe"].resolved_file is None
    assert imps["os"].kind == "stdlib"
    assert imps["app.payments.config"].kind == "internal"
    assert imps["app.payments.config"].resolved_file == "app/payments/config.py"


def test_from_import_alias_and_line(write_tree):
    repo = write_tree({"m.py": "import numpy as np\nfrom yaml import safe_load as sl\n"})
    imps = {i.name: i for i in by_path(index_repo(repo))["m.py"].imports}
    assert imps["numpy"].alias == "np" and imps["numpy"].line == 1
    assert imps["yaml"].line == 2


def test_relative_imports_resolved(write_tree):
    repo = write_tree({
        "app/__init__.py": "", "app/db/__init__.py": "", "app/api/__init__.py": "",
        "app/api/helpers.py": "", "app/api/routes.py":
        "from ..db import session\nfrom . import helpers\nfrom .helpers import h\n",
    })
    imps = by_path(index_repo(repo))["app/api/routes.py"].imports
    d = {i.name: i for i in imps}
    assert d["app.db"].kind == "internal" and d["app.db"].resolved_file == "app/db/__init__.py"
    assert d["app.api.helpers"].kind == "internal" and d["app.api.helpers"].resolved_file == "app/api/helpers.py"


def test_star_import_and_try_conditional_flags(write_tree):
    repo = write_tree({"m.py": (
        "import sys\n"
        "try:\n    from json_fast import *\nexcept ImportError:\n    import json\n"
        "if sys.version_info >= (3, 11):\n    import tomllib\n"
    )})
    d = {i.name: i for i in by_path(index_repo(repo))["m.py"].imports}
    assert d["json_fast.*"].in_try_except and not d["json_fast.*"].conditional
    assert d["json"].in_try_except
    assert d["tomllib"].conditional and not d["tomllib"].in_try_except
    assert not d["sys"].conditional and not d["sys"].in_try_except


DEFS_SRC = '''\
class C:
    """A class."""
    def method(self):
        pass

    async def amethod(self):
        pass


@app.post("/x")
def top(a, b, *args, c=1, **kw):
    def inner():
        pass
    return inner


async def async_view():
    pass
'''


def test_definition_ids_types_and_nesting(write_tree):
    repo = write_tree({"m.py": DEFS_SRC})
    d = {x.id: x.type for x in by_path(index_repo(repo))["m.py"].definitions}
    assert d == {
        "m.py::C": "class", "m.py::C.method": "method", "m.py::C.amethod": "async_method",
        "m.py::top": "function", "m.py::top.<locals>.inner": "function", "m.py::async_view": "async_function",
    }


def test_decorators_params_lines_docstring(write_tree):
    repo = write_tree({"m.py": DEFS_SRC})
    d = {x.name: x for x in by_path(index_repo(repo))["m.py"].definitions}
    assert d["top"].decorators == ["app.post('/x')"]
    assert d["top"].params == ["a", "b", "*args", "c", "**kw"]
    assert d["top"].line == 11 and d["top"].end_line == 14
    assert d["C"].docstring == "A class."


def test_syntax_error_recorded_and_others_continue(write_tree):
    repo = write_tree({"old.py": "print 'python two'\n", "new.py": "x = 1\n"})
    f = by_path(index_repo(repo))
    assert f["old.py"].parse_error and "SyntaxError" in f["old.py"].parse_error
    assert f["new.py"].parse_error is None and f["old.py"].sha256


def test_null_bytes_file_does_not_crash(write_tree):
    repo = write_tree({"ok.py": "x = 1\n"})
    (repo / "bad.py").write_bytes(b"x = 1\x00\n")
    f = by_path(index_repo(repo))
    assert f["bad.py"].parse_error and f["ok.py"].parse_error is None


def test_unchanged_files_not_reparsed(write_tree, tmp_path_factory):
    repo = write_tree({"app/__init__.py": "", "app/a.py": "import os\n"})
    cache = tmp_path_factory.mktemp("cache")
    index_repo(repo, cache)
    n = parser.PARSE_COUNT
    again = index_repo(repo, cache)
    assert parser.PARSE_COUNT == n and len(again.files) == 2


def test_cache_invalidated_when_module_set_changes(write_tree, tmp_path_factory):
    repo = write_tree({"app/__init__.py": "", "app/a.py": "import os\n"})
    cache = tmp_path_factory.mktemp("cache")
    index_repo(repo, cache)
    n = parser.PARSE_COUNT
    (repo / "app" / "b.py").write_text("x = 1\n")
    index_repo(repo, cache)
    assert parser.PARSE_COUNT > n


def test_huge_file_skipped_with_error(write_tree):
    repo = write_tree({"ok.py": "x = 1\n", "gen.py": "x = 1\n" * 200_000})
    idx = index_repo(repo)
    assert any("too large" in e for e in idx.errors)
    assert by_path(idx)["gen.py"].parse_error and by_path(idx)["gen.py"].imports == []


def test_invalid_escape_sequences_do_not_emit_warnings(write_tree):
    import warnings
    repo = write_tree({"m.py": 'import re\npat = "\.txt"\n'})
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        idx = index_repo(repo)
    assert idx.files[0].parse_error is None


def test_script_directory_imports_resolve_to_siblings(write_tree):
    # vulpy-style: files are run from their own directory, so `import libuser` means ./libuser.py
    repo = write_tree({
        "bad/libuser.py": "", "bad/mod_user/__init__.py": "", "bad/vulpy.py":
        "import libuser\nfrom mod_user import login\nimport flask\n",
    })
    d = {i.name: i for i in by_path(index_repo(repo))["bad/vulpy.py"].imports}
    assert d["libuser"].kind == "internal" and d["libuser"].resolved_file == "bad/libuser.py"
    assert d["mod_user"].kind == "internal" and d["mod_user"].resolved_file == "bad/mod_user/__init__.py"
    assert d["flask"].kind == "external"
