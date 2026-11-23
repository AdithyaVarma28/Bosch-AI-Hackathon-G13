from guardian.stage2_code.parser import index_repo


def one(write_tree, files, path):
    idx = index_repo(write_tree(files))
    return {f.path: f for f in idx.files}[path]


def calls(write_tree, src):
    return one(write_tree, {"m.py": src}, "m.py").calls


def sensitive(write_tree, src):
    return one(write_tree, {"m.py": src}, "m.py").sensitive_calls


# ---- calls and alias resolution -------------------------------------------------
def test_alias_import_as(write_tree):
    assert "yaml.load" in {c.target for c in calls(write_tree, "import yaml as y\ny.load(x)\n")}


def test_alias_from_import_as(write_tree):
    assert "yaml.load" in {c.target for c in calls(write_tree, "from yaml import load as l\nl(x)\n")}


def test_dotted_module_alias(write_tree):
    assert "os.path.join" in {c.target for c in calls(write_tree, "import os.path as p\np.join('a','b')\n")}


def test_plain_dotted_import_resolves_attribute_chain(write_tree):
    assert "stripe.Charge.create" in {c.target for c in calls(write_tree, "import stripe\nstripe.Charge.create()\n")}


def test_caller_is_enclosing_function_or_module(write_tree):
    src = "import stripe, requests\nrequests.get('u')\ndef get_client():\n    return stripe.Charge.create()\n"
    c = {x.target: x.caller for x in calls(write_tree, src)}
    assert c["stripe.Charge.create"] == "m.py::get_client" and c["requests.get"] == "m.py::<module>"


def test_nested_function_and_method_callers(write_tree):
    src = "import os\nclass C:\n    def m(self):\n        os.getcwd()\n"
    assert {x.caller for x in calls(write_tree, src) if x.target == "os.getcwd"} == {"m.py::C.m"}


def test_call_kinds_and_import_name(write_tree):
    src = "import stripe, os\nstripe.x()\nos.getcwd()\n"
    k = {c.target: (c.kind, c.import_name) for c in calls(write_tree, src)}
    assert k["stripe.x"] == ("external", "stripe") and k["os.getcwd"] == ("stdlib", "os")


def test_internal_calls_resolved_to_module(write_tree):
    files = {"app/__init__.py": "", "app/payments/__init__.py": "", "app/payments/service.py": "def charge(): pass\n",
             "app/api/__init__.py": "", "app/api/routes.py": "from app.payments.service import charge\ncharge()\n"}
    c = one(write_tree, files, "app/api/routes.py").calls
    assert any(x.kind == "internal" and x.target == "app.payments.service.charge" for x in c)


def test_unknown_object_method_calls_not_invented(write_tree):
    src = "class C:\n    def m(self):\n        self.client.send()\n        helper().go()\n"
    assert not any(c.target.startswith("self.") for c in calls(write_tree, src))


def test_call_lines(write_tree):
    assert {(c.target, c.line) for c in calls(write_tree, "import os\n\nos.getcwd()\n")} == {("os.getcwd", 3)}


# ---- sensitive calls ------------------------------------------------------------
def test_deserialize_flags_load_not_safe_load(write_tree):
    s = {(x.target, x.category) for x in sensitive(write_tree, "import yaml\nyaml.load(a)\nyaml.safe_load(b)\n")}
    assert ("yaml.load", "deserialize") in s and not any(t == "yaml.safe_load" for t, _ in s)


def test_all_categories(write_tree):
    src = ("import requests, subprocess, pickle, hashlib\n"
           "requests.post('u')\nsubprocess.run(['ls'])\neval('1')\npickle.loads(b'')\n"
           "open('f', 'w')\nhashlib.md5(b'')\n")
    assert {x.category for x in sensitive(write_tree, src)} == {
        "network", "subprocess", "code_exec", "deserialize", "file_write", "crypto"}


def test_open_write_flagged_read_not(write_tree):
    src = "open('a')\nopen('b', 'r')\nopen('c', 'w')\nopen('d', mode='a')\n"
    assert [x.line for x in sensitive(write_tree, src) if x.category == "file_write"] == [3, 4]


def test_aliased_sensitive_call_detected(write_tree):
    assert {x.category for x in sensitive(write_tree, "from subprocess import run as r\nr(['ls'])\n")} == {"subprocess"}


def test_os_system_and_exec_builtins(write_tree):
    s = {(x.target, x.category) for x in sensitive(write_tree, "import os\nos.system('ls')\nexec('x=1')\n")}
    assert s == {("os.system", "subprocess"), ("exec", "code_exec")}


# ---- env reads ------------------------------------------------------------------
def test_env_reads_forms_and_dynamic(write_tree):
    src = ("import os\nname = 'x'\n"
           "os.environ['STRIPE_KEY']\nos.environ.get('A', 'd')\nos.getenv('B')\nos.environ[name]\n")
    e = {x.var: x.how for x in one(write_tree, {"m.py": src}, "m.py").env_reads}
    assert e == {"STRIPE_KEY": "os.environ[]", "A": "os.environ.get", "B": "os.getenv", "<dynamic>": "os.environ[]"}


def test_env_reads_through_aliases(write_tree):
    src = "from os import environ, getenv\nenviron['X']\ngetenv('Y')\n"
    assert {x.var for x in one(write_tree, {"m.py": src}, "m.py").env_reads} == {"X", "Y"}


# ---- routes ---------------------------------------------------------------------
def test_flask_routes(write_tree):
    src = ("from flask import Flask\napp = Flask(__name__)\n"
           "@app.route('/checkout', methods=['POST'])\ndef checkout():\n    pass\n"
           "@app.route('/home')\ndef home():\n    pass\n"
           "@app.get('/ping')\ndef ping():\n    pass\n")
    r = {(x.framework, x.method, x.path, x.handler) for x in one(write_tree, {"app/r.py": src}, "app/r.py").routes}
    assert r == {("flask", "POST", "/checkout", "app/r.py::checkout"), ("flask", "GET", "/home", "app/r.py::home"),
                 ("flask", "GET", "/ping", "app/r.py::ping")}


def test_fastapi_routes(write_tree):
    src = "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/z')\nasync def z():\n    pass\n"
    r = {(x.framework, x.method, x.path) for x in one(write_tree, {"m.py": src}, "m.py").routes}
    assert r == {("fastapi", "POST", "/z")}


DJANGO_FILES = {
    "introduction/__init__.py": "", "introduction/views.py": "def login(r): pass\nclass Lab: pass\n",
    "introduction/urls.py": (
        "from django.urls import path, re_path, include\nfrom . import views\nfrom .views import login\n"
        "urlpatterns = [\n"
        "    path('introduction/', views.login, name='intro'),\n"
        "    path('login/', login),\n"
        "    re_path(r'^b/$', views.Lab.as_view()),\n"
        "    path('api/', include('app.urls')),\n"
        "]\n"),
}


def test_django_urls_path_re_path_include(write_tree):
    r = {(x.path, x.handler) for x in one(write_tree, DJANGO_FILES, "introduction/urls.py").routes}
    assert ("introduction/", "introduction/views.py::login") in r
    assert ("login/", "introduction/views.py::login") in r
    assert ("^b/$", "introduction/views.py::Lab") in r
    assert ("api/", "include:app.urls") in r
    assert all(x.framework == "django" for x in one(write_tree, DJANGO_FILES, "introduction/urls.py").routes)


# ---- entry points ---------------------------------------------------------------
def test_cli_entrypoints(write_tree):
    src = ("import click, argparse\nimport typer\n"
           "@click.command()\ndef a():\n    pass\n"
           "app = typer.Typer()\n@app.command()\ndef b():\n    pass\n"
           "p = argparse.ArgumentParser()\n"
           "if __name__ == '__main__':\n    a()\n")
    kinds = {e.kind for e in one(write_tree, {"m.py": src}, "m.py").cli_entrypoints}
    assert kinds == {"click", "typer", "argparse", "main_guard"}
