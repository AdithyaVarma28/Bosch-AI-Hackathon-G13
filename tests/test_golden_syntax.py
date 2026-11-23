"""Characterisation tests: modern and unusual syntax must neither crash nor lose facts."""
from guardian.stage2_code.parser import index_repo

MODERN = '''\
import os
import requests


def f(items):
    data = [requests.get(u) for u in items]
    g = lambda x: os.system(x)
    if (n := os.getenv("N")):
        pass
    match n:
        case "a":
            os.getcwd()
        case _:
            pass
    return data, g


async def agen(client):
    async with client.session() as s:
        return [x async for x in s.stream()]


def h(a=os.getenv("DEFAULT_ENV")):
    pass


class K:
    attr = os.getenv("CLASS_ENV")

    @staticmethod
    def sm(*args, **kwargs):
        return requests.post("http://x.invalid", *args, **kwargs)


type Alias = list[int]
x: int = 1
print(f"{os.getenv('IN_FSTRING')} done")
'''


def index(write_tree, src):
    return {f.path: f for f in index_repo(write_tree({"m.py": src})).files}["m.py"]


def test_modern_syntax_parses_without_error(write_tree):
    assert index(write_tree, MODERN).parse_error is None


def test_calls_inside_comprehensions_lambdas_and_match_are_found(write_tree):
    f = index(write_tree, MODERN)
    assert {(s.target, s.category) for s in f.sensitive_calls} == {
        ("requests.get", "network"), ("os.system", "subprocess"), ("requests.post", "network")}
    callers = {c.target: c.caller for c in f.calls}
    assert callers["os.getcwd"] == "m.py::f" and callers["os.system"] == "m.py::f"
    assert callers["requests.post"] == "m.py::K.sm"


def test_env_reads_in_walrus_defaults_class_bodies_and_fstrings(write_tree):
    f = index(write_tree, MODERN)
    assert {e.var for e in f.env_reads} == {"N", "DEFAULT_ENV", "CLASS_ENV", "IN_FSTRING"}


def test_default_argument_call_belongs_to_the_enclosing_scope(write_tree):
    f = index(write_tree, MODERN)
    assert [c.caller for c in f.calls if c.target == "os.getenv" and c.line == 23] == ["m.py::<module>"]


def test_definitions_cover_async_static_and_nested(write_tree):
    f = index(write_tree, MODERN)
    ids = {d.id: d.type for d in f.definitions}
    assert ids["m.py::agen"] == "async_function" and ids["m.py::K.sm"] == "method" and ids["m.py::K"] == "class"
    assert next(d for d in f.definitions if d.name == "sm").params == ["*args", "**kwargs"]


def test_string_url_inside_a_call_argument_is_found(write_tree):
    f = index(write_tree, MODERN)
    assert [(u.url, u.line) for u in f.string_urls] == [("http://x.invalid", 32)]


def test_empty_file_and_comment_only_file(write_tree):
    idx = index_repo(write_tree({"empty.py": "", "c.py": "# just a comment\n"}))
    assert all(f.parse_error is None and f.imports == [] for f in idx.files)


def test_future_import_and_conditional_function_level_import(write_tree):
    src = "from __future__ import annotations\ndef f():\n    if True:\n        import json\n"
    imps = {i.name: i for i in index(write_tree, src).imports}
    assert imps["__future__"].kind == "stdlib" and imps["json"].conditional
