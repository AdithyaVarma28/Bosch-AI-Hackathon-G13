"""S1 facts and S2 lockfile parsing."""
import json

from guardian.cartographer.ci import parse_workflow
from guardian.cartographer.docker import parse_compose, parse_dockerfile
from guardian.cartographer.manifests import parse_package_json, parse_pyproject, parse_requirements
from guardian.sbom.lockfiles import parse_lockfile, parse_package_lock


# ------------------------------------------------------------------ manifests
def test_requirements_kinds_includes_and_indexes():
    text = ("--index-url https://pypi.org/simple\n--extra-index-url https://internal.example/simple\n-r base.txt\n"
            "flask==2.0.1  # web\nrequests[socks]>=2.0 ; python_version>'3.8'\n"
            "git+https://github.com/x/y.git@v1#egg=ylib\n./local_pkg\nhttps://example.com/pkg-1.0.whl\n")
    p = parse_requirements("requirements.txt", text)
    kinds = {d.name: d.kind for d in p.deps}
    assert kinds == {"flask": "registry", "requests": "registry", "ylib": "vcs", "./local_pkg": "path", "pkg-1.0.whl": "url"}
    req = next(d for d in p.deps if d.name == "requests")
    assert req.extras == ["socks"] and req.markers and req.line == 5
    assert [(i.type, i.line) for i in p.indexes] == [("index-url", 1), ("extra-index-url", 2)]
    assert p.includes == [("-r", "base.txt")]


def test_dev_requirements_scope():
    assert all(d.scope == "dev" for d in parse_requirements("requirements-dev.txt", "pytest==7\n").deps)


def test_pyproject_groups_and_sources():
    text = """
[project]
name = "x"
dependencies = ["httpx>=0.27"]
[project.optional-dependencies]
test = ["pytest"]
[project.scripts]
x = "x.cli:main"
[tool.poetry.dependencies]
python = "^3.11"
rich = {git = "https://github.com/x/rich", rev = "abc"}
[[tool.poetry.source]]
name = "private"
url = "https://private.example/simple"
"""
    p = parse_pyproject("pyproject.toml", text)
    d = {x.name: x for x in p.deps}
    assert d["httpx"].scope == "prod" and d["pytest"].scope == "dev" and d["rich"].kind == "vcs"
    assert p.indexes[0].url == "https://private.example/simple"
    assert p.manifest.entry_points == {"x": "x.cli:main"}


def test_package_json_scopes_kinds_scripts():
    text = json.dumps({"dependencies": {"express": "^4", "fromgit": "github:o/r", "local": "file:../x"},
                       "devDependencies": {"jest": "29"}, "scripts": {"postinstall": "node x.js", "test": "jest"}}, indent=2)
    p = parse_package_json("package.json", text)
    d = {x.name: x for x in p.deps}
    assert d["express"].scope == "prod" and d["jest"].scope == "dev"
    assert d["fromgit"].kind == "vcs" and d["local"].kind == "path"
    assert [s.name for s in p.scripts] == ["postinstall"]


def test_malformed_manifest_does_not_raise():
    from guardian.cartographer.manifests import parse_manifest
    assert parse_manifest("package.json", "{not json").errors


# ------------------------------------------------------------------ lockfiles
V2 = {"lockfileVersion": 3, "packages": {
    "": {"dependencies": {"a": "1"}, "devDependencies": {"grunt": "1"}},
    "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha512-a",
                       "dependencies": {"b": "^2"}},
    "node_modules/a/node_modules/b": {"version": "2.0.0", "integrity": "sha512-b2"},
    "node_modules/b": {"version": "1.0.0", "integrity": "sha512-b1"},
    "node_modules/grunt": {"version": "1.0.0", "dev": True, "hasInstallScript": True},
    "node_modules/fromgit": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/o/r.git#abc"}}}
V1 = {"lockfileVersion": 1, "dependencies": {
    "a": {"version": "1.0.0", "requires": {"b": "^2"}, "dependencies": {"b": {"version": "2.0.0"}}},
    "b": {"version": "1.0.0"}, "grunt": {"version": "1.0.0", "dev": True}, "fromgit": {"version": "1.0.0"}}}


def test_v2_nested_edge_resolution_and_flags():
    r = parse_package_lock("package-lock.json", json.dumps(V2))
    assert any(e.src == "pkg:npm/a@1.0.0" and e.dst == "pkg:npm/b@2.0.0" for e in r.edges)  # nested b@2 shadows root b@1
    c = {x.purl: x for x in r.components}
    assert c["pkg:npm/a@1.0.0"].direct and c["pkg:npm/grunt@1.0.0"].scope == "dev"
    assert c["pkg:npm/grunt@1.0.0"].origin.has_install_script
    assert c["pkg:npm/fromgit@1.0.0"].origin.registry is None


def test_v1_and_v2_same_components():
    a = {c.purl for c in parse_package_lock("p", json.dumps(V2)).components}
    b = {c.purl for c in parse_package_lock("p", json.dumps(V1)).components}
    assert a == b


def test_malformed_lock_reports_error():
    r = parse_lockfile("package-lock.json", "{bad")
    assert r.components == [] and r.errors


def test_requirements_only_pins_become_components():
    r = parse_lockfile("requirements.txt", "flask==2.0.1\nrequests>=2\n")
    assert [c.name for c in r.components] == ["flask"] and any(e.startswith("unpinned:") for e in r.errors)


def test_poetry_lock_edges():
    text = """
[[package]]
name = "requests"
version = "2.31.0"
[package.dependencies]
urllib3 = ">=1.21"
[[package]]
name = "urllib3"
version = "2.2.1"
"""
    r = parse_lockfile("poetry.lock", text)
    assert [(e.src, e.dst) for e in r.edges] == [("pkg:pypi/requests@2.31.0", "pkg:pypi/urllib3@2.2.1")]


# ------------------------------------------------------------------ docker / ci
def test_dockerfile_multistage_digest_latest():
    d = parse_dockerfile("Dockerfile", "FROM node@sha256:" + "a" * 64 + " AS build\nFROM alpine:latest\nCOPY --from=build /a /a\n"
                         "USER app\nEXPOSE 8080/tcp\nRUN curl -s https://x.invalid/i.sh | sh\n")
    assert d.stages[0].digest and d.stages[0].name == "build" and d.stages[1].tag == "latest"
    assert d.user == "app" and d.exposed_ports == [8080] and d.remote_fetches


def test_workflow_on_key_is_not_boolean():
    w = parse_workflow("w.yml", "on: pull_request_target\njobs: {}\n")
    assert w.triggers == ["pull_request_target"]


def test_uses_pinning():
    w = parse_workflow("w.yml", "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
                                "      - uses: actions/setup-node@" + "a" * 40 + "\n")
    assert [(u.action, u.pinned_to_sha, u.line) for u in w.actions] == [("actions/checkout", False, 5), ("actions/setup-node", True, 6)]


def test_compose_tag_digest():
    s = parse_compose("docker-compose.yml", "services:\n  db:\n    image: postgres:16\n")
    assert (s[0].image, s[0].tag, s[0].digest) == ("postgres:16", "16", None)


# ------------------------------------------------------------------ fixture facts
def test_fixture_facts(fixture_ctx):
    f = fixture_ctx.facts
    assert {"npm", "pypi"} <= set(f.ecosystems)
    assert any(s.name == "postinstall" and "| sh" in s.command for s in f.lifecycle_scripts)
    assert {e.file: e.var_names for e in f.config.env_files}[".env.example"] == ["DATABASE_URL", "STRIPE_KEY"]
    assert any(s.image == "postgres:16" and s.digest is None for s in f.config.compose_services)
    assert f.ci_workflows[0].actions[0].pinned_to_sha is False
    assert len(f.dependency_history) == 5 and f.dependency_history[-1].baseline
    c2 = f.dependency_history[-2]
    assert "colorama" in c2.added and any(c.name == "PyYAML" and c.to_version == "5.4" for c in c2.changed)
    assert all(d.evidence_id for d in f.declared_dependencies)
