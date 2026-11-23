"""Ecosystems beyond Python/JS: Maven, Gradle, Go, Cargo, RubyGems, Composer, NuGet (offline)."""
import pytest

from guardian.cartographer.manifests import parse_manifest
from guardian.detectors.infra import detect_container
from guardian.detectors.packages import detect_registry_signals
from guardian.purl import make_purl, parse_purl
from guardian.sbom.lockfiles import parse_lockfile


@pytest.mark.parametrize("eco,name,ver,purl", [
    ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
    ("golang", "github.com/gin-gonic/gin", "v1.6.2", "pkg:golang/github.com/gin-gonic/gin@v1.6.2"),
    ("cargo", "Serde_Json", "1.0.0", "pkg:cargo/serde-json@1.0.0"),
    ("gem", "rack", "2.0.1", "pkg:gem/rack@2.0.1"),
    ("composer", "Monolog/Monolog", "2.0.0", "pkg:composer/monolog/monolog@2.0.0"),
    ("nuget", "Newtonsoft.Json", "12.0.1", "pkg:nuget/newtonsoft.json@12.0.1"),
])
def test_purls_round_trip(eco, name, ver, purl):
    assert make_purl(eco, name, ver) == purl
    e, n, v = parse_purl(purl)
    assert e == eco and v == ver and make_purl(e, n, v) == purl


def test_pom_properties_scopes_repositories():
    from guardian.fixture_polyglot import POM
    p = parse_manifest("pom.xml", POM)
    d = {x.name: x for x in p.deps}
    assert d["com.fasterxml.jackson.core:jackson-databind"].spec == "2.9.8"          # ${jackson.version} substituted
    assert d["junit:junit"].scope == "dev" and d["org.apache.logging.log4j:log4j-core"].scope == "prod"
    assert p.indexes[0].url == "https://repo.example.invalid/maven"


def test_gradle_go_cargo_gem_composer_csproj_manifests():
    from guardian.fixture_polyglot import CARGO_TOML, COMPOSER_JSON, CSPROJ, GEMFILE, GO_MOD, GRADLE
    import json
    g = {x.name: x.scope for x in parse_manifest("build.gradle", GRADLE).deps}
    assert g == {"org.springframework:spring-web": "prod", "org.junit.jupiter:junit-jupiter": "dev"}
    go = parse_manifest("go.mod", GO_MOD)
    assert go.manifest.project_name == "example.com/inventory"
    assert {(x.name, x.markers) for x in go.deps} == {("github.com/gin-gonic/gin", None),
                                                     ("golang.org/x/crypto", "indirect")}
    cargo = parse_manifest("Cargo.toml", CARGO_TOML)
    assert {(x.name, x.scope) for x in cargo.deps} == {("serde", "prod"), ("smallvec", "prod"), ("criterion", "dev")}
    assert cargo.scripts and cargo.scripts[0].name == "build.rs"
    gem = parse_manifest("Gemfile", GEMFILE)
    assert {(x.name, x.scope) for x in gem.deps} == {("nokogiri", "prod"), ("rack", "prod"), ("rspec", "dev")}
    assert len(gem.indexes) == 2
    comp = parse_manifest("composer.json", json.dumps(COMPOSER_JSON))
    assert {x.name for x in comp.deps} == {"monolog/monolog", "guzzlehttp/guzzle", "phpunit/phpunit"}  # php itself skipped
    cs = parse_manifest("Shipping.Api.csproj", CSPROJ)
    assert {(x.name, x.scope) for x in cs.deps} == {("Newtonsoft.Json", "prod"), ("xunit", "dev")}


def test_lockfiles_edges_and_direct():
    from guardian.fixture_polyglot import CARGO_LOCK, COMPOSER_LOCK, GEMFILE_LOCK, NUGET_LOCK
    import json
    cargo = parse_lockfile("Cargo.lock", CARGO_LOCK)
    assert ("pkg:cargo/serde@1.0.100", "pkg:cargo/serde-derive@1.0.100") in {(e.src, e.dst) for e in cargo.edges}
    assert cargo.direct_names == {"serde", "smallvec"} and cargo.has_integrity
    gem = parse_lockfile("Gemfile.lock", GEMFILE_LOCK)
    assert ("pkg:gem/nokogiri@1.10.0", "pkg:gem/mini_portile2@2.4.0") in {(e.src, e.dst) for e in gem.edges}
    comp = parse_lockfile("composer.lock", json.dumps(COMPOSER_LOCK))
    assert comp.namespaces["Monolog\\"] == "monolog/monolog"
    assert ("pkg:composer/monolog/monolog@2.0.0", "pkg:composer/psr/log@1.1.3") in {(e.src, e.dst) for e in comp.edges}
    nu = parse_lockfile("packages.lock.json", json.dumps(NUGET_LOCK))
    assert ("pkg:nuget/xunit@2.4.1", "pkg:nuget/xunit.core@2.4.1") in {(e.src, e.dst) for e in nu.edges}


def test_polyglot_sbom(polyglot_ctx):
    ecos = {c.ecosystem for c in polyglot_ctx.components}
    assert {"maven", "golang", "cargo", "gem", "composer", "nuget"} <= ecos
    c = {x.purl: x for x in polyglot_ctx.components}
    assert c["pkg:golang/github.com/gin-gonic/gin@v1.6.2"].direct
    assert not c["pkg:golang/golang.org/x/crypto@v0.0.0-20200622213623-75b288015ac9"].direct   # // indirect
    assert c["pkg:golang/github.com/gin-gonic/gin@v1.6.2"].origin.integrity.startswith("h1:")
    assert c["pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8"].direct
    assert c["pkg:maven/junit/junit@4.12"].scope == "dev"


def test_polyglot_imports_mapped_to_packages(polyglot_ctx):
    rows = {(r["ecosystem"], r["name"]): r["status"] for r in polyglot_ctx.graph.discrepancies()}
    for key in [("maven", "com.fasterxml.jackson.core:jackson-databind"), ("maven", "org.apache.logging.log4j:log4j-core"),
                ("golang", "github.com/gin-gonic/gin"), ("cargo", "serde"), ("cargo", "smallvec"), ("gem", "nokogiri"),
                ("gem", "rack"), ("composer", "monolog/monolog"), ("composer", "guzzlehttp/guzzle"), ("nuget", "Newtonsoft.Json")]:
        assert rows.get(key) == "declared+resolved+imported", key
    imps = {(f.language, i.name): i.kind for f in polyglot_ctx.code_index.files for i in f.imports}
    assert imps[("go", "example.com/inventory/internal/store")] == "internal"
    assert imps[("go", "os/exec")] == "stdlib" and imps[("java", "java.io.ObjectInputStream")] == "stdlib"
    assert imps[("rust", "std")] == "stdlib" and imps[("csharp", "System.Diagnostics")] == "stdlib"
    assert imps[("php", "Billing\\Invoice")] == "internal" and imps[("ruby", "json")] == "stdlib"


def test_polyglot_routes_env_sinks(polyglot_ctx):
    files = {f.path: f for f in polyglot_ctx.code_index.files}
    routes = {(r.framework, r.method, r.path) for f in files.values() for r in f.routes}
    assert {("spring", "POST", "/orders"), ("go-http", "GET", "/items"), ("laravel", "POST", "/invoices"),
            ("aspnet", "POST", "labels"), ("rails/sinatra", "POST", "/reports/upload")} <= routes
    env = {e.name for f in files.values() for e in f.env_reads}
    assert {"PAYMENT_API_KEY", "PORT", "PRICING_DB_URL", "REPORT_TOKEN", "BILLING_SECRET", "CARRIER_KEY"} <= env
    sinks = {(f.language, s.category) for f in files.values() for s in f.sensitive_calls}
    assert {("java", "deserialize"), ("java", "subprocess"), ("go", "subprocess"), ("rust", "subprocess"),
            ("ruby", "deserialize"), ("php", "deserialize"), ("csharp", "deserialize")} <= sinks
    svcs = {s.name for f in files.values() for s in f.external_services}
    assert "sync.partner.example.net" in svcs
    paths = polyglot_ctx.graph.execution_paths()
    assert any(p["route"] == "POST /orders" and p["sink"] == "PAYMENT_API_KEY" for p in paths)


def test_polyglot_index_and_container_signals(polyglot_ctx):
    sig = {(f.signals["type"], f.classification) for f in detect_registry_signals(polyglot_ctx) if f.signals.get("signal") == "extra_index"}
    assert ("gem-source", "S") in sig and ("nuget-source", "S") in sig and ("maven-repository", "W") in sig
    assert "DF007" in {f.signals["rule"] for f in detect_container(polyglot_ctx)}   # golang:1.20 is EOL
