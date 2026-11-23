"""S3 code index + S4 unified graph (Definition of Done checks on the fixture)."""
from guardian.graph import UnifiedGraph
from guardian.models import Component, DepEdge


def _file(ctx, path):
    return next(f for f in ctx.code_index.files if f.path == path)


def test_route_and_input_source(fixture_ctx):
    r = _file(fixture_ctx, "app/api/routes.py")
    assert [(x.method, x.path, x.handler) for x in r.routes] == [("POST", "/checkout", "app/api/routes.py::checkout")]
    assert any(i.name == "request.json" and i.function == "app/api/routes.py::checkout" for i in r.input_sources)


def test_resolved_internal_call_chain(fixture_ctx):
    calls = {(c.caller, c.resolved_target) for f in fixture_ctx.code_index.files for c in f.calls if c.resolved_target}
    assert ("app/api/routes.py::checkout", "app/payments/service.py::charge") in calls
    assert ("app/payments/service.py::charge", "app/payments/client.py::get_client") in calls
    assert ("app/api/routes.py::checkout", "app/utils/helpers.py::send_event") in calls


def test_env_db_services_sensitive(fixture_ctx):
    client = _file(fixture_ctx, "app/payments/client.py")
    assert [(e.name, e.how) for e in client.env_reads] == [("STRIPE_KEY", "os.environ[]")]
    assert any(s.name == "Stripe" and s.via == "sdk" for s in client.external_services)
    models = _file(fixture_ctx, "app/models.py")
    assert models.db_models[0].table == "orders"
    svc = _file(fixture_ctx, "app/payments/service.py")
    assert any(a.operation == "write" and a.model == "Order" and a.function.endswith("::charge") for a in svc.db_access)
    helpers = _file(fixture_ctx, "app/utils/helpers.py")
    assert any(s.via == "url" and s.domain == "collect.analytics-example.net" for s in helpers.external_services)
    assert any(s.category == "network" and s.target == "requests.post" for s in helpers.sensitive_calls)
    load = _file(fixture_ctx, "app/config/load.py")
    assert any(s.category == "deserialize" and s.target == "yaml.load" for s in load.sensitive_calls)


def test_dist_map_and_coverage(fixture_ctx):
    ci = fixture_ctx.code_index
    assert ci.import_name_to_distribution["yaml"] == "PyYAML"
    assert ci.coverage.files_failed == 0 and ci.coverage.internal_calls_resolved >= 4
    assert _file(fixture_ctx, "tests/test_api.py").is_test


def test_syntax_error_is_recorded(tmp_path, make_ctx):
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "bad.py").write_text("def x(:\n")
    (tmp_path / "repo" / "ok.py").write_text("import os\n")
    from guardian.codeindex.parser import build_code_index
    idx = build_code_index(make_ctx(tmp_path / "repo"))
    assert idx.coverage.files_failed == 1 and idx.coverage.files_parsed == 1


def test_discrepancy_layers(fixture_ctx):
    rows = {r["name"]: r["status"] for r in fixture_ctx.graph.discrepancies()}
    assert rows["colorama"] == "declared-not-imported"
    assert rows["PyYAML"] == "declared+resolved+imported"
    assert rows["minimist"] == "transitive-only"


def test_paths_blast_radius_execution(fixture_ctx):
    g = fixture_ctx.graph
    assert g.paths_to("pkg:npm/minimist@0.0.8") == [["pkg:npm/mkdirp@0.5.1", "pkg:npm/minimist@0.0.8"]]
    br = g.blast_radius("pkg:pypi/requests@2.25.1")
    assert "route:POST /checkout" in br["exposed_routes"]
    sinks = {(p["route"], p["sink"]) for p in g.execution_paths()}
    assert ("POST /checkout", "orders") in sinks and ("POST /checkout", "STRIPE_KEY") in sinks
    assert ("POST /checkout", "collect.analytics-example.net") in sinks


def _c(n, direct=False):
    return Component(purl=f"pkg:npm/{n}@1", name=n, version="1", ecosystem="npm", direct=direct)


def test_diamond_depth_fan_in_cycle_orphan():
    comps = [_c("a", True), _c("b"), _c("c"), _c("d"), _c("x")]
    edges = [DepEdge(src="pkg:npm/a@1", dst=f"pkg:npm/{t}@1") for t in "bc"] + \
            [DepEdge(src=f"pkg:npm/{s}@1", dst="pkg:npm/d@1") for s in "bc"] + [DepEdge(src="pkg:npm/d@1", dst="pkg:npm/b@1")]
    g = UnifiedGraph.build("p", None, comps, edges, None)
    m = g.metrics()
    assert m["pkg:npm/d@1"]["depth"] == 2 and m["pkg:npm/d@1"]["fan_in"] == 2
    assert all(p[0] == "pkg:npm/a@1" for p in g.paths_to("pkg:npm/d@1"))
    assert g.validation["cycles"] and g.validation["orphans"] == ["pkg:npm/x@1"]
    assert m["pkg:npm/x@1"]["depth"] is None
