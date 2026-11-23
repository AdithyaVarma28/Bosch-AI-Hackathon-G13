"""S6 detectors and S7 scoring on the fixture (offline: no OSV needed)."""
from guardian.detectors.changes import detect_changes
from guardian.detectors.infra import detect_ci, detect_container, detect_secrets, redact
from guardian.detectors.osv import cvss3_score, severity_band
from guardian.detectors.packages import (detect_discrepancies, detect_install_scripts, detect_name_confusion,
                                         levenshtein)
from guardian.detectors.vulns import detect_vulns
from guardian.fixture import FAKE_TOKEN
from guardian.models import Dossier, Finding
from guardian.scoring import correlate, score


def test_lockfile_changes(fixture_ctx):
    sig = {(f.signals["signal"], f.classification) for f in detect_changes(fixture_ctx)}
    assert ("integrity_changed_same_version", "S") in sig
    assert ("resolved_host_changed", "S") in sig
    assert ("non_registry_source", "S") in sig
    assert ("new_dependency", "W") in sig and ("large_version_jump", "W") in sig


def test_baseline_commit_raises_nothing(fixture_ctx):
    base = fixture_ctx.facts.dependency_history[-1].commit
    assert not [f for f in detect_changes(fixture_ctx) if f.signals.get("commit") == base]


def test_install_script_pipe_to_shell_is_strong(fixture_ctx):
    f = detect_install_scripts(fixture_ctx)[0]
    assert f.classification == "S" and f.signals["pattern"] == "pipe_to_shell"


def test_typosquat_without_metadata_is_weak(fixture_ctx):
    fs = detect_name_confusion(fixture_ctx, popular_npm={"lodash"}, popular_pypi=set())
    assert [(f.signals["similar_to"], f.classification) for f in fs] == [(["lodash"], "W")]


def test_short_and_exact_names_ignored(fixture_ctx):
    assert levenshtein("lodahs", "lodash") == 2
    fs = detect_name_confusion(fixture_ctx, popular_npm={"debug", "ms", "mkdirp"}, popular_pypi=set())
    assert not fs


def test_container_and_ci_rules(fixture_ctx):
    rules = {f.signals["rule"] for f in detect_container(fixture_ctx)}
    assert {"DF001", "DF003", "DF004", "DC001"} <= rules
    ci = {f.signals["rule"]: f for f in detect_ci(fixture_ctx)}
    assert {"CI001", "CI002", "CI003", "CI004"} <= set(ci)
    assert ci["CI004"].classification == "S"
    assert ci["CI001"].subject == "actions/checkout@v4"   # SHA-pinned setup-node is not flagged


def test_secret_found_but_never_stored(fixture_ctx):
    fs = detect_secrets(fixture_ctx)
    assert fs and fs[0].signals["kind"] == "github_token" and FAKE_TOKEN not in fs[0].model_dump_json()
    for e in fixture_ctx.store.all_evidence():
        assert FAKE_TOKEN not in e.excerpt
    assert redact(FAKE_TOKEN).startswith("ghp_") and "AAAA" not in redact(FAKE_TOKEN)


def test_declared_not_imported(fixture_ctx):
    names = {f.signals["name"] for f in detect_discrepancies(fixture_ctx)}
    assert "colorama" in names and "PyYAML" not in names


def test_offline_osv_is_unavailable_not_crash(fixture_ctx):
    fs = detect_vulns(fixture_ctx)
    assert fs and (fs[0].cls == "sbom_quality" and fs[0].signals["source"] == "unavailable" or fs[0].cls == "vuln")


def test_cvss_vector_scoring():
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert severity_band({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]})[1] == "Critical"
    assert severity_band({"database_specific": {"severity": "MODERATE"}})[1] == "Medium"


def _vuln(sev, scope="prod", **kw):
    return Finding(cls="vuln", subject="pkg:npm/a@1", title="a", locator=kw.pop("loc", "GHSA-x"), detector="vulns",
                   classification="C", signals={"severity_band": sev, "scope": scope, **kw})


def test_priority_bands():
    d = Dossier(exposure="unknown")
    band = lambda f: score([f], d, "high")[0].band
    assert band(_vuln("Low", kev=True, cves=["CVE-1"])) == "P0"
    assert band(_vuln(None, advisory_id="MAL-2025-1")) == "P0"
    assert band(_vuln("High")) == "P1"            # unknown reachability is not downgraded
    assert band(_vuln("High", scope="dev")) == "P2"
    assert band(_vuln("Low", scope="dev")) == "P3"
    f = score([_vuln(None)], d, "high")[0]
    assert f.band == "Unprioritized" and "severity" in f.band_reason


def test_correlate_dedupes_and_merges_evidence():
    a = Finding(cls="ci", subject="w", title="t", locator="l", detector="ci", raw_evidence_ids=["ev_a"], signals={"rule": "CI001"})
    b = a.model_copy(update={"raw_evidence_ids": ["ev_b"]})
    out = correlate([a, b])
    assert len(out) == 1 and set(out[0].raw_evidence_ids) == {"ev_a", "ev_b"}
    assert out[0].attack_class == "Unpinned third-party action"
