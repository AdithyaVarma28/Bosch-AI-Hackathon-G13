"""Stage 5 on the full mini-shop fixture (fake packages from its local PyPI-style index), offline."""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardian.cli import app
from guardian.stage5_anomalies.detectors.d1_typosquat import candidates, osa
from guardian.stage5_anomalies.sandbox import UnsafeArchive, safe_extract, scan_python

ROOT = Path(__file__).resolve().parents[1]
DUMP = ROOT / "tests" / "data" / "osv_minishop.zip"


@pytest.fixture(scope="module")
def full(tmp_path_factory):
    if not shutil.which("git"):
        pytest.skip("git is needed")
    base = tmp_path_factory.mktemp("stage5")
    r = subprocess.run([sys.executable, str(ROOT / "tests/fixtures/make_mini_shop_full.py"), str(base)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture failed: {r.stderr[-300:]}")
    os.environ["GUARDIAN_VULNDB"] = str(base / "vulndb")
    os.environ["GUARDIAN_PYPI_URL"] = str(base / "fake-pypi" / "pypi")
    try:
        res = CliRunner().invoke(app, ["scan", str(base / "mini-shop"), "--output", str(base / "output"), "--offline",
                                       "--skip-sbom", "--osv-dump", str(DUMP)])
    finally:
        os.environ.pop("GUARDIAN_PYPI_URL", None)
    assert res.exit_code == 0, res.output
    d = base / "output" / "mini-shop"
    cards = json.loads((d / "anomaly_findings.json").read_text(encoding="utf-8"))
    return {"dir": d, "cards": {c["component_name"]: c for c in cards}, "log": res.output, "list": cards}


def checks(c):
    return {s["check"]: s["strength"] for s in c["signals"]}


def test_typosquat_with_install_hook_is_critical(full):
    c = full["cards"]["reqeusts 2.31.0"]
    assert checks(c)["typosquat_edit_distance"] == "strong" and checks(c)["install_hook_behaviour"] == "strong"
    assert c["suspicion"] == "high" and c["exposure"] == "install_path" and c["project_risk"] == "critical"
    assert any(e["type"] == "package_code" and e["file"].endswith("setup.py") for e in c["evidence"])
    assert c["review"]["status"] == "pending"


def test_suspicious_update_deep_check(full):
    c = full["cards"]["minishop-utils 1.1"]
    assert checks(c)["new_behaviour_in_update"] == "strong" and checks(c)["wheel_to_sdist_only"] == "medium"


def test_legit_update_normal_explanation(full):
    c = full["cards"]["shopfront-theme 2.4.1"]
    assert c["normal_explanation_verified"] and c["suspicion"] == "low"


def test_lockfile_hash_mismatch(full):
    c = full["cards"]["requests 2.31.0"]
    assert checks(c)["hash_mismatch"] == "strong" and checks(c)["lockfile_only_change"] == "medium"


def test_build_env(full):
    wf = full["cards"][".github/workflows/ci.yml"]
    assert checks(wf)["pull_request_target_checkout_head"] == "strong" and wf["exposure"] == "build_env"
    img = full["cards"]["python:latest"]
    assert checks(img)["remote_script"] == "medium"


def test_unexpected_changes(full):
    assert checks(full["cards"]["colorama 0.4.6"])["new_dependency_unused"] == "medium"
    assert checks(full["cards"]["app/utils/helpers.py"])["new_outbound_domain"] == "strong"


def test_invariants(full):
    for c in full["list"]:
        text = json.dumps(c).lower()
        assert "malicious" not in text.replace("malicious intent not established", "")
        assert " executed" not in c["explanation"].lower().replace("not executed", "")
        assert {"suspicion", "exposure", "project_risk", "confidence"} <= set(c)
        for s in c["signals"]:
            if s["metadata_only"]:
                assert s["strength"] != "strong"
    g = json.loads((full["dir"] / "graph.json").read_text(encoding="utf-8"))
    assert any(n["type"] == "Anomaly" for n in g["nodes"]) and any(e["type"] == "FLAGS" for e in g["edges"])
    assert any(n["type"] == "Vulnerability" for n in g["nodes"])           # Stage 4 nodes kept


def test_review_anomaly(full):
    aid = full["cards"]["reqeusts 2.31.0"]["finding_id"]
    res = CliRunner().invoke(app, ["review", str(full["dir"]), aid, "--action", "confirm", "--by", "tester"])
    assert res.exit_code == 0, res.output
    cards = json.loads((full["dir"] / "anomaly_findings.json").read_text(encoding="utf-8"))
    assert next(c for c in cards if c["finding_id"] == aid)["review"]["status"] == "confirmed"


# --------------------------------------------------------------------------- units

def test_safe_extract_rejects_traversal_and_links(tmp_path):
    z = tmp_path / "bad.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../evil.py", "x")
    with pytest.raises(UnsafeArchive):
        safe_extract(z, tmp_path / "out1")
    t = tmp_path / "bad.tar.gz"
    with tarfile.open(t, "w:gz") as tf:
        ti = tarfile.TarInfo("pkg/link")
        ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
        tf.addfile(ti)
    with pytest.raises(UnsafeArchive):
        safe_extract(t, tmp_path / "out2")
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "0" * 5_000_000)
    with pytest.raises(UnsafeArchive):
        safe_extract(bomb, tmp_path / "out3")


def test_ast_scanner():
    facts = scan_python("import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\nimport urllib.request\nurllib.request.urlopen('https://x.invalid')\n", "a.py")
    cats = {f["category"] for f in facts}
    assert {"code_exec", "decode", "obfuscated_exec", "network", "domain"} <= cats


def test_typosquat_rules():
    assert osa("reqeusts", "requests") == 1
    top = {"requests": 10**9, "python-dateutil": 10**9}
    assert candidates("reqeusts", top)[0]["looks_like"] == "requests"
    assert candidates("python_dateutil", top) == [] or candidates("pythondateutil", top)[0]["check"] == "separator"
