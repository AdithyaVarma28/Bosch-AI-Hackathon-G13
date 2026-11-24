"""Stage 3 knowledge engine on the team's mini-shop fixture (tests/fixtures/make_mini_shop.sh).

Runs the real Stage 1-2 scan, then Stage 3 offline, and checks the expected results from
docs/stage3.md section 11. A fake LLM provider exercises card validation, the agent loop,
evidence checking and the cache without network calls.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardian.cli import app
from guardian.stage3_knowledge import run_stage3
from guardian.stage3_knowledge.context import Budgets
from guardian.stage3_knowledge.investigator.tools import EvidenceLedger
from guardian.stage3_knowledge.llm import LLM
from guardian.stage3_knowledge.schema import Evidence

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "make_mini_shop.sh"


def _bash() -> str | None:
    found = shutil.which("bash")
    if found and "system32" in found.lower():  # WSL launcher, not Git Bash
        git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
        return str(git_bash) if git_bash.exists() else None
    return found


@pytest.fixture(scope="module")
def scanned(tmp_path_factory):
    bash = _bash()
    if not bash or not shutil.which("git"):
        pytest.skip("bash and git are needed to build the mini-shop fixture")
    base = tmp_path_factory.mktemp("stage3")
    r = subprocess.run([bash, str(FIXTURE), "mini-shop"], cwd=base, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture script failed: {r.stderr[-300:]}")
    repo, out = base / "mini-shop", base / "output"
    res = CliRunner().invoke(app, ["scan", str(repo), "--output", str(out), "--offline", "--skip-sbom"])
    assert res.exit_code == 0, res.output
    return {"repo": repo, "dir": out / "mini-shop", "base": base, "log": res.output}


def load(d: Path, name: str):
    return json.loads((d / name).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- outputs + graph invariants

def test_scan_writes_every_stage3_file(scanned):
    for name in ("graph.json", "cards.json", "paths.json", "blast_radius.json", "changes.json", "findings.json",
                 "coverage.json", "ui_bundle.json"):
        assert (scanned["dir"] / name).exists(), name
    assert "stage 3D" in scanned["log"]


def test_every_node_and_edge_says_how_it_was_found(scanned):
    g = load(scanned["dir"], "graph.json")
    for n in g["nodes"]:
        assert n.get("discovered_by") and "evidence" in n and "confidence" in n and "analyzed_at" in n, n["id"]
    for e in g["edges"]:
        assert e.get("discovered_by") and "evidence" in e, e


def test_modules_and_dependencies(scanned):
    g = load(scanned["dir"], "graph.json")
    names = {n["name"] for n in g["nodes"] if n["type"] == "Module"}
    assert {"api", "payments", "config", "utils", "tests", "models"} <= names
    deps = {(e["source"], e["target"]) for e in g["edges"] if e["type"] == "DEPENDS_ON"}
    assert ("module:app/api", "module:app/payments") in deps
    assert ("module:app/api", "module:app/utils") in deps
    assert ("module:app/payments", "module:app/models") in deps


def test_declared_vs_used_and_tables(scanned):
    g = {n["id"]: n for n in load(scanned["dir"], "graph.json")["nodes"]}
    assert "declared_unused" in g["pkg:pypi/colorama@0.4.6"]["tags"]
    assert "table:orders" in g                                  # __tablename__ read from the class body
    assert g["pkg:pypi/pytest@8.0.0"]["scope"] == "dev"


# --------------------------------------------------------------------------- 3C

def test_execution_paths(scanned):
    paths = load(scanned["dir"], "paths.json")
    by_steps = {tuple(s.split("::")[-1] for s in p["steps"]): p for p in paths}
    pay = by_steps[("checkout", "charge", "get_client")]
    assert pay["entry"] == "route:POST /checkout" and pay["input"] == "request.json"
    assert {"svc:Stripe", "env:STRIPE_KEY"} <= set(pay["sinks"])
    ev = by_steps[("checkout", "send_event")]
    assert "svc:analytics.external-service.com" in ev["sinks"]


def test_blast_radius(scanned):
    br = {v["name"].lower(): v for v in load(scanned["dir"], "blast_radius.json").values()}
    assert br["stripe"]["radius"] == "large"
    assert br["pyyaml"]["radius"] == "internal"
    assert br["colorama"]["radius"] == "none"
    assert "env:STRIPE_KEY" in br["stripe"]["secrets_nearby"]


def test_time_travel_diff(scanned):
    ch = load(scanned["dir"], "changes.json")
    labels = [i["label"] for i in ch["items"]]
    assert ch["mode"] == "git-files"
    assert "+ colorama 0.4.6" in labels
    assert "PyYAML 5.4.1 → 6.0.1" in labels
    assert "+ module app/utils" in labels
    assert any(l.startswith("+CONTACTS fn:send_event → svc:analytics.external-service.com") for l in labels)
    head = ch["commits"][0]
    assert head["type"] == "notable" and ch["commits"][-1]["type"] == "baseline"
    assert len({c["short"] for c in ch["commits"]}) == len(ch["commits"])  # one entry per commit


# --------------------------------------------------------------------------- 3B + 3D

def test_cards(scanned):
    cards = load(scanned["dir"], "cards.json")
    pay = cards["module:app/payments"]
    assert pay["sensitivity"] == "high" and "env:STRIPE_KEY" in pay["data_touched"]
    for card in cards.values():
        for e in card["evidence"]:
            assert e["file"] and (e.get("lines") or e.get("line"))
    assert "repo:mini-shop" in cards


def test_investigator_findings(scanned):
    findings = load(scanned["dir"], "findings.json")
    send = next(f for f in findings if f["subject"].endswith("::send_event"))
    assert send["notable"] and send["status"] == "resolved"
    assert any(e.get("commit") for e in send["evidence"]) and any(e.get("file") for e in send["evidence"])
    col = next(f for f in findings if f["subject"] == "pkg:pypi/colorama@0.4.6")
    assert "No import" in col["answer"] and any(e.get("commit") for e in col["evidence"])
    assert all(f["steps_used"] <= 8 for f in findings) and len(findings) <= 20


def test_ui_bundle_matches_dashboard_contract(scanned):
    b = load(scanned["dir"], "ui_bundle.json")
    for key in ("repo", "modules", "edges", "paths", "packages", "changes", "findings", "coverage"):
        assert key in b
    for key in ("files", "calls", "modules", "filesCarded", "questions", "knownUnknowns"):
        assert key in b["coverage"]
    names = {m["name"] for m in b["modules"]}
    assert all(e["from"] in names and e["to"] in names for e in b["edges"])


def test_evidence_ledger_only_accepts_what_tools_returned():
    led = EvidenceLedger()
    led.add_file("app/x.py", 3, 9)
    led.commits.add("abc1234")
    assert led.covers(Evidence(file="app/x.py", lines="4-5"))
    assert not led.covers(Evidence(file="app/x.py", lines="20-22"))
    assert not led.covers(Evidence(file="app/other.py", lines="1"))
    assert led.covers(Evidence(commit="abc1234ffff"))
    assert not led.covers(Evidence(commit="9999999"))


# --------------------------------------------------------------------------- fake LLM

class FakeProvider:
    """Cards: first answer cites a missing file and an unknown id; the retry is valid.
    Investigator: one query_graph call, then a finding with one real and one invented citation."""
    name, model = "fake", "fake-model"

    def __init__(self):
        self.calls = 0

    def create(self, *, system, messages, tools, json_schema, max_tokens, effort):
        self.calls += 1
        if json_schema:
            prompt = messages[0]["content"]
            facts = json.loads(prompt.split("```json", 1)[1].split("```", 1)[0])
            files = [f["path"] for f in facts.get("files", []) if f.get("path")] or ["app/__init__.py"]
            retry = "failed validation" in prompt
            card = {"purpose": f"Fake purpose for {facts['id']}", "responsibilities": ["r"], "inputs": [], "outputs": [],
                    "data_touched": [] if retry else ["table:ghost"], "external": [], "sensitivity": "low",
                    "sensitivity_reasons": [], "confidence": 0.9, "open_questions": [],
                    "evidence": [{"file": files[0], "lines": "1"}] + ([] if retry else [{"file": "nope.py", "lines": "1-2"}])}
            return {"content": [{"type": "text", "text": json.dumps(card)}], "stop_reason": "end_turn"}
        subject = re.search(r"Subject: (\S+)", messages[0]["content"]).group(1)
        if len(messages) == 1:
            return {"content": [{"type": "tool_use", "id": "tu_1", "name": "query_graph",
                                 "input": {"node_id": subject, "direction": "both"}}], "stop_reason": "tool_use"}
        result = json.loads(messages[-1]["content"][0]["content"])
        real = (result.get("node", {}).get("evidence") or [{}])[0]
        ev = [{"file": real.get("file", ""), "lines": str(real.get("lines") or real.get("line") or ""), "commit": ""},
              {"file": "app/invented.py", "lines": "1-3", "commit": ""}]
        return {"content": [{"type": "tool_use", "id": "tu_2", "name": "submit_finding", "input": {
            "answer": "fake answer", "evidence": ev, "confidence": 0.8, "status": "resolved", "notable": False,
            "notable_reason": "", "new_questions": []}}], "stop_reason": "tool_use"}


def test_llm_cards_and_agent_are_validated_and_cached(scanned, tmp_path):
    out1, cache = tmp_path / "run1", tmp_path / "cache"
    fake = FakeProvider()
    ctx = run_stage3(scanned["dir"], output_dir=out1, repo_path=scanned["repo"], log=lambda *_: None,
                     llm=LLM(provider=fake, cache_dir=cache), budgets=Budgets(card_calls=10, questions=5))
    ai_cards = [c for c in ctx.cards.values() if c["discovered_by"] == "ai"]
    assert ai_cards and ctx.llm.used("card") <= 10                       # card budget respected
    assert all(c["data_touched"] == [] and all(e["file"] != "nope.py" for e in c["evidence"]) for c in ai_cards)
    ai_findings = [f for f in ctx.findings if f["discovered_by"] == "ai"]
    assert ai_findings and all("app/invented.py" in " ".join(f["dropped_evidence"]) for f in ai_findings)
    assert all(e["file"] != "app/invented.py" for f in ai_findings for e in f["evidence"])



def test_rescan_of_unchanged_repo_uses_the_cache(scanned, tmp_path):
    cache = tmp_path / "cache"
    first = FakeProvider()
    ctx = run_stage3(scanned["dir"], output_dir=tmp_path / "run1", repo_path=scanned["repo"], log=lambda *_: None,
                     llm=LLM(provider=first, cache_dir=cache), budgets=Budgets(card_calls=100, questions=5))
    assert first.calls > 0
    again = FakeProvider()
    ctx2 = run_stage3(scanned["dir"], output_dir=tmp_path / "run2", repo_path=scanned["repo"], log=lambda *_: None,
                      llm=LLM(provider=again, cache_dir=cache), budgets=Budgets(card_calls=100, questions=5))
    assert again.calls == 0                                                   # same input -> cached output
    assert {k: c["purpose"] for k, c in ctx2.cards.items()} == {k: c["purpose"] for k, c in ctx.cards.items()}
    assert [f["answer"] for f in ctx2.findings] == [f["answer"] for f in ctx.findings]


# --------------------------------------------------------------------------- API

def test_api_endpoints(scanned):
    from fastapi.testclient import TestClient

    from guardian.stage3_knowledge.api import create_app

    c = TestClient(create_app(scanned["dir"]))
    assert c.get("/graph", params={"level": "repo"}).json()["nodes"]
    mod = c.get("/graph", params={"level": "module", "id": "module:app/payments"}).json()
    assert any(n["id"] == "env:STRIPE_KEY" for n in mod["nodes"])
    node = c.get("/node/fn:app/utils/helpers.py::send_event").json()
    assert node["findings"] and node["node"]["type"] == "Function"
    assert c.get("/node/file:app/models.py").json()["card"]                # lazy card
    assert c.get("/paths", params={"entry": "route:POST /checkout"}).json()["paths"]
    assert c.get("/blast-radius/stripe").json()["radius"] == "large"
    assert c.get("/diff").json()["items"]
    assert c.get("/coverage").json()["files_parsed"]
    assert c.get("/ui-bundle").json()["repo"]["name"] == "mini-shop"
    assert c.get("/node/nope").status_code == 404
