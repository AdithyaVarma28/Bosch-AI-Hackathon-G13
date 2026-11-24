"""Heal agent: human-approved fixes applied to a clone, verified in place, rolled back on failure, looped to a threshold."""
from __future__ import annotations

import subprocess
from importlib import resources
from pathlib import Path

import pytest

from guardian.context import Settings
from guardian.day2 import heal as H
from guardian.day2.decisions import open_d2, record
from guardian.day2.heal import HealConfig, HealError, heal

DATA = Path(str(resources.files("guardian.data")))


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def clone(fixture_repo, tmp_path):
    clones = tmp_path / "out" / "clones"
    clones.mkdir(parents=True)
    dst = clones / "demo__guardian-fixture"
    subprocess.run(["git", "clone", "-q", str(fixture_repo), str(dst)], check=True)
    return dst


def settings(tmp: Path) -> Settings:
    return Settings(offline=True, use_llm=False, use_docker=False, cache_dir=tmp / "cache", sandbox="none",
                    advisory_db=DATA / "fixture_advisories.json", registry_snapshot=DATA / "fixture_registry.json")


def cfg(tmp: Path, **kw) -> HealConfig:
    return HealConfig(out_dir=tmp / "out", allowed_root=tmp / "out" / "clones", **kw)


def deps_only(plan, run_dir):
    """The human: approves dependency plans, skips everything else."""
    return ("approve", "reviewed") if plan.plan_key.startswith("pkg:") else None


def test_loop_applies_approved_fixes_and_reaches_threshold(clone, tmp_path):
    main = git(clone, "rev-parse", "--abbrev-ref", "HEAD")
    base = git(clone, "rev-parse", "HEAD")
    st = heal(clone.name, settings(tmp_path), cfg(tmp_path, max_iterations=3), approver=deps_only, reviewer="alice")
    assert st.status == "threshold_met", st.stop_reason
    assert [i.remaining for i in st.iterations][0] == 2 and st.iterations[-1].remaining == 0
    applied = [f for f in st.fixes if f.status == "applied"]
    assert {f.plan_key for f in applied} >= {"pkg:pypi/flask@2.0.1", "pkg:npm/minimist@0.0.8"}
    assert all(f.approved_by == "alice" and f.commit for f in applied)
    # changes live on the heal branch of the clone, one commit per fix; the original branch is untouched
    assert git(clone, "rev-parse", "--abbrev-ref", "HEAD") == st.branch and st.branch.startswith("guardian/heal-")
    assert git(clone, "rev-parse", main) == base
    log = git(clone, "log", "--format=%s", f"{base}..HEAD").splitlines()
    assert len(log) == len(applied) and all(s.startswith("guardian heal:") for s in log)
    req = (clone / "requirements.txt").read_text()
    assert "flask==2.2.5  # guardian: upgraded flask 2.0.1 -> 2.2.5 (fixes GHSA-m2qf-hxjv-5gpq)" in req
    note = (clone / "GUARDIAN_HEAL.md").read_text(encoding="utf-8")
    assert "Approved by: alice" in note and "`requirements.txt`" in note and "`package-lock.json`" in note
    fl = next(f for f in applied if f.plan_key.startswith("pkg:pypi/flask"))
    assert fl.files == [str((clone / "requirements.txt").resolve())]
    assert git(clone, "status", "--porcelain") == ""
    # every decision journaled with the allowed set; the human gate came first
    assert st.journal[0].action == "await_approval" and all(d.action in d.allowed for d in st.journal)
    assert (tmp_path / "out" / "heal" / clone.name / "heal.html").exists()


def test_pauses_without_a_human_and_resumes_after_approval(clone, tmp_path):
    st = heal(clone.name, settings(tmp_path), cfg(tmp_path))
    assert st.status == "awaiting_approval" and not st.fixes
    assert git(clone, "log", "--format=%s", "-1").startswith("feat:")            # nothing applied without approval
    run_dir = Path(st.current.run_dir)
    s, d2 = open_d2(run_dir)
    flask = next(p for p in d2.plans() if p.plan_key.startswith("pkg:pypi/flask"))
    s.close()
    record(run_dir, flask.plan_key, "approve", "bob", flask.plan_hash[:16])      # approval from the UI/API/CLI
    st = heal(clone.name, settings(tmp_path), cfg(tmp_path))
    assert any(f.status == "applied" and f.plan_key == flask.plan_key and f.approved_by == "bob" for f in st.fixes)
    assert "flask==2.2.5" in (clone / "requirements.txt").read_text()


def test_failed_in_place_verification_rolls_back_and_falls_back(clone, tmp_path, monkeypatch):
    real = H._verify_in_place
    calls = {"n": 0}

    def flaky(h, plan, before):
        calls["n"] += 1
        if plan.plan_key.startswith("pkg:pypi/flask") and calls.setdefault("flask", 0) == 0:
            calls["flask"] = 1
            return False, "target still present: injected failure", {"run": None}
        return real(h, plan, before)
    monkeypatch.setattr(H, "_verify_in_place", flaky)
    approve_flask = lambda p, r: ("approve", "ok") if p.plan_key.startswith("pkg:pypi/flask") else None  # noqa: E731
    st = heal(clone.name, settings(tmp_path), cfg(tmp_path, max_iterations=1), approver=approve_flask, reviewer="alice")
    flask = [f for f in st.fixes if f.plan_key.startswith("pkg:pypi/flask")]
    assert [f.status for f in flask] == ["rolled_back", "applied"]
    assert flask[0].candidate_id != flask[1].candidate_id                         # next validated finalist
    assert st.attempts["pkg:pypi/flask@2.0.1"] == 1
    assert len(git(clone, "log", "--format=%s", f"{st.base_commit}..HEAD").splitlines()) == 1   # rolled-back commit gone
    assert st.status in ("stopped", "awaiting_approval") and "budget" in (st.stop_reason + " ".join(d.reason for d in st.journal))


def test_guards(clone, tmp_path):
    (clone / "requirements.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(HealError, match="uncommitted"):
        heal(clone.name, settings(tmp_path), cfg(tmp_path))
    git(clone, "checkout", "--", "requirements.txt")
    elsewhere = tmp_path / "elsewhere"
    subprocess.run(["git", "clone", "-q", str(clone), str(elsewhere)], check=True)
    with pytest.raises(HealError, match="outside"):
        heal(str(elsewhere), settings(tmp_path), cfg(tmp_path))
