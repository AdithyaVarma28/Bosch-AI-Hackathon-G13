"""CLI: guardian scan <github-url-or-path> (detection -> remediation, one pipeline) | remediate | approve | serve ..."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .context import Settings

app = typer.Typer(add_completion=False, help="Software Supply Chain Guardian (Day 1: visibility and detection; "
                                            "Day 2: prioritize, remediate, validate, verify)")
console = Console()
ICON = {"ok": "[green]ok[/]", "degraded": "[yellow]degraded[/]", "skipped": "[dim]skipped[/]", "failed": "[red]failed[/]"}


@app.command()
def scan(target: str = typer.Argument(..., help="https://github.com/<owner>/<repo> or a local directory"),
         out: Path = typer.Option(Path("output"), help="output directory"),
         offline: bool = typer.Option(False, help="no network: OSV/registries/LLM from cache only"),
         no_llm: bool = typer.Option(False, "--no-llm", help="disable the LLM agents (rule-based explanations)"),
         no_docker: bool = typer.Option(False, "--no-docker", help="disable sandboxed resolution and tool containers"),
         history: int = typer.Option(50, help="commits of dependency history to analyse"),
         explain: int = typer.Option(10, help="max findings explained by the Evidence Agent"),
         model: str = typer.Option(None, help="Groq model id (default env GROQ_MODEL or openai/gpt-oss-120b)"),
         remediate: bool = typer.Option(True, "--remediate/--detect-only",
                                        help="run the whole pipeline (detection + Day 2 up to the approval gate), "
                                             "or stop after detection"),
         sandbox: str = typer.Option("docker", help="Day 2 sandbox: docker | local | none"),
         advisory_db: Path = typer.Option(None, help="offline OSV snapshot JSON ('fixture' = bundled demo data)"),
         registry_snapshot: Path = typer.Option(None, help="offline registry snapshot JSON ('fixture' = bundled demo data)")):
    """One pipeline: detect (SBOM, graph, vulnerabilities, suspicious changes) -> prioritize -> investigate -> plan
    fixes -> stop at the human approval gate. Approve with `guardian approve`, then `guardian remediate <run_dir>`."""
    from .orchestrator import run_pipeline
    settings = Settings(offline=offline, use_llm=not no_llm, use_docker=not no_docker, history_depth=history,
                        max_explanations=explain, llm_model=model, sandbox=sandbox,
                        advisory_db=_data_file(advisory_db, "fixture_advisories.json"),
                        registry_snapshot=_data_file(registry_snapshot, "fixture_registry.json"), remediate=remediate)

    def emit(ev: dict) -> None:
        console.print(f"  {ev['node']:<16} {ICON.get(ev['status'], ev['status'])}  [dim]{ev.get('seconds', '')}s[/]  {ev.get('message', '')}")

    console.print(f"[bold]Guardian[/] scanning {target}")
    res = run_pipeline(target, out, settings, emit)
    if not res.report_path or not res.report_path.exists():
        console.print("[red]scan failed[/]")
        raise typer.Exit(1)
    rep = json.loads(res.report_path.read_text(encoding="utf-8"))
    if rep.get("status") == "failed":
        console.print(f"[red]scan failed:[/] {rep.get('errors')}")
        raise typer.Exit(1)
    t = Table(title="Findings by band")
    for b in ("P0", "P1", "P2", "P3", "Unprioritized"):
        t.add_column(b)
    t.add_row(*[str(rep["summary"]["bands"].get(b, 0)) for b in ("P0", "P1", "P2", "P3", "Unprioritized")])
    console.print(t)
    for f in rep["findings"][:12]:
        console.print(f"  [{f['band']}] {f['title']}  [dim]{f['locator']}[/]")
    if res.day2 is not None:
        _print_day2(res.day2)
    console.print(f"\nReport: [bold]{res.run_dir / 'report.html'}[/]  (detection and remediation in one page)\n"
                  f"JSON:   {res.report_path}")


@app.command()
def chaos(target: str = typer.Argument(..., help="local repository path (experiments run on a throwaway copy)"),
          out: Path = typer.Option(Path("output/chaos"), help="output directory"),
          only: str = typer.Option(None, help="comma-separated experiment ids (default: all)"),
          monkey: int = typer.Option(0, help="extra random multi-fault experiments (chaos monkey)"),
          seed: int = typer.Option(None, help="seed for the chaos monkey (reproducible)"),
          online: bool = typer.Option(False, help="allow network (default: offline, cache only)"),
          list_: bool = typer.Option(False, "--list", help="list experiments and exit")):
    """Chaos engineering: inject faults into Guardian's pipeline and verify it degrades safely."""
    from .chaos import EXPERIMENTS, run_chaos
    if list_:
        for e in EXPERIMENTS:
            console.print(f"  [bold]{e.id:<22}[/] {e.category:<18} {e.name}")
        return

    def emit(r: dict) -> None:
        mark = "[green]PASS[/]" if r["passed"] else "[red]FAIL[/]"
        console.print(f"  {mark} {r['id']:<22} {r['seconds']:>5}s  {r['name']}")
        for p in r["probes"]:
            if not p["ok"]:
                console.print(f"        [red]✘ {p['probe']}[/] {p['detail']}")

    console.print(f"[bold]Guardian chaos[/] on a copy of {target}")
    s = run_chaos(target, out, [x.strip() for x in only.split(",")] if only else None, monkey, seed, offline=not online, emit=emit)
    console.print(f"\nResilience score: [bold]{s['resilience_score']}%[/] ({s['passed']}/{s['experiments']})\nScorecard: {s['path']}")
    if s["passed"] != s["experiments"]:
        raise typer.Exit(1)


@app.command()
def fixture(dest: Path = typer.Argument(Path("output/fixtures"))):
    """Build the guardian-fixture demo repository (5 commits, planted signals)."""
    from .fixture import make_fixture
    console.print(str(make_fixture(dest)))
    console.print("[dim]Offline Day 2 demo data: --advisory-db fixture --registry-snapshot fixture[/]")


# =============================================================================== Day 2
def _data_file(value: Path | None, name: str) -> Path | None:
    """'fixture' selects the bundled offline snapshot for the guardian-fixture demo."""
    if value is None:
        return None
    if str(value) == "fixture":
        from importlib import resources
        return Path(str(resources.files("guardian.data").joinpath(name)))
    return value


def _d2_settings(offline: bool, no_llm: bool, no_docker: bool, sandbox: str, advisory_db: Path | None,
                 registry_snapshot: Path | None, policy: Path | None, max_queue: int, finalists: int, model: str | None) -> Settings:
    return Settings(offline=offline, use_llm=not no_llm, use_docker=not no_docker, llm_model=model,
                    advisory_db=_data_file(advisory_db, "fixture_advisories.json"),
                    registry_snapshot=_data_file(registry_snapshot, "fixture_registry.json"), sandbox=sandbox,
                    policy_path=policy, max_queue=max_queue, max_finalists=finalists)


def _print_day2(res) -> None:
    from .day2.models import RemediationPlan  # noqa: F401
    t = Table(title="Remediation plans")
    for c in ("plan", "status", "recommended", "hash"):
        t.add_column(c)
    for p in res.plans:
        rec = p.candidate(p.recommended) if p.recommended else None
        t.add_row(p.title[:60], p.status, (rec.summary[:70] if rec else "-"), p.plan_hash[:16])
    console.print(t)
    for r in res.reports:
        color = {"Verified": "green", "Partially verified": "yellow"}.get(r.verdict, "red")
        console.print(f"  [{color}]{r.verdict}[/] ({r.confidence}) {r.title[:80]}")
    waiting = [p for p in res.plans if p.status == "awaiting_approval"]
    if waiting:
        console.print("\n[bold]Awaiting approval[/] (review the plan, then):")
        for p in waiting:
            console.print(f"  guardian approve {res.run_dir} \"{p.plan_key}\" --hash {p.plan_hash[:16]} --reviewer <name>")
        console.print(f"  then: guardian remediate {res.run_dir}")
    console.print(f"\nUnified report: [bold]{res.run_dir / 'report.html'}[/] (Remediation tab; standalone: day2/remediation.html)")


def _emit(ev: dict) -> None:
    console.print(f"  {ev['node']:<16} {ICON.get(ev['status'], ev['status'])}  [dim]{ev.get('seconds', '')}s[/]  {ev.get('message', '')}")


@app.command()
def remediate(run_dir: Path = typer.Argument(..., help="a finished Day 1 run directory (output/<repo>/<run_id>)"),
              finding: list[str] = typer.Option(None, "--finding", help="only these plan keys / finding ids (repeatable)"),
              replan: bool = typer.Option(False, help="regenerate plans even if a plan is awaiting a decision"),
              sandbox: str = typer.Option("docker", help="docker | local (runs repo code on this machine) | none"),
              offline: bool = typer.Option(False), no_llm: bool = typer.Option(False, "--no-llm"),
              no_docker: bool = typer.Option(False, "--no-docker"),
              advisory_db: Path = typer.Option(None, help="offline OSV snapshot JSON ('fixture' = bundled demo data)"),
              registry_snapshot: Path = typer.Option(None, help="offline registry snapshot JSON ('fixture' = bundled demo data)"),
              policy: Path = typer.Option(None, help="extra policy YAML (floor rules cannot be weakened)"),
              max_queue: int = typer.Option(5, help="plans per run (top of the Fix-now bucket)"),
              finalists: int = typer.Option(3, help="tournament round-2 size"),
              interactive: bool = typer.Option(False, help="ask for approval in the terminal, then continue"),
              model: str = typer.Option(None)):
    """Day 2: prioritize -> investigate -> plan -> (approval) -> validate -> rescan -> verify. Re-run to resume."""
    from .day2.pipeline import run_day2
    s = _d2_settings(offline, no_llm, no_docker, sandbox, advisory_db, registry_snapshot, policy, max_queue, finalists, model)
    console.print(f"[bold]Guardian Day 2[/] on {run_dir}")
    res = run_day2(run_dir, s, only=finding or None, replan=replan, emit=_emit)
    _print_day2(res)
    if interactive:
        waiting = [p for p in res.plans if p.status == "awaiting_approval"]
        if not waiting:
            return
        reviewer = typer.prompt("Reviewer name")
        from .day2.decisions import record
        decided = False
        for p in waiting:
            console.print(f"\n[bold]{p.title}[/]  rev {p.revision}  hash {p.plan_hash[:16]}")
            for cid in p.finalists:
                c = p.candidate(cid)
                console.print(f"  finalist {c.id}: {c.summary}  [dim](compat {c.compatibility})[/]")
                if c.diff:
                    console.print(f"[dim]{c.diff[:1500]}[/]")
            choice = typer.prompt("approve / reject / skip", default="skip")
            if choice in ("approve", "reject"):
                reason = typer.prompt("Reason", default="")
                record(run_dir, p.plan_key, choice, reviewer, p.plan_hash, reason)
                decided = True
        if decided:
            res = run_day2(run_dir, s, only=finding or None, emit=_emit)
            _print_day2(res)


@app.command()
def heal(target: str = typer.Argument(None, help="clone under output/clones (name or path), or a GitHub URL"),
         list_: bool = typer.Option(False, "--list", help="list clones under output/clones and exit"),
         reviewer: str = typer.Option(None, help="your name: enables interactive approval in this terminal"),
         max_iterations: int = typer.Option(3, help="maximum observe -> fix cycles"),
         max_retries: int = typer.Option(2, help="fallback attempts per plan (next finalist, self-correction)"),
         bands: str = typer.Option("P0,P1", help="bands counted towards the threshold"),
         max_remaining: int = typer.Option(0, help="stop when at most this many counted findings remain"),
         count_signals: bool = typer.Option(False, help="count non-CVE findings too (not only vulnerabilities)"),
         require_verified: bool = typer.Option(False, help="apply only 'Verified' fixes (default also 'Partially verified')"),
         restart: bool = typer.Option(False, help="start a new heal branch instead of resuming"),
         skip_pending: bool = typer.Option(False, help="continue without deciding the plans waiting in this iteration "
                                                       "(skipped, not rejected; asked again next iteration)"),
         allow_any_path: bool = typer.Option(False, help="allow repositories outside output/clones"),
         out: Path = typer.Option(Path("output")), sandbox: str = typer.Option("docker"), offline: bool = typer.Option(False),
         no_llm: bool = typer.Option(False, "--no-llm"), no_docker: bool = typer.Option(False, "--no-docker"),
         advisory_db: Path = typer.Option(None), registry_snapshot: Path = typer.Option(None), model: str = typer.Option(None)):
    """Agentic heal loop on a cloned repo: scan -> plan -> HUMAN APPROVAL -> validate -> apply to the clone (branch
    guardian/heal-*) -> verify in place (rollback + next candidate on failure) -> repeat until the threshold is met."""
    from .day2.heal import HealConfig, HealError, heal as run_heal
    clones = Path(out) / "clones"
    if list_ or not target:
        for d in sorted(p for p in clones.glob("*") if (p / ".git").exists()):
            console.print(f"  {d.name}")
        return
    cfg = HealConfig(max_iterations=max_iterations, max_retries=max_retries, bands=tuple(b.strip() for b in bands.split(",") if b.strip()),
                     max_remaining=max_remaining, count_signals=count_signals,
                     accept=("Verified",) if require_verified else ("Verified", "Partially verified"), out_dir=out,
                     allowed_root=None if allow_any_path else clones)
    s = _d2_settings(offline, no_llm, no_docker, sandbox, advisory_db, registry_snapshot, None, 5, 3, model)

    def approver(plan, run_dir):
        console.print(f"\n[bold]{plan.title}[/]  rev {plan.revision}  hash {plan.plan_hash[:16]}")
        for cid in plan.finalists:
            c = plan.candidate(cid)
            console.print(f"  finalist {c.id}: {c.summary}  [dim](compatibility {c.compatibility}; rollback: {c.rollback})[/]")
            if c.diff:
                console.print(f"[dim]{c.diff[:1200]}[/]")
        choice = typer.prompt("approve / reject / skip", default="skip")
        if choice not in ("approve", "reject"):
            return None
        return choice, typer.prompt("Reason", default="")

    try:
        st = run_heal(target, s, cfg, approver=approver if reviewer else None, reviewer=reviewer, emit=_emit, restart=restart,
                      skip_pending=skip_pending)
    except HealError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    color = {"threshold_met": "green", "awaiting_approval": "yellow"}.get(st.status, "red")
    console.print(f"\n[{color}]{st.status}[/]: {st.stop_reason}")
    console.print(f"branch {st.branch} in {st.clone_path}")
    for f in st.fixes:
        console.print(f"  it{f.iteration} {f.status:<12} {f.summary[:80]}  {(f.commit or '')[:10]}")
        if f.status == "applied":
            for path in f.files:
                console.print(f"      changed: {path}")
    if st.status == "awaiting_approval":
        run_dir = st.current.run_dir
        console.print(f"\nApprove in the UI or with `guardian approve {run_dir} <plan> --hash <hash> --reviewer <name>`,"
                      f" then run `guardian heal {target}` again (or pass --reviewer to approve here).")
    console.print(f"Heal report: [bold]{Path(out) / 'heal' / st.repo / 'heal.html'}[/]")


@app.command()
def plans(run_dir: Path = typer.Argument(...)):
    """List Day 2 plans with their candidates, finalists and hashes."""
    from .day2.decisions import open_d2
    st, d2 = open_d2(run_dir)
    try:
        for p in d2.plans():
            console.print(f"\n[bold]{p.title}[/]\n  key {p.plan_key}  rev {p.revision}  status {p.status}\n  hash {p.plan_hash}")
            for c in sorted(p.candidates, key=lambda c: c.rank or 99):
                mark = "[green]finalist[/]" if c.id in p.finalists else (f"[red]rejected[/] {c.rejected_reason}" if c.rejected_reason else "")
                console.print(f"   {c.rank or '-':>2} {c.id} [{c.action}] {c.summary[:90]}  compat={c.compatibility} {mark}")
    finally:
        st.close()


def _decide(run_dir, plan, decision, reviewer, hash_, reason, candidate=None, expires=None):
    from .day2.decisions import PlanNotFound, record
    try:
        p = record(run_dir, plan, decision, reviewer, hash_, reason, candidate, expires)
    except (PlanNotFound, ValueError, PermissionError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    console.print(f"{decision}: {p.title}  rev {p.revision}  hash {p.plan_hash[:16]}  status {p.status}")
    if decision == "approve":
        console.print(f"next: guardian remediate {run_dir}")


@app.command()
def approve(run_dir: Path = typer.Argument(...), plan: str = typer.Argument(..., help="plan key, finding id or unique substring"),
            hash_: str = typer.Option(..., "--hash", help="the plan hash you reviewed (>= 12 chars)"),
            reviewer: str = typer.Option(..., help="your name"), reason: str = typer.Option(""),
            candidate: list[str] = typer.Option(None, help="approve only these candidate ids (creates a new revision)")):
    """Approve the exact plan hash you reviewed (append-only record)."""
    _decide(run_dir, plan, "approve", reviewer, hash_, reason, candidate or None)


@app.command()
def reject(run_dir: Path = typer.Argument(...), plan: str = typer.Argument(...), hash_: str = typer.Option(..., "--hash"),
           reviewer: str = typer.Option(...), reason: str = typer.Option(...)):
    """Reject a plan."""
    _decide(run_dir, plan, "reject", reviewer, hash_, reason)


@app.command("accept-risk")
def accept_risk(run_dir: Path = typer.Argument(...), plan: str = typer.Argument(...), hash_: str = typer.Option(..., "--hash"),
                reviewer: str = typer.Option(...), reason: str = typer.Option(...),
                expires: str = typer.Option(..., help="YYYY-MM-DD")):
    """Accept the risk with a reason and an expiry date (checked by the risk-acceptance policy rule)."""
    _decide(run_dir, plan, "accept_risk", reviewer, hash_, reason, None, expires)


@app.command("export-patch")
def export_patch_cmd(run_dir: Path = typer.Argument(...), plan: str = typer.Argument(...), reviewer: str = typer.Option(...),
                     reason: str = typer.Option("")):
    """Second approval (bound to the verified diff hash) and a git patch file. Nothing is pushed."""
    from .day2.decisions import PlanNotFound, export_patch
    try:
        p = export_patch(run_dir, plan, reviewer, reason)
    except (PlanNotFound, ValueError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    console.print(f"patch: {p}")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000, out: Path = Path("output")):
    """Start the HTTP API (POST /runs, GET /runs/{id}/report ...)."""
    import uvicorn

    from .api import create_app
    uvicorn.run(create_app(out), host=host, port=port)


if __name__ == "__main__":
    app()
