from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(help="Guardian: supply-chain context for Python repositories.", no_args_is_help=True)


@app.callback()
def main() -> None:
    """Guardian CLI."""


def _force_rmtree(path: Path) -> None:
    """``shutil.rmtree`` that also deletes read-only files (git objects on Windows)."""
    import os
    import shutil
    import stat

    def _retry(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass

    if Path(path).exists():
        import sys
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=_retry)
        else:  # pragma: no cover
            shutil.rmtree(path, onerror=_retry)


def _require_dir(target: str) -> Path:
    repo = Path(target).resolve()
    if not repo.is_dir():
        typer.echo(f"error: {target} is not a directory", err=True)
        raise typer.Exit(code=1)
    return repo


@app.command()
def index(
    target: str = typer.Argument(..., help="Local path to a repository"),
    out: str = typer.Option("output", "--out", "--output", "-o", help="Output directory"),
    facts: Optional[str] = typer.Option(None, help="Stage 1 facts.json: its resolved packages sharpen the import-name map"),
) -> None:
    """Stage 2 only: write <out>/<repo>/code_index.json (imports, calls, routes, env reads, ...)."""
    from guardian.models.facts import ScanFacts
    from guardian.stage2_code.parser import index_repo

    repo = _require_dir(target)
    resolved = None
    if facts:
        resolved = ScanFacts.model_validate_json(Path(facts).read_text(encoding="utf-8")).resolved_packages
    idx = index_repo(repo, cache_dir=Path(out) / ".cache", resolved=resolved)
    dest = Path(out) / repo.name
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "code_index.json").write_text(idx.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(f"{repo.name}: {len(idx.files)} files, {len(idx.errors)} errors -> {dest / 'code_index.json'}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Local path to a repository"),
    out: str = typer.Option("output", "--out", "--output", "-o", help="Output directory"),
    docker: bool = typer.Option(False, "--docker", help="Run pip dependency resolution inside Docker"),
    offline: bool = typer.Option(False, "--offline", help="Skip remote PyPI API calls (and LLM calls in Stage 3)"),
    skip_sbom: bool = typer.Option(False, "--skip-sbom", help="Skip Syft SBOM generation"),
    stage3: bool = typer.Option(True, "--stage3/--no-stage3", help="Run Stage 3 (knowledge graph) after Stages 1-2"),
    stage4: bool = typer.Option(True, "--stage4/--no-stage4", help="Run Stage 4 (vulnerability investigation) after Stage 3"),
    stage5: bool = typer.Option(True, "--stage5/--no-stage5", help="Run Stage 5 (supply-chain anomalies) after Stage 4"),
    llm: str = typer.Option("auto", "--llm", help="LLM for Stages 3-5: auto | groq | gemini | anthropic | offline"),
    osv_dump: Optional[str] = typer.Option(None, "--osv-dump", help="OSV PyPI all.zip for offline vulnerability matching"),
    day2: bool = typer.Option(True, "--day2/--no-day2", help="Day 2: prioritize findings and plan remediations after Stage 5"),
) -> None:
    """Stages 1 -> 5 (+ Day 2): facts.json, code_index.json, summary.json, the Stage 3 knowledge graph, Stage 4 findings."""
    from guardian.adapters import declared_vs_used
    from guardian.stage1_facts.collector import run_stage1_collection
    from guardian.stage2_code.parser import index_repo

    repo = _require_dir(target)
    dest = Path(out) / repo.name
    facts = run_stage1_collection(repo_path=repo, output_dir=dest, use_docker=docker, offline=offline,
                                  skip_sbom=skip_sbom)
    idx = index_repo(repo, cache_dir=Path(out) / ".cache", resolved=facts.resolved_packages)
    (dest / "code_index.json").write_text(idx.model_dump_json(indent=2), encoding="utf-8")
    link = declared_vs_used(facts, idx)
    (dest / "summary.json").write_text(link.model_dump_json(indent=2), encoding="utf-8")

    routes = sum(len(f.routes) for f in idx.files)
    sensitive = sum(len(f.sensitive_calls) for f in idx.files)
    typer.echo(f"{repo.name}: stage 1 -> {len(facts.declared_dependencies)} declared, "
               f"{len(facts.resolved_packages)} resolved, {len(facts.ci_workflows)} workflows, "
               f"{len(facts.containers)} dockerfiles, {len(facts.errors)} stage-1 warnings")
    typer.echo(f"{repo.name}: stage 2 -> {len(idx.files)} files, {routes} routes, "
               f"{sensitive} sensitive calls, {len(idx.errors)} errors")
    typer.echo(f"{repo.name}: declared but never imported: {link.declared_not_imported or 'none'}; "
               f"imported but not declared: {link.imported_not_declared or 'none'}")
    if stage3:
        from guardian.stage3_knowledge import run_stage3
        s3 = run_stage3(dest, repo_path=repo, llm_provider="offline" if offline and llm == "auto" else llm,
                        log=typer.echo)
        if stage4:
            from guardian.stage4_vulns import run_stage4
            s4 = run_stage4(s3, offline=offline, osv_dump=osv_dump, log=typer.echo)
            if stage5:
                try:
                    from guardian.stage5_anomalies import run_stage5
                except ImportError:
                    run_stage5 = None
                if run_stage5:
                    run_stage5(s4, offline=offline, log=typer.echo)
                    if day2:
                        from guardian.day2 import run_day2
                        run_day2(dest, repo=repo, llm=s3.llm, offline=offline, osv_dump=osv_dump, log=typer.echo)
    typer.echo(f"output: {dest}")


@app.command()
def vulns(
    scan_dir: str = typer.Argument(..., help="Folder with the Stage 3 output (graph.json, ...)"),
    offline: bool = typer.Option(False, "--offline", help="No network: OSV dump and cached feeds only"),
    osv_dump: Optional[str] = typer.Option(None, "--osv-dump", help="OSV PyPI all.zip (default: <output>/.cache/vulndb)"),
    image: Optional[list[str]] = typer.Option(None, "--image", help="Container image(s) for Grype (default: Dockerfile base images)"),
    llm: str = typer.Option("auto", "--llm", help="auto | groq | gemini | anthropic | offline"),
    model: Optional[str] = typer.Option(None, "--model", help="LLM model id (default claude-opus-5-5)"),
) -> None:
    """Stage 4 only: find known vulnerabilities and investigate them on an existing Stage 3 output."""
    from guardian.stage4_vulns import run_stage4_from_output

    run_stage4_from_output(scan_dir, llm_provider="offline" if offline else llm, model=model, offline=offline,
                           osv_dump=osv_dump, images=image or None, log=typer.echo)


@app.command()
def remediate(
    scan_dir: str = typer.Argument(..., help="Scan folder with Stage 4/5 output (vuln_findings.json, ...)"),
    repo: Optional[str] = typer.Option(None, "--repo", help="The scanned repository (default: from scan.json / graph.json)"),
    offline: bool = typer.Option(False, "--offline", help="No network: OSV dump and cached data only"),
    osv_dump: Optional[str] = typer.Option(None, "--osv-dump", help="OSV PyPI dump for offline version checks"),
    llm: str = typer.Option("auto", "--llm", help="auto | groq | gemini | anthropic | offline"),
    agent: bool = typer.Option(False, "--agent", help="Let the remediation agent write first proposals for Critical/High"),
) -> None:
    """Day 2: prioritize every finding (SSVC-inspired) and plan remediations with human approval gates."""
    from guardian.day2 import run_day2
    from guardian.stage3_knowledge.llm import LLM

    out = Path(scan_dir)
    model = LLM(provider="offline" if llm == "offline" else None if llm == "auto" else llm, cache_dir=out / ".llm_cache")
    run_day2(out, repo=repo, llm=model, offline=offline, osv_dump=osv_dump, log=typer.echo, use_agent=agent or None)


@app.command()
def vulndb(
    action: str = typer.Argument("download", help="download: fetch the OSV PyPI dump for offline scans"),
    dest: Optional[str] = typer.Option(None, "--dest", help="Where to store all.zip (default: output/.cache/vulndb)"),
) -> None:
    """Download the OSV PyPI vulnerability dump so scans work without network."""
    from guardian.stage4_vulns.sources import download_dump

    if action != "download":
        typer.echo("error: only 'download' is supported", err=True)
        raise typer.Exit(code=1)
    target = Path(dest) if dest else Path("output") / ".cache" / "vulndb" / "osv-PyPI-all.zip"
    download_dump(target, log=typer.echo)


@app.command()
def review(
    scan_dir: str = typer.Argument(..., help="Output folder of a scan"),
    finding_id: str = typer.Argument(..., help="Finding id, e.g. F-002 or A-001"),
    action: str = typer.Option(..., "--action", help="confirm | dismiss | override"),
    reason: Optional[str] = typer.Option(None, "--reason", help="dismiss: false_positive | not_used | accepted_risk | mitigated_elsewhere; override: free text"),
    risk: Optional[str] = typer.Option(None, "--risk", help="override: low | medium | high | critical"),
    note: Optional[str] = typer.Option(None, "--note"),
    by: Optional[str] = typer.Option(None, "--by", help="Reviewer name"),
) -> None:
    """Record a human review decision (resumes the paused review workflow, persisted in triage.json)."""
    from guardian.stage4_vulns.review import ReviewError, load_cards, submit_review
    from guardian.stage4_vulns.schema import ReviewDecision

    out = Path(scan_dir)
    target = next((f for f in ("vuln_findings.json", "anomaly_findings.json")
                   if any(c.get("finding_id") == finding_id for c in load_cards(out / f))), None)
    if not target:
        typer.echo(f"error: finding {finding_id} not found in {out}", err=True)
        raise typer.Exit(code=1)
    try:
        card = submit_review(out, target, finding_id, ReviewDecision(action=action, reason=reason, new_risk=risk,
                                                                     note=note, by=by))
    except (ReviewError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"{finding_id}: {card['review']['status']} (project risk {card['project_risk']})")


@app.command()
def knowledge(
    scan_dir: str = typer.Argument(..., help="Stage 1-2 output folder (facts.json + code_index.json)"),
    repo: Optional[str] = typer.Option(None, "--repo", help="Path to the scanned repository (source reads, git diff)"),
    baseline_dir: Optional[str] = typer.Option(None, "--baseline-dir", help="Stage 1-2 output of a baseline commit (full graph diff)"),
    baseline_commit: Optional[str] = typer.Option(None, "--baseline-commit", help="Baseline commit (default: oldest dependency commit)"),
    llm: str = typer.Option("auto", "--llm", help="auto | groq | gemini | anthropic | offline"),
    model: Optional[str] = typer.Option(None, "--model", help="LLM model id (default claude-opus-5-5)"),
) -> None:
    """Stage 3 only: build the knowledge graph from an existing Stage 1-2 output folder."""
    from guardian.stage3_knowledge import run_stage3

    run_stage3(scan_dir, repo_path=repo, baseline_dir=baseline_dir, baseline_commit=baseline_commit,
               llm_provider=llm, model=model, log=typer.echo)


@app.command()
def serve(
    scan_dir: str = typer.Argument(..., help="Folder with the Stage 3 output (graph.json, ...)"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Serve the Stage 3 API and the dashboard (open http://host:port/)."""
    import uvicorn

    from guardian.stage3_knowledge.api import create_app

    uvicorn.run(create_app(scan_dir), host=host, port=port)



@app.command()
def web(
    root: str = typer.Option("output/scans", "--root", help="Folder of scan snapshots (one sub-folder per scan)"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Stage 6: serve the /api backend and the web app (open http://host:port/)."""
    import uvicorn

    from guardian.webapp import create_web_app

    uvicorn.run(create_web_app(root), host=host, port=port)


@app.command()
def demo(
    root: str = typer.Option("output/scans", "--root", help="Where to store the demo snapshots"),
    workdir: str = typer.Option("output/demo-fixture", "--workdir", help="Where to build the mini-shop fixture"),
    llm: str = typer.Option("offline", "--llm", help="offline (default) | groq | gemini | anthropic | auto: AI for the stored scans"),
) -> None:
    """Build the precomputed demo scans (mini-shop baseline + HEAD). No OSV/PyPI network; no LLM unless --llm."""
    import os
    import shutil
    import subprocess
    import sys

    from guardian.stage4_vulns.schema import ReviewDecision
    from guardian.stage4_vulns.review import submit_review
    from guardian.webapp.store import run_pipeline

    here = Path(__file__).resolve().parents[1]
    work = Path(workdir).resolve()
    _force_rmtree(work)
    subprocess.run([sys.executable, str(here / "tests" / "fixtures" / "make_mini_shop_full.py"), str(work)], check=True)
    os.environ["GUARDIAN_PYPI_URL"] = str(work / "fake-pypi" / "pypi")
    dump = here / "tests" / "data" / "osv_minishop.zip"
    base_repo = work / "mini-shop-baseline"
    subprocess.run(["git", "clone", "-q", str(work / "mini-shop"), str(base_repo)], check=True)
    first = subprocess.run(["git", "-C", str(base_repo), "rev-list", "--max-parents=0", "HEAD"], capture_output=True,
                           text=True, check=True).stdout.split()[0]
    subprocess.run(["git", "-C", str(base_repo), "checkout", "-q", first], check=True)
    for sid, repo in (("demo-minishop-baseline", base_repo), ("demo-minishop-head", work / "mini-shop")):
        dest = Path(root) / sid
        kept = work / f".llm_cache-{sid}"          # keep LLM answers across rebuilds (saves free quota)
        if (dest / ".llm_cache").is_dir():
            shutil.copytree(dest / ".llm_cache", kept, dirs_exist_ok=True)
        _force_rmtree(dest)
        dest.mkdir(parents=True)
        if kept.is_dir():
            shutil.copytree(kept, dest / ".llm_cache")
        typer.echo(f"demo: scanning {repo.name} -> {dest} (LLM: {llm})")
        run_pipeline(repo, dest, offline=True, llm=llm, osv_dump=str(dump),
                     log=(typer.echo if llm != "offline" else (lambda m: None)), scan_id=sid)
        import json
        from datetime import datetime, timezone
        facts = json.loads((dest / "facts.json").read_text(encoding="utf-8"))
        (dest / "scan.json").write_text(json.dumps({
            "scan_id": sid, "repo": "mini-shop", "repo_path": str(repo), "commit": facts["repo"]["commit"],
            "created_at": datetime.now(timezone.utc).isoformat(), "status": "done", "demo": True,
            "label": "baseline (first commit)" if "baseline" in sid else "HEAD"}, indent=2), encoding="utf-8")
    head = Path(root) / "demo-minishop-head"
    cards = json.loads((head / "vuln_findings.json").read_text(encoding="utf-8"))
    pyyaml = next((c for c in cards if c["component_name"] == "PyYAML"), None)
    if pyyaml:   # one confirmed vulnerable dependency with a recorded review decision
        submit_review(head, "vuln_findings.json", pyyaml["finding_id"],
                      ReviewDecision(action="confirm", by="demo reviewer", note="startup config loader; upgrade planned"))
    typer.echo(f"demo scans ready in {root}: run `guardian web --root {root}`")


@app.command("demo-check")
def demo_check(
    url: str = typer.Argument(..., help="GitHub link of a candidate demo repository"),
    root: str = typer.Option("output/scans", "--root", help="Where the scan snapshots are stored"),
    approve: int = typer.Option(4, "--approve", help="How many validated vulnerability fixes to approve (build health is always approved)"),
    runs: int = typer.Option(1, "--runs", help="Run the whole flow this many times (the plan asks for 2 passes in a row)"),
    llm: str = typer.Option("offline", "--llm", help="offline (default) | auto | groq …: AI for the scan and probes"),
) -> None:
    """Run the full flow (scan → plan → validate → approve → fixed repo → report) headless on a GitHub link and
    print the demo-repository criteria table (docs/DAY_2_COMPLETION_PLAN.md section 3.1)."""
    import json as _json

    from guardian.day2.democheck import run as run_check, table

    results = []
    for i in range(runs):
        typer.echo(f"== run {i + 1} of {runs}")
        res = run_check(url, Path(root), approve=approve, llm=llm, log=typer.echo)
        results.append(res)
        typer.echo(table(res))
    if runs > 1:
        ok = all(all(c["ok"] for c in r.get("criteria") or []) for r in results)
        typer.echo(f"stable: {'yes' if ok else 'no'} ({runs} runs, all criteria passing in every run: {ok})")
    Path(root, "demo_check_last.json").write_text(_json.dumps(results, indent=2, default=str), encoding="utf-8")


if __name__ == "__main__":
    app()
