"""CLI: guardian scan <github-url-or-path> | guardian fixture | guardian serve"""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .context import Settings

app = typer.Typer(add_completion=False, help="Software Supply Chain Guardian (Day 1: visibility and detection)")
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
         model: str = typer.Option(None, help="Groq model id (default env GROQ_MODEL or openai/gpt-oss-120b)")):
    """Scan a repository and write facts.json, sbom.cdx.json, code_index.json, graph.json, report.json/html."""
    from .orchestrator import run_pipeline
    settings = Settings(offline=offline, use_llm=not no_llm, use_docker=not no_docker, history_depth=history,
                        max_explanations=explain, llm_model=model)

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
    console.print(f"\nReport: [bold]{res.run_dir / 'report.html'}[/]\nJSON:   {res.report_path}")


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


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000, out: Path = Path("output"),
          web: Path | None = None):
    """Start the HTTP API and, if built, the web dashboard (web/dist)."""
    import uvicorn

    from .api import create_app
    if web is None:
        default = Path(__file__).resolve().parents[2] / "web" / "dist"
        web = default if default.exists() else None
    uvicorn.run(create_app(out, web), host=host, port=port)


if __name__ == "__main__":
    app()
