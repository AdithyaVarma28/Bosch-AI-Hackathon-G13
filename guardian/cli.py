from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from guardian.stage1_facts.collector import run_stage1_collection

app = typer.Typer(
    name="guardian",
    help="Software Supply Chain Guardian: Multi-Layer Dependency Graph & Security Context",
    no_args_is_help=True,
    add_completion=False
)
console = Console()


@app.callback()
def main():
    """Software Supply Chain Guardian CLI"""
    pass


@app.command("scan")
def scan(
    repo_path: Path = typer.Argument(..., help="Path to Python repository to analyze"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Directory for facts.json and sbom"),
    use_docker: bool = typer.Option(False, "--docker", help="Run pip dependency resolution inside Docker"),
    offline: bool = typer.Option(False, "--offline", help="Skip remote PyPI API calls"),
    skip_sbom: bool = typer.Option(False, "--skip-sbom", help="Skip Syft SBOM generation"),
):
    """Deterministic Fact Collection (Stage 1)."""
    if not repo_path.exists():
        console.print(f"[red]Error:[/red] Target repository path does not exist: {repo_path}")
        raise typer.Exit(code=1)

    repo_name = repo_path.resolve().name
    target_output = output or (Path("output") / repo_name)

    console.print(Panel(
        f"[bold cyan]Software Supply Chain Guardian[/bold cyan] - Stage 1 Fact Collection\n"
        f"Scanning: [green]{repo_path.resolve()}[/green]\n"
        f"Output:   [yellow]{target_output.resolve()}[/yellow]",
        border_style="cyan"
    ))

    with console.status("[bold green]Collecting deterministic supply chain facts...", spinner="dots"):
        facts = run_stage1_collection(
            repo_path=repo_path,
            output_dir=target_output,
            use_docker=use_docker,
            offline=offline,
            skip_sbom=skip_sbom
        )

    # Summary table
    table = Table(title="Stage 1 Collection Summary", border_style="dim")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right", style="green")

    table.add_row("Declared Dependencies", str(len(facts.declared_dependencies)))
    table.add_row("Package Indexes", str(len(facts.package_indexes)))
    table.add_row("Resolved Packages", str(len(facts.resolved_packages)))
    table.add_row("PyPI Metadata Records", str(len(facts.package_metadata)))
    table.add_row("CI/CD Workflows", str(len(facts.ci_workflows)))
    table.add_row("Container Dockerfiles", str(len(facts.containers)))
    table.add_row("Dependency Commits Analyzed", str(len(facts.dependency_history)))
    table.add_row("Environment Files", str(len(facts.config.env_files)))
    table.add_row("Compose Services", str(len(facts.config.compose_services)))
    table.add_row("Files Hashed", str(len(facts.file_hashes)))
    table.add_row("Warnings / Errors", str(len(facts.errors)))

    console.print(table)

    if facts.sbom_path:
        console.print(f"[bold green]✔[/bold green] Syft CycloneDX SBOM written to: [blue]{facts.sbom_path}[/blue]")
    console.print(f"[bold green]✔[/bold green] Facts saved to: [blue]{target_output / 'facts.json'}[/blue]")

    if facts.errors:
        console.print(Panel(
            "\n".join(f"- {e}" for e in facts.errors[:10]),
            title=f"[yellow]Warnings / Errors ({len(facts.errors)})[/yellow]",
            border_style="yellow"
        ))


if __name__ == "__main__":
    app()
