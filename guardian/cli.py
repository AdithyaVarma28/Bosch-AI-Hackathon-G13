from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(help="Guardian: supply-chain context for Python repositories.", no_args_is_help=True)


@app.callback()
def main() -> None:
    """Guardian CLI."""


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
    offline: bool = typer.Option(False, "--offline", help="Skip remote PyPI API calls"),
    skip_sbom: bool = typer.Option(False, "--skip-sbom", help="Skip Syft SBOM generation"),
) -> None:
    """Stage 1 facts + Stage 2 code index, linked: writes facts.json, code_index.json, summary.json."""
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
    typer.echo(f"output: {dest}")


if __name__ == "__main__":
    app()
