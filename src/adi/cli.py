"""KAI command-line interface."""

from __future__ import annotations

import asyncio
import sys

import typer
from rich.console import Console
from rich.table import Table

from kai import __version__
from kai.assessment import Assessment, discover_skills_dir
from kai.config.settings import load_config
from kai.runtime.docker_runtime import DockerKaliRuntime
from kai.scope.models import AssessmentMode, Scope
from kai.tools.registry import ToolRegistry

app = typer.Typer(add_completion=False, help="KAI — autonomous security assessment workspace.")
console = Console()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, version: bool = typer.Option(False, "--version")):
    if version:
        console.print(f"kai {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


@app.command()
def doctor():
    """Check that KAI's environment is ready."""
    console.print("[bold]KAI Environment Check[/bold]\n")
    ok = True

    console.print(f"[green]✓[/green] Python {sys.version_info.major}.{sys.version_info.minor}")

    config = load_config()
    console.print(f"[green]✓[/green] Config loaded (runtime type: {config.runtime.type})")

    docker_runtime = DockerKaliRuntime(image=config.runtime.image)
    docker_available = asyncio.run(docker_runtime.is_available())
    if docker_available:
        console.print(f"[green]✓[/green] Docker runtime available (image: {config.runtime.image})")
    else:
        console.print(
            f"[yellow]✗[/yellow] Docker runtime unavailable "
            f"(no Docker daemon reachable, or image '{config.runtime.image}' not built). "
            f"KAI will refuse to run tools against real targets without an isolated runtime "
            f"unless runtime.type=local is explicitly opted into in .kai.yaml."
        )
        ok = False

    try:
        import sqlalchemy  # noqa: F401
        console.print("[green]✓[/green] SQLite/SQLAlchemy ready")
    except ImportError:
        console.print("[red]✗[/red] SQLAlchemy not installed")
        ok = False

    try:
        import playwright  # noqa: F401
        console.print("[green]✓[/green] Playwright installed")
    except ImportError:
        console.print("[yellow]○[/yellow] Playwright not installed (browser capabilities disabled)")

    registry = ToolRegistry(discover_skills_dir())
    tools = registry.discover()
    available = [t for t in tools if t.available]
    console.print(f"[green]✓[/green] {len(tools)} security tool skill(s) registered, "
                  f"{len(available)} available on PATH")
    for tool in tools:
        mark = "[green]✓[/green]" if tool.available else "[yellow]○[/yellow]"
        console.print(f"    {mark} {tool.metadata.name}")

    import os
    if os.environ.get("KAI_LLM_API_KEY") or config.provider.api_key_env in os.environ:
        console.print("[green]✓[/green] LLM provider configured")
    else:
        console.print(
            f"[yellow]○[/yellow] LLM provider not configured "
            f"(set ${config.provider.api_key_env}) — deterministic tool execution still works, "
            f"but autonomous planning will not."
        )

    console.print()
    if ok:
        console.print("[bold green]KAI is ready.[/bold green]")
    else:
        console.print("[bold yellow]KAI has warnings above — see docs/architecture.md.[/bold yellow]")


@app.command()
def tools():
    """List discovered security tool skills."""
    registry = ToolRegistry(discover_skills_dir())
    discovered = registry.discover()
    table = Table(title="Tool Skills")
    table.add_column("Name")
    table.add_column("Available")
    table.add_column("Risk")
    table.add_column("Capabilities")
    for tool in discovered:
        table.add_row(
            tool.metadata.name,
            "yes" if tool.available else "no",
            tool.metadata.risk_level,
            ", ".join(tool.metadata.capabilities),
        )
    console.print(table)


@app.command()
def lab(
    target: str = typer.Argument(..., help="Target host/IP/URL for the lab assessment."),
    name: str = typer.Option(None, help="Assessment name (defaults to target)."),
    max_actions: int = typer.Option(150, help="Action budget for this assessment."),
):
    """Create and start a LAB-mode assessment against an isolated target
    (CTF box, local vulnerable app, mock exam environment)."""
    config = load_config()
    scope = Scope(
        name=name or f"lab-{target}",
        mode=AssessmentMode.LAB,
        targets=[target],
        max_actions=max_actions,
    )
    assessment = Assessment.create(scope, config)
    console.print(f"[bold]Assessment created:[/bold] {assessment.id}")
    console.print(f"Target: {target}")
    console.print(f"Workspace: {assessment.directory}")
    console.print()
    console.print(
        "[yellow]Note:[/yellow] the autonomous planning loop (Phase 2) is not yet active in "
        "this build. Use 'kai run-tool' or the Python API to execute tools against this "
        "assessment's workspace."
    )


@app.command("run-tool")
def run_tool(
    assessment_id: str = typer.Argument(...),
    tool: str = typer.Argument(...),
    target: str = typer.Argument(...),
    ports: str = typer.Option(None, help="Port spec, e.g. '22,80,443' (nmap-style tools)."),
):
    """Directly execute a single tool inside an assessment's runtime and
    fold results into its knowledge graph. Useful for Phase 1 manual
    operation and for testing tool skills end-to-end."""
    config = load_config()
    assessment = Assessment.resume(assessment_id, config)
    params = {"ports": ports} if ports else {}

    async def _run():
        return await assessment.executor.run(tool, target, params, reason_summary="manual invocation")

    try:
        observations = asyncio.run(_run())
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    console.print(f"[bold]{len(observations)} observation(s) recorded[/bold]")
    for obs in observations:
        console.print(f"  • {obs}")


@app.command()
def status(assessment_id: str = typer.Argument(...)):
    """Show the current state of an assessment."""
    config = load_config()
    assessment = Assessment.resume(assessment_id, config)
    scope = assessment.workspace.load_scope()
    hosts = assessment.workspace.list_hosts()
    services = assessment.workspace.list_services()
    hypotheses = assessment.workspace.list_hypotheses()
    findings = assessment.workspace.list_findings()

    console.print(f"[bold]Assessment:[/bold] {assessment.id} ({scope.name})")
    console.print(f"Mode: {scope.mode.value}")
    console.print(f"Assets:       {len(hosts)}")
    console.print(f"Services:     {len(services)}")
    console.print(f"Hypotheses:   {len(hypotheses)}")
    confirmed = [f for f in findings if f.status == "confirmed"]
    console.print(f"Confirmed:    {len(confirmed)}")


@app.command()
def assessments():
    """List all known assessments."""
    ids = Assessment.list_ids()
    if not ids:
        console.print("No assessments yet. Run 'kai lab <target>' or 'kai audit <target>'.")
        return
    for assessment_id in ids:
        console.print(assessment_id)


@app.command()
def resume(assessment_id: str = typer.Argument(...)):
    """Resume an existing assessment (alias of 'status' for Phase 1)."""
    status(assessment_id)


if __name__ == "__main__":
    app()
