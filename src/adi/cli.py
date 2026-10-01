"""Adi command-line interface."""

from __future__ import annotations

import asyncio
import sys

import typer
from rich.console import Console
from rich.table import Table

from adi import __version__
from adi.assessment import Assessment, discover_skills_dir
from adi.config.settings import load_config
from adi.llm.base import LLMError, MalformedResponseError
from adi.llm.router import ProviderNotConfiguredError, build_provider
from adi.runtime.docker_runtime import DockerKaliRuntime
from adi.scope.models import AssessmentMode, Scope
from adi.tools.registry import ToolRegistry

app = typer.Typer(add_completion=False, help="Adi — autonomous security assessment workspace.")
console = Console()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, version: bool = typer.Option(False, "--version")):
    if version:
        console.print(f"adi {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


@app.command()
def doctor():
    """Check that Adi's environment is ready."""
    console.print("[bold]Adi Environment Check[/bold]\n")
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
            f"Adi will refuse to run tools against real targets without an isolated runtime "
            f"unless runtime.type=local is explicitly opted into in .adi.yaml."
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
    if os.environ.get("ADI_LLM_API_KEY") or config.provider.api_key_env in os.environ:
        console.print("[green]✓[/green] LLM provider configured")
    else:
        console.print(
            f"[yellow]○[/yellow] LLM provider not configured "
            f"(set ${config.provider.api_key_env}) — deterministic tool execution still works, "
            f"but autonomous planning will not."
        )

    console.print()
    if ok:
        console.print("[bold green]Adi is ready.[/bold green]")
    else:
        console.print("[bold yellow]Adi has warnings above — see docs/architecture.md.[/bold yellow]")


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
    goal: str = typer.Option(
        "Assess the target and identify what is discoverable within scope.",
        help="The goal given to the planner in --autonomous mode.",
    ),
    max_actions: int = typer.Option(150, help="Action budget for this assessment."),
    autonomous: bool = typer.Option(
        False, "--autonomous", help="Run the LLM-driven autonomous planning loop."
    ),
):
    """Create (and optionally autonomously run) a LAB-mode assessment against
    an isolated target (CTF box, local vulnerable app, mock exam environment)."""
    config = load_config()
    scope = Scope(
        name=name or f"lab-{target}",
        mode=AssessmentMode.LAB,
        goal=goal,
        targets=[target],
        max_actions=max_actions,
    )
    assessment = Assessment.create(scope, config)
    console.print(f"[bold]Assessment created:[/bold] {assessment.id}")
    console.print(f"Target: {target}")
    console.print(f"Workspace: {assessment.directory}")
    console.print()

    if not autonomous:
        console.print(
            "Use 'adi lab ... --autonomous' to run the agent loop, or 'adi run-tool' / the "
            "Python API to execute individual tools against this assessment's workspace."
        )
        return

    _run_autonomous(assessment, config)


def _run_autonomous(assessment: Assessment, config) -> None:
    try:
        llm = build_provider(config, role="planner")
    except ProviderNotConfiguredError as exc:
        console.print(f"[red]Cannot start autonomous mode:[/red] {exc}")
        raise typer.Exit(1)

    orchestrator = assessment.build_orchestrator(llm)

    async def _run():
        return await orchestrator.run()

    try:
        outcomes = asyncio.run(_run())
    except (LLMError, MalformedResponseError) as exc:
        console.print(f"[red]Autonomous assessment stopped:[/red] {exc}")
        raise typer.Exit(1)

    console.print(f"\n[bold]{len(outcomes)} step(s) taken[/bold]\n")
    for outcome in outcomes:
        action = outcome.action
        marker = {
            "completed": "[green]✓[/green]", "completed_assessment": "[green]✓[/green]",
            "blocked": "[yellow]⊘[/yellow]", "failed": "[red]✗[/red]",
            "stopped": "[yellow]■[/yellow]", "paused": "[yellow]⏸[/yellow]",
        }.get(outcome.status, "•")
        if action:
            console.print(f"{marker} {action.action_type.value} "
                           f"{action.tool or ''} {action.target or ''} — {outcome.detail}")
            if config.ui.show_reason_summaries and action.reason_summary:
                console.print(f"    reason: {action.reason_summary}")
        else:
            console.print(f"{marker} {outcome.status}: {outcome.detail}")

    console.print(f"\nAssessment: {assessment.id}")
    console.print("Run 'adi status <assessment-id>' for the current attack-surface summary.")


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
    from adi.agent.reasoner import HypothesisEngine

    config = load_config()
    assessment = Assessment.resume(assessment_id, config)
    scope = assessment.workspace.load_scope()
    hosts = assessment.workspace.list_hosts()
    services = assessment.workspace.list_services()
    actions = assessment.workspace.list_actions()
    findings = assessment.workspace.list_findings()
    hyp_engine = HypothesisEngine(assessment.workspace)
    active = hyp_engine.active()
    rejected = hyp_engine.rejected()

    console.print(f"[bold]Assessment:[/bold] {assessment.id} ({scope.name})")
    console.print(f"Goal: {scope.goal}")
    console.print(f"Mode: {scope.mode.value}")
    console.print(f"Actions used:  {len(actions)} / {scope.max_actions}")
    console.print(f"Assets:        {len(hosts)}")
    console.print(f"Services:      {len(services)}")
    console.print(f"Hypotheses:    {len(active)} active, {len(rejected)} rejected")
    confirmed = [f for f in findings if f.status == "confirmed"]
    console.print(f"Confirmed:     {len(confirmed)}")
    if actions:
        last = actions[-1]
        console.print(f"Last action:   {last.action_type} {last.tool} {last.target} [{last.status}]")
    else:
        console.print("Last action:   (none yet)")


@app.command()
def assessments():
    """List all known assessments."""
    ids = Assessment.list_ids()
    if not ids:
        console.print("No assessments yet. Run 'adi lab <target>' or 'adi audit <target>'.")
        return
    for assessment_id in ids:
        console.print(assessment_id)


@app.command()
def resume(assessment_id: str = typer.Argument(...)):
    """Resume an existing assessment (alias of 'status' for Phase 1)."""
    status(assessment_id)


if __name__ == "__main__":
    app()
