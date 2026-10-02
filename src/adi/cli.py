"""Adi command-line interface."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from adi import __version__
from adi.assessment import Assessment, discover_skills_dir
from adi.config.settings import load_config
from adi.llm.base import LLMError, MalformedResponseError
from adi.llm.router import ProviderNotConfiguredError, build_provider
from adi.reporting.redaction import known_secrets, redact_text
from adi.runtime.docker_runtime import DockerKaliRuntime
from adi.scope.models import AssessmentMode, Scope
from adi.tools.registry import ToolRegistry

app = typer.Typer(add_completion=False, help="Adi — autonomous security assessment workspace.")
class RedactingConsole(Console):
    """Redact at the rendering boundary, including untrusted table cells."""
    secrets: tuple[str, ...] = ()

    def print(self, *objects, **kwargs):
        secrets = self.secrets + known_secrets()
        cleaned = []
        for obj in objects:
            if isinstance(obj, Table):
                for column in obj.columns:
                    column._cells[:] = [Text(redact_text(str(c), secrets)) for c in column._cells]
            elif isinstance(obj, str):
                obj = redact_text(obj, secrets)
            cleaned.append(obj)
        return super().print(*cleaned, **kwargs)


console = RedactingConsole()


def _load_assessment(assessment_id, config):
    assessment = Assessment.resume(assessment_id, config)
    console.secrets = known_secrets(assessment.workspace.load_scope())
    return assessment


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version"),
    plain: bool = typer.Option(False, "--plain", help="Launch the interactive Product Shell directly."),
):
    if version:
        console.print(f"adi {__version__}")
        raise typer.Exit()
    if plain:
        from adi.product.plain_shell import run_plain_shell

        run_plain_shell(load_config())
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
        import sqlalchemy  # noqa: F401 - availability probe
        console.print("[green]✓[/green] SQLite/SQLAlchemy ready")
    except ImportError:
        console.print("[red]✗[/red] SQLAlchemy not installed")
        ok = False

    try:
        import playwright  # noqa: F401 - availability probe
        console.print("[green]✓[/green] Playwright installed")
    except ImportError:
        console.print("[yellow]○[/yellow] Playwright not installed (browser capabilities disabled)")

    registry = ToolRegistry(discover_skills_dir())
    tools = registry.discover()
    available = [t for t in tools if t.available]
    if docker_available:
        asyncio.run(registry.detect_runtime(docker_runtime))
        tools = registry.all()
    console.print(f"[green]✓[/green] {len(tools)} security tool skill(s) registered, "
                  f"{len(available)} available on PATH")
    for tool in sorted(tools, key=lambda t: (t.metadata.category[0], t.metadata.name)):
        mark = "[green]✓[/green]" if tool.available else "[yellow]○[/yellow]"
        console.print(f"    {mark} {tool.metadata.name} [{tool.runtime}] {tool.version}")
    console.print("\nSource tools (local offline scanning):")
    for tool in tools:
        if "source" in tool.metadata.category:
            console.print(f"  {tool.metadata.name}: {_tool_version(tool) if tool.available else 'unavailable'}")

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
    """List discovered security tool skills, their availability, and which
    capability each one provides."""
    registry = ToolRegistry(discover_skills_dir())
    registry.discover()
    runtime = DockerKaliRuntime(image=load_config().runtime.image)
    if asyncio.run(runtime.is_available()):
        asyncio.run(registry.detect_runtime(runtime))
    discovered = sorted(registry.all(), key=lambda t: t.metadata.name)
    table = Table(title="Tool Skills")
    table.add_column("Name")
    table.add_column("Available")
    table.add_column("Version")
    table.add_column("Runtime")
    table.add_column("Trust")
    table.add_column("Risk")
    table.add_column("Capabilities")
    for tool in discovered:
        version = _tool_version(tool) if tool.available else "-"
        table.add_row(
            tool.metadata.name,
            "[green]available[/green]" if tool.available else "[yellow]unavailable[/yellow]",
            version,
            ", ".join(f"{name}:{'yes' if state['available'] else 'no'}" for name, state in tool.availability_by_runtime.items()),
            tool.metadata.trust_level.value,
            tool.metadata.risk_level,
            ", ".join(tool.metadata.capabilities),
        )
    console.print(table)
    console.print("\nRun 'adi tool <name>' for detailed skill information.")


def _tool_version(tool) -> str:
    """Best-effort version probe — never fails the command if the binary
    doesn't support a version flag or isn't actually runnable."""
    return tool.version


@app.command()
def tool(name: str = typer.Argument(..., help="Tool name, e.g. 'nmap' or 'ffuf'.")):
    """Show detailed skill information for one tool — not just its raw
    tool.yaml, but what it's for, when Adi selects it, and its limitations."""
    registry = ToolRegistry(discover_skills_dir())
    registry.discover()
    registered = registry.get(name)
    if registered is None:
        console.print(f"[red]No skill named '{name}' is registered.[/red]")
        raise typer.Exit(1)

    meta = registered.metadata
    console.print(f"[bold]{meta.name}[/bold]")
    console.print(f"Capabilities: {', '.join(meta.capabilities) or 'none'}")
    console.print(f"Categories:   {', '.join(meta.category) or 'none'}")
    console.print(f"Risk level:   {meta.risk_level}")
    console.print(f"Trust:        {meta.trust_level.value}")
    console.print(f"Runtime:      {registered.runtime}")
    console.print(f"Parser:       deterministic {meta.parser}; preferred {meta.output.preferred_format}")
    console.print(f"Permissions:  {meta.scope_requirements.model_dump()}")
    console.print(f"Availability by runtime: {registered.availability_by_runtime}")
    status_text = "[green]available[/green]" if registered.available else "[yellow]unavailable[/yellow]"
    console.print(f"Availability: {status_text}")
    if registered.available:
        console.print(f"Installed at: {registered.binary_path}")
        console.print(f"Version:      {_tool_version(registered)}")
    console.print(f"Timeout:      {meta.execution.timeout_seconds}s")
    if meta.capabilities:
        for cap in meta.capabilities:
            siblings = [t.metadata.name for t in registry.by_capability(cap) if t.metadata.name != meta.name]
            if siblings:
                console.print(f"Shares capability '{cap}' with: {', '.join(siblings)} "
                               f"(Adi picks by priority + availability — see 'adi tools')")

    skill_md = meta.skill_dir / "SKILL.md" if meta.skill_dir else None
    if skill_md and skill_md.exists():
        console.print()
        console.print(skill_md.read_text())
    else:
        console.print("\n[yellow]No SKILL.md found for this tool.[/yellow]")


@app.command()
def lab(
    target: str = typer.Argument(..., help="Target host/IP/URL for the lab assessment."),
    name: str = typer.Option(None, help="Assessment name (defaults to target)."),
    goal: str = typer.Option(
        "Assess the target and identify what is discoverable within scope.",
        help="The goal given to the planner in --autonomous mode.",
    ),
    max_actions: int = typer.Option(150, help="Action budget for this assessment."),
    approval_mode: bool = typer.Option(False, "--approval-mode", help="Require operator approval for elevated tool actions."),
    autonomous: bool = typer.Option(
        False, "--autonomous", help="Run the LLM-driven autonomous planning loop."
    ),
):
    """Create (and optionally autonomously run) a LAB-mode assessment against
    an isolated target (CTF box, local vulnerable app, mock exam environment)."""
    config = load_config()
    scope = Scope(
        approval_mode=approval_mode,
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
    assessment = _load_assessment(assessment_id, config)
    params = {"ports": ports} if ports else {}

    async def _run():
        return await assessment.executor.run(tool, target, params, reason_summary="manual invocation")

    try:
        observations = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001 - surface plugin/runtime errors at the CLI boundary
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    console.print(f"[bold]{len(observations)} observation(s) recorded[/bold]")
    for obs in observations:
        console.print(f"  • {obs}")


@app.command()
def status(assessment_id: str = typer.Argument(...)):
    """Show the current state of an assessment, including discovered web
    attack surface and security validation state."""
    config = load_config()
    assessment = _load_assessment(assessment_id, config)
    ws = assessment.workspace
    scope = ws.load_scope()
    hosts = ws.list_hosts()
    services = ws.list_services()
    endpoints = ws.list_endpoints()
    sessions = ws.list_sessions()
    actions = ws.list_actions()
    hypotheses = ws.list_hypotheses()
    findings = ws.list_findings()
    exchanges = ws.list_http_exchanges()
    observations = ws.list_observations()
    evidence = ws.list_evidence()
    validations = ws.list_validation_actions()
    reviews = ws.list_critic_reviews()
    positives = ws.list_positive_observations()

    parameter_count = sum(len(ws.list_parameters(e.id)) for e in endpoints)
    form_count = sum(1 for e in endpoints if "POST" in e.methods_json and ws.list_parameters(e.id))
    technologies = {o.value.get("name") for o in observations if o.type == "technology_fingerprint"}
    web_apps = len({e.host_id for e in endpoints})

    hyp_counts = {s: 0 for s in
                  ("new", "investigating", "supported", "validating", "confirmed", "rejected", "blocked")}
    for h in hypotheses:
        hyp_counts[h.status] = hyp_counts.get(h.status, 0) + 1
    finding_counts = {s: 0 for s in ("indicated", "supported", "confirmed")}
    for f in findings:
        finding_counts[f.status] = finding_counts.get(f.status, 0) + 1

    console.print(f"[bold]Assessment:[/bold] {assessment.id} ({scope.name})")
    console.print(f"Mode:          {scope.mode.value}")
    console.print(f"Goal:          {scope.goal}")
    console.print(f"Actions used:  {len(actions)} / {scope.max_actions}")
    console.print()
    console.print(f"Assets:                {len(hosts)}")
    console.print(f"Services:              {len(services)}")
    console.print(f"Web applications:      {web_apps}")
    console.print(f"Endpoints:             {len(endpoints)}")
    console.print(f"Parameters:            {parameter_count}")
    console.print(f"Forms:                 {form_count}")
    console.print(f"Sessions:              {', '.join(s.name for s in sessions) or 'none'}")
    console.print(f"Technologies:          {', '.join(sorted(t for t in technologies if t)) or 'none'}")
    console.print(f"HTTP exchanges:        {len(exchanges)}")
    console.print()
    console.print("Hypotheses:    " + ", ".join(f"{k} {v}" for k, v in hyp_counts.items()))
    console.print("Findings:      " + ", ".join(f"{k} {v}" for k, v in finding_counts.items())
                   or "Findings:      none")
    console.print(f"Evidence:              {len(evidence)}")
    console.print(f"Validation actions:    {len(validations)}")
    console.print(f"Critic reviews:        {len(reviews)}")
    console.print(f"Positive observations: {len(positives)}")
    console.print()
    if validations:
        last_v = validations[-1]
        console.print(f"Last validation: {last_v.created_at} {last_v.action_type} -> {last_v.outcome}")
    if actions:
        last = actions[-1]
        console.print(f"Last action:   {last.action_type} {last.tool} {last.target} [{last.status}]")
    else:
        console.print("Last action:   (none yet)")
    console.print(f"Current state: {ws.assessment_status()}")
    from adi.source.repository import SourceWorkspace
    summary = SourceWorkspace(ws).summary()
    if summary:
        console.print("\nSource: " + str(summary), markup=False)


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
    """Reopen persisted assessment state without repeating completed validation."""
    status(assessment_id)


@app.command("evidence")
def evidence_cmd(
    assessment_id: str = typer.Argument(...),
    evidence_id: str = typer.Argument(None, help="Evidence ID (e.g. EV-003) for full detail."),
):
    """List evidence, or show full sanitized detail for one item."""
    from adi.reporting.ids import display_id_map, resolve_id

    config = load_config()
    assessment = _load_assessment(assessment_id, config)
    ws = assessment.workspace
    items = ws.list_evidence()
    id_map = display_id_map(items, "EV")

    if evidence_id is None:
        table = Table(title="Evidence")
        for col in ("ID", "Type", "Source", "Timestamp", "Hypothesis", "Finding", "Summary"):
            table.add_column(col)
        for e in items:
            table.add_row(id_map[e.id], e.type, e.source, str(e.created_at)[:19],
                          ", ".join(_json(e.related_hypothesis_ids_json)) or "-",
                          ", ".join(_json(e.related_finding_ids_json)) or "-",
                          (e.summary or "")[:60])
        console.print(table)
        return

    raw_id = resolve_id(items, "EV", evidence_id)
    record = ws.get_evidence(raw_id) if raw_id else None
    if record is None:
        console.print(f"[red]No evidence '{evidence_id}' found.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Evidence {id_map[record.id]}[/bold] ({record.id})")
    console.print(f"Type:              {record.type}")
    console.print(f"Source:            {record.source}")
    console.print(f"Timestamp:         {record.created_at}")
    console.print(f"Subject:           {record.subject}")
    console.print(f"Summary:           {record.summary}")
    console.print(f"Confidence:        {record.confidence}")
    console.print(f"Hash:              {record.hash}")
    console.print(f"Related hypotheses: {', '.join(_json(record.related_hypothesis_ids_json)) or 'none'}")
    console.print(f"Related findings:   {', '.join(_json(record.related_finding_ids_json)) or 'none'}")
    if record.raw_reference:
        console.print(f"Raw reference:     {record.raw_reference}")
    console.print("\n[bold]Sanitized preview:[/bold]")
    console.print((record.sanitized_preview or "(none)")[:2000], markup=False)


@app.command("hypotheses")
def hypotheses_cmd(assessment_id: str = typer.Argument(...)):
    """List all hypotheses for an assessment."""
    from adi.reporting.ids import display_id_map

    config = load_config()
    ws = _load_assessment(assessment_id, config).workspace
    items = ws.list_hypotheses()
    id_map = display_id_map(items, "ADI-H")

    table = Table(title="Hypotheses")
    for col in ("ID", "Status", "Category", "Confidence", "Title", "Evidence"):
        table.add_column(col)
    for h in items:
        evidence_count = len(set(_json(h.supporting_observation_ids_json)) |
                             set(_json(h.contradicting_observation_ids_json)))
        table.add_row(id_map[h.id], h.status, h.category or "-", f"{h.confidence:.2f}",
                      h.title[:60], str(evidence_count))
    console.print(table)
    console.print("\nRun 'adi hypothesis <assessment-id> <id>' for full detail.")


@app.command("hypothesis")
def hypothesis_cmd(assessment_id: str = typer.Argument(...), hypothesis_id: str = typer.Argument(...)):
    """Show full detail for one hypothesis."""
    from adi.reporting.ids import resolve_id

    config = load_config()
    ws = _load_assessment(assessment_id, config).workspace
    items = ws.list_hypotheses()
    raw_id = resolve_id(items, "ADI-H", hypothesis_id)
    record = next((h for h in items if h.id == raw_id), None)
    if record is None:
        console.print(f"[red]No hypothesis '{hypothesis_id}' found.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]{record.title}[/bold]")
    console.print(f"Category:   {record.category or 'uncategorized'}")
    console.print(f"Status:     {record.status}")
    console.print(f"Confidence: {record.confidence:.2f}")
    console.print("Supporting evidence:    " + ", ".join(_json(record.supporting_observation_ids_json)))
    console.print("Contradicting evidence: " + ", ".join(_json(record.contradicting_observation_ids_json)))
    import json
    console.print("Validation plan: " + json.dumps(_json(record.validation_plan_json)))

    validations = ws.list_validation_actions(hypothesis_id=record.id)
    console.print(f"\nValidation actions used: {len(validations)}")
    limit = ws.validation_limit(record.id, persist=False)
    console.print(f"Remaining validation budget: {max(0, limit - len(validations))} / {limit}")
    for v in validations:
        console.print(f"  - {v.id} {v.action_type}: {v.outcome} — {v.detail}\n    Reason: {v.reason_summary or 'not recorded'}")

    related_findings = [f for f in ws.list_findings() if f.hypothesis_id == record.id]
    console.print("\nRelated findings: " + (", ".join(f.id for f in related_findings) or "none"))


@app.command("findings")
def findings_cmd(assessment_id: str = typer.Argument(...)):
    """List all findings for an assessment."""
    from adi.reporting.ids import display_id_map

    config = load_config()
    ws = _load_assessment(assessment_id, config).workspace
    items = ws.list_findings()
    id_map = display_id_map(items, "ADI-F")

    table = Table(title="Findings")
    for col in ("ID", "Severity", "Confidence", "Status", "Category", "Title", "Affected"):
        table.add_column(col)
    for f in items:
        endpoints = ", ".join(_json(f.affected_endpoints_json))
        table.add_row(id_map[f.id], f.severity.upper(), f"{f.confidence:.2f}", f.status,
                      f.category, f.title[:50], endpoints[:30] or "-")
    console.print(table)
    console.print("\nRun 'adi finding <assessment-id> <id>' for full detail.")


@app.command("finding")
def finding_cmd(assessment_id: str = typer.Argument(...), finding_id: str = typer.Argument(...)):
    """Show full sanitized detail for one finding."""
    from adi.reporting.ids import resolve_id

    config = load_config()
    ws = _load_assessment(assessment_id, config).workspace
    items = ws.list_findings()
    raw_id = resolve_id(items, "ADI-F", finding_id)
    record = next((f for f in items if f.id == raw_id), None)
    if record is None:
        console.print(f"[red]No finding '{finding_id}' found.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]{record.title}[/bold]")
    console.print(f"Severity:   {record.severity.upper()}")
    console.print(f"Confidence: {record.confidence:.2f}")
    console.print(f"Status:     {record.status}")
    console.print(f"Category:   {record.category}")
    console.print("Affected assets: " + (", ".join(_json(record.affected_assets_json)) or "none"))
    console.print("Affected endpoints: " + (", ".join(_json(record.affected_endpoints_json)) or "none"))
    console.print("Affected roles: " + (", ".join(_json(record.affected_roles_json)) or "none"))
    console.print(f"\nSummary: {record.summary}")
    console.print(f"\nImpact: {record.impact or '(not characterized)'}")
    console.print(f"\nValidation summary: {record.validation_summary or '(none)'}")
    console.print("Evidence: " + (", ".join(_json(record.evidence_ids_json)) or "none"))
    if record.critic_review_id:
        review = ws.get_critic_review(record.critic_review_id)
        if review:
            console.print(f"\nCritic review: {review.decision} — concerns: {'; '.join(_json(review.concerns_json)) or 'none'}")
    if not record.critic_review_id:
        console.print("Critic review: not recorded (deterministic path)")
    from adi.reporting.builder import ReportBuilder
    source_detail = next((f for f in ReportBuilder(ws).build().findings if f.id == record.id), None)
    if source_detail and source_detail.source_evidence:
        console.print("Runtime Evidence: " + ", ".join(source_detail.runtime_evidence))
        console.print("Source Evidence: " + ", ".join(source_detail.source_evidence))
        console.print("Source Locations / Affected Code: " + ", ".join(source_detail.source_locations))
        console.print("Root Cause: " + source_detail.root_cause.get("summary", "not established"))
        for slice in source_detail.affected_code:
            console.print(slice['location'] + '\n' + slice['snippet'], markup=False)
    console.print(f"\nRemediation: {record.remediation or '(none)'}")
    references = _json(record.references_json)
    if not references:
        from adi.reporting.builder import ReportBuilder
        report = ReportBuilder(ws).build()
        detail = next((f for f in report.findings + report.supported_items if f.id == record.id), None)
        references = detail.references if detail else []
    console.print("References: " + (", ".join(references) or "none"))


def _json(value: str):
    import json as _j
    try:
        return _j.loads(value) if value else []
    except _j.JSONDecodeError:
        return []


@app.command("report")
def report_cmd(
    assessment_id: str = typer.Argument(...),
    format: str = typer.Option("both", "--format", help="markdown | json | both"),
    output: str = typer.Option(None, "--output", help="Output directory (default: .adi/assessments/<id>/reports/)"),
):
    """Generate a Markdown/JSON security assessment report from stored state."""
    from adi.reporting.builder import ReportBuilder
    from adi.reporting.json_report import write_reports

    config = load_config()
    assessment = _load_assessment(assessment_id, config)
    report = ReportBuilder(assessment.workspace).build()

    out_dir = Path(output) if output else assessment.directory / "reports"
    if format not in ("markdown", "json", "both"):
        raise typer.BadParameter("format must be markdown, json or both")
    formats = {"markdown": ("markdown",), "json": ("json",), "both": ("markdown", "json")}[format]
    written = write_reports(report, out_dir, formats)

    console.print(f"[bold]Report generated for {assessment.id}[/bold]")
    for fmt, path in written.items():
        console.print(f"  {fmt}: {path}")
    console.print(f"\nConfirmed findings: {len(report.findings)}  |  "
                  f"Rejected hypotheses: {len(report.rejected_hypotheses)}  |  "
                  f"Positive controls: {len(report.positive_security_observations)}")


@app.command("teach")
def teach_cmd(assessment_id: str, hypothesis_id: str):
    """Explain a hypothesis using stored actions and evidence, never hidden reasoning."""
    from adi.reporting.ids import resolve_id
    from adi.reporting.teach import explain_hypothesis
    ws = _load_assessment(assessment_id, load_config()).workspace
    raw_id = resolve_id(ws.list_hypotheses(), "ADI-H", hypothesis_id)
    if raw_id is None:
        raise typer.BadParameter("hypothesis not found")
    for label, value in explain_hypothesis(ws, raw_id).items():
        console.print(f"{label}: {value}", markup=False)


@app.command()
def audit(
    repository: Path = typer.Argument(..., help="Operator-accessible source repository."),  # noqa: B008
    target: str = typer.Option('', '--target', help="Explicitly authorized runtime application URL."),
    scope_file: Path = typer.Option(None, '--scope', help="YAML scope with test-account references and permissions."),  # noqa: B008
    autonomous: bool = typer.Option(False, '--autonomous'),
):
    """Bind a source repository, index locally, optionally assess its scoped runtime."""
    import yaml

    from adi.source.repository import SourceWorkspace
    config = load_config()
    scope = Scope.model_validate(yaml.safe_load(scope_file.read_text())) if scope_file else Scope(
        name=f'source-{repository.name}', mode=AssessmentMode.SOURCE_AND_RUNTIME,
        targets=[target] if target else [],
        goal='Index source, correlate observed runtime routes, validate controlled hypotheses and report.')
    if target and not scope.host_is_target(__import__('urllib.parse', fromlist=['urlsplit']).urlsplit(target).hostname or ''):
        raise typer.BadParameter('target outside supplied scope')
    assessment = Assessment.create(scope, config)
    try:
        snapshot = SourceWorkspace(assessment.workspace).index(repository, target)
    except (ValueError, OSError, PermissionError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f'Assessment: {assessment.id}\nRepository: {snapshot.repository.root_path}\n'
                  f'Indexed files: {snapshot.repository.files_count}; source routes: {len(snapshot.routes)}')
    if autonomous:
        _run_autonomous(assessment, config)


@app.command('source')
def source_cmd(assessment_id: str):
    """Summarize persisted source intelligence and staleness."""
    from adi.source.repository import SourceWorkspace
    source = SourceWorkspace(_load_assessment(assessment_id, load_config()).workspace)
    import json
    console.print(json.dumps(source.summary(), indent=2), markup=False)


@app.command('source-index')
def source_index_cmd(assessment_id: str):
    """Refresh the operator-bound repository; invalidates scans/correlations if changed."""
    from adi.source.repository import SourceWorkspace
    source = SourceWorkspace(_load_assessment(assessment_id, load_config()).workspace)
    snapshot = source.load()
    if not snapshot:
        raise typer.BadParameter('no bound repository; use adi audit')
    source.index(Path(snapshot.repository.root_path), snapshot.repository.application_origin)
    source_cmd(assessment_id)


@app.command('routes')
def routes_cmd(assessment_id: str):
    from adi.source.repository import SourceWorkspace
    source = SourceWorkspace(_load_assessment(assessment_id, load_config()).workspace)
    snapshot = source.load()
    if not snapshot:
        raise typer.BadParameter('no source index')
    table = Table(title='Source Routes' + (' (STALE)' if snapshot.repository.stale else ''))
    for col in ('Method', 'Source Route', 'Runtime Match', 'Handler', 'Middleware', 'File:Line'):
        table.add_column(col)
    for r in snapshot.routes:
        matches = [c.runtime_path for c in snapshot.correlations if c.route_id == r.id]
        table.add_row(r.method, r.path, ', '.join(matches) or '-', r.handler,
                      ', '.join(r.middleware), r.location.display())
    console.print(table)


@app.command('correlations')
def correlations_cmd(assessment_id: str):
    from adi.source.repository import SourceWorkspace
    source = SourceWorkspace(_load_assessment(assessment_id, load_config()).workspace)
    for c in source.correlate():
        snapshot = source.require_current()
        route = next(r for r in snapshot.routes if r.id == c.route_id)
        console.print(f'{c.method} {c.runtime_path} ↔ {route.location.display()} confidence {c.confidence}')


@app.command('source-search')
def source_search_cmd(assessment_id: str, query: str):
    from adi.source.index import SourceIndex
    from adi.source.repository import SourceWorkspace
    index = SourceIndex(SourceWorkspace(_load_assessment(assessment_id, load_config()).workspace).require_current())
    for loc in index.search_text(query):
        console.print(loc.display() + '\n' + index.retrieve_context(loc), markup=False)


@app.command('source-scan')
def source_scan_cmd(assessment_id: str, capability: str):
    from adi.source.scanners import SourceScanner
    if capability not in ('scan_source_patterns', 'scan_secrets', 'scan_dependencies'):
        raise typer.BadParameter('unknown source scan capability')
    assessment = _load_assessment(assessment_id, load_config())
    result = asyncio.run(SourceScanner(assessment.workspace, assessment.registry).scan(capability))
    console.print(str(result), markup=False)




@app.command()
def capabilities(assessment_id: str = typer.Option(None)):
    """Show capability providers and current scope permission."""
    registry = ToolRegistry(discover_skills_dir())
    registry.discover()
    scope = _load_assessment(assessment_id, load_config()).workspace.load_scope() if assessment_id else None
    for cap in registry.capabilities():
        allowed = all(getattr(scope.permissions, p) for p in cap.required_scope_permissions) if scope else None
        console.print(f"{cap.id} risk={cap.risk_level} permission={allowed if scope else 'no scope loaded'}")
        for provider in registry.by_capability(cap.id):
            console.print(f"  {provider.metadata.name}: {'available' if provider.available else 'unavailable'} [{provider.runtime}] {provider.version}")


@app.command()
def capability(name: str, assessment_id: str = typer.Option(None)):
    """Describe a capability and deterministic fallback policy."""
    registry = ToolRegistry(discover_skills_dir())
    registry.discover()
    match = next((c for c in registry.capabilities() if c.id == name), None)
    if not match:
        raise typer.BadParameter('unknown capability')
    scope = _load_assessment(assessment_id, load_config()).scope_engine.scope if assessment_id else None
    data = match.model_dump(mode='json')
    data['currently_available_tools'] = [t.metadata.name for t in registry.ranked(name)]
    data['current_scope_permission'] = (all(getattr(scope.permissions, p) for p in match.required_scope_permissions)
                                        if scope else 'no scope loaded')
    console.print_json(json.dumps(data))


@app.command('discover-tools')
def discover_tools():
    """Refresh known reviewed executables in PATH without filesystem traversal."""
    tools()


@app.command('run-capability')
def run_capability_cmd(assessment_id: str, name: str, target: str,
                       inputs_file: Path = typer.Option(None)):  # noqa: B008 - Typer CLI declaration
    """Run typed capability inputs; authentication uses references, never candidate values."""
    from adi.reporting.redaction import known_secrets, redact_text
    assessment = _load_assessment(assessment_id, load_config())
    parameters = json.loads(inputs_file.read_text()) if inputs_file else {}
    try:
        observations = asyncio.run(assessment.executor.run_capability(
            name, target, parameters, reason_summary='operator typed capability request'))
    except Exception as exc:
        console.print(redact_text(str(exc), known_secrets(assessment.workspace.load_scope())))
        raise typer.Exit(1) from exc
    console.print(f'{len(observations)} normalized observations recorded')


@app.command()
def shell(
    plain: bool = typer.Option(True, help="Line-oriented interactive mode (default; the TUI lands separately)."),
):
    """Launch the interactive Product Shell: chat-driven security
    assessment workflow over the real Core (scope, orchestrator, tools,
    evidence, findings). `adi shell` (equivalently `adi --plain`) is the
    primary way to use Adi day to day; the other subcommands remain for
    scripted/non-interactive automation."""
    from adi.product.plain_shell import run_plain_shell

    run_plain_shell(load_config())


if __name__ == "__main__":
    app()
