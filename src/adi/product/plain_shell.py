"""Line-oriented interactive Product Shell (`adi --plain` / `adi shell
--plain`). Works over SSH, in accessibility tools, and in any basic
terminal. Same `ProductController` the Textual TUI will drive — this is
not a stripped-down reimplementation, it is the reference consumer of the
Product layer.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

from rich.console import Console

from adi.config.models import AdiConfig
from adi.llm.base import LLMError
from adi.product.console import ExpertConsole
from adi.product.controller import ControllerState, ProductController
from adi.product.events import Event, EventType
from adi.product.explain import build_evidence_trace, explain_why
from adi.product.nlu import interpret_scope_command
from adi.product.onboarding import setup_provider, test_message
from adi.product.terminal_safety import sanitize_for_terminal
from adi.reporting.redaction import known_secrets, redact_text

_HELP = """\
Common commands:
  /new <target>            start a new assessment against <target>
  /resume <name>           resume a named session
  /sessions                list known sessions
  /status                  show current assessment status
  /scope                   show the active scope (targets/permissions/budgets)
  /provider <name>         switch the active AI provider profile
  /provider add            connect AI interactively
  /provider edit <name>    edit provider settings
  /provider remove <name>  delete profile and credentials
  /provider test <name>    test provider/model
  /models                  discover models for active provider
  /model [id]              show or switch model
  /providers               list configured provider profiles
  /findings                list findings recorded so far
  /hypotheses              list hypotheses
  /evidence                list evidence
  /tools                   browse discovered tool skills
  /tool <name>             show detail for one tool
  /capabilities            browse capabilities + fallback order
  /capability <name>       show detail for one capability
  /run <capability> <target> [k=v ...]   reviewed capability request (preview + confirm)
  /tool-run <tool> <target> [k=v ...]    reviewed specific-tool request (preview + confirm)
  /attack-surface          hierarchical view of hosts/services/endpoints/source
  /source                  source intelligence summary (languages, routes, deps)
  /trace <finding-id>      evidence trace: finding -> hypothesis -> validation -> evidence
  /why <id>                explain an action/hypothesis/finding from stored state (no LLM)
  /source-search <query>   find indexed source matching a term or path ("where is X implemented?")
  /settings                effective configuration across layers, with origin
  /pause  /continue  /stop control the assessment loop
  /report                  generate markdown + JSON reports
  /teach on|off             toggle teach mode
  /mode expert|normal       toggle expert mode
  /help                     show this message
  /exit                     quit

Anything else is sent as chat: it narrows the assessment's current focus
(goal) and starts/continues the loop. Natural-language scope phrases like
"only localhost" or "don't perform authentication testing" are proposed
as an explicit scope change you must confirm — chat can never silently
widen scope.
"""


class PlainShell:
    """Line-oriented Product Shell. Also the shared command interpreter
    reused by the Textual TUI (`adi.product.tui.app`) — the TUI does not
    reimplement command handling, it feeds lines into the same `_handle()`
    and redirects rendering through `output_sink` instead of a live
    terminal `Console`."""

    def __init__(
        self, config: AdiConfig, project_root: Path | None = None,
        output_sink: Callable[[str], None] | None = None,
    ):
        self.config = config
        self.project_root = project_root or Path.cwd()
        self.controller = ProductController(config, self.project_root)
        import os

        self.console = Console(no_color=bool(os.environ.get("NO_COLOR")), highlight=False)
        self.output_sink = output_sink
        self.prompt = self._terminal_prompt
        self.teach = False
        self.expert = False
        self.controller.events.subscribe(self._on_event)

    # -- event rendering ---------------------------------------------------

    def _on_event(self, event: Event) -> None:
        line = _render_event(event, teach=self.teach, expert=self.expert)
        if line:
            self._print(line)

    def _print(self, text: str) -> None:
        secrets = known_secrets(self.controller.assessment.workspace.load_scope()) if self.controller.assessment else ()
        cleaned = sanitize_for_terminal(redact_text(text, secrets))
        if self.output_sink is not None:
            self.output_sink(cleaned)
        else:
            self.console.print(cleaned)

    # -- main loop ----------------------------------------------------------

    async def run(self) -> None:
        self._print("[bold]Adi[/bold] — plain interactive mode. Type /help for commands.")
        if self.controller.models.active_profile() is None:
            await self._first_run_wizard()
        candidate = self.controller.auto_resume_candidate()
        if candidate is not None:
            self._print(
                f"Recent session '{candidate.name}' ({candidate.target}) — "
                f"type '/resume {candidate.name}' to continue it, or /new <target> to start fresh."
            )
        while True:
            try:
                line = await asyncio.to_thread(input, "> ")
            except (EOFError, KeyboardInterrupt):
                break
            line = line.strip()
            if not line:
                continue
            if line in ("/exit", "/quit"):
                break
            try:
                should_exit = await self._handle(line)
            except Exception as exc:  # noqa: BLE001 - user-visible errors must stay concise
                self._print(f"[red]Error:[/red] {exc}")
                continue
            if should_exit:
                break
        if self.controller.assessment is not None and self.controller.state == ControllerState.RUNNING:
            await self.controller.stop()

    async def _terminal_prompt(self, label: str, secret: bool = False) -> str:
        if secret:
            import getpass

            return await asyncio.to_thread(getpass.getpass, label)
        answer = await asyncio.to_thread(input, label)
        if answer.strip() == "/cancel":
            raise ValueError("Setup cancelled. Run /provider add to retry.")
        return answer

    async def _first_run_wizard(self) -> None:
        self._print("No AI provider configured.")
        try:
            await setup_provider(self.controller.models, self.prompt, self._print)
        except (EOFError, KeyboardInterrupt):
            self._print("Setup skipped. Run /provider add to connect AI.")
        except (LLMError, ValueError) as exc:
            self._print(f"Setup incomplete: {exc}. Run /provider add to retry.")

    async def _provider_command(self, rest: str) -> None:
        manager = self.controller.models
        action, _, name = rest.strip().partition(" ")
        name = name.strip()
        if action == "add":
            await setup_provider(manager, self.prompt, self._print)
        elif action == "choose":
            self._print("Available profiles: " + ", ".join(manager.store.profiles))
            name = (await self.prompt("Provider name: ", False)).strip()
            manager.set_active(name)
            self._print(f"Active provider: {name}")
        elif action == "edit":
            active = manager.active_profile()
            await setup_provider(manager, self.prompt, self._print, edit=name or (active.name if active else ""))
        elif action == "remove":
            manager.remove_profile(name)
            self._print("Provider and credentials removed.")
        elif action == "test":
            profile = manager.require_profile(name) if name else manager.active_profile()
            if profile is None:
                self._print("No AI provider configured. Run /provider add.")
                return
            self._print(test_message(await manager.test_connection(profile)))
        elif action:
            manager.set_active(rest.strip())
            self._print(f"Switched active provider to '{rest.strip()}'")
        else:
            active = manager.active_profile()
            self._print(f"Active provider: {active.name if active else '(none configured)'}")
            if active:
                self._print(f"Provider: {active.kind} | Model: {active.model}")
            else:
                self._print("Run /provider add or Ctrl+P → Add AI Provider.")

    async def _handle(self, line: str) -> bool:
        if line.startswith("/"):
            return await self._handle_command(line)
        await self._handle_chat(line)
        return False

    async def _handle_chat(self, text: str) -> None:
        if self.controller.assessment is None:
            self._print("No active assessment yet. Use /new <target> first.")
            return
        scope = self.controller.assessment.workspace.load_scope()
        proposal = interpret_scope_command(text, scope)
        if proposal is not None:
            self._print(f"Proposed scope change: {proposal.description}")
            answer = await asyncio.to_thread(input, "Apply this scope change? [y/N] ")
            if answer.strip().lower() in ("y", "yes"):
                await self.controller.update_scope_fields(**proposal.fields)
                self._print("Scope updated.")
            else:
                self._print("Scope change discarded.")
            return
        await self.controller.set_goal(text)
        self._print(f"Focus updated: {text}")
        await self.controller.start()

    async def _handle_command(self, line: str) -> bool:
        parts = line.split(maxsplit=1)
        cmd, rest = parts[0], (parts[1] if len(parts) > 1 else "")

        if cmd == "/help":
            self._print(_HELP)
        elif cmd == "/new":
            if not rest:
                self._print("Usage: /new <target>")
            else:
                await self.controller.new_assessment(rest.strip())
                self._print(f"Created assessment for {rest.strip()} (session '{self.controller.session_name}')")
        elif cmd == "/resume":
            name = rest.strip() or (self.controller.auto_resume_candidate().name if self.controller.auto_resume_candidate() else "")
            if not name:
                self._print("Usage: /resume <session-name>. See /sessions.")
            else:
                await self.controller.resume_assessment(name)
                self._print(f"Resumed session '{name}'")
        elif cmd == "/sessions":
            sessions = self.controller.sessions.list()
            if not sessions:
                self._print("No sessions yet.")
            for s in sessions:
                self._print(f"  {s.name}  target={s.target}  last_activity={_fmt_ts(s.last_activity)}")
        elif cmd == "/status":
            self._print_status()
        elif cmd == "/scope":
            self._print_scope()
        elif cmd == "/providers":
            if not self.controller.models.list_profiles():
                self._print("No AI provider configured. Run /provider add.")
            for p in self.controller.models.list_profiles():
                active = " (active)" if self.controller.models.active_profile() and p.name == self.controller.models.active_profile().name else ""
                self._print(f"  {p.name}  kind={p.kind}  model={p.model}  locality={p.locality}{active}")
        elif cmd == "/provider":
            await self._provider_command(rest)
        elif cmd == "/models":
            active = self.controller.models.active_profile()
            if active is None:
                self._print("No AI provider configured. Run /provider add.")
            else:
                models = await self.controller.models.list_models(active)
                for model in models:
                    self._print(model)
                if not models:
                    self._print("Model discovery unavailable. Use /model <model-id> for manual entry.")
        elif cmd == "/model":
            if rest.strip() == "choose":
                active = self.controller.models.active_profile()
                if active:
                    models = await self.controller.models.list_models(active)
                    for model in models:
                        self._print(model)
                    selected = await self.prompt("Model ID: ", False)
                    self.controller.models.set_model(selected)
            elif rest.strip():
                self.controller.models.set_model(rest.strip())
            active = self.controller.models.active_profile()
            self._print(f"Model: {active.model}" if active else "No AI provider configured. Run /provider add.")
        elif cmd == "/findings":
            self._print_findings()
        elif cmd == "/hypotheses":
            self._print_hypotheses()
        elif cmd == "/evidence":
            self._print_evidence()
        elif cmd == "/tools":
            self._print_tools()
        elif cmd == "/tool":
            self._print_tool_detail(rest.strip())
        elif cmd == "/capabilities":
            self._print_capabilities()
        elif cmd == "/capability":
            self._print_capability_detail(rest.strip())
        elif cmd == "/run":
            await self._run_console_command(rest, by_capability=True)
        elif cmd == "/tool-run":
            await self._run_console_command(rest, by_capability=False)
        elif cmd == "/attack-surface":
            self._print_attack_surface()
        elif cmd == "/source":
            self._print_source_summary()
        elif cmd == "/trace":
            self._print_trace(rest.strip())
        elif cmd == "/why":
            self._print_why(rest.strip())
        elif cmd == "/source-search":
            self._print_source_search(rest.strip())
        elif cmd == "/settings":
            self._print_settings()
        elif cmd == "/pause":
            await self.controller.pause()
            self._print("Paused — no new actions will be scheduled.")
        elif cmd == "/continue":
            await self.controller.continue_()
            if self.controller.assessment is not None:
                await self.controller.start()  # no-op if already running
            self._print("Continuing.")
        elif cmd == "/stop":
            await self.controller.stop()
            self._print("Stopped.")
        elif cmd == "/report":
            await self._generate_report()
        elif cmd == "/teach":
            self.teach = rest.strip().lower() == "on"
            self._print(f"Teach mode: {'on' if self.teach else 'off'}")
        elif cmd == "/mode":
            self.expert = rest.strip().lower() == "expert"
            self._print(f"Mode: {'expert' if self.expert else 'normal'}")
        elif cmd == "/clear":
            self.console.clear()
        else:
            self._print(f"Unknown command: {cmd}. Type /help.")
        return False

    def _require_assessment(self) -> bool:
        if self.controller.assessment is None:
            self._print("No active assessment. Use /new <target> or /resume <name>.")
            return False
        return True

    def _print_status(self) -> None:
        if not self._require_assessment():
            return
        ws = self.controller.assessment.workspace
        self._print(f"Assessment: {self.controller.assessment.id} ({ws.assessment_status()})")
        self._print(f"Controller state: {self.controller.state}")
        self._print(f"Services: {len(ws.list_services())}  Endpoints: {len(ws.list_endpoints())}  "
                     f"Hypotheses: {len(ws.list_hypotheses())}  Findings: {len(ws.list_findings())}")

    def _print_scope(self) -> None:
        if not self._require_assessment():
            return
        scope = self.controller.assessment.workspace.load_scope()
        self._print(f"Targets: {', '.join(scope.targets) or '(none)'}")
        self._print(f"Goal: {scope.goal}")
        self._print(f"Authentication testing: {scope.permissions.authentication_testing}")
        self._print(f"Max actions: {scope.max_actions}")

    def _print_findings(self) -> None:
        if not self._require_assessment():
            return
        findings = self.controller.assessment.workspace.list_findings()
        if not findings:
            self._print("No findings yet.")
        for f in findings:
            self._print(f"  {f.id}  {f.severity:<8}  {f.status:<10}  {f.title}")

    def _print_hypotheses(self) -> None:
        if not self._require_assessment():
            return
        hyps = self.controller.assessment.workspace.list_hypotheses()
        if not hyps:
            self._print("No hypotheses yet.")
        for h in hyps:
            self._print(f"  {h.id}  {h.status:<12}  {h.title}")

    def _print_evidence(self) -> None:
        if not self._require_assessment():
            return
        items = self.controller.assessment.workspace.list_evidence()
        if not items:
            self._print("No evidence yet.")
        for e in items:
            self._print(f"  {e.id}  {e.type:<12}  {e.summary}")

    def _console(self) -> ExpertConsole | None:
        if self.controller.assessment is None:
            self._print("No active assessment. Use /new <target> or /resume <name>.")
            return None
        return ExpertConsole(self.controller.assessment)

    def _print_tools(self) -> None:
        console_ = self._console()
        if console_ is None:
            return
        for t in console_.list_tools():
            status = "available" if t["available"] else "unavailable"
            self._print(f"  {t['name']:<20} {status:<12} risk={t['risk']:<10} caps={', '.join(t['capabilities'])}")
        self._print("\nUse '/tool <name>' for detail.")

    def _print_tool_detail(self, name: str) -> None:
        console_ = self._console()
        if console_ is None:
            return
        if not name:
            self._print("Usage: /tool <name>")
            return
        detail = console_.describe_tool(name)
        if detail is None:
            self._print(f"No tool named '{name}'.")
            return
        for key, value in detail.items():
            self._print(f"  {key}: {value}")

    def _print_capabilities(self) -> None:
        console_ = self._console()
        if console_ is None:
            return
        for c in console_.list_capabilities():
            self._print(f"  {c['id']:<28} risk={c['risk']:<10} permission={c['permission']} "
                         f"available={','.join(c['available_tools']) or '-'}")
        self._print("\nUse '/capability <name>' for detail.")

    def _print_capability_detail(self, name: str) -> None:
        console_ = self._console()
        if console_ is None:
            return
        if not name:
            self._print("Usage: /capability <name>")
            return
        detail = console_.describe_capability(name)
        if detail is None:
            self._print(f"No capability named '{name}'.")
            return
        for key, value in detail.items():
            self._print(f"  {key}: {value}")

    async def _run_console_command(self, rest: str, *, by_capability: bool) -> None:
        console_ = self._console()
        if console_ is None:
            return
        parts = rest.split()
        label = "/run <capability> <target> [k=v ...]" if by_capability else "/tool-run <tool> <target> [k=v ...]"
        if len(parts) < 2:
            self._print(f"Usage: {label}")
            return
        name, target, *kv_pairs = parts
        parameters = {}
        for pair in kv_pairs:
            if "=" in pair:
                key, value = pair.split("=", 1)
                parameters[key] = value

        if by_capability:
            preview = console_.preview(name, target, parameters)
        else:
            # Tool-specific preview reuses the same ScopeEngine/executor
            # path; we resolve the tool's own declared capability (first
            # one) so the preview still reflects real scope/risk/approval.
            tool_entry = self.controller.assessment.registry.get(name)
            if tool_entry is None:
                self._print(f"No tool named '{name}'.")
                return
            capability = tool_entry.metadata.capabilities[0] if tool_entry.metadata.capabilities else name
            preview = console_.preview(capability, target, parameters)
            preview.candidate_tools = [name]

        for line in preview.render_lines():
            self._print(f"  {line}")

        if preview.scope_reason != "within scope" and not preview.requires_approval:
            self._print("[red]Blocked by scope policy — not executable.[/red]")
            return

        answer = await asyncio.to_thread(input, "Execute? [Approve once/Reject] (y/N) ")
        if answer.strip().lower() not in ("y", "yes"):
            self._print("Rejected.")
            return

        result = await console_.execute(
            preview.capability, target, parameters,
            grant_elevated_approval=preview.requires_approval,
        )
        if result.ok:
            self._print(f"[green]✓[/green] {result.detail}")
        else:
            self._print(f"[yellow]![/yellow] {result.detail}")

    def _print_attack_surface(self) -> None:
        if not self._require_assessment():
            return
        ws = self.controller.assessment.workspace
        self._print("target")
        hosts = ws.list_hosts()
        services = ws.list_services()
        for host in hosts:
            self._print(f"├── {host.address}")
            for svc in [s for s in services if s.host_id == host.id]:
                self._print(f"│   ├── {svc.port} {svc.protocol}")
        endpoints = ws.list_endpoints()
        if endpoints:
            self._print("└── web")
            for ep in endpoints[:50]:
                import json as _json

                methods = ", ".join(_json.loads(ep.methods_json)) if ep.methods_json else "?"
                self._print(f"    ├── {methods} {ep.path}")
        source = ws.load_source()
        if source is not None:
            self._print("└── source")
            for route in getattr(source, "routes", [])[:50]:
                self._print(f"    ├── {route.method} {route.path} -> {route.handler}")

    def _print_source_summary(self) -> None:
        if not self._require_assessment():
            return
        source = self.controller.assessment.workspace.load_source()
        if source is None:
            self._print("No source intelligence indexed yet. The agent indexes it via "
                         "'index_source_repository', or bind a source root in /scope.")
            return
        languages = getattr(source, "languages", [])
        frameworks = [f.name for f in getattr(source, "frameworks", [])]
        routes = getattr(source, "routes", [])
        dependencies = getattr(source, "dependencies", [])
        self._print(f"Languages:   {', '.join(languages) or '-'}")
        self._print(f"Frameworks:  {', '.join(frameworks) or '-'}")
        self._print(f"Routes:      {len(routes)}")
        self._print(f"Dependencies: {len(dependencies)}")

    def _print_trace(self, finding_id: str) -> None:
        if not self._require_assessment():
            return
        if not finding_id:
            self._print("Usage: /trace <finding-id>")
            return
        trace = build_evidence_trace(self.controller.assessment.workspace, finding_id)
        if trace is None:
            self._print(f"No finding with id '{finding_id}'.")
            return
        for line in trace.render_lines():
            self._print(f"  {line}")

    def _print_source_search(self, query: str) -> None:
        if not self._require_assessment():
            return
        if not query:
            self._print("Usage: /source-search <query>  (e.g. 'where is this endpoint implemented?' "
                        "-> /source-search <path-or-term>)")
            return
        from adi.source.index import SourceIndex
        from adi.source.repository import SourceWorkspace

        source_ws = SourceWorkspace(self.controller.assessment.workspace)
        snapshot = source_ws.load()
        if snapshot is None:
            self._print("No source index yet — the agent indexes it via 'index_source_repository', "
                        "or run it explicitly with '/run index_source_repository <path>'.")
            return
        index = SourceIndex(source_ws.require_current())
        locations = index.search_text(query)
        if not locations:
            self._print(f"No matches for '{query}' in the indexed source.")
            return
        for loc in locations[:10]:
            self._print(f"  {loc.display()}")
            self._print(f"    {index.retrieve_context(loc).strip()[:300]}")

    def _print_why(self, subject_id: str) -> None:
        if not self._require_assessment():
            return
        if not subject_id:
            self._print("Usage: /why <action-id|hypothesis-id|finding-id>")
            return
        self._print(explain_why(self.controller.assessment.workspace, subject_id))

    def _print_settings(self) -> None:
        """Effective configuration with its origin, across the layers
        documented in docs/configuration.md. `AdiConfig` itself doesn't
        track per-field provenance, so origin is inferred from which
        layer's file exists — this is a best-effort summary, not a
        guarantee every value traces to the exact line it came from."""
        core_config_path = self.project_root / ".adi.yaml"
        core_origin = "project (.adi.yaml)" if core_config_path.exists() else "default"
        self._print("[bold]AI[/bold]")
        active = self.controller.models.active_profile()
        providers_path = self.controller.models.path
        providers_origin = "project (.adi/product/providers.json)" if providers_path.exists() else "default (none configured)"
        self._print(f"  active provider: {active.name if active else '(none)'}  [{providers_origin}]")
        self._print(f"  role assignments: {self.controller.models.store.roles.model_dump()}")

        self._print("\n[bold]Privacy[/bold]")
        policy = self.controller.models.store.privacy
        for field_name, value in policy.model_dump().items():
            self._print(f"  {field_name}: {value}  [{'project' if providers_path.exists() else 'default'}]")

        self._print("\n[bold]Runtime[/bold]")
        self._print(f"  type: {self.config.runtime.type}  [{core_origin}]")
        self._print(f"  allow_local: {self.config.runtime.allow_local}  [{core_origin}]")

        self._print("\n[bold]Security[/bold]")
        if self.controller.assessment is not None:
            scope = self.controller.assessment.workspace.load_scope()
            self._print(f"  authentication_testing: {scope.permissions.authentication_testing}  [assessment scope]")
            self._print(f"  approval_mode: {scope.approval_mode}  [assessment scope]")
        else:
            self._print("  (no active assessment)")

        self._print("\n[bold]UI[/bold]")
        self._print(f"  teach: {self.teach}  [session]")
        self._print(f"  expert: {self.expert}  [session]")

        self._print("\n[bold]Advanced[/bold]")
        from adi.product.credentials import keyring_available

        self._print(f"  credential store: {'OS keyring' if keyring_available() else 'file fallback (~/.config/adi)'}  [environment]")

    async def _generate_report(self) -> None:
        if not self._require_assessment():
            return
        from adi.reporting.builder import ReportBuilder
        from adi.reporting.json_report import write_reports

        assessment = self.controller.assessment
        report = ReportBuilder(assessment.workspace).build()
        paths = write_reports(report, assessment.directory / "reports")
        for kind, path in paths.items():
            self._print(f"Report ({kind}): {path}")


def _fmt_ts(ts: float) -> str:
    import datetime

    return datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).strftime("%Y-%m-%d %H:%M")


def _render_event(event: Event, *, teach: bool, expert: bool) -> str | None:
    data = event.data
    if event.type == EventType.ASSESSMENT_STARTED:
        return f"[bold green]Assessment created[/bold green]: {data.get('target')} (session '{data.get('session')}')"
    if event.type == EventType.ASSESSMENT_RESUMED:
        return f"[bold green]Assessment resumed[/bold green]: session '{data.get('session')}'"
    if event.type == EventType.TOOL_COMPLETED:
        suffix = f" — {data.get('detail')}" if expert else ""
        return f"[green]✓[/green] {data.get('capability') or 'action'}{suffix}"
    if event.type == EventType.TOOL_FAILED:
        return f"[yellow]![/yellow] {data.get('capability') or 'action'} failed: {data.get('detail')}"
    if event.type == EventType.APPROVAL_REQUIRED:
        return f"[yellow]◉[/yellow] blocked (scope/risk): {data.get('detail')}"
    if event.type == EventType.ASSESSMENT_COMPLETED:
        return f"[bold]Assessment complete.[/bold] {data.get('detail', '')}"
    if event.type == EventType.ASSESSMENT_PAUSED:
        return "[dim]Paused.[/dim]"
    if event.type == EventType.ASSESSMENT_STOPPED:
        return "[dim]Stopped.[/dim]"
    if event.type == EventType.MODEL_ERROR:
        return f"[red]Provider unavailable:[/red] {data.get('error')}"
    if event.type == EventType.SCOPE_CHANGED:
        return "[dim]Scope updated.[/dim]"
    if event.type == EventType.NOTICE and teach:
        return f"[dim]{data.get('detail', '')}[/dim]"
    return None


def run_plain_shell(config: AdiConfig, project_root: Path | None = None) -> None:
    shell = PlainShell(config, project_root)
    asyncio.run(shell.run())
