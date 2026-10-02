"""Textual TUI — second consumer of `ProductController`/`PlainShell`'s
command interpreter. No orchestration logic lives here: this module only
renders events and forwards submitted lines to `PlainShell._handle`,
exactly like the plain shell does. That keeps both UIs backed by the
same real Core integration (Assessment/Orchestrator/ScopeEngine/...).
"""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import ClassVar

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import Hit, Hits, Provider
from textual.containers import Horizontal
from textual.widgets import Footer, Header, Input, RichLog, Static

from adi.config.models import AdiConfig
from adi.product.plain_shell import PlainShell


class ScopePanel(Static):
    """Right-hand side panel: target, scope, findings, model — refreshed
    after every rendered event so it never claims stale state."""

    def refresh_from(self, shell: PlainShell) -> None:
        assessment = shell.controller.assessment
        lines = []
        if assessment is None:
            lines.append("[dim]No active assessment.[/dim]")
            lines.append("Use /new <target> to begin.")
        else:
            scope = assessment.workspace.load_scope()
            ws = assessment.workspace
            lines.append("[bold]TARGET[/bold]")
            lines.append(", ".join(scope.targets) or "(none)")
            lines.append("")
            lines.append("[bold]SCOPE[/bold]")
            lines.append(f"Auth testing  {'on' if scope.permissions.authentication_testing else 'off'}")
            lines.append(f"Discovery     {'on' if scope.permissions.discovery else 'off'}")
            lines.append("")
            lines.append("[bold]FINDINGS[/bold]")
            findings = ws.list_findings()
            by_sev: dict[str, int] = {}
            for f in findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            if not by_sev:
                lines.append("(none yet)")
            for sev, count in by_sev.items():
                lines.append(f"{sev:<10} {count}")
            lines.append("")
            lines.append("[bold]MODEL[/bold]")
            active = shell.controller.models.active_profile()
            lines.append(active.name if active else "(none configured)")
            lines.append("")
            lines.append("[bold]STATE[/bold]")
            lines.append(shell.controller.state)
        self.update("\n".join(lines))


class AdiCommands(Provider):
    """Populates Ctrl+P with Adi-specific actions, each just forwarding a
    line into `PlainShell._handle` — identical to typing it, so there is
    exactly one place commands are interpreted."""

    _ACTIONS: ClassVar[list[tuple[str, str, str]]] = [
        ("New assessment", "/new ", "Start a new assessment against a target"),
        ("Resume session", "/resume ", "Resume a named session"),
        ("List sessions", "/sessions", "Show known sessions"),
        ("Switch provider", "/provider ", "Switch the active AI provider profile"),
        ("List providers", "/providers", "List configured provider profiles"),
        ("Findings", "/findings", "List findings recorded so far"),
        ("Hypotheses", "/hypotheses", "List hypotheses"),
        ("Evidence", "/evidence", "List evidence"),
        ("Attack surface", "/attack-surface", "Hierarchical hosts/services/endpoints/source view"),
        ("Source summary", "/source", "Source intelligence summary"),
        ("Scope", "/scope", "Show the active authorization scope"),
        ("Tools browser", "/tools", "Browse discovered tool skills"),
        ("Capabilities browser", "/capabilities", "Browse capabilities and fallback order"),
        ("Generate report", "/report", "Generate markdown + JSON reports"),
        ("Pause assessment", "/pause", "Stop scheduling new actions"),
        ("Continue assessment", "/continue", "Resume scheduling"),
        ("Stop assessment", "/stop", "End the assessment safely"),
        ("Help", "/help", "Show the command reference"),
    ]

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        app = self.app
        assert isinstance(app, AdiApp)
        for title, line, help_text in self._ACTIONS:
            score = matcher.match(title)
            if score > 0:
                yield Hit(
                    score, matcher.highlight(title),
                    partial(app.run_command_line, line),
                    help=help_text,
                )


class AdiApp(App):
    """Primary Product Shell screen. Keyboard-first, works at small
    terminal widths (Textual reflows automatically), honors NO_COLOR via
    Textual's own ANSI-detection plus our own sanitization in
    `PlainShell._print`."""

    CSS = """
    Screen { layout: vertical; }
    #body { height: 1fr; }
    #chat { width: 2fr; border: round $surface; }
    #side { width: 1fr; border: round $surface; padding: 0 1; }
    #input { dock: bottom; }
    """

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("ctrl+f", "show_findings", "Findings"),
        Binding("ctrl+e", "show_evidence", "Evidence"),
        Binding("ctrl+s", "show_scope", "Scope"),
        Binding("question_mark", "show_help", "Help"),
        Binding("ctrl+p", "command_palette", "Commands"),
    ]

    COMMANDS: ClassVar[set] = App.COMMANDS | {AdiCommands}

    def __init__(self, config: AdiConfig, project_root: Path | None = None):
        super().__init__()
        self.shell = PlainShell(config, project_root, output_sink=self._write_line)
        self._log: RichLog | None = None
        self._side: ScopePanel | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            yield RichLog(id="chat", wrap=True, markup=True)
            yield ScopePanel(id="side")
        yield Input(placeholder="Type a message or /help ...", id="input")
        yield Footer()

    def on_mount(self) -> None:
        self._log = self.query_one("#chat", RichLog)
        self._side = self.query_one("#side", ScopePanel)
        self.title = "ADI"
        self._write_line("[bold]Adi[/bold] — Ctrl+P for commands, ? for help, Ctrl+C to quit.")
        candidate = self.shell.controller.auto_resume_candidate()
        if candidate is not None:
            self._write_line(
                f"Recent session '{candidate.name}' ({candidate.target}) — "
                f"/resume {candidate.name} to continue it."
            )
        self._refresh_side()

    def _write_line(self, text: str) -> None:
        if self._log is not None:
            self._log.write(Text.from_markup(text) if "[" in text else text)
        self._refresh_side()

    def _refresh_side(self) -> None:
        if self._side is not None:
            self._side.refresh_from(self.shell)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        line = event.value.strip()
        event.input.value = ""
        if not line:
            return
        self._write_line(f"[dim]> {line}[/dim]")
        if line in ("/exit", "/quit"):
            self.exit()
            return
        try:
            await self.shell._handle(line)
        except Exception as exc:  # noqa: BLE001 - the TUI must never crash on a bad command
            self._write_line(f"[red]Error:[/red] {exc}")
        self._refresh_side()

    def run_command_line(self, line: str) -> None:
        """Invoked by `AdiCommands` hits from the Ctrl+P palette. A command
        that needs an argument (trailing space, e.g. '/new ') is placed in
        the input box for the operator to complete rather than run blind;
        a complete command runs immediately through the same `_handle()`
        every other entry point uses."""
        input_widget = self.query_one("#input", Input)
        if line.endswith(" "):
            input_widget.value = line
            input_widget.focus()
            return
        self._write_line(f"[dim]> {line}[/dim]")
        self.run_worker(self.shell._handle(line))

    def action_show_findings(self) -> None:
        self.run_worker(self.shell._handle("/findings"))

    def action_show_evidence(self) -> None:
        self.run_worker(self.shell._handle("/evidence"))

    def action_show_scope(self) -> None:
        self.run_worker(self.shell._handle("/scope"))

    def action_show_help(self) -> None:
        self.run_worker(self.shell._handle("/help"))


def run_tui(config: AdiConfig, project_root: Path | None = None) -> None:
    AdiApp(config, project_root).run()
