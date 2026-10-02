"""Textual TUI — second consumer of `ProductController`/`PlainShell`'s
command interpreter. No orchestration logic lives here: this module only
renders events and forwards submitted lines to `PlainShell._handle`,
exactly like the plain shell does. That keeps both UIs backed by the
same real Core integration (Assessment/Orchestrator/ScopeEngine/...).
"""

from __future__ import annotations

from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
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
            lines.append(f"[bold]TARGET[/bold]")
            lines.append(", ".join(scope.targets) or "(none)")
            lines.append("")
            lines.append(f"[bold]SCOPE[/bold]")
            lines.append(f"Auth testing  {'on' if scope.permissions.authentication_testing else 'off'}")
            lines.append(f"Discovery     {'on' if scope.permissions.discovery else 'off'}")
            lines.append("")
            lines.append(f"[bold]FINDINGS[/bold]")
            findings = ws.list_findings()
            by_sev: dict[str, int] = {}
            for f in findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            if not by_sev:
                lines.append("(none yet)")
            for sev, count in by_sev.items():
                lines.append(f"{sev:<10} {count}")
            lines.append("")
            lines.append(f"[bold]MODEL[/bold]")
            active = shell.controller.models.active_profile()
            lines.append(active.name if active else "(none configured)")
            lines.append("")
            lines.append(f"[bold]STATE[/bold]")
            lines.append(shell.controller.state)
        self.update("\n".join(lines))


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

    BINDINGS = [
        Binding("ctrl+f", "show_findings", "Findings"),
        Binding("ctrl+e", "show_evidence", "Evidence"),
        Binding("ctrl+s", "show_scope", "Scope"),
        Binding("question_mark", "show_help", "Help"),
        Binding("ctrl+p", "command_palette", "Commands"),
    ]

    COMMANDS = App.COMMANDS

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
        except Exception as exc:  # the TUI must never crash on a bad command
            self._write_line(f"[red]Error:[/red] {exc}")
        self._refresh_side()

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
