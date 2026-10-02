# The Product Shell (TUI & plain mode)

`adi shell` (or bare `adi`, once wired — see
[product-implementation-status.md](product-implementation-status.md))
opens the interactive Product Shell: a chat-first security workbench over
the real Core (scope, orchestrator, tools, evidence, findings, source
intelligence). It has two front ends sharing one command interpreter:

- **Textual TUI** (default): `adi shell`
- **Plain line mode** (SSH-friendly, accessibility tools, basic terminals):
  `adi shell --plain` or `adi --plain`

Both call into `adi.product.plain_shell.PlainShell._handle()` for every
command and chat message — the TUI (`adi.product.tui.app.AdiApp`) only
redirects rendering through an `output_sink` instead of a live `Console`.
Neither front end re-implements orchestration: both drive the same
`ProductController`.

## Layout (TUI)

```
┌──────────────────────────────────────────────────────────────┐
│ ADI                                                    clock  │
├──────────────────────────────────────────┬───────────────────┤
│ chat / activity log                      │ TARGET            │
│                                          │ SCOPE              │
│ > focus on authorization                 │ FINDINGS           │
│ ✓ enumerate_services — 3 services        │ MODEL              │
│ ◉ validating H-004                       │ STATE              │
├──────────────────────────────────────────┴───────────────────┤
│ > type a message or /command                                  │
├────────────────────────────────────────────────────────────────┤
│ Ctrl+F findings  Ctrl+E evidence  Ctrl+S scope  Ctrl+P commands│
└──────────────────────────────────────────────────────────────┘
```

The right-hand panel (`ScopePanel`) re-renders after every event, so it
never shows stale state — it reads directly from `ProductController`
(`assessment`, `models.active_profile()`, `state`), not from a cached
copy.

## Keyboard

| Key | Action |
|---|---|
| Ctrl+P | Textual's built-in command palette |
| Ctrl+F | `/findings` |
| Ctrl+E | `/evidence` |
| Ctrl+S | `/scope` |
| ? | `/help` |
| Ctrl+C | quit |

## Slash commands

See `/help` inside the shell for the live list; it covers sessions,
status, scope, providers/models, findings/hypotheses/evidence, the
expert command console (`/run`, `/tool-run`, `/tools`, `/capabilities`),
attack-surface/source views, pause/continue/stop, report generation, and
teach/expert mode toggles.

## NO_COLOR / small terminals

- `NO_COLOR=1` disables ANSI color in the plain shell (`Console(no_color=
  True)`); the Textual TUI defers to the terminal's own capability
  detection.
- The plain shell has no minimum terminal width — it's line-oriented.
- The TUI reflows via Textual's own layout engine; it has been exercised
  headlessly (see `tests/unit/test_tui.py`, Textual's `run_test()` pilot)
  but not yet manually verified at very small real-terminal sizes — see
  `product-implementation-status.md` for exactly what has and hasn't
  been manually verified in this environment.

## Terminal safety

Everything rendered that originated outside Adi's own code — tool output,
HTTP bodies, source content, finding/hypothesis titles, external
banners — passes through `adi.product.terminal_safety.
sanitize_for_terminal()` before reaching the console, stripping ANSI/VT
escape sequences and raw control bytes. See
`tests/unit/test_terminal_safety.py`.
