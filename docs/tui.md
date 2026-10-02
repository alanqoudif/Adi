# The Product Shell (TUI & plain mode)

`adi shell` (or bare `adi`)
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
| Ctrl+Q | quit |

## Connect AI

On an empty project the welcome log offers OpenAI, Anthropic, OpenRouter,
Ollama, LM Studio, vLLM, Custom OpenAI-compatible, and Continue without AI.
Use `/provider add` or Ctrl+P → **Add AI Provider** to open setup. Answer
prompts in the input field; API key entry is masked and never copied to
the chat log. `/cancel` cancels setup without saving. The input regains
normal behavior after setup or cancellation.

Setup discovers model IDs and accepts either a model number or manual ID.
A minimal completion tests reachability, authentication, the selected
model and response shape before saving by default. Failed tests do not
save credentials or replace an existing profile. Explicitly skipping the
test labels the connection unverified.

| Command | Action |
|---|---|
| `/providers` | List saved profiles |
| `/provider` | Show active provider and model |
| `/provider add` | Interactive connection setup |
| `/provider edit <name>` | Edit endpoint, key or model |
| `/provider remove <name>` | Remove profile, credential and role pins |
| `/provider test <name>` | Test a profile; no name tests the active profile |
| `/provider <name>` | Switch active provider |
| `/models` | Discover models for the active provider |
| `/model` | Show active model |
| `/model <id>` | Switch model, including a manually entered ID |

Ctrl+P also offers **Switch AI Provider**, **Test Active Provider**,
**Choose Model**, and **Provider Settings**. The status panel shows provider,
profile and model even before an assessment exists, and refreshes after
management commands. With no AI it shows the Add AI Provider shortcut.
An AI instruction without a configured provider returns setup instructions.

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
