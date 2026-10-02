# Adi Product Shell — Implementation Status

Persistent engineering checklist for turning Adi into the full terminal
security workbench. Updated as work lands. Not a roadmap for approval —
a tracker.

Baseline at start of this effort: 269 passed, 1 skipped (`pytest -q`),
existing Core (Phase 1–6) untouched and must stay green throughout.

Legend: NOT STARTED / IN PROGRESS / IMPLEMENTED / TESTED / ENV BLOCKED

## Core (existing, preserved)
- ScopeEngine, risk/budget policy — TESTED (pre-existing)
- Orchestrator / Planner / Critic / HypothesisEngine — TESTED (pre-existing)
- ToolRegistry / CapabilityResolver(-ish via registry) / ToolExecutor — TESTED
- Runtimes (docker/local/mock) — TESTED
- Evidence store, redaction, integrity — TESTED
- Findings pipeline, severity, verifier, dedup — TESTED
- Source intelligence (discovery, routes, deps, secrets, correlation) — TESTED
- Validation engine + validators — TESTED
- Reporting (markdown/json/teach) — TESTED
- CLI (`adi assess/run-tool/resume/report/doctor/...`) — TESTED

## Product layer (new)
- Typed event bus (`adi.product.events`) — TESTED
- ModelManager / provider profiles (anthropic/openai/openrouter/ollama/
  vllm/lmstudio/openai-compatible/mock), role routing, live switching,
  model discovery (`/models` probe), connection testing — TESTED
- Credential storage (OS keyring + env-ref + 0600 fallback file, never
  plaintext in any DB/log) — TESTED (keyring backend not exercised live in
  this sandbox — see "Environmental limitations"; fallback path is tested)
- Privacy routing (per-category local/remote policy, blocks remote source
  code/raw evidence by default) — TESTED
- ProductController (chat → goal/scope → real Orchestrator.run loop →
  typed events; pause/continue/stop) — TESTED, vertical slice through real
  Core (MockRuntime + MockLLM, no Core code path bypassed)
- Session registry (human-readable names over assessment ids, resume,
  auto-resume candidate) — TESTED
- Plain interactive mode (`adi shell` / `adi --plain`) — TESTED
  (slash commands: /new /resume /sessions /status /scope /provider(s)
  /findings /hypotheses /evidence /pause /continue /stop /report /teach
  /mode /help /clear /exit; chat sets goal + starts loop; NL scope
  proposals require explicit y/N confirmation, never auto-applied)
- Natural-language scope interpreter (`adi.product.nlu`) — TESTED
  (deterministic regex matcher, not LLM-driven — scope changes stay
  reproducible/auditable and immune to prompt injection from tool output)
- Textual TUI (`adi.product.tui.app.AdiApp`) — TESTED headlessly (Textual's
  `run_test()` pilot: launches, renders, accepts real input events, drives
  real Core; see `tests/unit/test_tui.py`). Single main screen (chat +
  scope panel); findings/evidence/hypotheses/attack-surface/source still
  render as text in the chat log via slash commands rather than as
  dedicated scrollable widgets/panes — see "remaining TUI depth" below.
  Manual real-terminal verification NOT performed in this sandbox (no TTY
  available to the agent) — see Environmental limitations.
- Expert command console (`adi.product.console.ExpertConsole`) + sanitized
  command preview + approval integration — TESTED. `/run`/`/tool-run` go
  through the exact same `ScopeEngine`/`ToolExecutor` path as autonomous
  execution; "approve once" for the one Core-supported elevated-approval
  mechanism (`audit_credentials` + `approval_mode`), revoked immediately
  after use.
- Tool/capability browser (`/tools /tool /capabilities /capability`) —
  TESTED, reads live from `ToolRegistry` (same data `adi tools`/
  `adi capabilities` already expose).
- Attack-surface view (`/attack-surface`) — TESTED (hierarchical
  hosts/services/endpoints + source routes text rendering).
- Source intelligence view (`/source`) — TESTED (languages/frameworks/
  routes/dependencies summary). Deep source browsing (`/source-search
  <query>`, reusing `adi.source.index.SourceIndex` the same way the CLI's
  `source-search` command does) — TESTED.
- Findings/hypotheses/evidence text UX (`/findings /hypotheses
  /evidence`) — TESTED. Evidence-trace view (`/trace <finding-id>`:
  finding→hypothesis→validation actions→supporting observations→critic
  review→evidence, purely from stored state) — TESTED
  (`tests/unit/test_explain.py`, over a real confirmed finding from the
  Phase 4 fixture, not synthetic data).
- Explainability (`/why <id>` for an action/hypothesis/finding) — TESTED.
  Deterministic (reads `ActionRecord.reason_summary`/`.scope_reason`,
  `CriticReviewRecord`, hypothesis/finding linkage) — explicitly not an
  LLM call, per spec ("do not invent hidden chain-of-thought").
- First-run setup wizard — TESTED (`tests/unit/test_plain_shell.py::
  test_first_run_wizard_adds_provider_profile`), triggered automatically
  by `adi shell --plain` when no profile is configured.
- Doctor expansion (Product Shell section: keyring backend, configured
  profiles, session count) — TESTED.
- Crash/interruption recovery — TESTED (`Workspace.
  mark_interrupted_actions`, `tests/unit/test_crash_recovery.py`).
- Provider failure recovery — TESTED for the "profile fails to resolve"
  case (`tests/unit/test_plain_shell.py::
  test_provider_failure_then_switch_and_continue`); a live network outage
  against a real remote provider was not exercised (no outbound network
  in this sandbox).
- Terminal escape/control-sequence sanitization — TESTED
  (`adi.product.terminal_safety`, applied in `PlainShell._print` before
  every render).
- Secret-redaction regression — TESTED
  (`tests/unit/test_security_regression.py::
  test_redaction_strips_known_secrets_from_plain_shell_output`).
- Privacy-routing regression — TESTED
  (`test_privacy_routing_cannot_be_bypassed_by_role_name`).
- NO_COLOR — TESTED (`Console(no_color=...)` in `PlainShell.__init__`).
- Full headless local acceptance test — TESTED
  (`tests/integration/test_product_shell_acceptance.py`: fixture provider
  + fixture target, through `ProductController`/`ExpertConsole`, covering
  new-assessment → autonomous run → one confirmed finding with an
  evidence trace + one rejected hypothesis → report generation → process
  "restart" → resume by session name → identical state restored).
- Documentation: `docs/tui.md`, `docs/providers.md`,
  `docs/privacy-routing.md`, `docs/sessions.md`,
  `docs/interactive-security.md`, `docs/expert-mode.md`,
  `docs/configuration.md` — DONE. README now leads with the product
  workflow — DONE.
- Command console (`/run`, `/tool-run`) reusing Scope/Risk/Resolver — NOT STARTED
- Findings/hypotheses/evidence/attack-surface/source browsers (TUI) — NOT STARTED
- Approvals UI — NOT STARTED
- Teach mode / expert mode — NOT STARTED
- Pause/continue/stop, crash recovery — NOT STARTED
- First-run setup wizard — NOT STARTED
- Doctor expansion (providers, local model servers) — NOT STARTED
- Docs (tui.md, providers.md, privacy-routing.md, sessions.md,
  interactive-security.md, configuration.md, expert-mode.md) — NOT STARTED
- Full local acceptance test (fake provider, fixture target) — NOT STARTED
- Security regression proof (no raw shell, no self-approval, etc.) — NOT STARTED

## Dependency order chosen
1. Events + ModelManager/config/credentials (this commit)
2. Session registry + ProductController wired to real Orchestrator
3. Plain interactive shell (`adi --plain`) — first real vertical slice
4. Slash commands + command console + approvals (shared by plain & TUI)
5. Textual TUI shell reusing ProductController/events
6. Rich views (findings/evidence/attack-surface/source/hypotheses)
7. Teach/expert modes, pause/continue/stop, crash recovery
8. First-run wizard, doctor expansion
9. Hardening pass + security regression tests
10. Docs + full acceptance test

## Next task (continuation pointer)
Commits so far: `374a54e` (events/ModelManager/controller), `b68c16a`
(plain shell), `346fd0f` (status doc), `96ad1ba` (expert console/TUI/
terminal safety/crash recovery), `d8a09be` (first-run wizard/doctor/
security regression), `f74faf1` (controller bugfix + full acceptance
test), plus this commit (docs/README + provider-failure-recovery test).
309 passed, 1 skipped (full suite, last background run); Core untouched.

Remaining, in priority order:
1. **Dedicated TUI panes** for findings/hypotheses/evidence/attack-surface
   (currently rendered as text in the chat log via slash commands, which
   satisfies "browsable" but not "a navigable widget/pane with its own
   scroll/selection") — add `Screen` subclasses or a tabbed container,
   still reading through the same `ExpertConsole`/`Workspace` calls.
2. **Command palette parity**: Textual's built-in `Ctrl+P` palette
   (`App.COMMANDS`) is enabled but not populated with Adi-specific
   actions (New assessment, Resume, Switch model, ...) — add a
   `Provider`/`Hits` implementation per Textual's command-palette API.
3. **`/settings` with origin tracking** (assessment vs. project vs.
   global vs. default) — `docs/configuration.md` documents the current
   per-surface state; a unified view is not built.
4. Manual real-terminal verification of the TUI (this sandbox has no
   TTY attached to the agent) — ask the user to run `adi shell` and
   report back, or verify in an environment with one.

`ruff check .` passes clean repo-wide (re-verified after every subsequent
checkpoint below). Full suite re-run after every checkpoint; see the
commit log for exact pass counts at each point.

Files added/changed this pass: `src/adi/product/console.py`,
`src/adi/product/terminal_safety.py`, `src/adi/product/tui/app.py`,
`src/adi/knowledge/workspace.py` (`mark_interrupted_actions`), `docs/
{tui,providers,privacy-routing,sessions,interactive-security,
expert-mode,configuration}.md`, `README.md`. Tests: `test_expert_console.py`,
`test_terminal_safety.py`, `test_tui.py`, `test_crash_recovery.py`,
`test_security_regression.py`, `test_doctor_product.py`,
`test_product_shell_acceptance.py` (integration).

## Environmental limitations encountered
- OS keyring backend not exercised live in this sandboxed dev environment
  (no Secret Service/macOS Keychain session available to pytest); the
  fallback encrypted-permission file store is real and tested, and
  `keyring_available()` lets `doctor` report which path is active.
- No live remote LLM credential available in this session; provider
  connection logic is implemented and unit-tested against the `mock` kind
  and the OpenAI-compatible HTTP path is exercised by existing Core tests
  (`PlannerFixture`) but not against a real OpenRouter/Ollama endpoint —
  will be reported as NOT AVAILABLE unless the user supplies one later.
