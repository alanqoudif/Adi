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
- Textual TUI — NOT STARTED
- Command console (`/run`, `/tool-run`) + command preview — NOT STARTED
  (CLI already has `run-capability`/`run-tool`; plain shell needs the same
  surfaced as in-shell slash commands with autocomplete + preview)
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
Done so far (commits `374a54e`, `b68c16a`): events, ModelManager/providers/
credentials/privacy-routing, SessionRegistry, ProductController (real
vertical slice through Assessment/Orchestrator), plain shell with slash
commands + NL scope proposals. 281 passed, 1 skipped; Core untouched.

Next, in dependency order:
1. **Command console + command preview** in `plain_shell.py`: `/run
   <capability> <target> [params]` and `/tool-run <tool> ...` routed
   through `assessment.executor.run_capability` / `.run` (same path as
   `adi run-capability`/`run-tool` in `cli.py`) with a sanitized preview
   (capability, provider tool, runtime, budget, rate — no secrets) and
   explicit approve/reject before any elevated/approval-required call.
   Needs `ScopeEngine`'s existing approval-required signal surfaced as a
   typed event (`APPROVAL_REQUIRED` already exists on the bus; wire a
   confirm prompt consuming it instead of auto-blocking).
2. **Tool/capability browser** (`/tools`, `/tool <name>`, `/capabilities`,
   `/capability <name>`) reading `ToolRegistry`/executor's resolver
   directly (same data `adi tools`/`adi capabilities` already expose in
   `cli.py` — reuse, don't reimplement).
3. **Attack surface / source views** (`/attack-surface`, `/source`) over
   `Workspace.list_hosts/list_services/list_endpoints` + `load_source()`.
4. **Approvals view** (`/approvals`) + first-run wizard (`adi` with no
   provider configured walks through ModelManager.add_profile +
   test_connection).
5. **Textual TUI** (`src/adi/product/tui/`) as a second consumer of
   `ProductController`/`EventBus` — do not duplicate controller logic.
6. **Crash recovery**: mark in-flight `ActionRecord`s `INTERRUPTED` on
   `Assessment.resume` if `status == "running"` at process start.
7. Doctor expansion, docs (tui/providers/privacy-routing/sessions/
   interactive-security/configuration/expert-mode), full deterministic
   local acceptance test, security regression tests (model cannot
   self-approve/expand scope/enable auth-testing — partially provable
   already: `update_scope_fields` is never called from `_drive()`/planner
   path, only from operator-confirmed `plain_shell` input).

Files: `src/adi/product/{events,credentials,models,sessions,controller,
nlu,plain_shell}.py`, `tests/unit/test_product_controller.py`,
`tests/unit/test_plain_shell.py`. `Workspace.update_scope` added to
`src/adi/knowledge/workspace.py` (minimal, additive).

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
