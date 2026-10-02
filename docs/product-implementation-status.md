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
- Typed event bus (`adi.product.events`) — IN PROGRESS
- ModelManager / provider profiles (Anthropic, OpenAI-compatible incl.
  OpenRouter/Ollama/vLLM/LM Studio/custom) — IN PROGRESS
  (LLM base/anthropic/openai_compatible already existed; adding profile
  storage, discovery, live switching, roles)
- Credential storage (OS keyring + env-ref, never plaintext in DB) — NOT STARTED
- Privacy routing (local_only / remote_allowed policy) — NOT STARTED
- ProductController (chat → structured intent → existing Orchestrator) — NOT STARTED
- Session registry (human-readable names, resume) — NOT STARTED
- Plain interactive mode (`adi --plain` / `adi shell`) — NOT STARTED
- Textual TUI — NOT STARTED
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
Implement `adi.product.events` (typed event dataclasses + in-proc bus),
`adi.product.models` (ModelManager, ProviderProfile, keyring-backed
CredentialRef), wired into a new `adi.product.controller.ProductController`
that drives the existing `Assessment`/`Orchestrator` and emits events. Then
`adi --plain` as the first consumer. Files: see `src/adi/product/`.
