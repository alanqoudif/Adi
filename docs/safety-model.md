# Safety Model

KAI is built for authorized security testing only: education, CTFs, labs,
and systems the operator owns or is explicitly authorized to assess. Safety
is enforced in code, not only documented.

## Scope enforcement (`kai.scope.engine.ScopeEngine`)

Every target-facing action — running a tool, sending an HTTP request,
driving a browser — must pass through `ScopeEngine.authorize()` before
execution. See `kai.tools.executor.ToolExecutor.run`, which authorizes and
logs the decision (allowed or blocked, with reason) to the action audit
trail *before* anything is executed, including when the action is blocked.

Rules enforced today (Phase 1):
- The target host must be inside `scope.targets` (or a subdomain of one) or
  inside `scope.allowed_ips`, and must not be in `scope.excluded_hosts`.
- Authentication-testing capabilities (`credential_audit`, `brute_force`,
  `password_spray`) require `permissions.authentication_testing: true`.
- Active-validation capabilities require `permissions.active_validation: true`.
- Source-analysis and discovery/web-enumeration capabilities respect their
  corresponding `permissions.*` flags.
- Any action classified `risk: high` is always blocked — nothing in Phase 1
  escalates to high risk automatically; this is reserved for an explicit
  operator-approval flow (Phase 2+, spec section 44).

An out-of-scope host discovered through a redirect or a link is never
auto-followed for active testing — it must be recorded as an external
dependency observation instead.

## Execution isolation

`DockerKaliRuntime` (`kai.runtime.docker_runtime`) is the default. It:
- runs with `cap_drop=["ALL"]` and `no-new-privileges`,
- mounts only the assessment's own `raw/` output directory, never the host
  home directory, SSH keys, browser profiles, cloud credentials, or the
  Docker socket,
- enforces a memory limit, a pids limit, and a per-execution timeout.

`LocalRuntime` exists for development convenience only. It is opt-in: it
requires both `runtime.type: local` **and** `runtime.allow_local: true` in
`.kai.yaml` — the default config refuses to construct it
(`kai.assessment.build_runtime`).

All argv is executed via `asyncio.create_subprocess_exec` (no shell), so
target strings can never inject shell metacharacters into a command line.

## Honesty about failure

KAI never fabricates successful tool output. If Docker is unavailable,
`kai doctor` and `DockerKaliRuntime.is_available()` report that plainly. If
a tool is not installed, `ToolExecutor.run` raises `ToolExecutionError`
rather than inventing results. Fixtures with canned tool output exist only
under `tests/fixtures/` and are never read by production code paths.

## Secrets

Test-account passwords are referenced by environment-variable name
(`TestAccount.password_env`), never stored as plaintext in scope config,
the database, logs, or reports. The planner/LLM only ever sees that an
account reference exists (e.g. "authorized test account A is available"),
never the resolved secret — see spec sections 24/48 (not yet implemented;
Phase 3+ introduces the HTTP/session subsystem that resolves these).

## What is explicitly out of scope for this project

Destructive actions, persistence mechanisms, stealth/evasion techniques,
automatic expansion of testing to hosts outside the configured scope, and
intentional denial-of-service are not features KAI will ever implement.
