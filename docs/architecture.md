# Architecture (Phase 1)

```
┌──────────┐     ┌────────────────┐     ┌───────────────┐
│  CLI     │────▶│  Assessment    │────▶│  ScopeEngine   │  (authorizes every action)
│ (Typer)  │     │  (lifecycle)   │     └───────────────┘
└──────────┘     │                │     ┌───────────────┐
                  │                │────▶│ ToolRegistry  │  (discovers skills/*/tool.yaml)
                  │                │     └───────────────┘
                  │                │     ┌───────────────┐
                  │                │────▶│ ExecutionRuntime │ (Docker / Local / Mock)
                  │                │     └───────────────┘
                  │                │     ┌───────────────┐
                  │                │────▶│  Workspace     │  (SQLite: hosts/services/
                  └────────────────┘     └───────────────┘   observations/actions/
                                                               hypotheses/findings)
```

`ToolExecutor` (`kai.tools.executor`) is the single path from "run this
tool" to stored knowledge:

```
authorize (ScopeEngine)
  → record action (audit trail, even if blocked)
  → build argv (skill's adapter.py)
  → execute (ExecutionRuntime)
  → persist raw stdout/stderr to assessment/raw/
  → parse (skill's parser.py, deterministic)
  → record observations (Workspace, folded into typed Host/Service rows)
```

## Why observations are separate from findings

An `Observation` (`kai.knowledge.observations`) is a raw, falsifiable fact
from a deterministic parser — "port 80 is open", "header X-Powered-By:
Express present". It is never, by itself, a vulnerability. Phase 2
introduces `Hypothesis` (already has DB schema and `Workspace` CRUD methods
in Phase 1 — `kai.knowledge.db.HypothesisRecord`) and Phase 4 introduces the
`FindingVerifier` that is the only path to a `confirmed` `Finding`. The
database schema for both already exists so later phases don't need a
migration.

## Persistence

Each assessment is a directory:

```
.kai/assessments/<assessment-id>/
├── state.db     # SQLAlchemy/SQLite — hosts, services, observations,
│                # actions (audit log), hypotheses, findings
└── raw/         # raw stdout/stderr per executed action, for auditability
```

`Assessment.resume()` (`kai.assessment`) reopens this directory and rebuilds
the `ScopeEngine`/`ToolRegistry`/runtime from the stored `Scope` — nothing
needs to be rediscovered.

## Tool skills

A tool is a directory under `skills/<name>/`:
- `tool.yaml` — typed metadata (`kai.tools.registry.ToolMetadata`): capabilities,
  risk level, supported target types, execution timeout.
- `SKILL.md` — natural-language knowledge for the planner (Phase 2 loads
  this only when the tool is actually selected, not into the main prompt).
- `adapter.py` — `build_argv(target, parameters, binary) -> list[str]`.
- `parser.py` — `parse(stdout, stderr, context) -> list[Observation]`,
  deterministic, no LLM involved.

Adding a tool means adding a directory; nothing in `kai.tools.executor` or
the orchestrator needs to change (spec section 68).

## Known Phase 1 limitations (by design, not oversight)

- No autonomous planner yet — `kai run-tool` executes a single named tool.
  Phase 2 adds `kai.agent.orchestrator`/`planner` driven by an LLM producing
  `PlannedAction`s.
- Only one tool skill (`nmap`) is implemented; Phase 3 adds the web-focused
  tools (httpx, whatweb, ffuf/feroxbuster, nuclei).
- `DockerKaliRuntime` is implemented against the `docker` SDK but is
  untested in this environment (no Docker daemon available during
  development) — `LocalRuntime` and `MockRuntime` are the tested paths.
  Build `docker/Dockerfile.kali` and verify `kai doctor` reports the Docker
  runtime available before relying on it for isolated execution.
