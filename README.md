# KAI — Autonomous Security Assessment Workspace

KAI is an agentic security workspace for **authorized** testing: CTFs,
university labs, intentionally vulnerable applications, internal staging
systems, and infrastructure you own or are explicitly authorized to assess.

It is not a chatbot, a command generator, or a dashboard over a few Kali
commands. The design goal is: KAI understands an attack surface the way
Claude Code understands a codebase — it maintains a persistent, typed model
of a target, reasons about it, chooses and runs real security tools inside
an isolated runtime, and treats scanner output as evidence to be validated,
not as a finding.

## What KAI is not

- Not a vulnerability-scanner UI, not a static Kali command encyclopedia.
- A scanner alert is never automatically a confirmed finding — see
  [docs/architecture.md](docs/architecture.md) for the observation →
  hypothesis → finding pipeline.
- Not for testing systems you do not own or are not authorized to test.
  See [docs/safety-model.md](docs/safety-model.md).

## Status: Phase 1 of 6

This repository currently implements **Phase 1** of the roadmap below:
assessment persistence, scope enforcement, isolated tool execution, and one
fully working tool skill (`nmap`) end to end, with tests. There is
deliberately no autonomous planner yet — see
[docs/architecture.md](docs/architecture.md#known-phase-1-limitations-by-design-not-oversight).

| Phase | Scope | Status |
|---|---|---|
| 1 | Core runtime: CLI, scope, Docker/Local/Mock runtimes, tool registry, nmap skill, assessment persistence | ✅ done |
| 2 | Agent loop: LLM abstraction, planner, typed actions, hypotheses | not started |
| 3 | Web capabilities: httpx, whatweb, ffuf/feroxbuster, nuclei, Playwright | not started |
| 4 | Validation engine: evidence store, finding verifier, critic, reporting | not started |
| 5 | Source intelligence: repo indexing, Semgrep/Gitleaks/Trivy, source↔runtime correlation | not started |
| 6 | Tool expansion: Hydra, SMB/LDAP, packet/TLS tools | not started |

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

```bash
kai doctor          # checks Python, Docker, tool registry, LLM config
kai tools           # lists discovered tool skills and their availability
```

Create a lab assessment and run nmap against an authorized local target
(use `runtime.type: local` in `.kai.yaml` for development without Docker —
see [docs/safety-model.md](docs/safety-model.md) for why this is opt-in):

```bash
cat > .kai.yaml <<'EOF'
runtime:
  type: local
  allow_local: true
EOF

kai lab 127.0.0.1 --name my-lab
kai assessments                       # find the generated assessment id
kai run-tool <assessment-id> nmap 127.0.0.1 --ports 1-1024
kai status <assessment-id>
```

## Adding a new tool

Create `skills/<name>/` with `tool.yaml` (capabilities, risk level, target
types), `SKILL.md` (when/how to use it, false-positive risks, verification
strategy), `adapter.py::build_argv(...)`, and `parser.py::parse(...)`
returning `kai.knowledge.observations.Observation`s. Nothing in the executor
or orchestrator needs to change — see `skills/nmap/` as the reference
implementation and [docs/architecture.md](docs/architecture.md).

## Development

```bash
pytest -q
ruff check src tests
```

## Roadmap

See the phase table above and `docs/architecture.md`. Phase 2 adds the
provider-neutral LLM abstraction and the planner that turns target state
into typed `PlannedAction`s, authorized by the same `ScopeEngine` already in
place.
