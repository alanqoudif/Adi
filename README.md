# Adi — AI Security Workbench for the Terminal

Adi is an AI-assisted cybersecurity workbench for **authorized** testing:
CTFs, university labs, intentionally vulnerable applications, internal
staging systems, and infrastructure you own or are explicitly authorized
to assess.

It is not a chatbot, a command generator, or a dashboard over a few Kali
commands. The design goal is: Adi understands an attack surface the way
Claude Code understands a codebase — it maintains a persistent, typed model
of a target, reasons about it, chooses and runs real security tools inside
an isolated runtime, and treats scanner output as evidence to be validated,
not as a finding.

## Day to day: `cd project && adi shell`

```bash
cd your-project
adi shell            # Textual TUI — or: adi shell --plain / adi --plain
```

First run walks you through picking an AI provider (Anthropic, OpenAI,
OpenRouter, Ollama, vLLM, LM Studio, or any OpenAI-compatible endpoint —
local models are first-class, no vendor lock-in) and confirms the
connection. Then you just talk to it:

```
> Assess this application and focus on authorization.
✓ enumerate_services — 3 services
✓ feroxbuster — 17 endpoints
◉ validating H-004 — object authorization
! ADI-F-001 confirmed — Broken Object Authorization · High
> show me the evidence for ADI-F-001
> generate the report
```

Everything it does — discovery, tool selection, validation, findings — is
typed, scoped, and auditable; the model never gets raw shell access (see
[docs/interactive-security.md](docs/interactive-security.md)). Experts can
drop into the same scope/risk-checked execution path explicitly with
`/run <capability> <target>` or `/tool-run <tool> <target>` (preview +
confirm before anything elevated runs — see
[docs/expert-mode.md](docs/expert-mode.md)).

Multiple AI provider profiles, live model switching, per-role routing
(planner/critic/code_analyst/reporter), and privacy routing that blocks
source code/raw evidence from reaching a remote model by default are all
built in — see [docs/providers.md](docs/providers.md) and
[docs/privacy-routing.md](docs/privacy-routing.md). Sessions are
human-readable and resumable (`/sessions`, `/resume <name>`, auto-resume
nudge on restart) — see [docs/sessions.md](docs/sessions.md). The full
command/keyboard surface (findings/evidence/hypotheses/attack-surface/
source browsers, scope editing, approvals, pause/continue/stop, teach/
expert modes) is in [docs/tui.md](docs/tui.md) and `/help` inside the
shell.

Everything below this point documents the underlying Core — scope
enforcement, the agent loop, tool execution, validation — that the
Product Shell above is built on, and remains available as a scripted,
non-interactive CLI (`adi lab`, `adi assess`, `adi run-tool`, ...) for
automation.

## What Adi is not

- Not a vulnerability-scanner UI, not a static Kali command encyclopedia.
- A scanner alert is never automatically a confirmed finding — see
  [docs/architecture.md](docs/architecture.md) for the observation →
  hypothesis → finding pipeline.
- Not for testing systems you do not own or are not authorized to test.
  See [docs/safety-model.md](docs/safety-model.md).

## Status: Phase 4 of 6

This repository implements **Phases 1–4**: assessment persistence, scope
enforcement, isolated tool execution, an LLM-driven agent loop, and now a
full HTTP/web-discovery subsystem — Adi can start from just a root URL and
autonomously discover links, forms, parameters, technologies, and API
endpoints (via its own HTTP/HTML crawl, content-discovery tools, and —
when Playwright is installed — real browser network capture), all folded
into one canonical Endpoint/Parameter/Session model regardless of which
mechanism found them. See [docs/agent-loop.md](docs/agent-loop.md) and
[docs/web-discovery.md](docs/web-discovery.md) for details and exact
current limitations.

| Phase | Scope | Status |
|---|---|---|
| 1 | Core runtime: CLI, scope, Docker/Local/Mock runtimes, tool registry, nmap skill, assessment persistence | ✅ done |
| 2 | Agent loop: LLM abstraction, planner, typed actions, context builder, hypothesis engine, loop prevention | ✅ done |
| 3 | Web capabilities: HTTP workspace, HTML/JS discovery, whatweb/ffuf/feroxbuster/nuclei, Playwright, rate limiting | ✅ done |
| 4 | Validation engine: evidence store, finding verifier, critic, positive controls, CLI inspection, persistent reports and teach mode | ✅ done |
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
adi doctor          # checks Python, Docker, tool registry, LLM config
adi tools           # lists discovered tool skills and their availability
```

Create a lab assessment and run nmap against an authorized local target
(use `runtime.type: local` in `.adi.yaml` for development without Docker —
see [docs/safety-model.md](docs/safety-model.md) for why this is opt-in):

```bash
cat > .adi.yaml <<'EOF'
runtime:
  type: local
  allow_local: true
EOF

adi lab 127.0.0.1 --name my-lab
adi assessments                       # find the generated assessment id
adi run-tool <assessment-id> nmap 127.0.0.1 --ports 1-1024
adi status <assessment-id>
```

To run the autonomous agent loop instead of invoking tools by hand, set an
LLM provider and pass `--autonomous`:

```bash
export ADI_LLM_API_KEY=sk-...        # or ADI_LLM_PROVIDER=openai-compatible + ADI_LLM_BASE_URL
adi lab 127.0.0.1 --autonomous --goal "Enumerate services and report findings."
```

Without a configured provider, `--autonomous` fails with a clear message
rather than faking a plan — see [docs/agent-loop.md](docs/agent-loop.md).

## Phase 4: controlled validation and reports

The validation/evidence/finding pipeline separates confirmed issues from rejected
false indications and stores positive security controls independently. Reports and
teach mode reconstruct facts from SQLite after restart. See [validation](docs/validation.md),
[evidence](docs/evidence.md), [findings](docs/findings.md), and [reporting](docs/reporting.md).

Safe local acceptance example (localhost only, deterministic planner fixture;
real CLI/Orchestrator/HTTP/validation/critic/reporting code):

```bash
source .venv/bin/activate
python examples/phase4_lab.py --output .adi/phase4-demo
# The script prints the stored assessment ID and exact report paths.
cd .adi/phase4-demo
adi resume <assessment-id>
adi hypotheses <assessment-id>
adi findings <assessment-id>
adi evidence <assessment-id> EV-001
adi teach <assessment-id> ADI-H-002
adi report <assessment-id>
```

The local demonstration confirms controlled cross-user order access (High, 0.95),
rejects the correctly protected route (403), records critic ACCEPT and the positive
control, and regenerates reports in a new process. No finding is inserted manually.
Real-model readiness is checked separately with `python examples/phase4_smoke.py`;
without provider credentials it explicitly reports a skip.

Phase 4 completion gates preserve the original 178 passing tests and cover redaction,
severity, false positives, critic, evidence trace, deduplication, persisted budgets,
resume, report regeneration and the autonomous local lab. Playwright's package was
installed, but Chromium's CDN download timed out repeatedly; the existing browser test
remains skipped. Docker image/daemon availability and configured real-model access
are environment-dependent. Phase 5 has not begun.

Implemented validators: object/function authorization, anonymous authentication,
cookie Secure/HttpOnly, logout behavior, security headers, CORS reflection and verbose
error disclosure. Reserved validation action types (including rate-limit probing)
remain explicitly unsupported. Severity uses conservative category impact defaults,
not full CVSS or inferred business impact. Pending authenticated work needs fresh
login after restart; cookie credentials are not persisted in reports or SQLite.

## Adding a new tool

Create `skills/<name>/` with `tool.yaml` (capabilities, risk level, target
types), `SKILL.md` (when/how to use it, false-positive risks, verification
strategy), `adapter.py::build_argv(...)`, and `parser.py::parse(...)`
returning `adi.knowledge.observations.Observation`s. Nothing in the executor
or orchestrator needs to change — see `skills/nmap/` as the reference
implementation and [docs/architecture.md](docs/architecture.md).

## Development

```bash
pytest -q
ruff check .
```

## Roadmap

See the phase table above and `docs/architecture.md`. Phases 1–4 are implemented.
Source intelligence (Phase 5) and tool expansion (Phase 6) remain unstarted.

### Phase 5: source code intelligence

Index an operator-accessible repository with `adi audit ./repository --target <authorized-url>`.
Use `adi source`, `adi routes`, `adi source-search`, and `adi correlations` to inspect
bounded, redacted source intelligence. `--autonomous` uses the configured provider;
source hypotheses validate through the existing scoped runtime/evidence/critic pipeline.
Source alerts and affected dependencies never automatically become runtime exploits.

Run `.venv/bin/python examples/phase5_smoke.py` for the real loopback FastAPI/Semgrep
acceptance demo with a scripted planner/critic. See [Phase 5 acceptance](docs/phase5-acceptance.md)
for exact commands, tool availability, fixture provenance, safety limits and source-enriched reports.
Phase 6 has not started.

## Core v1: capability-first tool intelligence (Phase 6)

Adi plans **Goal → Capability → reviewed Tool → scoped execution → Evidence → common knowledge**. The planner supplies typed requests, never raw shell commands. Runtime-aware availability/version probes, deterministic selection, bounded fallback, persistent incompatibility memory, reviewed Skill V2 contracts, common parsers and tool evidence complete the original six-phase core.

Reviewed tool support: Nmap, RustScan, WhatWeb, ffuf, feroxbuster, Nuclei, OpenSSL, smbclient, enum4linux-ng, ldapsearch, tcpdump, tshark, dig, host, nslookup, ssh-keyscan, Hydra, Medusa, Semgrep, Gitleaks, Trivy and OSV Scanner.

For the October 2, 2026 acceptance environment:

- **Live target/capture tested:** Nmap, OpenSSL, feroxbuster, tcpdump (authorized generated pcap), ldapsearch (local rootDSE fixture). Prior Phase 5 tests also exercise live Semgrep.
- **New deterministic parser fixture coverage:** RustScan, OpenSSL, SMB providers, LDAP, packet metadata providers, Hydra/Medusa, DNS providers and SSH metadata. Auth execution/lockout is tested against a real loopback HTTP service using an explicitly labelled provider fixture, not a live Hydra binary.
- **Absent locally:** RustScan, WhatWeb, ffuf, smbclient, enum4linux-ng, tshark, Hydra, Medusa, Gitleaks, Trivy and OSV Scanner. Optional tools do not fabricate success.
- **Installed with availability/version checks:** dig, host, nslookup, ssh-keyscan and Nuclei. This does not claim live target E2E for them.
- **Unavailable gates:** real-model smoke (no provider configured), Kali container build/live execution, existing Playwright browser-download gate. Optional John/Hashcat/SSL scanners were not added.

```bash
.venv/bin/adi tools
.venv/bin/adi capabilities
.venv/bin/adi capability inspect_tls
.venv/bin/adi tool hydra
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/python examples/phase6_smoke.py
```

See [tool intelligence](docs/tool-intelligence.md), [capabilities](docs/capabilities.md), [adding tools](docs/tool-plugins.md), [authentication safeguards](docs/authentication-auditing.md), [runtime tools](docs/runtime-tools.md), and [Phase 6 acceptance report](docs/phase6-acceptance.md). The smoke creates only local HTTP/TLS lab services and writes evidence under `.adi/phase6-acceptance/`. It needs loopback-server permissions and the listed installed tools. Its state-based planner is deterministic and explicitly labelled; it does not pretend to be a real model.
