# Phase 5 — source intelligence and source/runtime correlation

Phase 5 only. No Hydra, broad Kali discovery, automatic target edits, persistence,
stealth, destructive tests, external credential usage, or Phase 6 work was added.

## Architecture

`adi.source` adds typed repository/file/symbol/route/middleware/framework/config,
auth-control/database-access/data-flow, secret, SAST, dependency vulnerability,
source hypothesis, correlation and root-cause entities. The provider-independent
local index supports text, restricted regex, symbol, route, middleware and config
search plus bounded retrieval through indexed helper/service calls.

The operator selects the repository with `adi audit`. Planner source actions cannot
switch that root or read arbitrary files. No target source module is imported or
executed by analysis. Source analysis permission and runtime scope are separate.

Discovery excludes generated/dependency directories, honors root and nested
`.gitignore` and `.adiignore` patterns, skips symlinks/binary/unreadable files, and
limits individual reads, indexed files, total bytes and discovered files. Oversized
and binary files retain metadata, not content. Defaults: 512 KB/file, 5,000 indexed
files, 20 MB total read budget, 20,000 discovered files. Index text is redacted before
SQLite persistence, including duplicate occurrences of detected secret values in
other files. Secrets retain SHA256 fingerprints and location, never original values.

The SQLite `source_snapshot` stores the typed sanitized index and cached scan state.
File hashes, paths, sizes, mtimes and ignore rules form the repository fingerprint.
Unchanged files use cached hashes during freshness checks. Changed/missing repositories
invalidate correlations and prevent old source hypotheses from validation/finalization,
even after refresh. Historical runtime findings remain evidence records; reports label
stale source root-cause information. Git is optional; commit/branch are metadata.

The planner receives a source summary and capped requested code slices. Source code
is untrusted evidence, not instructions. Middleware names only indicate relevance;
implementations and called helpers are retrieved. Guard patterns never prove enforcement.
Source-only authorization/SAST suspicion remains supported, never confirmed. Controlled
runtime refutation rejects it. Confirmation uses the existing validation/scope/critic
pipeline; source context and code-aware remediation are attached to confirmed BOLA.
Runtime-first investigation uses the same persisted correlations and source evidence.

## Language and framework support

Language detection: Python, JavaScript, TypeScript, Go, Java, PHP, Ruby, C#, Shell,
YAML, JSON and Terraform (also TOML/XML). Semantic route plugins: Python AST for
FastAPI/Flask; conservative JavaScript/TypeScript syntax for Express. Python route
prefixes, dependency middleware and local helper calls are inspected; Express named
handlers, simple mounts and local/global middleware are recognized.

Framework signals: Express, FastAPI, Flask, Django, Next.js, React, NestJS, Laravel,
Spring Boot and Rails, with source location, signal and confidence. Detection does
not imply deep semantic support for every framework.

Manifest parsers: package.json/package-lock.json, pnpm-lock.yaml/yarn.lock,
requirements.txt, pyproject.toml/poetry.lock/Pipfile.lock, go.mod/go.sum,
pom.xml/build.gradle, composer.json/composer.lock and Gemfile.lock. Constraints are
kept as constraints; parsing never resolves them into invented installed versions.

## Tool support

Four source skills include fixed argv adapters, typed JSON parsers and fixtures:
Semgrep, Gitleaks, Trivy and OSV Scanner. Source scanners stage only bounded indexed
files, hash-check copies, run without shell interpolation, suppress raw diagnostics,
remove temporary artifacts, and cache successful scans by repository fingerprint.
Semgrep uses bundled local rules, disables metrics/version checks and uses temporary
settings/log paths. Gitleaks requests fully redacted JSON. Trivy/OSV use offline mode
and require pre-populated local advisory databases. Source tools cannot run through
the runtime executor, which would otherwise persist raw scanner output.

Dependency capability resolution tries OSV first and Trivy second, including fallback
when the first scanner fails. Normalized vulnerability records deduplicate advisory
aliases and retain provenance. `KNOWN_AFFECTED_DEPENDENCY` does not mean runtime
exploitability. Imported scanner JSON remains an indication. Secret presence can be
confirmed independently from operator files; credential validity is never tested.

Tool flags follow the upstream [Semgrep metrics documentation](https://github.com/semgrep/semgrep/blob/develop/metrics.md),
[Gitleaks CLI](https://github.com/gitleaks/gitleaks/blob/master/README.md),
[Trivy offline guidance](https://www.trivy.dev/docs/v0.55/guide/advanced/air-gap/), and
[OSV v2 migration guidance](https://google.github.io/osv-scanner/migration-guide.html).

## Acceptance results

The actual local demo binds FastAPI only to 127.0.0.1. Object 1 belongs to user_a;
object 2 belongs to user_b. Both identities are fake, explicitly controlled accounts.

- Six source routes discovered: GET /, POST /api/login, GET /api/orders/{id},
  GET /api/orders-safe/{id}, GET /api/private, GET /api/parse-literal.
- Three observed method/origin/template correlations: login and both object routes.
  `/api/orders/{id}` correlates to `/api/orders/1` with confidence 0.98.
- Source: `src/routes/orders.py:19-25`, `src/middleware/auth.py:4-7`,
  `src/services/orders.py:9-10`. Authentication is present; ID-only object return
  has no established ownership restriction.
- Broken endpoint: user_a 200; user_b 200 with the same protected object.
  ADI-F-001, High, confirmed; scripted Critic ACCEPT. Root cause and precise
  remediation reference the route and service. This is real HTTP, not mocked HTTP.
- Safe endpoint: source helper ownership guard is observed; user_b receives 403.
  Hypothesis REJECTED and a positive ownership-control observation is recorded.
- Real installed Semgrep flags one broad `ast.literal_eval` indication. Independent
  source inspection recognizes literal-only parsing and rejects this rule's
  dynamic-execution implication. No confirmed finding is created from the alert.
- Fake secret: built-in deterministic presence scan plus Gitleaks JSON fixture;
  value redacted, SHA256 retained, test-only context recorded. Tests assert the
  original string is absent from SQLite, source index, CLI and both report formats.
- ADI-TEST-001: synthetic advisory fixture for adi-test-vulnerable-lib 1.0.0,
  fixed 1.0.1. OSV/Trivy fixture results deduplicate to one affected-dependency
  record. This is explicitly test data, not a claimed live CVE/database result.
- Finding → hypothesis → source snippets/routes + runtime exchanges → authorized
  supporting validation → scope decision → persisted critic ACCEPT. Tests verify
  real exchange IDs, evidence links, source locations, and restart persistence.
- No model provider was configured. MockLLM drives deterministic planner/critic
  acceptance. No external model call occurred. Automatic approval review rejected
  an earlier demo variant that could transmit evidence; the completed variant is local.
- Semgrep 1.179.0 is available and was actually executed. Gitleaks, Trivy and
  OSV Scanner are unavailable here; their adapters/parsers/fallback are tested with
  explicitly labeled fixtures, not represented as real scans.

The executable demo prints its current assessment ID and writes `acceptance.json`,
`reports/report.md` and `reports/report.json` beneath `.adi/assessments/<id>/`.
A repeat run creates a new assessment rather than silently reusing an old finding.

## Exact commands

```sh
cd /Users/faisal/dev/Adi
.venv/bin/python -m pip install -e '.[dev,phase5-lab,source-tools]'
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check src skills tests examples
.venv/bin/python examples/phase5_smoke.py
.venv/bin/adi doctor
```

For a provider-driven run (requires an already configured provider):

```sh
# Terminal 1, keep loopback-only binding:
cd /Users/faisal/dev/Adi/tests/fixtures/phase5_app
/Users/faisal/dev/Adi/.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8765

# Terminal 2:
cd /Users/faisal/dev/Adi
.venv/bin/adi audit ./tests/fixtures/phase5_app \
  --target http://127.0.0.1:8765 --scope examples/phase5-scope.yaml --autonomous
```

```sh
.venv/bin/adi source <assessment-id>
.venv/bin/adi routes <assessment-id>
.venv/bin/adi correlations <assessment-id>
.venv/bin/adi source-search <assessment-id> find_order
.venv/bin/adi source-scan <assessment-id> scan_source_patterns
.venv/bin/adi source-index <assessment-id>
.venv/bin/adi finding <assessment-id> ADI-F-001
.venv/bin/adi teach <assessment-id> ADI-H-001
.venv/bin/adi report <assessment-id>
.venv/bin/adi resume <assessment-id>
```

## Remaining limits

This is lightweight static analysis, not a compiler or commercial SAST engine.
Dynamic registration, imported Express router mounts, complex middleware chains,
ambiguous helper names, advanced lockfile dialects and interprocedural reachability
need more language plugins. Ignore matching supports common patterns/negation/nested
rules rather than every Git wildmatch edge case. Regex search restricts complex
patterns. Correlation requires an operator application binding and a real observed
exchange at the matching origin, not a route guessed from source alone.

Guard and query patterns are structured observations, not semantic proofs. Authorization
confirmation conservatively requires equivalent nonempty protected responses; differing
responses need further review. Root-cause confidence remains bounded; a visible guard
that fails at runtime is described as ineffective rather than absent. Development
config is labeled; production exposure is not inferred from `.env.example` or debug
settings alone. Fake secret presence is not credential validity or severity.

Semgrep's bundled rules are intentionally small. Dependency version constraints need a
lockfile/scanner to establish an affected installed version. Offline dependency tools
need their local databases. Gitleaks history scans, full taint analysis, auto-fix,
autonomous code commits, exploit generation and Phase 6 are outside this phase.

## Recorded quality gate and artifacts (2026-10-02)

- Full suite: **224 passed, 1 skipped**. Ruff and `git diff --check`: PASS.
- Installed dependency consistency (`pip check`): PASS.
- Browser skip: existing Playwright Chromium is not configured/available; no browser
  result is claimed. Loopback HTTP and real Semgrep tests pass.
- Docker Kali runtime is unavailable in this environment. The Phase 5 lab and source
  scanners run locally; runtime scanning continues to require the existing explicit
  local-runtime opt-in or an available Docker runtime.
- Final demo assessment: `assess-d6dcb36d5803`; finding `ADI-F-001`
  (`find-28cdcfd35bc6`), hypothesis `hyp-6fd443f49733`.
- Source evidence: `ev-e8e7d87cd023`, `ev-8b80aeb1e934`, `ev-e99165a505c1`,
  `ev-8298ee98e61b`, `ev-0193dc788807`.
- Runtime evidence: `ev-cd62d6a83585`; validation `val-69bf31671c34` is
  scope-authorized and supporting; critic `crit-80546df79147` ACCEPT.
- Local report directory:
  `/Users/faisal/dev/Adi/.adi/assessments/assess-d6dcb36d5803/reports/`.
  `report.md`, `report.json` and sibling `acceptance.json` preserve the demo results.

Implementation commit: the commit containing this acceptance document (`git log -1`).
No push, deployment, target source fix or Phase 6 step is part of this acceptance.
