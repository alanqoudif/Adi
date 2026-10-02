# Phase 4 completion acceptance

Baseline: `89615d2`. Phase 5 remains unstarted.

## Quality gates

- Full suite: **194 passed, 1 skipped** (`python -m pytest -q -rs`).
- `ruff check .` and `git diff --check`: PASS.
- Mandatory authorization, false-positive, critic, evidence-trace, dedup, resume,
  report, severity, redaction, budget persistence and checkpoint-upgrade tests: PASS.
- Real autonomous CLI lab, fresh-process resume and report regeneration: PASS.
- `adi doctor`: Python/SQLite/tools ready; default Docker daemon/image unavailable;
  ffuf/whatweb unavailable; LLM unconfigured. Lab uses opted-in local runtime.
- Playwright dependency installed. Normal `python -m playwright install chromium`
  attempted; Chrome for Testing 153.0.8010.12 / Chromium v1243 CDN requests to
  `cdn.playwright.dev` timed out after 30,000 ms on all download retries.
  Existing browser test remains skipped; skip conditions were not weakened.
- Real-model smoke test skipped: provider credentials unavailable.
  Configured defaults: provider `anthropic`, model `claude-sonnet-5-5`.
  Planner action validity: not tested against a real model. See `.adi/phase4-smoke.json`.

## Actual stored demonstration

Assessment: `assess-1eff86d8aabe` (`local-phase4-lab`).

CLI invocation: `adi lab http://127.0.0.1:64647 --autonomous --name local-phase4-lab --max-actions 20`.

The example starts an isolated local application plus a deterministic provider fixture
and invokes the production CLI/router/planner/Orchestrator. This is not a real-model
claim. The fixture only selects actions; no final finding is inserted manually.

Attack surface: 4 persisted endpoints, including `/phase4`, `/api/login`,
`/api/orders-broken/1`, `/api/orders-safe/1`.

- Hypothesis ADI-H-001: `hyp-589cfb1b331f`.
- Controlled resource: order 1 belongs to user_a, declared by the local lab.
- Validation `val-ac869e581328`: user_a baseline 200, user_b request 200;
  the protected response body hashes are equal.
- Scope authorization: recorded true.
- Critic: ACCEPT, `crit-175b87013ee9`.
- Finding ADI-F-001: `find-2ed0e44e7236`; confirmed, High, confidence 0.95.
- Evidence EV-001: `ev-b6fb4376b7d0`.
- HTTP exchanges: `http-643b0244ece7`, `http-c63b32d32810`.
- Impact: another authenticated user reads a controlled order; no wider business impact inferred.
- Remediation: enforce server-side object ownership on each resource request.

Safe hypothesis ADI-H-002: `hyp-f10f782562c8`.

- Validation `val-084cbbd5c8ed`: owner 200, user_b 403.
- Decision: REJECTED; absent from confirmed findings.
- Evidence EV-002: `ev-8e973ca8c509`; HTTP exchanges
  `http-7e4b14e34af4`, `http-e1bad06c8b84`.
- Positive control ADI-P-001: `pos-db20c973c4cb`, cross-user object access correctly denied.

All findings, evidence, critic reviews, positive controls and budgets survive fresh-process
resume. Both hypotheses used one action of their persistent eight-action limit.
Resolved hypotheses refuse another validation; repeated finalization returns the
stored finding without repeating critic review. Report regeneration reads SQLite.

## Report artifacts

- `/Users/faisal/dev/Adi/.adi/phase4-demo/.adi/assessments/assess-1eff86d8aabe/reports/report.md`
- `/Users/faisal/dev/Adi/.adi/phase4-demo/.adi/assessments/assess-1eff86d8aabe/reports/report.json`
- `.adi/phase4-demo/acceptance.json` and `acceptance.log` contain the stored demo facts/CLI output.

## Reproduce

```bash
cd /Users/faisal/dev/Adi
source .venv/bin/activate
python -m pytest -q
ruff check .
adi doctor
python -m pytest -q tests/integration/test_phase4_mandatory_validation.py tests/integration/test_phase4_report.py tests/integration/test_phase4_completion.py
python -m pytest -q -rs tests/integration/test_browser_discovery.py
python examples/phase4_smoke.py
python examples/phase4_lab.py --output .adi/phase4-demo
```

Each rerun prints a fresh assessment ID. To inspect this recorded run:

```bash
cd /Users/faisal/dev/Adi/.adi/phase4-demo
adi resume assess-1eff86d8aabe
adi status assess-1eff86d8aabe
adi evidence assess-1eff86d8aabe EV-001
adi hypotheses assess-1eff86d8aabe
adi hypothesis assess-1eff86d8aabe ADI-H-002
adi findings assess-1eff86d8aabe
adi finding assess-1eff86d8aabe ADI-F-001
adi teach assess-1eff86d8aabe ADI-H-002
adi report assess-1eff86d8aabe
```

## Remaining limitations

Severity uses conservative category defaults rather than full CVSS. Cookie validation
checks Secure/HttpOnly; complete SameSite semantics are not assessed. Reserved action
types, including automated rate-limit probing and source intelligence, remain explicitly
unsupported. Pending authenticated work needs a fresh login after restart because
credential-bearing session jars are ephemeral. Raw local HTTP artifacts are sensitive;
reports and CLI export only redacted metadata/previews. Pattern redaction cannot identify
every arbitrary unlabelled secret. These limits are documented; Phase 5 was not started.
