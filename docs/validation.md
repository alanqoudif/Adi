# Phase 4 validation

An observation describes what was seen. A Hypothesis is a falsifiable security
question; a Finding is a verified issue. A scanner indication alone remains
supported and cannot confirm an issue.

The accepted pipeline is unchanged: discovery → hypothesis → typed validation
→ evidence → deterministic verifier → critic (when configured) → deduplication
→ calculated severity → finding. Validation outcomes are supports, refutes,
inconclusive and error. Hypotheses move through new, investigating, supported,
validating, confirmed/rejected, or blocked; confirmed/rejected are terminal.

Implemented validators cover controlled object and function authorization,
anonymous authentication boundaries, cookie attributes, logout behavior,
security headers, credentialed CORS reflection, and verbose error disclosure.
Other action enum values are reserved and return an explicit unsupported error;
rate-limit probing and source intelligence are not implemented in Phase 4.

Every validation checks target scope and active-validation permission before
HTTP execution. HTTP requests and redirect hops also use the existing scope
engine. Eight actions per hypothesis are the default. The configured limit is
persisted on first use; executed action counts reconstruct budgets after restart.
Completed hypotheses refuse further validation. Session cookie jars are ephemeral;
pending authenticated work must log in again after process restart.

The critic challenges ownership, public-resource assumptions, caching, session
identity and response meaning. It accepts, rejects, or asks for a specific further
test. Its decision and concerns persist separately. Autonomous assessments require
the configured critic; direct deterministic API assessments can omit it explicitly.

Reasons are stored at execution time: the planner's concise reason summary, or a
deterministic description of the selected validator and stored hypothesis. Results
and verifier decisions explain confirmation/rejection without model chain-of-thought.
`adi teach <id> <hypothesis-id>` reconstructs Observed, Security question, Validation,
Result, Why and Lesson from those records; legacy missing reasons are labelled missing.

## Safe acceptance lab

```bash
python examples/phase4_lab.py --output .adi/phase4-demo
```

This starts only localhost servers and invokes the real `adi lab URL --autonomous`
CLI through a deterministic provider fixture, explicitly not a real LLM. It discovers
controlled resources and ownership, logs in two test users, validates both routes,
confirms the broken route with critic ACCEPT, rejects the safe route, records its
positive control, generates reports, then resumes and regenerates in fresh processes.
No final finding is manually inserted. See `acceptance.json` and `acceptance.log`.

Run `python examples/phase4_smoke.py` separately to test a configured real planner.
It records provider/model and structured-action validity without recording keys.
Only an exact anonymous-authentication check against the isolated fixture can execute.
