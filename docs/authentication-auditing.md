# Controlled authentication auditing

This capability is elevated risk. It is restricted to explicit operator-authorized test systems; it is not a spraying, harvesting or credential-reuse workflow.

`audit_credentials` requires authentication_testing permission, one in-scope target, explicit service/port, at most three named scope test accounts, a candidate-source reference defined by the operator, lockout acknowledgment, a reason/test context, total and per-account budgets, rate and timeout. Reviewed services are SSH/FTP/HTTP GET for Hydra and SSH/FTP for Medusa. Other modules and arbitrary module options are rejected.

The operator scope maps `credential_candidate_sources` identifiers to explicitly supplied local JSON files containing account/candidate pairs. These original operator files are inputs; Adi does not copy them into the assessment, reports or repository. Candidates are never accepted from Phase 5 secret discovery or the planner's raw parameters.

The request defaults to three attempts total, two per account, at most ten total/three per account, and at most ten attempts/minute (or the tighter scope rate). Each invocation receives one candidate, one task and stop-on-success settings. The executor spaces attempts, reserves budgets before execution, and persists service/account stop state before any next attempt. Successful candidates become boolean CredentialAuditObservation records plus authorized reference, never plaintext passwords. Provider work directories are ephemeral, so restore artifacts are discarded.

LOCKOUT_SIGNAL, RATE_LIMITED, timeout, parser error, instability/connection failure, or configured success immediately stops the service audit. Stop state also blocks Medusa fallback and survives resume. Resuming does not reset budgets. Unknown provider output is a parser failure, not permission to continue.

`scope.approval_mode: true` requires an explicit operator-approved `audit_credentials:TARGET` entry in `approved_elevated_actions`. The CLI does not automatically approve actions. `adi lab --approval-mode` enables that scope gate. Use operator-edited scope files/API to supply reviewed test accounts and approval entries; candidate values must not be included in approval text.

Important limitation: provider modules do not necessarily expose every remote lockout response, particularly SSH. Adi stops on all observable safety signals and keeps candidate sets tiny, but cannot infer an unreported lockout. No real Hydra/Medusa binary was present in the acceptance environment; parsers and typed invocations were fixture-tested, and local HTTP auth/lockout behavior was exercised with an explicitly labelled protocol fixture runtime.

Run a typed request with `adi run-capability ID audit_credentials TARGET --inputs-file request.json`. The JSON contains CredentialAuditRequest fields except target, with only a source reference, never candidate passwords. `tests/integration/test_phase6_local_lab.py` is the reproducible tiny authorized auth demonstration.
