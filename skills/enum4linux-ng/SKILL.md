# enum4linux-ng — Skill V2

## PURPOSE
Only bounded OS/identity inspection is invoked (-O). Text metadata is supported; JSON fixtures verify cross-tool normalization. Share enumeration uses smbclient. No -A, RID cycling, user/group dumps, or password inputs.

## CAPABILITIES
inspect_smb, inspect_smb_identity, enumerate_smb

## WHEN TO USE
Select only when this capability resolves an unanswered assessment question.

## WHEN NOT TO USE
Do not run outside authorized scope, to repeat already answered questions, or when parser/version compatibility failed.

## REQUIRED INPUTS
{'target': 'one authorized host', 'parameters': 'typed reviewed operation only'}. Authentication requires CredentialAuditRequest and operator candidate references.

## SUPPORTED TARGET TYPES
One host/IP, or an authorized service URL. No CIDR expansion or extra argv.

## RISK
low. No elevated privileges are granted by a skill.

## SCOPE REQUIREMENTS
ScopeEngine approval always precedes execution. Authentication additionally requires authentication_testing, test accounts, budgets and lockout acknowledgment.

## IMPORTANT OPTIONS
Only reviewed typed options in adapter.py are accepted. No raw shell passthrough.

## OUTPUT FORMATS
text; deterministic parser with bounded observations.

## INTERPRETATION
Outputs are observations, not automatically vulnerabilities. Maintain provenance through ToolEvidence.

## FALSE POSITIVE RISKS
Version differences, filtered ports, service proxies and incomplete outputs can mislead. Validate findings using Phase 4 verifiers.

## COMMON ERRORS
Permission denied, unavailable binary, connection refusal, timeout and parser mismatch are classified centrally.

## RATE / LOCKOUT CONSIDERATIONS
Central scope concurrency and runtime limits apply. Auth uses one candidate per process, conservative rate, persistent budgets and immediate stop on safety signals.

## SAFE VALIDATION STRATEGY
Use sanitized fixtures and explicitly scoped loopback labs. Never test public services during development.

## RELATED TOOLS
Consult adi capability for reviewed alternative providers.

## FALLBACKS
Only available reviewed providers. Lockout/rate-limit never triggers auth fallback.

## VERSION DIFFERENCES
Probe only declared local version_args. Unknown version does not mean unavailable; unsupported option disables this binary/path/version for the assessment.

## NORMALIZED OUTPUT MODEL
IdentityObservation, Service; evidence includes action, runtime, version, selected capability and observation IDs.
