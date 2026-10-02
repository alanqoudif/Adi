# trivy source scan

Run only through SourceScanner on the operator-bound repository. It stages bounded files,
uses fixed local/offline flags and caches by repository fingerprint. Do not route this
skill through the runtime ToolExecutor, which stores raw scanner output.
Never confirm runtime exploitation from an alert. Never use discovered credentials.
trivy must be installed separately. Missing offline advisory databases produce an
honest unavailable result; dependency scanning falls back through the capability registry.


## Skill V2 contract
Intent and scope remain defined above. Use only the typed adapter; no arbitrary extra argv. Versions use the declared local probe. Unsupported options disable the provider for this assessment. Deterministic observations retain ToolEvidence provenance; scanner indications require Phase 4 validation. Scope rate limits and central concurrency apply. Inspect `adi capability` for available fallbacks.


## PURPOSE
Use this reviewed provider only for the capabilities declared in tool.yaml.


## CAPABILITIES
The machine-readable contract is authoritative; use adi capability to compare providers.


## WHEN TO USE
Resolve an unanswered assessment question within the approved scope.


## WHEN NOT TO USE
Avoid duplicate scans, incompatible versions, outside-scope targets and unnecessary noise.


## REQUIRED INPUTS
Only declared typed adapter parameters and authorized targets or source snapshots.


## SUPPORTED TARGET TYPES
See supports in tool.yaml; source scanners use a bound repository snapshot.


## RISK
Use risk_level in tool.yaml; scope and approval cannot be overridden by tool metadata.


## SCOPE REQUIREMENTS
All target actions require ScopeEngine; source actions require source_analysis permission.


## IMPORTANT OPTIONS
No arbitrary shell/extra arguments; the adapter controls the operation.


## OUTPUT FORMATS
Deterministic parser uses the preferred format in tool.yaml.


## INTERPRETATION
Observations and scanner indications require Phase 4 verification before findings.


## FALSE POSITIVE RISKS
Incomplete output, fingerprints and template heuristics may mislead.


## COMMON ERRORS
Unavailable executable, version mismatch, timeout, scope block and parser failure.


## RATE / LOCKOUT CONSIDERATIONS
Scope rate and concurrency bounds apply; this tool cannot bypass authentication permission.


## SAFE VALIDATION STRATEGY
Use sanitized fixtures and explicitly scoped local lab targets.


## RELATED TOOLS
adi capability lists reviewed interchangeable providers.


## FALLBACKS
Use only compatible, available reviewed providers; never invent flags through the LLM.


## VERSION DIFFERENCES
Declared local probes preserve unknown versions. Incompatible invocations disable the provider on resume.


## NORMALIZED OUTPUT MODEL
Typed Observation entities with action and ToolEvidence provenance; source scanners retain their Phase 5 evidence contract.
