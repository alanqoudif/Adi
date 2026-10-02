# Capability-first tool intelligence

Goal → CapabilityRequest → reviewed candidates → runtime/version/performance ranking → typed argv → ScopeEngine → bounded runtime → deterministic parser → common observations → workspace → planner.

The planner supplies a capability and typed parameters. `ToolRegistry.ranked()` considers declared priority, past failures, parser quality, structured output, privileges and noise. It presents at most three reviewed candidates. Availability and known incompatibility eliminate candidates before execution. The executor records why it chose a provider, including unavailable or incompatible alternatives. A planner-specified provider still passes the identical scope and adapter gates.

`ToolFailure` classifies unavailable binaries, unsupported options, argument errors, privileges, connection/DNS/TLS/auth failures, timeouts, rate limits, lockouts, target reachability, parser failures and partial results. Recovery tries at most three reviewed providers for unavailable/incompatible/parser failures. Lockout, rate limiting and authentication failures do not initiate fallback retries. Successful partial observations survive errors; evidence distinguishes PARTIAL_SUCCESS from its underlying failure cause.

Assessment-local `tool-performance.json` tracks successful/failed runs, timeouts, parser failures, version incompatibilities and average duration. Keys include tool/runtime/path/version. Resume excludes the same incompatible provider; changed paths/versions receive a fresh compatibility record. This is operational metadata, not model training.

Every execution has an action record, scope decision, sanitized stdout/stderr, and ToolEvidence containing capability, provider, runtime, version, argv, timestamps, exit status and normalized observation IDs. Evidence uses the existing Phase 4 `tool_result` type and can be linked to hypotheses/findings. Tool observations never automatically become findings. Nmap facts carry deterministic confidence; heuristic identity text is lower confidence; scanner alerts remain indications.

The scheduler serializes target tool runs per executor and retains the scope concurrency guard. Existing global budgets remain, with additional tool/network/elevated limits. Capture interfaces, files and credential datasets require operator scope configuration. No sudo, privilege escalation, shell-string planner execution, Metasploit modules or secret harvesting are exposed.

Temporary discovery is opt-in, PATH-only and executable-name allowlisted. It performs only bounded `--help` reading and creates TEMPORARY_INFERRED metadata. Its sole usable operation is local help inspection; target-facing execution needs a reviewed adapter/parser. Inferred capability/risk guesses cannot grant privileges or authentication rights. SkillCache keys include content hash, executable path and version; version probes have a path/stat/arguments cache.
