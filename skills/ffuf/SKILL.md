# ffuf

## PURPOSE
Fast web fuzzer — content discovery (same capability as feroxbuster) and,
with a custom wordlist, parameter/value fuzzing.

## WHEN TO USE
- Same situations as feroxbuster (`discover_web_content`); Adi's registry
  picks whichever of the two is actually installed, preferring feroxbuster
  when both are available (see `ToolRegistry.resolve`).
- When a maintained wordlist already exists for a specific fuzz point
  (e.g. fuzzing a parameter value, not just a path).

## WHEN NOT TO USE
- Against a target with no confirmed HTTP service.
- As a first action before a direct HTTP crawl has had a chance to find
  the linked surface for free.

## WHAT QUESTIONS THIS TOOL CAN ANSWER
- What paths exist on this server that aren't linked anywhere?

## REQUIRED INPUTS
- `target`: a base URL. The adapter appends `/FUZZ` itself.
- `parameters.wordlist` (optional): resolved the same way as feroxbuster's
  — see `adi.tools.wordlists.resolve_web_content_wordlist`.

## SUPPORTED TARGET TYPES
URL only.

## IMPORTANT OPTIONS
This adapter requests JSON output via `-of json -o /dev/stdout` (ffuf has
no native "write JSON to stdout" flag — writing to `/dev/stdout` is the
standard Unix workaround; this tool is only run inside the Linux-based
isolated runtime, so this is safe to rely on).

## OUTPUT FORMATS
A single JSON document (`-of json`) with a `results` array.

## HOW TO INTERPRET RESULTS
Each result becomes a `web_endpoint` observation, same as feroxbuster.

## FALSE POSITIVE RISKS
Same wildcard-response caveat as feroxbuster — ffuf's `-fc`/`-fs` filters
can exclude a known-garbage response size/status if needed.

## FAILURE MODES
No wordlist resolvable → fails fast with a clear error. Connection refused
→ the HTTP service isn't actually up.

## COMMON ERRORS
`ffuf: command not found` — not installed; registry falls back to
feroxbuster if available.

## RATE LIMIT CONSIDERATIONS
Same as feroxbuster — bounded by Adi's shared rate limiter.

## ACCOUNT LOCKOUT CONSIDERATIONS
Not applicable.

## SAFE VALIDATION STRATEGIES
Re-fetch a discovered path directly via `http_request`.

## RELATED TOOLS
`feroxbuster` — same capability; the registry resolves between them.

## WHEN ANOTHER TOOL IS BETTER
feroxbuster's built-in recursion is more convenient for deep directory
trees; ffuf is more flexible for fuzzing a single specific position.

## HOW TO VERIFY A RESULT
Re-fetch the discovered path directly.

## HOW TO STORE RESULTS IN THE TARGET GRAPH
Same canonical `EndpointRecord` model as every other discovery path.


## Skill V2 contract
Intent and scope remain defined above. Use only the typed adapter; no arbitrary extra argv. Versions use the declared local probe. Unsupported options disable the provider for this assessment. Deterministic observations retain ToolEvidence provenance; scanner indications require Phase 4 validation. Scope rate limits and central concurrency apply. Inspect `adi capability` for available fallbacks.


## CAPABILITIES
The machine-readable contract is authoritative; use adi capability to compare providers.


## RISK
Use risk_level in tool.yaml; scope and approval cannot be overridden by tool metadata.


## SCOPE REQUIREMENTS
All target actions require ScopeEngine; source actions require source_analysis permission.


## INTERPRETATION
Observations and scanner indications require Phase 4 verification before findings.


## RATE / LOCKOUT CONSIDERATIONS
Scope rate and concurrency bounds apply; this tool cannot bypass authentication permission.


## SAFE VALIDATION STRATEGY
Use sanitized fixtures and explicitly scoped local lab targets.


## FALLBACKS
Use only compatible, available reviewed providers; never invent flags through the LLM.


## VERSION DIFFERENCES
Declared local probes preserve unknown versions. Incompatible invocations disable the provider on resume.


## NORMALIZED OUTPUT MODEL
Typed Observation entities with action and ToolEvidence provenance; source scanners retain their Phase 5 evidence contract.
