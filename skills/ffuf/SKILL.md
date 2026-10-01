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
