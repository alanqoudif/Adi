# feroxbuster

## PURPOSE
Recursive web content/directory discovery — finds paths that exist on a
web server but aren't linked from anywhere Adi has already crawled.

## WHEN TO USE
- After an initial HTTP/HTML crawl has exhausted its linked pages and
  unlinked content (admin panels, backup files, hidden API routes) is
  still plausible.
- When `robots.txt`/`sitemap.xml` discovery (lower cost, try first) didn't
  turn up enough of the application's surface.

## WHEN NOT TO USE
- Against a target with no HTTP service confirmed yet — enumerate services
  first (nmap) and confirm an HTTP(S) port is open.
- As the first action against a freshly discovered web app — try a direct
  HTTP request and HTML link/form extraction first; it's cheaper and often
  finds most of the real, linked surface for free.

## WHAT QUESTIONS THIS TOOL CAN ANSWER
- What paths exist on this web server that aren't linked anywhere?

## REQUIRED INPUTS
- `target`: a base URL, e.g. `http://host/`.
- `parameters.wordlist` (optional): path to a wordlist. If omitted, Adi
  resolves one from `.adi.yaml`'s `wordlists.web_content` or a handful of
  common Kali/Homebrew SecLists/dirb install paths — see
  `adi.tools.wordlists`. If none can be found, the action fails with a
  clear error rather than silently using nothing.

## SUPPORTED TARGET TYPES
URL only.

## IMPORTANT OPTIONS
This adapter always requests `--json --silent --no-state` so output is
JSONL on stdout with no on-disk state file left behind.

## OUTPUT FORMATS
JSONL (`--json --silent`) — one JSON object per line, each describing a
single HTTP response observed during the scan.

## HOW TO INTERPRET RESULTS
Each response with status < 500 becomes a `web_endpoint` observation. A
404 is not stored as an endpoint (it means the path doesn't exist), but a
403 is — "exists but forbidden" is itself useful attack-surface knowledge.

## FALSE POSITIVE RISKS
- A wildcard-response server (returns 200 for everything) will flood the
  endpoint list with garbage — feroxbuster's own wildcard detection helps,
  but treat a very high hit rate as a reason to double-check manually.

## FAILURE MODES
- No wordlist resolvable: fails fast with a clear error (see above) —
  never silently scans with zero words.
- Connection refused: the target's HTTP service isn't actually up; recheck
  with a direct HTTP request first.

## COMMON ERRORS
`feroxbuster: command not found` — not installed; the registry marks it
unavailable and Adi falls back to `ffuf` if available (same capability,
`discover_web_content`).

## RATE LIMIT CONSIDERATIONS
Content discovery is high-volume by nature. Adi's shared rate limiter
(`adi.scope.rate_limiter`) bounds concurrency; keep scope's
`rate_limits.requests_per_second` conservative against production systems.

## ACCOUNT LOCKOUT CONSIDERATIONS
Not applicable — no authentication involved.

## SAFE VALIDATION STRATEGIES
Re-requesting a single discovered path directly (via `http_request`)
confirms it independently of the scanner.

## RELATED TOOLS
`ffuf` — same capability, different engine; the registry picks whichever
is actually installed (see `ToolRegistry.resolve`).

## WHEN ANOTHER TOOL IS BETTER
If only a single known path needs fuzzing a specific parameter (not whole
directory discovery), `ffuf`'s parameter-fuzzing options are more direct.

## HOW TO VERIFY A RESULT
Re-fetch the discovered path directly and inspect its actual response.

## HOW TO STORE RESULTS IN THE TARGET GRAPH
Each result becomes a `web_endpoint` observation folded into the same
canonical `EndpointRecord` model used by HTTP/HTML discovery, robots.txt,
sitemap.xml, and `ffuf` — one graph, regardless of which tool found it.
