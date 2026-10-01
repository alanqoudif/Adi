# whatweb

## PURPOSE
Enrichment: identifies web technologies (frameworks, servers, CMSes, JS
libraries) via response signatures, more thoroughly than Adi's own built-in
header/cookie/HTML heuristics (`adi.http.extractors`).

## WHEN TO USE
- After a web application is confirmed, when the technology stack is still
  largely unknown and more detail would change testing strategy.

## WHEN NOT TO USE
- Adi's own HTTP crawl already produces `technology_fingerprint`
  observations from headers, cookies, and HTML markers for free — only run
  whatweb when that isn't enough (e.g. CMS/plugin version detection).
- Not installed? Adi's HTTP functionality works fully without it — this is
  pure enrichment, never a dependency.

## WHAT QUESTIONS THIS TOOL CAN ANSWER
- What CMS, framework, or server software (and version) is this?

## REQUIRED INPUTS
- `target`: a URL.

## SUPPORTED TARGET TYPES
URL only.

## IMPORTANT OPTIONS
`-a 3` (aggression level 3: more plugin checks without being fully
intrusive), `--log-json=-` for JSON to stdout, `--no-errors` to suppress
per-target error noise.

## OUTPUT FORMATS
JSON array (`--log-json=-`), one object per target with a `plugins` map.

## HOW TO INTERPRET RESULTS
Each plugin WhatWeb identifies becomes a `technology_fingerprint`
observation. The `HTTPServer` plugin (derived directly from the `Server`
header) is treated as high confidence; everything else as medium — WhatWeb
itself does not expose a numeric confidence score.

## FALSE POSITIVE RISKS
Plugin signatures can match coincidentally on generic markers (e.g. a
common meta tag). Treat anything beyond `HTTPServer`/`X-Powered-By`-derived
plugins as a hint, not a confirmed fact.

## FAILURE MODES
Target unreachable → whatweb reports an HTTP error for that target; the
parser emits a `tool_error` observation rather than fabricating plugins.

## COMMON ERRORS
`whatweb: command not found` — not installed; the registry marks it
unavailable and Adi continues using its own header/cookie/HTML-based
fingerprinting instead.

## RATE LIMIT CONSIDERATIONS
Single request per target at `-a 3`; negligible load.

## ACCOUNT LOCKOUT CONSIDERATIONS
Not applicable.

## SAFE VALIDATION STRATEGIES
Cross-check a WhatWeb-reported technology against Adi's own header-based
fingerprint for the same host — agreement raises confidence.

## RELATED TOOLS
Adi's built-in `adi.http.extractors.fingerprint_from_headers` /
`fingerprint_from_cookies` — always available, lower-detail.

## WHEN ANOTHER TOOL IS BETTER
If only the `Server`/`X-Powered-By` headers matter, Adi's own HTTP crawl
already captured that — no need to also run whatweb.

## HOW TO VERIFY A RESULT
Inspect the raw response headers/body directly for the claimed signature.

## HOW TO STORE RESULTS IN THE TARGET GRAPH
Each plugin becomes a `technology_fingerprint` observation against the
target host — the same observation type Adi's own HTTP crawl produces, so
technologies from every source end up in one deduplicated list.
