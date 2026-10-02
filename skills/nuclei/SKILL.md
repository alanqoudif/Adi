# nuclei

## PURPOSE
Template-based scanning for known vulnerability signatures, misconfigurations,
and exposures.

## WHEN TO USE
- Once a web application's technology is reasonably well understood (so
  template tags can be scoped sensibly) and broad template-based coverage
  would add information beyond manual HTTP inspection.

## WHEN NOT TO USE
- Against a target with no confirmed HTTP service.
- As a substitute for validation — a nuclei hit is never, by itself, a
  reason to report a vulnerability as confirmed (see "CRITICAL" below).

## WHAT QUESTIONS THIS TOOL CAN ANSWER
- Does this target match any known vulnerability/misconfiguration template?

## REQUIRED INPUTS
- `target`: a URL.
- `parameters.severity` (optional): comma-separated severity filter, e.g.
  `"medium,high,critical"`.
- `parameters.tags` (optional): comma-separated template tag filter.

## SUPPORTED TARGET TYPES
URL only.

## IMPORTANT OPTIONS
`-jsonl -silent` for clean JSONL output with no banner noise.

## OUTPUT FORMATS
JSONL — one JSON object per matched template.

## HOW TO INTERPRET RESULTS — CRITICAL
**A nuclei alert becomes a `scanner_alert` Observation, never a confirmed
Finding.** The architecture rule is:

```
nuclei alert -> ScannerIndication (Observation) -> Hypothesis -> independent validation
```

never:

```
nuclei alert -> Confirmed Finding
```

This is enforced by the parser itself: `parser.py` only ever returns
`Observation(type=SCANNER_ALERT, ...)` objects — it has no access to (and
cannot call) anything that creates a `Finding`. Promoting an indication to
a hypothesis, and a hypothesis to a confirmed finding after real
validation, is the orchestrator/reasoner's job in a later phase
(`adi.agent.reasoner`), not this parser's.

## FALSE POSITIVE RISKS
Template-based detection is signature matching — version banners can be
spoofed, generic templates can false-positive on coincidental response
patterns, and a template can be stale relative to the actual deployed
version. Treat every alert as "worth investigating," not "true."

## FAILURE MODES
No templates installed/reachable (nuclei downloads templates on first run
and needs network access) → nuclei itself reports an error; the parser
emits a `tool_error` observation rather than fabricating a clean scan.

## COMMON ERRORS
`nuclei: command not found` — not installed; registry marks it unavailable.
Template download failures — a network/connectivity issue, not a scan
result.

## RATE LIMIT CONSIDERATIONS
nuclei defaults to a high internal request rate; Adi's shared rate limiter
still bounds overall tool concurrency, but consider passing a lower
`-rate-limit` via `parameters` for sensitive targets.

## ACCOUNT LOCKOUT CONSIDERATIONS
Some templates probe authentication endpoints — avoid broad unfiltered
scans against targets with lockout policies; prefer a scoped `tags` filter.

## SAFE VALIDATION STRATEGIES
Independently reproduce the specific request/response the template
matched on via a direct `http_request` before treating the indication as
supported.

## RELATED TOOLS
Adi's own HTTP/HTML discovery for the attack-surface mapping nuclei scans
run against.

## WHEN ANOTHER TOOL IS BETTER
For simple content discovery, feroxbuster/ffuf are more appropriate;
nuclei is for signature-based vulnerability/misconfiguration matching.

## HOW TO VERIFY A RESULT
Reproduce the exact matched request manually and inspect the response —
never take `matched-at` as sufficient evidence by itself.

## HOW TO STORE RESULTS IN THE TARGET GRAPH
`scanner_alert` observations, never folded into Endpoint/Finding tables
directly — they exist to seed hypotheses, which is a separate, explicit
step.
