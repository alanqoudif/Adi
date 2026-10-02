# Web Discovery (Phase 3)

Starting from only a root URL, Adi derives the web attack surface itself —
nothing here is ever manually injected in production code; every Endpoint/
Parameter row is created by a deterministic parser or extractor acting on
a real response.

```
root URL
  -> HTTP request (adi.http.client.HTTPClient)
  -> HTTPExchange persisted (redacted headers, evidence on disk)
  -> HTML parsed (adi.http.extractors, stdlib html.parser — never the LLM)
  -> links / forms / inline-JS fetch() calls / tech hints extracted
  -> Endpoint / Parameter rows created or merged (adi.knowledge.workspace)
  -> robots.txt / sitemap.xml (separate, planner-chosen capability)
  -> ffuf / feroxbuster (discover_web_content capability, tool-agnostic)
  -> whatweb (fingerprint_web_application, enrichment only)
  -> nuclei (web_template_scan -> ScannerIndication, NEVER a Finding)
  -> Playwright browser visit, when installed (real XHR/fetch network capture)
  -> ContextBuilder renders a bounded web-state summary
  -> planner replans against the updated surface
```

One endpoint model, five sources: direct HTTP/HTML crawling, robots.txt/
sitemap.xml, ffuf/feroxbuster, and (when available) a real browser's
network capture all write into the same `EndpointRecord`/`ParameterRecord`
tables via `adi.http.workspace.HTTPWorkspace` — the knowledge graph never
ends up with two competing ideas of "what endpoints exist."

## Canonical URL handling

`adi.http.normalization.canonicalize_url` drops default ports and
fragments, lowercases scheme/host, and sorts query parameters — so
`http://host:80/` and `http://host/` always collapse to one endpoint, while
`?id=1` and `?id=2` never do. See `tests/unit/test_url_normalization.py`.

## Scope-enforced redirects

Every redirect hop is authorized individually
(`adi.scope.engine.ScopeEngine.is_host_authorized`) inside
`adi.http.client.HTTPClient` — `httpx`'s own `follow_redirects=True` is
never used blindly. A redirect to an unauthorized host is recorded and not
followed (`tests/unit/test_http_client.py::test_redirect_to_out_of_scope_host_is_not_followed`).

## Capability-first tool selection

The planner asks for a capability (`discover_web_content`), never a
specific binary. `adi.tools.registry.ToolRegistry.resolve()` picks the
best **available** tool deterministically (lowest `execution.priority`,
then name) — feroxbuster is preferred over ffuf when both are installed,
but either one alone works, and the orchestrator doesn't change when a
tool goes from available to unavailable. See
`tests/unit/test_capability_resolution.py`.

## Nuclei: indication, never a finding

`skills/nuclei/parser.py` can only ever return
`Observation(type=SCANNER_ALERT, ...)` — it has no access to anything that
creates a `Finding`. Promoting an indication to a hypothesis and then to a
confirmed finding after independent validation is Phase 4's job. See
`tests/unit/test_nuclei_parser.py`.

## What's real vs. what's honestly gated

Verified live in this environment (not just unit-tested against fixtures):
- The full HTTP client, HTML/JS extraction, robots.txt/sitemap.xml
  discovery, and endpoint/parameter folding, against a real local test
  server (`tests/fixtures/webapp/app.py`, stdlib-only).
- The real `feroxbuster` binary (installed here), run through
  `ToolExecutor` end to end, discovering the same endpoints as the HTTP
  crawl independently.
- `nuclei` is installed but was not run live against anything (no network
  access to download templates in this environment) — its parser is
  verified against a fixture built from nuclei's documented JSONL schema.
- `whatweb` and `ffuf` are not installed here — their skills exist and are
  tested against fixtures built from each tool's documented output format,
  but have not been run live. The registry correctly reports them
  unavailable (`adi doctor`, `adi tools`).
- Playwright (`adi.runtime.browser.BrowserRuntime`) is implemented for
  real — typed navigate/click/fill/submit/extract operations plus network
  request capture folding into the same Endpoint model
  (`HTTPWorkspace.record_browser_visit`) — but the `playwright` package and
  browser binaries are not installed in this environment, so
  `tests/integration/test_browser_discovery.py` skips itself automatically
  rather than faking a pass. In its absence, Adi falls back to the lower-
  confidence static regex-based JS `fetch()` extraction in
  `adi.http.extractors`, which the mandatory Phase 3 acceptance test
  (`tests/integration/test_phase3_mandatory_autonomous_discovery.py`)
  relies on and passes.

## Rate limiting

`adi.scope.rate_limiter.RateLimiter` is shared by the internal HTTP client
and `ToolExecutor` — both draw from the same `Scope.rate_limits`
configuration rather than each subsystem independently deciding how hard
to hit the target.
