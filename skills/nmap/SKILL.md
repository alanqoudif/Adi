# nmap

## PURPOSE
Network discovery and port/service enumeration. Answers "what is alive and
what is listening" for a host, hostname, or CIDR range.

## WHEN TO USE
- First step against a new IP/hostname/CIDR target with no prior service
  knowledge.
- Re-confirming a service is still up before a later validation step.

## WHEN NOT TO USE
- Against a target you already have full, current port/service knowledge
  for — re-running nmap for the same information wastes the action budget.
- To enumerate web application *content* (routes/paths) — use ffuf/feroxbuster.
- To determine web application technology — use whatweb.

## WHAT QUESTIONS THIS TOOL CAN ANSWER
- Which hosts in a range are up?
- Which TCP ports are open on a host?
- What service and version is running on a given port?

## REQUIRED INPUTS
- `target`: an IP, hostname, or CIDR range inside the assessment scope.

## SUPPORTED TARGET TYPES
host, hostname, CIDR.

## IMPORTANT OPTIONS
- `-sV`: service/version detection (default parameters used by this adapter).
- `-oX -`: XML output to stdout, parsed deterministically — never parse
  nmap's human-readable `-oN` text output.
- `ports`: parameter to restrict the scan to a specific port list, e.g.
  `"1-1024"` or `"80,443,8080"`. Omit for nmap's default top-1000 ports.

## OUTPUT FORMATS
XML (`-oX -`). The parser never relies on nmap's text/greppable output.

## HOW TO INTERPRET RESULTS
Each open port becomes an `open_port` observation with host, port, protocol,
service name, product, and version (when nmap could determine them). A host
with any open port also yields a `host_up` observation.

## FALSE POSITIVE RISKS
- Service/version fingerprints are nmap's best guess from probes/banners,
  not a confirmed fact — treat `product`/`version` as a hypothesis input
  (e.g. "possibly outdated OpenSSH"), not as confirmed vulnerable software.
- A firewall or IDS may report ports as `filtered`/`closed` inaccurately.

## FAILURE MODES
- No route to host / all ports filtered: likely a firewall or the target is
  down — record as an observation, do not retry nmap with the same options.
- Permission denied for SYN scan: this adapter uses a TCP connect scan by
  default, which does not require elevated privileges.

## COMMON ERRORS
- `nmap: command not found` — tool is not installed; the registry will mark
  it unavailable.
- Hostname does not resolve — record as a `tool_error` observation.

## RATE LIMIT CONSIDERATIONS
A full port range scan against many hosts can be slow and noisy. Prefer
restricting `ports` when the goal is a specific service family.

## ACCOUNT LOCKOUT CONSIDERATIONS
Not applicable — nmap does not authenticate.

## SAFE VALIDATION STRATEGIES
Re-running nmap against the same single port is a safe, idempotent way to
confirm a service is still reachable before active validation.

## RELATED TOOLS
`httpx` (confirm an HTTP service responds and capture headers), `whatweb`
(fingerprint web technology once an HTTP service is known).

## WHEN ANOTHER TOOL IS BETTER
If the target is already known to be a single web application and only
HTTP/HTTPS matter, `httpx` directly against the known port is faster and
less noisy than a full nmap scan.

## HOW TO VERIFY A RESULT
Cross-check an open port with a direct protocol-level probe (e.g. an HTTP
request for port 80/443) before building further hypotheses on top of it.

## HOW TO STORE RESULTS IN THE TARGET GRAPH
`open_port` / `service_banner` / `service_version` observations are folded
automatically into typed `Host`/`Service` records by
`adi.knowledge.workspace.Workspace._apply_observation`.


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
