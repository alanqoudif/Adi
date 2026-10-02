# Phase 6 / final core-v1 acceptance report

The original six-phase core implementation ends here. No GUI, cloud deployment, performance benchmarking or CI/CD productization was started. Local implementation/test gates passed; environmental gates are listed separately and are not represented as successful.

## 1. Commit

The Phase 6 commit is the commit containing this report. Obtain its exact hash with `git log -1 --format=%H -- docs/phase6-acceptance.md`. The final chat response reports that hash after commit creation.

## 2. Quality gates

- PASS: full pytest suite, **269 passed, 1 skipped**, preserving Phase 1–5 coverage.
- PASS: `ruff check .` and `git diff --check`.
- PASS: 42 dedicated capability/safety tests plus 3 actual loopback auth/LDAP integration tests.
- SKIPPED: retained Playwright/browser-runtime environmental gate; browser setup did not derail Phase 6.
- One benign pytest collection warning: the imported Scope TestAccount model is not a test class.

## 3. Supported capabilities

New/reviewed: enumerate_services, identify_service_versions, inspect_dns, inspect_tls, inspect_certificate, inspect_smb, enumerate_smb, enumerate_smb_shares, inspect_smb_identity, inspect_ldap, inspect_ssh, capture_network_metadata, inspect_pcap and audit_credentials.

Preserved: discover_hosts, enumerate_ports, detect_services, discover_web_content, fingerprint_web_application, web_template_scan, scan_source_patterns, scan_secrets, scan_dependencies and the existing source/runtime planner capabilities. Capability models describe intent separately from executable metadata.

## 4–7. Reviewed tools and test status

| Tool | Status in this environment |
|---|---|
| Nmap | Live loopback HTTP/TLS discovery; existing XML fixtures |
| OpenSSL | Live TLS/certificate inspection, hostname/IP SAN matching and deterministic fixtures |
| feroxbuster | Live scoped content discovery and endpoint enrichment; existing fixtures |
| ldapsearch | Live anonymous rootDSE against local protocol fixture; LDIF fixture |
| tcpdump | Live analysis of explicitly authorized, generated header-only pcap; text fixture |
| Semgrep | Installed; preserved Phase 5 live local source tests |
| dig / host / nslookup | Installed and version-probed; deterministic new DNS fixtures; no public DNS scan |
| ssh-keyscan | Installed; deterministic metadata fixture; version unknown; no auth attempts |
| Nuclei | Installed/version-probed; preserved parser tests; no new public target scan |
| RustScan | Not installed; typed adapter and deterministic fixture |
| smbclient / enum4linux-ng | Not installed; reviewed bounded operations and normalization fixtures |
| tshark | Not installed; reviewed metadata-only adapter and TSV fixture |
| Hydra / Medusa | Not installed; gated typed requests, argv and parsers fixture-tested; local HTTP auth runtime explicitly simulated |
| WhatWeb / ffuf | Not installed; preserved existing fixtures/adapters, Skill V2 upgrade; ffuf fallback simulated |
| Gitleaks / Trivy / OSV Scanner | Not installed; preserved source fixtures/adapters and Skill V2 upgrade |

Optional John, Hashcat and additional SSL scanners were not implemented and are not claimed as supported. No tools were installed merely to inflate the count.

## 8. Fallback demo

Unit/integration fixture: feroxbuster unavailable → ffuf available → discover_web_content resolves automatically → WebEndpoint observations are persisted, without changing the planner's capability request.

Live demo: ffuf is explicitly unavailable and made the preferred provider for this test; installed feroxbuster is selected and returns **three normalized web endpoints**. This override belongs only to the acceptance driver. It does not fake ffuf availability. The separate version test produces unknown-option failure in feroxbuster and successfully selects the compatible ffuf fixture.

## 9. Dynamic discovery demo

A temporary executable `adi-safe-fake` is created in a test-local PATH and explicitly allowlisted. Only bounded `--help` is invoked. The result has TEMPORARY_INFERRED trust, low confidence, local-help provenance and only inspect_local_tool_help capability. Target-facing/elevated/auth execution remains blocked pending reviewed plugin support.

## 10. Disabled authentication policy demo

The state-based local assessment requests audit_credentials with authentication_testing=false. The result is BLOCKED and recorded before any candidate loading or auth runtime execution, even when no auth provider is installed. Direct provider calls cannot disguise their auth capability. Approval-mode and out-of-scope requests also remain blocked.

## 11. Tiny authorized auth demo

Two loopback integration cases use explicit operator test account/candidate reference, one attempt, one account and the conservative rate. A protocol fixture runtime receives the reviewed Hydra-shaped argv and sends exactly one real HTTP authentication request:

- valid local test credential → CredentialAuditObservation(success=true) → stop;
- local service returns account-locked response → LOCKOUT_SIGNAL → stop.

A second call sends **zero further requests**. The database, raw evidence, metadata and state files are checked for absence of candidate plaintext. Fixture candidates remain only in the operator-owned temporary input file. This is not reported as live Hydra or Medusa binary testing.

## 12. Common normalization

Nmap 445/tcp XML, enum4linux-ng identity/share JSON and smbclient share text produce one host/transport/445 service. Equivalent `public` shares merge through `normalized_entities('smb_share')`, retaining both provider sources and observation IDs. LDAP creates rootDSE/naming-context metadata rather than a directory dump. tcpdump/tshark create bounded flow observations, not packet payloads. OpenSSL retains TLS version, cipher, certificate subject/issuer/expiry and hostname result without promoting a self-signed certificate to a vulnerability.

## 13. Failure recovery/resume

An installed fixture provider emits an unsupported option. The centralized classifier returns UNSUPPORTED_VERSION; its runtime/path/version key is disabled in assessment-local performance state. A compatible provider succeeds. Reloading that state skips the incompatible provider. Attempts are bounded to three reviewed candidates and cannot form an infinite command-invention loop. Malformed output retains sanitized raw evidence and records PARSER_FAILURE. Partial timeout observations survive, with PARTIAL_SUCCESS evidence and the underlying TIMEOUT cause.

## 14. Evidence trace

See [sanitized live acceptance JSON](phase6-demo.json) and the local `.adi/phase6-acceptance/acceptance.json`.

Assessment `assess-f2808d8ad68c` discovered local ports 57095/57096. Each provider's evidence includes capability, selection reason, action ID, scope decision, runtime/path/version, sanitized argv, time, status, raw reference and parsed observation IDs. The chain is:

CapabilityRequest → selected provider → persisted action/scope decision → ExecutionResult → ToolEvidence → referenced Observation rows → canonical workspace entity → Phase 4 hypothesis/finding links when applicable.

Four live ToolEvidence items were produced: Nmap (three observations), OpenSSL (one TLS observation), feroxbuster (three web observations), tcpdump (one flow). Separate LDAP/auth tests prove their respective execution/policy paths. No vulnerability is claimed by this metadata-only lab.

## 15. Real-model status

UNAVAILABLE: no configured provider credential/base URL was present. The acceptance planner is a labelled deterministic, state-based driver: it reacts to discovered services and unanswered metadata questions and requests capabilities, never a fixed list of binaries. It is not represented as an LLM assessment. Configure the existing provider to run a model smoke using the same scoped production loop.

## 16. Remaining limitations/environmental gates

- Kali container build and container live execution unverified: no runnable configured image/daemon. The Dockerfile now pins the verified official multi-platform base digest and installs an explicit reviewed package list, without broad metapackages. APT packages still come from a rolling repository, so byte-identical rebuilds are not claimed.
- Hydra, Medusa, SMB providers, RustScan and tshark need installed-tool/local-service validation in an environment that provides them; normalized fixtures do not imply production availability.
- Provider modules may not expose every lockout signal (especially SSH). Strict tiny budgets/rates and observable-signal stops are enforced, but unreported remote account state cannot be inferred.
- Authentication approval is operator-provided scope authorization, not an automatic interactive approval grant. Original operator candidate data is intentionally external to the assessment.
- Temporary tools support help inspection only; inferred target execution and downloaded plugins are not enabled.
- enum4linux-ng uses bounded OS/identity text, not broad -A/user/RID enumeration. SMB shares use smbclient. LDAP is anonymous rootDSE only. SSH inspection provides banners/key algorithms, not authentication.
- Capture requires explicit context and privileges; the non-root Kali runtime cannot silently gain them. Existing authorized pcap inspection is preferred.
- Skill V2 documentation and legacy parser list compatibility remain supported. New parsers also expose ParsedToolResult. The performance state and central scheduling operate within the assessment process; concurrent independent processes are not an assessment-sharing feature.

## 17. Exact local commands

```bash
cd /Users/faisal/dev/Adi
.venv/bin/ruff check .
.venv/bin/pytest -q
.venv/bin/pytest tests/unit/test_phase6_intelligence.py tests/integration/test_phase6_local_lab.py -q
.venv/bin/python examples/phase6_smoke.py
.venv/bin/adi tools
.venv/bin/adi capabilities
.venv/bin/adi capability inspect_tls
.venv/bin/adi tool hydra
.venv/bin/adi discover-tools
.venv/bin/adi doctor
```

The suite/demo require loopback server permission. The smoke requires Nmap/OpenSSL/feroxbuster; tcpdump is optional for its existing-capture segment. It opens no public test target. `adi doctor` may return a warning/failure for unavailable Docker while still correctly listing optional missing tools.

For a configured existing assessment: `adi run-capability ID CAPABILITY TARGET --inputs-file request.json`. Use only typed references for auth requests and enable authorization in operator scope. See [authentication auditing](authentication-auditing.md) and [runtime tools](runtime-tools.md).

Tool flag/format verification used primary upstream sources: [Hydra source](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra.c), [enum4linux-ng documentation](https://github.com/cddmp/enum4linux-ng/blob/master/README.md), and [Kali container documentation](https://www.kali.org/docs/containers/official-kalilinux-docker-images/).

STOP: no additional phase has been started.
