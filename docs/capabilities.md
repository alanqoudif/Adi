# Capabilities

Run `adi capabilities`, `adi capabilities --assessment-id ID`, and `adi capability NAME`. Tool availability alone never grants scope permission.

| Capability | Reviewed providers | Normalized knowledge |
|---|---|---|
| discover_hosts / enumerate_services | Nmap, RustScan | Host, Service, Observation |
| identify_service_versions | Nmap | Service |
| fingerprint_web_application | WhatWeb | Technology fingerprints |
| discover_web_content | feroxbuster, ffuf | Web endpoints |
| web_template_scan | Nuclei | Scanner indications requiring verification |
| inspect_dns | dig, host, nslookup | DNSRecord, ResolutionObservation |
| inspect_tls / inspect_certificate | OpenSSL | TLSObservation |
| inspect_smb / enumerate_smb | smbclient, enum4linux-ng | canonical Service, shares, identities |
| enumerate_smb_shares | smbclient | SMBShare |
| inspect_smb_identity | enum4linux-ng | IdentityObservation |
| inspect_ldap | ldapsearch | rootDSE metadata, DirectoryNamingContext |
| capture_network_metadata / inspect_pcap | tcpdump, tshark | NetworkFlowObservation |
| inspect_ssh | ssh-keyscan | banner/algorithm observations; no login |
| audit_credentials | Hydra, Medusa | CredentialAuditObservation; explicit auth permission |
| scan_source_patterns | Semgrep | Phase 5 source/SAST indications |
| scan_secrets | Gitleaks | redacted secret indications |
| scan_dependencies | Trivy, OSV Scanner | dependency records/indications |

`Capability` includes risk, permissions, schema, common entity types, provider list, fallback policy, timeout, rate policy and approval requirements. Tool contracts remain distinct from these capability contracts. `CredentialAuditRequest` defines the stricter audit inputs.

A SMB service is keyed by host + transport + port, irrespective of provider. Observations remain separate provenance records. `Workspace.normalized_entities('smb_share')` merges equivalent shares and retains source names/observation IDs. Other new entity families use that same projection, rather than presenting disconnected per-tool output to the planner.

Offline hash tools (John/Hashcat), SSL scanners and exploitation frameworks are not implemented. They are optional/future work, not required providers of any enabled capability.
