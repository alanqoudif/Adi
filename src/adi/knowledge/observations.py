"""Typed observation model.

An observation is a raw, falsifiable fact produced by a deterministic parser
(or occasionally by a tightly-constrained LLM reading). It is NOT a
vulnerability, NOT a hypothesis, and NOT a finding — see docs/agent-loop.md
for the distinction Adi must preserve.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class ObservationType(str, Enum):
    DNS_RECORD = "dns_record"
    RESOLUTION_OBSERVATION = "resolution_observation"
    TLS_OBSERVATION = "tls_observation"
    SMB_SHARE = "smb_share"
    IDENTITY_OBSERVATION = "identity_observation"
    LDAP_OBSERVATION = "ldap_observation"
    DIRECTORY_NAMING_CONTEXT = "directory_naming_context"
    NETWORK_FLOW_OBSERVATION = "network_flow_observation"
    CREDENTIAL_AUDIT_OBSERVATION = "credential_audit_observation"
    SSH_OBSERVATION = "ssh_observation"
    HOST_UP = "host_up"
    OPEN_PORT = "open_port"
    SERVICE_BANNER = "service_banner"
    SERVICE_VERSION = "service_version"
    HTTP_STATUS = "http_status"
    HTTP_HEADER = "http_header"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
    WEB_ENDPOINT = "web_endpoint"
    ENDPOINT_PARAMETER = "endpoint_parameter"
    SESSION_OBSERVED = "session_observed"
    SCANNER_ALERT = "scanner_alert"
    SOURCE_PATTERN = "source_pattern"
    TOOL_ERROR = "tool_error"
    RATE_LIMIT_INDICATOR = "rate_limit_indicator"


class Observation(BaseModel):
    """A single fact, as produced by a tool parser."""

    type: ObservationType
    subject: str  # e.g. an IP, a host:port, a URL
    value: dict
    source: str  # tool/adapter name, e.g. "nmap"
    confidence: float = 1.0

    def __str__(self) -> str:  # concise, for activity logs
        return f"[{self.type.value}] {self.subject}: {self.value}"
