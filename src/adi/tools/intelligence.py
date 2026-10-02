"""Capability contracts, deterministic failures, and assessment-local performance memory."""
from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class TrustLevel(str, Enum):
    BUILT_IN_REVIEWED = 'BUILT_IN_REVIEWED'
    LOCAL_DISCOVERED = 'LOCAL_DISCOVERED'
    TEMPORARY_INFERRED = 'TEMPORARY_INFERRED'


class ToolFailure(str, Enum):
    NOT_INSTALLED = 'NOT_INSTALLED'
    UNSUPPORTED_VERSION = 'UNSUPPORTED_VERSION'
    INVALID_ARGUMENT = 'INVALID_ARGUMENT'
    PERMISSION_DENIED = 'PERMISSION_DENIED'
    CONNECTION_REFUSED = 'CONNECTION_REFUSED'
    TIMEOUT = 'TIMEOUT'
    DNS_FAILURE = 'DNS_FAILURE'
    TLS_FAILURE = 'TLS_FAILURE'
    AUTH_FAILURE = 'AUTH_FAILURE'
    RATE_LIMITED = 'RATE_LIMITED'
    LOCKOUT_SIGNAL = 'LOCKOUT_SIGNAL'
    TARGET_UNREACHABLE = 'TARGET_UNREACHABLE'
    PARSER_FAILURE = 'PARSER_FAILURE'
    PARTIAL_SUCCESS = 'PARTIAL_SUCCESS'
    UNKNOWN = 'UNKNOWN'


def classify_failure(text: str, exit_code: int = 0, timed_out: bool = False):
    text = text.lower()
    # Safety signals outrank exit status and partial success.
    signals = [
        (ToolFailure.LOCKOUT_SIGNAL, ('locked out', 'account locked', 'lockout', 'too many failed')),
        (ToolFailure.RATE_LIMITED, ('rate limit', 'too many requests', '429')),
        (ToolFailure.UNSUPPORTED_VERSION, ('unknown option', 'unrecognized option', 'unsupported option')),
        (ToolFailure.PERMISSION_DENIED, ('permission denied', 'operation not permitted')),
        (ToolFailure.CONNECTION_REFUSED, ('connection refused',)),
        (ToolFailure.DNS_FAILURE, ('name or service not known', 'could not resolve', 'nxdomain')),
        (ToolFailure.TLS_FAILURE, ('handshake failure', 'certificate verify failed')),
        (ToolFailure.AUTH_FAILURE, ('authentication failed', 'logon_failure', 'invalid credentials')),
        (ToolFailure.TARGET_UNREACHABLE, ('no route to host', 'network unreachable')),
        (ToolFailure.INVALID_ARGUMENT, ('invalid argument', 'usage:')),
    ]
    for failure, patterns in signals:
        if any(p in text for p in patterns):
            return failure
    if timed_out:
        return ToolFailure.TIMEOUT
    if exit_code == 127:
        return ToolFailure.NOT_INSTALLED
    return ToolFailure.UNKNOWN if exit_code else None


class CapabilityRequest(BaseModel):
    capability: str
    target: str
    inputs: dict = Field(default_factory=dict)
    reason: str = ''


class Capability(BaseModel):
    id: str
    name: str
    category: str = 'security'
    description: str = ''
    risk_level: str = 'low'
    required_scope_permissions: list[str] = Field(default_factory=lambda: ['discovery'])
    input_schema: dict = Field(default_factory=lambda: {'target': 'authorized host or URL'})
    output_entity_types: list[str] = Field(default_factory=lambda: ['Observation'])
    candidate_tools: list[str] = Field(default_factory=list)
    fallback_policy: str = 'bounded reviewed candidates; never retry lockout/rate-limit'
    default_timeout: int = 60
    rate_policy: str = 'scope limits and central concurrency guard'
    approval_requirement: bool = False


class ParsedToolResult(BaseModel):
    observations: list = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    failure_classification: ToolFailure | None = None
    partial: bool = False
    parser_version: str = '1'


class ToolEvidence(BaseModel):
    action_id: str
    tool: str
    version: str
    runtime: str
    capability: str
    target: str
    selection_reason: str
    scope_decision: str
    sanitized_argv: list[str]
    started_at: str
    completed_at: str
    exit_code: int
    failure: ToolFailure | None = None
    parsed_observation_ids: list[str] = Field(default_factory=list)
    raw_reference: str | None = None
    partial: bool = False
    failure_cause: ToolFailure | None = None
    parser_version: str = '1'


class Performance(BaseModel):
    successful_runs: int = 0
    failed_runs: int = 0
    timeouts: int = 0
    parser_failures: int = 0
    version_incompatibilities: int = 0
    total_duration: float = 0
    average_duration: float = 0
    disabled: bool = False


class PerformanceMemory:
    def __init__(self, path: Path):
        self.path = path
        self.entries = json.loads(path.read_text()) if path.exists() else {}

    @staticmethod
    def key(tool):
        return '|'.join((tool.metadata.name, tool.runtime, tool.binary_path or '', tool.version))

    def get(self, tool):
        return Performance.model_validate(self.entries.get(self.key(tool), {}))

    def record(self, tool, failure, duration):
        state = self.get(tool)
        state.successful_runs += int(failure is None or failure == ToolFailure.PARTIAL_SUCCESS)
        state.failed_runs += int(failure is not None)
        state.timeouts += int(failure == ToolFailure.TIMEOUT)
        state.parser_failures += int(failure == ToolFailure.PARSER_FAILURE)
        state.version_incompatibilities += int(failure == ToolFailure.UNSUPPORTED_VERSION)
        state.total_duration += duration
        count = state.successful_runs + state.failed_runs
        state.average_duration = state.total_duration / max(1, count)
        state.disabled |= failure in {ToolFailure.UNSUPPORTED_VERSION, ToolFailure.PARSER_FAILURE}
        self.entries[self.key(tool)] = state.model_dump()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps(self.entries, indent=2))
        temporary.replace(self.path)


def safe_target(target: str) -> str:
    from urllib.parse import urlsplit
    if '://' in target and (urlsplit(target).username or urlsplit(target).password):
        raise ValueError('credential-bearing target URLs are forbidden')
    host = urlsplit(target).hostname if '://' in target else target.split(':', 1)[0]
    if not host or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.\-]*', host):
        raise ValueError('expected one explicit host; options, CIDRs and target lists forbidden')
    return host


def sanitize_target(target: str) -> str:
    from urllib.parse import urlsplit, urlunsplit
    if '://' in target:
        parts = urlsplit(target)
        if parts.username or parts.password:
            host = parts.hostname or ''
            netloc = host + (f':{parts.port}' if parts.port else '')
            return urlunsplit((parts.scheme, netloc, parts.path, '', ''))
    return target
