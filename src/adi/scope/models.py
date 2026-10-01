"""Typed scope configuration.

Scope is the technical boundary of an assessment. Every action the agent
takes must be authorized against a Scope before execution — see
`adi.scope.engine.ScopeEngine`.
"""

from __future__ import annotations

from enum import Enum
from ipaddress import ip_address, ip_network

from pydantic import BaseModel, Field, field_validator


class AssessmentMode(str, Enum):
    LAB = "lab"
    COMPANY_AUDIT = "company_audit"
    SOURCE_AND_RUNTIME = "source_and_runtime"


class TestAccount(BaseModel):
    """A reference to an authorized test identity.

    The password itself is never stored here — only a reference to where it
    can be resolved from (an environment variable), so it never ends up in
    the LLM context, logs, or reports. See `adi.evidence.sanitizer`.
    """

    name: str
    username: str
    role: str = "user"
    password_env: str | None = None


class Permissions(BaseModel):
    """Which capability categories are allowed in this assessment."""

    discovery: bool = True
    web_enumeration: bool = True
    authentication_testing: bool = False
    source_analysis: bool = True
    active_validation: bool = True


class RateLimits(BaseModel):
    requests_per_second: float = 5.0
    concurrent_tools: int = 2
    max_tool_runtime_seconds: int = 600
    authentication_requests_per_minute: float = 10.0


class Scope(BaseModel):
    """The authorized boundary for an assessment.

    `targets` and `allowed_ips` define what Adi is allowed to actively test.
    Anything observed (e.g. a redirect, a linked asset) that falls outside
    this boundary must be recorded as an external dependency, never tested.
    """

    name: str
    mode: AssessmentMode = AssessmentMode.LAB

    targets: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)
    allowed_protocols: list[str] = Field(default_factory=lambda: ["http", "https"])

    permissions: Permissions = Field(default_factory=Permissions)
    rate_limits: RateLimits = Field(default_factory=RateLimits)

    test_accounts: list[TestAccount] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    max_actions: int = 150
    max_consecutive_failures: int = 5

    @field_validator("allowed_ips")
    @classmethod
    def _validate_cidrs(cls, v: list[str]) -> list[str]:
        for entry in v:
            ip_network(entry, strict=False)
        return v

    def host_in_allowed_ips(self, host: str) -> bool:
        try:
            addr = ip_address(host)
        except ValueError:
            return False
        for cidr in self.allowed_ips:
            if addr in ip_network(cidr, strict=False):
                return True
        return False

    def host_is_target(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if host in (h.lower() for h in self.excluded_hosts):
            return False
        for target in self.targets:
            t = _strip_scheme(target).lower().rstrip(".")
            if host == t or host.endswith("." + t):
                return True
        return self.host_in_allowed_ips(host)


def _strip_scheme(value: str) -> str:
    for prefix in ("https://", "http://"):
        value = value.removeprefix(prefix)
    return value.split("/", 1)[0].split(":", 1)[0]
