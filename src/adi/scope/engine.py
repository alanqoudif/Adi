"""The ScopeEngine: the single technical choke point every action passes
through before execution.

No component should execute a tool, send an HTTP request, or drive a browser
without first calling `ScopeEngine.authorize`. This is deliberately decoupled
from the LLM: authorization is deterministic code, not a model judgment.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from kai.actions import ActionType, PlannedAction, RiskLevel
from kai.scope.models import Scope

# Capabilities that touch live credentials / account state and therefore
# require `permissions.authentication_testing` regardless of tool chosen.
_AUTH_TESTING_CAPABILITIES = {
    "credential_audit",
    "brute_force",
    "password_spray",
}

# Capabilities considered active validation (they cause the target to do
# something beyond passive observation) rather than pure discovery.
_ACTIVE_VALIDATION_CAPABILITIES = {
    "exploit_validation",
    "authorization_validation",
    "injection_validation",
}


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


class ScopeEngine:
    def __init__(self, scope: Scope):
        self.scope = scope

    def authorize(self, action: PlannedAction) -> ScopeDecision:
        if action.action_type in (
            ActionType.UPDATE_HYPOTHESIS,
            ActionType.VERIFY_FINDING,
            ActionType.GENERATE_REPORT,
            ActionType.ASK_USER,
            ActionType.COMPLETE,
            ActionType.LOAD_SKILL,
        ):
            return ScopeDecision(True, "internal action, not target-facing")

        host = self._extract_host(action.target)

        if host is not None and not self.scope.host_is_target(host):
            return ScopeDecision(
                False,
                f"host '{host}' is not within the authorized scope "
                f"({self.scope.name}); record as external dependency instead",
            )

        if action.capability in _AUTH_TESTING_CAPABILITIES:
            if not self.scope.permissions.authentication_testing:
                return ScopeDecision(
                    False,
                    "authentication_testing is disabled for this assessment scope",
                )

        if action.capability in _ACTIVE_VALIDATION_CAPABILITIES:
            if not self.scope.permissions.active_validation:
                return ScopeDecision(
                    False, "active_validation is disabled for this assessment scope"
                )

        if action.action_type == ActionType.SEARCH_CODE or action.capability.startswith("source"):
            if not self.scope.permissions.source_analysis:
                return ScopeDecision(False, "source_analysis is disabled for this assessment scope")

        if action.capability.startswith("discover") and not self.scope.permissions.discovery:
            return ScopeDecision(False, "discovery is disabled for this assessment scope")

        if action.capability.startswith("web") and not self.scope.permissions.web_enumeration:
            return ScopeDecision(False, "web_enumeration is disabled for this assessment scope")

        if action.risk == RiskLevel.HIGH:
            return ScopeDecision(
                False, "action classified as high risk requires explicit operator approval"
            )

        return ScopeDecision(True, "within scope")

    @staticmethod
    def _extract_host(target: str | None) -> str | None:
        if not target:
            return None
        if "://" in target:
            return urlparse(target).hostname
        # host[:port] or bare host/IP
        return target.split("/", 1)[0].split(":", 1)[0]
