"""The ScopeEngine: the single technical choke point every action passes
through before execution.

No component should execute a tool, send an HTTP request, or drive a browser
without first calling `ScopeEngine.authorize`. This is deliberately decoupled
from the LLM: authorization is deterministic code, not a model judgment.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from adi.actions import ActionType, PlannedAction, RiskLevel
from adi.scope.models import Scope

# Capabilities that touch live credentials / account state and therefore
# require `permissions.authentication_testing` regardless of tool chosen.
_AUTH_TESTING_CAPABILITIES = {
    "audit_credentials",
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
            ActionType.INVESTIGATE_HYPOTHESIS,
            ActionType.VERIFY_FINDING,
            ActionType.GENERATE_REPORT,
            ActionType.ASK_USER,
            ActionType.COMPLETE,
            ActionType.LOAD_SKILL,
        ) and action.target is None:
            return ScopeDecision(True, "internal action, not target-facing")

        if action.capability in {"password_spray", "brute_force", "exploit_framework"}:
            return ScopeDecision(False, "prohibited capability")
        if action.capability == "audit_credentials":
            if not action.target:
                return ScopeDecision(False, "authentication audit needs one explicit target")
            if self.scope.approval_mode:
                approval_key = f"audit_credentials:{action.target}"
                if approval_key not in self.scope.approved_elevated_actions:
                    return ScopeDecision(False, "elevated action requires operator approval")
        if (action.capability in {"discover_web_content", "fingerprint_web_application", "web_template_scan"}
                and not self.scope.permissions.web_enumeration):
            return ScopeDecision(False, "web_enumeration is disabled")
        if action.capability == "capture_network_metadata":
            try:
                bounded = (1 <= int(action.parameters.get("packet_count", 0)) <= 100
                           and 1 <= int(action.parameters.get("duration", 0)) <= 30)
            except (ValueError, TypeError):
                bounded = False
            if (action.parameters.get("interface") not in self.scope.authorized_capture_interfaces
                    or not action.parameters.get("reason") or not bounded):
                return ScopeDecision(False, "capture requires authorized interface, reason and bounds")
        if (action.capability == "inspect_pcap"
                and action.parameters.get("capture_file") not in self.scope.authorized_capture_files):
            return ScopeDecision(False, "capture file requires explicit operator authorization")

        host = self._extract_host(action.target)

        if host is not None and not self.scope.host_is_target(host):
            return ScopeDecision(
                False,
                f"host '{host}' is not within the authorized scope "
                f"({self.scope.name}); record as external dependency instead",
            )

        if (action.capability in _AUTH_TESTING_CAPABILITIES) and not self.scope.permissions.authentication_testing:
            return ScopeDecision(
                False,
                "authentication_testing is disabled for this assessment scope",
            )

        if (action.capability in _ACTIVE_VALIDATION_CAPABILITIES) and not self.scope.permissions.active_validation:
            return ScopeDecision(
                False, "active_validation is disabled for this assessment scope"
            )

        if (action.action_type == ActionType.SEARCH_CODE or action.capability.startswith("source")) and not self.scope.permissions.source_analysis:
            return ScopeDecision(False, "source_analysis is disabled for this assessment scope")

        discovery_capabilities = {
            "enumerate_services", "identify_service_versions", "inspect_dns", "inspect_tls",
            "inspect_certificate", "inspect_smb", "enumerate_smb", "enumerate_smb_shares",
            "inspect_smb_identity", "inspect_ldap", "inspect_ssh", "capture_network_metadata",
        }
        if (action.capability.startswith("discover") or action.capability in discovery_capabilities) and not self.scope.permissions.discovery:
            return ScopeDecision(False, "discovery is disabled for this assessment scope")

        if action.capability.startswith("web") and not self.scope.permissions.web_enumeration:
            return ScopeDecision(False, "web_enumeration is disabled for this assessment scope")

        if action.risk in {RiskLevel.HIGH, RiskLevel.PROHIBITED}:
            return ScopeDecision(
                False, "action classified as high risk requires explicit operator approval"
            )

        return ScopeDecision(True, "within scope")

    def is_host_authorized(self, host: str) -> bool:
        """Used outside the PlannedAction flow — e.g. per-hop redirect
        authorization in `adi.http.client.HTTPClient`, where there is no
        single action to build a ScopeDecision for."""
        return self.scope.host_is_target(host)

    @staticmethod
    def _extract_host(target: str | None) -> str | None:
        if not target:
            return None
        if "://" in target:
            return urlparse(target).hostname
        # host[:port] or bare host/IP
        return target.split("/", 1)[0].split(":", 1)[0]
