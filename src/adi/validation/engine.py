"""ValidationEngine: the single path from a typed `ValidationAction` to a
`ValidationResult`, enforcing the validation budget and the
stop-after-terminal-state rule before dispatching to a validator.

Mirrors `adi.tools.executor.ToolExecutor`'s role for security tools: one
choke point, consistent bookkeeping, no validator ever called directly by
the orchestrator.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from adi.agent.reasoner import HypothesisEngine
from adi.knowledge.hypotheses import HypothesisStatus
from adi.reporting.redaction import known_secrets, redact_structure
from adi.validation.context import ValidationContext
from adi.validation.models import (
    ValidationAction,
    ValidationActionType,
    ValidationOutcome,
    ValidationResult,
)
from adi.validation.policies import ValidationBudget, should_stop_validating
from adi.validation.validators.authentication import AuthenticationValidator
from adi.validation.validators.authorization import AuthorizationValidator
from adi.validation.validators.cors import CorsValidator
from adi.validation.validators.disclosure import InformationDisclosureValidator
from adi.validation.validators.headers import SecurityHeaderValidator
from adi.validation.validators.session import SessionValidator


class ValidationBudgetExhaustedError(RuntimeError):
    pass


class HypothesisAlreadyResolvedError(RuntimeError):
    pass


class ValidationEngine:
    def __init__(self, context: ValidationContext, budget: ValidationBudget | None = None):
        self.ctx = context
        self.budget = budget or ValidationBudget()
        self.hypothesis_engine = HypothesisEngine(context.workspace)

        for record in context.workspace.list_validation_actions():
            self.budget.record(record.hypothesis_id)

        self._authorization = AuthorizationValidator(context)
        self._authentication = AuthenticationValidator(context)
        self._session = SessionValidator(context)
        self._headers = SecurityHeaderValidator(context)
        self._cors = CorsValidator(context)
        self._disclosure = InformationDisclosureValidator(context)

    async def execute(self, action: ValidationAction) -> ValidationResult:
        hypothesis = self.hypothesis_engine.get(action.hypothesis_id)
        if hypothesis is None:
            raise ValueError(f"no hypothesis '{action.hypothesis_id}'")

        if should_stop_validating(hypothesis.status):
            raise HypothesisAlreadyResolvedError(
                f"hypothesis {action.hypothesis_id} is already {hypothesis.status.value} "
                f"— stop testing this path (spec section 43)"
            )
        if hypothesis.status == HypothesisStatus.NEW:
            # executing a validation action is itself "investigating"
            self.hypothesis_engine.transition(action.hypothesis_id, HypothesisStatus.INVESTIGATING)

        limit = self.ctx.workspace.validation_limit(
            action.hypothesis_id, self.budget.max_actions_per_hypothesis)
        if self.budget.used(action.hypothesis_id) >= limit:
            raise ValidationBudgetExhaustedError(
                f"hypothesis {action.hypothesis_id} has used its validation budget "
                f"({self.budget.max_actions_per_hypothesis} actions)"
            )

        scope = self.ctx.workspace.load_scope()
        urls = [v for k, v in action.parameters.items() if k in ("url", "logout_url", "protected_url")]
        authorized = bool(urls) and scope.permissions.active_validation and all(
            isinstance(u, str) and urlsplit(u).scheme in scope.allowed_protocols
            and scope.host_is_target(urlsplit(u).hostname or "") for u in urls)
        if not authorized:
            raise ValueError("validation target or active-validation permission is outside scope")
        if not action.reason_summary:
            action.reason_summary = (
                f"Test stored hypothesis '{hypothesis.title}' using {action.action_type.value}; "
                "compare observed behavior with the validator's expected secure behavior.")
        before = {e.id for e in self.ctx.workspace.list_http_exchanges()}
        result = await self._dispatch(action)
        exchanges = [e for e in self.ctx.workspace.list_http_exchanges() if e.id not in before]
        for eid in result.evidence_ids:
            self.ctx.workspace.attach_evidence_exchanges(eid, [e.id for e in exchanges])
        self.budget.record(action.hypothesis_id)

        self.ctx.workspace.record_validation_action(
            hypothesis_id=action.hypothesis_id, action_type=action.action_type.value,
            session_id=str(action.parameters.get("session_id", "")),
            parameters_json=json.dumps(redact_structure(action.parameters, known_secrets(scope))),
            outcome=result.outcome.value, scope_allowed=True,
            detail=result.detail, evidence_ids_json=json.dumps(result.evidence_ids),
            reason_summary=action.reason_summary,
        )
        self._record_positive_control(action, result)

        self._apply_outcome(action.hypothesis_id, result)
        return result

    async def _dispatch(self, action: ValidationAction) -> ValidationResult:
        p = action.parameters
        hid = action.hypothesis_id
        match action.action_type:
            case ValidationActionType.CHECK_OBJECT_AUTHORIZATION:
                return await self._authorization.check_object_access(
                    p["url"], p["owner_session"], p["other_session"], hid,
                    method=p.get("method", "GET"),
                )
            case ValidationActionType.CHECK_ROLE_BOUNDARY:
                return await self._authorization.check_function_boundary(
                    p["url"], p["normal_session"], p["privileged_session"], hid,
                    method=p.get("method", "GET"),
                )
            case ValidationActionType.CHECK_AUTH_BOUNDARY:
                return await self._authentication.check_auth_boundary(
                    p["url"], hid, expected_secure_status=tuple(p.get("expected_secure_status", (401, 403))),
                )
            case ValidationActionType.CHECK_COOKIE_ATTRIBUTE:
                return await self._session.check_cookie_attributes(
                    p["url"], hid, method=p.get("method", "GET"), body=p.get("body"),
                    session_id=p.get("session_id", "anonymous"),
                )
            case ValidationActionType.CHECK_SESSION_INVALIDATION:
                return await self._session.check_session_invalidation(
                    p["logout_url"], p["protected_url"], p["session_id"], hid,
                )
            case ValidationActionType.CHECK_SECURITY_HEADER:
                return await self._headers.check_security_headers(p["url"], hid)
            case ValidationActionType.CHECK_CORS_POLICY:
                return await self._cors.check_cors_policy(p["url"], hid)
            case ValidationActionType.VERIFY_SCANNER_INDICATION:
                return await self._disclosure.check_for_disclosure(p["url"], hid)
            case _:
                return ValidationResult(
                    action_type=action.action_type, outcome=ValidationOutcome.ERROR,
                    detail=f"validation action '{action.action_type.value}' is not implemented "
                           f"in this phase",
                )

    def _record_positive_control(self, action: ValidationAction, result: ValidationResult) -> None:
        """A REFUTES outcome means a security control behaved correctly —
        record that as a PositiveSecurityObservation (never a Finding)."""
        if result.outcome != ValidationOutcome.REFUTES:
            return
        p = action.parameters
        endpoint = p.get("url") or p.get("protected_url") or ""
        titles = {
            ValidationActionType.CHECK_OBJECT_AUTHORIZATION:
                ("authorization", "Cross-user object access correctly denied"),
            ValidationActionType.CHECK_ROLE_BOUNDARY:
                ("authorization", "Privileged endpoint correctly requires a privileged role"),
            ValidationActionType.CHECK_AUTH_BOUNDARY:
                ("authentication", "Anonymous access correctly rejected"),
            ValidationActionType.CHECK_COOKIE_ATTRIBUTE:
                ("session", "Session cookies carry Secure and HttpOnly"),
            ValidationActionType.CHECK_SESSION_INVALIDATION:
                ("session", "Logout correctly invalidates the session"),
            ValidationActionType.CHECK_SECURITY_HEADER:
                ("headers", "Recommended security headers present"),
            ValidationActionType.CHECK_CORS_POLICY:
                ("cors", "No risky CORS origin-reflection with credentials"),
            ValidationActionType.VERIFY_SCANNER_INDICATION:
                ("disclosure", "No verbose error output disclosed"),
        }
        entry = titles.get(action.action_type)
        if entry is None:
            return
        category, title = entry
        self.ctx.workspace.record_positive_observation(
            category=category, title=title, summary=result.detail, endpoint=endpoint,
            asset=urlsplit(endpoint).hostname or "",
            session=str(p.get("other_session") or p.get("session_id") or p.get("normal_session") or ""),
            evidence_ids_json=json.dumps(result.evidence_ids),
        )

    def _apply_outcome(self, hypothesis_id: str, result: ValidationResult) -> None:
        """Folds a validation result into the hypothesis's evidence lists
        and advances its status — SUPPORTS moves it toward VALIDATING,
        never straight to CONFIRMED (the FindingVerifier/Critic gate that)."""
        hypothesis = self.hypothesis_engine.get(hypothesis_id)
        if hypothesis is None or should_stop_validating(hypothesis.status):
            return

        if result.outcome == ValidationOutcome.SUPPORTS:
            target = HypothesisStatus.VALIDATING if hypothesis.status in (
                HypothesisStatus.SUPPORTED, HypothesisStatus.VALIDATING,
            ) else HypothesisStatus.SUPPORTED
            self.hypothesis_engine.transition(
                hypothesis_id, target, confidence=min(0.95, hypothesis.confidence + 0.3),
                new_supporting_observation_ids=result.evidence_ids,
            )
        elif result.outcome == ValidationOutcome.REFUTES:
            self.hypothesis_engine.transition(
                hypothesis_id,
                hypothesis.status if hypothesis.status != HypothesisStatus.NEW else HypothesisStatus.INVESTIGATING,
                new_contradicting_observation_ids=result.evidence_ids,
            )
