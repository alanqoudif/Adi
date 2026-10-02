"""ValidationEngine: the single path from a typed `ValidationAction` to a
`ValidationResult`, enforcing the validation budget and the
stop-after-terminal-state rule before dispatching to a validator.

Mirrors `adi.tools.executor.ToolExecutor`'s role for security tools: one
choke point, consistent bookkeeping, no validator ever called directly by
the orchestrator.
"""

from __future__ import annotations

import json

from adi.agent.reasoner import HypothesisEngine
from adi.knowledge.hypotheses import HypothesisStatus
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

        if self.budget.exhausted(action.hypothesis_id):
            raise ValidationBudgetExhaustedError(
                f"hypothesis {action.hypothesis_id} has used its validation budget "
                f"({self.budget.max_actions_per_hypothesis} actions)"
            )

        result = await self._dispatch(action)
        self.budget.record(action.hypothesis_id)

        self.ctx.workspace.record_validation_action(
            hypothesis_id=action.hypothesis_id, action_type=action.action_type.value,
            session_id=str(action.parameters.get("session_id", "")),
            parameters_json=json.dumps(action.parameters), outcome=result.outcome.value,
            detail=result.detail, evidence_ids_json=json.dumps(result.evidence_ids),
        )

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
