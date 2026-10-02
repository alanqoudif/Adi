"""Typed validation plans and actions (spec Phase 4 sections 5–6).

The LLM is never asked to return an arbitrary exploit string — only one of
these enum values plus structured parameters. A validator function answers
one specific security question; it never "runs an exploit."
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from adi.actions import RiskLevel


class ValidationActionType(str, Enum):
    COMPARE_HTTP_RESPONSES = "compare_http_responses"
    REPLAY_REQUEST = "replay_request"
    CHANGE_SESSION = "change_session"
    CHANGE_OBJECT_REFERENCE = "change_object_reference"
    CHECK_AUTH_BOUNDARY = "check_auth_boundary"
    CHECK_ROLE_BOUNDARY = "check_role_boundary"
    CHECK_METHOD_BEHAVIOR = "check_method_behavior"
    CHECK_SESSION_INVALIDATION = "check_session_invalidation"
    CHECK_CORS_POLICY = "check_cors_policy"
    CHECK_SECURITY_HEADER = "check_security_header"
    CHECK_COOKIE_ATTRIBUTE = "check_cookie_attribute"
    CHECK_REDIRECT_POLICY = "check_redirect_policy"
    CHECK_RATE_LIMIT_BEHAVIOR = "check_rate_limit_behavior"
    VERIFY_SCANNER_INDICATION = "verify_scanner_indication"
    VERIFY_SOURCE_HYPOTHESIS = "verify_source_hypothesis"
    # flagship: object/function-level authorization comparison across sessions
    CHECK_OBJECT_AUTHORIZATION = "check_object_authorization"


class ValidationOutcome(str, Enum):
    SUPPORTS = "supports"       # evidence supports the hypothesis
    REFUTES = "refutes"         # evidence contradicts the hypothesis
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"             # the validation action itself failed to run


class ObjectReference(BaseModel):
    """Optional (spec section 48) — improves authorization validation by
    making ownership explicit instead of inferred from sequential IDs."""

    type: str
    identifier: str
    owner_session: str
    discovered_from: str = ""


class ValidationAction(BaseModel):
    """One structured validation step, analogous to `PlannedAction` but
    scoped to proving/disproving a single hypothesis."""

    action_type: ValidationActionType
    hypothesis_id: str
    parameters: dict = Field(default_factory=dict)
    reason_summary: str = ""


class ValidationResult(BaseModel):
    action_type: ValidationActionType
    outcome: ValidationOutcome
    detail: str
    evidence_ids: list[str] = Field(default_factory=list)


class ValidationPlan(BaseModel):
    hypothesis_id: str
    objective: str
    preconditions: list[str] = Field(default_factory=list)
    required_sessions: list[str] = Field(default_factory=list)
    actions: list[ValidationActionType] = Field(default_factory=list)
    expected_secure_behavior: str = ""
    potential_failure_signal: str = ""
    max_actions: int = 8
    risk: RiskLevel = RiskLevel.MODERATE
    stop_conditions: list[str] = Field(default_factory=list)
