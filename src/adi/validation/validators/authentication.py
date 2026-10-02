"""AuthenticationValidator (spec Phase 4 section 11).

Answers: "does an unauthenticated (or wrongly-authenticated) request reach
content it shouldn't?" Deliberately does NOT do credential brute forcing —
that is explicitly out of scope for Phase 4 (spec section 67).
"""

from __future__ import annotations

from adi.evidence.models import EvidenceType
from adi.validation.models import ValidationActionType, ValidationOutcome, ValidationResult


class AuthenticationValidator:
    def __init__(self, ctx):
        self.ctx = ctx

    async def check_auth_boundary(
        self, url: str, hypothesis_id: str, expected_secure_status: tuple[int, ...] = (401, 403),
    ) -> ValidationResult:
        """Requests `url` as the anonymous session. If it returns a
        non-error response, the endpoint is reachable without
        authentication — supports a "missing authentication" hypothesis."""
        exchange, _ = await self.ctx.http_workspace.fetch_with_exchange(
            "GET", url, session_id="anonymous", source="validator_authentication",
        )
        status = exchange.response.status if exchange.response else None
        preview = exchange.response.body_preview if exchange.response else ""

        evidence = self.ctx.evidence_store.create(
            EvidenceType.HTTP_EXCHANGE, source="validator_authentication", subject=url,
            summary=f"anonymous -> {status}",
            raw_text=f"[anonymous] GET {url} -> {status}\n{preview}",
            related_hypothesis_ids=[hypothesis_id],
        )

        if exchange.error:
            return ValidationResult(
                action_type=ValidationActionType.CHECK_AUTH_BOUNDARY,
                outcome=ValidationOutcome.ERROR, detail=exchange.error, evidence_ids=[evidence.id],
            )

        if status is not None and status not in expected_secure_status and status < 400:
            return ValidationResult(
                action_type=ValidationActionType.CHECK_AUTH_BOUNDARY,
                outcome=ValidationOutcome.SUPPORTS,
                detail=f"anonymous request received status {status} "
                       f"(expected one of {expected_secure_status})",
                evidence_ids=[evidence.id],
            )
        if status in expected_secure_status:
            return ValidationResult(
                action_type=ValidationActionType.CHECK_AUTH_BOUNDARY,
                outcome=ValidationOutcome.REFUTES,
                detail=f"anonymous request correctly denied ({status})",
                evidence_ids=[evidence.id],
            )
        return ValidationResult(
            action_type=ValidationActionType.CHECK_AUTH_BOUNDARY,
            outcome=ValidationOutcome.INCONCLUSIVE,
            detail=f"ambiguous status {status}", evidence_ids=[evidence.id],
        )
