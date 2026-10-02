"""AuthorizationValidator — the flagship validator (spec Phase 4 section 9).

Answers one question: "does session B receive the protected resource
belonging to session A?" It never assumes ownership from a sequential ID —
ownership must be supplied (an `ObjectReference`, or simply told which
session is the owner) by whatever created the hypothesis.

Applies the safe-minimal-proof principle (spec section 8): one controlled
object, one comparison, stop as soon as the question is answered.
"""

from __future__ import annotations

from adi.evidence.models import EvidenceType
from adi.http.models import HTTPMethod
from adi.validation.models import ValidationActionType, ValidationOutcome, ValidationResult


class AuthorizationValidator:
    def __init__(self, ctx):
        self.ctx = ctx

    async def check_object_access(
        self, url: str, owner_session: str, other_session: str, hypothesis_id: str,
        method: HTTPMethod | str = "GET",
    ) -> ValidationResult:
        """Session `owner_session` is expected to own the resource at
        `url`. Fetches it as the owner (sanity check) and as
        `other_session`, then compares. `other_session` receiving an
        equivalent non-error response is the failure signal."""
        owner_exchange, _ = await self.ctx.http_workspace.fetch_with_exchange(
            method, url, session_id=owner_session, source="validator_authorization",
        )
        other_exchange, _ = await self.ctx.http_workspace.fetch_with_exchange(
            method, url, session_id=other_session, source="validator_authorization",
        )

        owner_status = owner_exchange.response.status if owner_exchange.response else None
        other_status = other_exchange.response.status if other_exchange.response else None
        owner_preview = owner_exchange.response.body_preview if owner_exchange.response else ""
        other_preview = other_exchange.response.body_preview if other_exchange.response else ""

        raw_text = (
            f"[{owner_session}] GET {url} -> {owner_status}\n{owner_preview}\n\n"
            f"[{other_session}] GET {url} -> {other_status}\n{other_preview}"
        )

        if owner_exchange.error or other_exchange.error:
            evidence = self.ctx.evidence_store.create(
                EvidenceType.HTTP_EXCHANGE, source="validator_authorization", subject=url,
                summary=f"request error: owner={owner_exchange.error}, other={other_exchange.error}",
                raw_text=raw_text, related_hypothesis_ids=[hypothesis_id],
            )
            return ValidationResult(
                action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION,
                outcome=ValidationOutcome.ERROR,
                detail=f"request failed: {owner_exchange.error or other_exchange.error}",
                evidence_ids=[evidence.id],
            )

        evidence = self.ctx.evidence_store.create(
            EvidenceType.HTTP_EXCHANGE, source="validator_authorization", subject=url,
            summary=f"{owner_session} -> {owner_status}, {other_session} -> {other_status}",
            raw_text=raw_text, related_hypothesis_ids=[hypothesis_id],
            metadata={"owner_session": owner_session, "other_session": other_session,
                      "owner_status": owner_status, "other_status": other_status},
        )

        if owner_status is None or owner_status >= 400:
            # can't even establish the owner's own access — inconclusive,
            # not evidence of anything about `other_session`.
            return ValidationResult(
                action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION,
                outcome=ValidationOutcome.INCONCLUSIVE,
                detail=f"owner session itself could not access the resource (status {owner_status}) "
                       f"— cannot establish a baseline",
                evidence_ids=[evidence.id],
            )

        if other_status is not None and other_status < 400:
            owner_body = owner_exchange.response.body_hash if owner_exchange.response else ''
            other_body = other_exchange.response.body_hash if other_exchange.response else ''
            if not owner_preview.strip() or not owner_body or owner_body != other_body:
                return ValidationResult(
                    action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION,
                    outcome=ValidationOutcome.INCONCLUSIVE,
                    detail='successful status without equivalent protected response; inspect controlled object before claiming bypass',
                    evidence_ids=[evidence.id],
                )
            return ValidationResult(
                action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION,
                outcome=ValidationOutcome.SUPPORTS,
                detail=f"{other_session} received status {other_status} for a resource owned by "
                       f"{owner_session} (expected 401/403/404)",
                evidence_ids=[evidence.id],
            )

        if other_status in (401, 403, 404):
            return ValidationResult(
                action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION,
                outcome=ValidationOutcome.REFUTES,
                detail=f"{other_session} was correctly denied ({other_status}) access to "
                       f"{owner_session}'s resource",
                evidence_ids=[evidence.id],
            )

        return ValidationResult(
            action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION,
            outcome=ValidationOutcome.INCONCLUSIVE,
            detail=f"ambiguous result: other_session status was {other_status}",
            evidence_ids=[evidence.id],
        )

    async def check_function_boundary(
        self, url: str, normal_session: str, privileged_session: str, hypothesis_id: str,
        method: HTTPMethod | str = "GET",
    ) -> ValidationResult:
        """Function-level authorization (spec section 10): does a normal
        user reach a privileged-only endpoint? Uses the same safe
        read-only-preferred comparison as object-level authorization."""
        normal_exchange, _ = await self.ctx.http_workspace.fetch_with_exchange(
            method, url, session_id=normal_session, source="validator_authorization",
        )
        normal_status = normal_exchange.response.status if normal_exchange.response else None
        normal_preview = normal_exchange.response.body_preview if normal_exchange.response else ""

        evidence = self.ctx.evidence_store.create(
            EvidenceType.HTTP_EXCHANGE, source="validator_authorization", subject=url,
            summary=f"{normal_session} (normal) -> {normal_status}",
            raw_text=f"[{normal_session}] {method} {url} -> {normal_status}\n{normal_preview}",
            related_hypothesis_ids=[hypothesis_id],
            metadata={"normal_session": normal_session, "privileged_session": privileged_session,
                      "normal_status": normal_status},
        )

        if normal_status is not None and normal_status < 400:
            return ValidationResult(
                action_type=ValidationActionType.CHECK_ROLE_BOUNDARY,
                outcome=ValidationOutcome.SUPPORTS,
                detail=f"a normal session ({normal_session}) received status {normal_status} from "
                       f"a privileged endpoint (expected 401/403)",
                evidence_ids=[evidence.id],
            )
        if normal_status in (401, 403):
            return ValidationResult(
                action_type=ValidationActionType.CHECK_ROLE_BOUNDARY,
                outcome=ValidationOutcome.REFUTES,
                detail=f"normal session correctly denied ({normal_status}) access to the "
                       f"privileged endpoint",
                evidence_ids=[evidence.id],
            )
        return ValidationResult(
            action_type=ValidationActionType.CHECK_ROLE_BOUNDARY,
            outcome=ValidationOutcome.INCONCLUSIVE,
            detail=f"ambiguous result: status {normal_status}",
            evidence_ids=[evidence.id],
        )
