"""SecurityHeaderValidator (spec Phase 4 section 14).

Deterministic presence checks only — no LLM tokens spent on header parsing
(spec section 26). Classification is conservative by design: a missing
header here is evidence for a *hardening* hypothesis, not automatically a
high-severity vulnerability — the severity engine (`adi.findings.severity`)
makes that call, never this validator.
"""

from __future__ import annotations

from adi.evidence.models import EvidenceType
from adi.validation.models import ValidationActionType, ValidationOutcome, ValidationResult

# header name (lowercase) -> whether its mere absence is worth noting
_RECOMMENDED_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


class SecurityHeaderValidator:
    def __init__(self, ctx):
        self.ctx = ctx

    async def check_security_headers(self, url: str, hypothesis_id: str) -> ValidationResult:
        exchange, _ = await self.ctx.http_workspace.fetch_with_exchange(
            "GET", url, session_id="anonymous", source="validator_headers",
        )
        if exchange.error or exchange.response is None:
            evidence = self.ctx.evidence_store.create(
                EvidenceType.HTTP_EXCHANGE, source="validator_headers", subject=url,
                summary=f"request error: {exchange.error}", raw_text=exchange.error or "",
                related_hypothesis_ids=[hypothesis_id],
            )
            return ValidationResult(
                action_type=ValidationActionType.CHECK_SECURITY_HEADER,
                outcome=ValidationOutcome.ERROR, detail=exchange.error or "no response",
                evidence_ids=[evidence.id],
            )

        present = {k.lower() for k in exchange.response.headers}
        missing = [h for h in _RECOMMENDED_HEADERS if h not in present]

        evidence = self.ctx.evidence_store.create(
            EvidenceType.CONFIGURATION, source="validator_headers", subject=url,
            summary=f"missing: {', '.join(missing) or 'none'}",
            raw_text="\n".join(f"{k}: {v}" for k, v in exchange.response.headers.items()),
            related_hypothesis_ids=[hypothesis_id],
            metadata={"missing_headers": missing},
        )

        if missing:
            return ValidationResult(
                action_type=ValidationActionType.CHECK_SECURITY_HEADER,
                outcome=ValidationOutcome.SUPPORTS,
                detail=f"missing recommended header(s): {', '.join(missing)} "
                       f"(hardening recommendation — not inherently exploitable)",
                evidence_ids=[evidence.id],
            )
        return ValidationResult(
            action_type=ValidationActionType.CHECK_SECURITY_HEADER,
            outcome=ValidationOutcome.REFUTES,
            detail="all checked recommended headers are present", evidence_ids=[evidence.id],
        )
