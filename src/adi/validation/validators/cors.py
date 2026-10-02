"""CorsValidator (spec Phase 4 section 13).

Actual policy reasoning, not a blanket "wildcard = vulnerable" rule: a
reflected, non-wildcard `Access-Control-Allow-Origin` combined with
`Access-Control-Allow-Credentials: true` is what actually allows an
arbitrary origin to make authenticated cross-origin requests — a bare
wildcard (which browsers refuse to pair with credentials) is not.
"""

from __future__ import annotations

from adi.evidence.models import EvidenceType
from adi.validation.models import ValidationActionType, ValidationOutcome, ValidationResult

_TEST_ORIGIN = "https://adi-cors-probe.invalid"


class CorsValidator:
    def __init__(self, ctx):
        self.ctx = ctx

    async def check_cors_policy(self, url: str, hypothesis_id: str) -> ValidationResult:
        exchange, _ = await self.ctx.http_workspace.fetch_with_exchange(
            "GET", url, session_id="anonymous", headers={"Origin": _TEST_ORIGIN},
            source="validator_cors",
        )
        if exchange.error or exchange.response is None:
            evidence = self.ctx.evidence_store.create(
                EvidenceType.HTTP_EXCHANGE, source="validator_cors", subject=url,
                summary=f"request error: {exchange.error}", raw_text=exchange.error or "",
                related_hypothesis_ids=[hypothesis_id],
            )
            return ValidationResult(
                action_type=ValidationActionType.CHECK_CORS_POLICY,
                outcome=ValidationOutcome.ERROR, detail=exchange.error or "no response",
                evidence_ids=[evidence.id],
            )

        headers = {k.lower(): v for k, v in exchange.response.headers.items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower() == "true"
        reflects_arbitrary_origin = acao == _TEST_ORIGIN

        evidence = self.ctx.evidence_store.create(
            EvidenceType.CONFIGURATION, source="validator_cors", subject=url,
            summary=f"ACAO={acao!r}, ACAC={acac}",
            raw_text=f"Origin sent: {_TEST_ORIGIN}\nAccess-Control-Allow-Origin: {acao}\n"
                     f"Access-Control-Allow-Credentials: {headers.get('access-control-allow-credentials', '')}",
            related_hypothesis_ids=[hypothesis_id],
            metadata={"acao": acao, "acac": acac},
        )

        if reflects_arbitrary_origin and acac:
            return ValidationResult(
                action_type=ValidationActionType.CHECK_CORS_POLICY,
                outcome=ValidationOutcome.SUPPORTS,
                detail="the server reflects an arbitrary Origin AND allows credentials — "
                       "any website can make authenticated cross-origin requests on a victim's behalf",
                evidence_ids=[evidence.id],
            )
        if acao == "*" and not acac:
            return ValidationResult(
                action_type=ValidationActionType.CHECK_CORS_POLICY,
                outcome=ValidationOutcome.REFUTES,
                detail="wildcard CORS without credentials — not exploitable for authenticated access",
                evidence_ids=[evidence.id],
            )
        return ValidationResult(
            action_type=ValidationActionType.CHECK_CORS_POLICY,
            outcome=ValidationOutcome.REFUTES,
            detail=f"no risky Origin-reflection + credentials combination observed (ACAO={acao!r})",
            evidence_ids=[evidence.id],
        )
