"""InformationDisclosureValidator (spec Phase 4 section 15).

Deterministic pattern matching for verbose error output — stack traces,
internal file paths, database errors. The matched snippet is stored as
evidence through the normal redaction path, so nothing beyond what's
necessary to prove the issue is retained unsanitized.
"""

from __future__ import annotations

import re

from adi.evidence.models import EvidenceType
from adi.validation.models import ValidationActionType, ValidationOutcome, ValidationResult

_DISCLOSURE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"Exception in thread", re.IGNORECASE),
    re.compile(r"\bat [\w.$]+\([\w.]+\.java:\d+\)"),  # Java stack frame
    re.compile(r"(?:/[\w.\-]+){2,}\.(?:py|rb|php|js|java)\b"),  # internal file path
    re.compile(r"SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax", re.IGNORECASE),
    re.compile(r"Warning:\s+\w+\(\):", re.IGNORECASE),  # PHP warning style
]


class InformationDisclosureValidator:
    def __init__(self, ctx):
        self.ctx = ctx

    async def check_for_disclosure(self, url: str, hypothesis_id: str) -> ValidationResult:
        exchange, _observations = await self.ctx.http_workspace.fetch_with_exchange(
            "GET", url, session_id="anonymous", source="validator_disclosure",
        )
        body = exchange.response.body_preview if exchange.response else ""
        if exchange.error:
            evidence = self.ctx.evidence_store.create(
                EvidenceType.HTTP_EXCHANGE, source="validator_disclosure", subject=url,
                summary=f"request error: {exchange.error}", raw_text=exchange.error,
                related_hypothesis_ids=[hypothesis_id],
            )
            return ValidationResult(
                action_type=ValidationActionType.VERIFY_SCANNER_INDICATION,
                outcome=ValidationOutcome.ERROR, detail=exchange.error, evidence_ids=[evidence.id],
            )

        matches = [p.search(body) for p in _DISCLOSURE_PATTERNS]
        hits = [m.group(0) for m in matches if m]

        evidence = self.ctx.evidence_store.create(
            EvidenceType.HTTP_EXCHANGE, source="validator_disclosure", subject=url,
            summary=f"{len(hits)} disclosure pattern(s) matched" if hits else "no disclosure pattern matched",
            raw_text=body, related_hypothesis_ids=[hypothesis_id],
            metadata={"matched_patterns": hits},
        )

        if hits:
            return ValidationResult(
                action_type=ValidationActionType.VERIFY_SCANNER_INDICATION,
                outcome=ValidationOutcome.SUPPORTS,
                detail=f"response contains verbose error output: {hits[0]!r}",
                evidence_ids=[evidence.id],
            )
        return ValidationResult(
            action_type=ValidationActionType.VERIFY_SCANNER_INDICATION,
            outcome=ValidationOutcome.REFUTES,
            detail="response did not contain recognizable verbose error output",
            evidence_ids=[evidence.id],
        )
