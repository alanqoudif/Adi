"""FindingVerifier (spec Phase 4 section 23).

Deterministic code, not an LLM judgment: given a hypothesis and its
evidence, decides whether there is enough to confirm it, whether it merely
remains supported (needs more review), or whether it should be rejected
outright. When uncertainty remains, the rule is always to stay at
SUPPORTED rather than jump to CONFIRMED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from adi.evidence.models import Evidence, EvidenceType
from adi.knowledge.hypotheses import Hypothesis

# Evidence types that, on their own, can never be sufficient to confirm —
# they indicate something worth investigating, not proof.
_SCANNER_ONLY_TYPES = {EvidenceType.SCANNER_INDICATION, EvidenceType.SAST_RESULT,
                       EvidenceType.SOURCE_SNIPPET, EvidenceType.SOURCE_ROUTE,
                       EvidenceType.SOURCE_CONFIG, EvidenceType.DEPENDENCY_RECORD,
                       EvidenceType.SECRET_INDICATION}


class VerificationStatus(str, Enum):
    CONFIRMED = "confirmed"
    SUPPORTED = "supported"
    REJECTED = "rejected"


@dataclass
class VerificationDecision:
    status: VerificationStatus
    reasons: list[str] = field(default_factory=list)


class FindingVerifier:
    def evaluate(self, hypothesis: Hypothesis, evidence: list[Evidence]) -> VerificationDecision:
        supporting = [e for e in evidence if e.id in hypothesis.supporting_observation_ids]
        contradicting = [e for e in evidence if e.id in hypothesis.contradicting_observation_ids]

        if not supporting and not contradicting:
            return VerificationDecision(
                VerificationStatus.REJECTED, ["no evidence at all — cannot confirm a hypothesis with nothing behind it"]
            )

        if contradicting and not supporting:
            return VerificationDecision(
                VerificationStatus.REJECTED,
                [f"{len(contradicting)} contradicting evidence item(s), no supporting evidence"],
            )

        if not supporting:
            return VerificationDecision(VerificationStatus.REJECTED, ["no supporting evidence"])

        if contradicting and all(e.type in _SCANNER_ONLY_TYPES for e in supporting):
            return VerificationDecision(VerificationStatus.REJECTED,
                ["runtime validation refutes source/scanner suspicion"])

        if contradicting:
            return VerificationDecision(
                VerificationStatus.SUPPORTED,
                [(f"{len(supporting)} supporting vs {len(contradicting)} contradicting evidence item(s) — "
                 f"contradiction present, narrow the hypothesis before confirming")],
            )

        scanner_only = all(e.type in _SCANNER_ONLY_TYPES for e in supporting)
        if scanner_only:
            return VerificationDecision(
                VerificationStatus.SUPPORTED,
                ["supporting evidence is scanner-only — requires independent validation before confirming"],
            )

        reproducible_types = {
            EvidenceType.HTTP_EXCHANGE, EvidenceType.CONFIGURATION,
            EvidenceType.RESPONSE_COMPARISON, EvidenceType.REPRODUCTION_RESULT,
        }
        if not any(e.type in reproducible_types for e in supporting):
            return VerificationDecision(
                VerificationStatus.SUPPORTED,
                ["supporting evidence exists but none of it is a reproducible controlled validation"],
            )

        return VerificationDecision(
            VerificationStatus.CONFIRMED,
            [f"{len(supporting)} reproducible, controlled evidence item(s), no contradicting evidence"],
        )
