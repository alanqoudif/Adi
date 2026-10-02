"""A conservative, explainable severity engine (spec Phase 4 section 28).

The LLM never assigns severity directly — it is computed from structured
factors, the same way CVSS reasons about impact, without implementing full
CVSS. CRITICAL requires a strong combination of factors; it is not
reachable from a single weak signal.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

_IMPACT_SCORE = {"none": 0, "low": 1, "high": 2}


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SeverityFactors(BaseModel):
    confidentiality_impact: str = "none"  # none | low | high
    integrity_impact: str = "none"
    availability_impact: str = "none"
    requires_authentication: bool = True
    requires_privileges: bool = False
    user_interaction: bool = False
    scope_changed: bool = False
    # how confident Adi is that this is actually exploitable as described —
    # NOT the hypothesis/finding confidence, a separate exploitability axis.
    exploitability_confidence: float = 0.7


def compute_severity(factors: SeverityFactors) -> SeverityLevel:
    impact_score = (
        _IMPACT_SCORE.get(factors.confidentiality_impact, 0) * 2
        + _IMPACT_SCORE.get(factors.integrity_impact, 0) * 2
        + _IMPACT_SCORE.get(factors.availability_impact, 0)
    )
    if impact_score == 0:
        # no confidentiality/integrity/availability impact at all — nothing
        # for ease-of-exploitation factors to amplify.
        return SeverityLevel.INFO

    score = (
        impact_score
        + (2 if not factors.requires_authentication else 0)
        + (1 if not factors.requires_privileges else 0)
        + (1 if not factors.user_interaction else 0)
        + (2 if factors.scope_changed else 0)
    )
    adjusted = score * max(0.0, min(1.0, factors.exploitability_confidence))

    if adjusted >= 9:
        return SeverityLevel.CRITICAL
    if adjusted >= 6:
        return SeverityLevel.HIGH
    if adjusted >= 3:
        return SeverityLevel.MEDIUM
    if adjusted >= 1:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


# Reasonable, documented defaults per validation category — a starting
# point the finding pipeline can override with specifics from the actual
# evidence (e.g. whether the endpoint returns write access, not just read).
CATEGORY_DEFAULT_FACTORS: dict[str, SeverityFactors] = {
    "broken_object_authorization": SeverityFactors(
        confidentiality_impact="high", integrity_impact="low",
        requires_authentication=True, requires_privileges=False,
        exploitability_confidence=0.9,
    ),
    "broken_function_authorization": SeverityFactors(
        confidentiality_impact="high", integrity_impact="high",
        requires_authentication=True, requires_privileges=False,
        exploitability_confidence=0.9,
    ),
    "missing_authentication": SeverityFactors(
        confidentiality_impact="high", integrity_impact="none",
        requires_authentication=False, requires_privileges=False,
        exploitability_confidence=0.9,
    ),
    "cookie_hardening": SeverityFactors(
        confidentiality_impact="low", integrity_impact="none",
        requires_authentication=True, exploitability_confidence=0.5,
    ),
    "cors_misconfiguration": SeverityFactors(
        confidentiality_impact="high", integrity_impact="low",
        requires_authentication=False, requires_privileges=False,
        user_interaction=True, exploitability_confidence=0.7,
    ),
    "information_disclosure": SeverityFactors(
        confidentiality_impact="low", requires_authentication=False,
        exploitability_confidence=0.6,
    ),
    "missing_security_header": SeverityFactors(
        confidentiality_impact="low", requires_authentication=False,
        exploitability_confidence=0.3,  # hardening recommendation, not a direct exploit
    ),
    "session_management": SeverityFactors(
        confidentiality_impact="low", requires_authentication=True,
        exploitability_confidence=0.5,
    ),
}


def severity_for_category(category: str) -> SeverityLevel:
    factors = CATEGORY_DEFAULT_FACTORS.get(category, SeverityFactors())
    return compute_severity(factors)
