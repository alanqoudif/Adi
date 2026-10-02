"""FindingPipeline: the only path from a hypothesis to a Finding.

    hypothesis + evidence
      -> FindingVerifier   (deterministic: CONFIRMED / SUPPORTED / REJECTED)
      -> Critic            (bounded-evidence second pass, only before CONFIRMED)
      -> FindingDeduplicator
      -> severity engine
      -> Finding row (+ hypothesis status advanced to match)

No other code path creates a Finding — this is where spec section 1's rule
("a vulnerability becomes CONFIRMED only when Adi has sufficient
reproducible evidence") and section 30 (dedup) and section 28 (severity)
all actually get enforced together.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from adi.agent.critic import Critic, CriticDecision
from adi.agent.reasoner import HypothesisEngine, InvalidHypothesisTransitionError
from adi.evidence.store import EvidenceStore
from adi.findings.deduplicator import FindingDeduplicator
from adi.findings.severity import severity_for_category
from adi.findings.verifier import FindingVerifier, VerificationDecision, VerificationStatus
from adi.knowledge.hypotheses import HypothesisStatus
from adi.knowledge.workspace import Workspace

# category -> (impact, remediation) — deterministic, templated prose. The
# LLM never authors these; they come from the validator-assigned category.
_CATEGORY_GUIDANCE: dict[str, tuple[str, str]] = {
    "broken_object_authorization": (
        "An authenticated user can read another user's resource by changing an object "
        "identifier, without any ownership check.",
        "Enforce an object-ownership check on every request that accepts an object "
        "identifier: verify the authenticated session is the resource's owner (or holds "
        "an explicit grant) before returning it.",
    ),
    "broken_function_authorization": (
        "A normal-privilege session can reach a function intended for a higher-privilege role.",
        "Enforce role/permission checks at the function/endpoint level, not only in the UI.",
    ),
    "missing_authentication": (
        "A protected-looking endpoint returns data without requiring any authentication.",
        "Require authentication on this endpoint and verify the session before returning data.",
    ),
    "cookie_hardening": (
        "A session-related cookie is missing the Secure and/or HttpOnly attribute, "
        "increasing the risk of session theft via network interception or script injection.",
        "Set `Secure`, `HttpOnly`, and an appropriate `SameSite` attribute on all "
        "session/authentication cookies.",
    ),
    "cors_misconfiguration": (
        "The server reflects an arbitrary Origin while allowing credentials, letting any "
        "website make authenticated cross-origin requests on a victim's behalf.",
        "Allow credentialed CORS only from an explicit allow-list of trusted origins; "
        "never reflect an arbitrary Origin when Access-Control-Allow-Credentials is true.",
    ),
    "information_disclosure": (
        "A response includes verbose error output (stack trace, internal file paths, or "
        "database error text) that can aid an attacker in understanding the application's "
        "internals.",
        "Disable verbose/debug error output in the deployed environment; return a generic "
        "error message and log the detail server-side only.",
    ),
    "missing_security_header": (
        "One or more recommended security headers are absent. This is a hardening gap, "
        "not by itself a directly exploitable vulnerability.",
        "Add the missing security headers appropriate to this application's threat model.",
    ),
}


@dataclass
class FindingPipelineResult:
    hypothesis_status: HypothesisStatus
    finding_id: str | None
    verification: VerificationDecision
    critic_decision: CriticDecision | None = None
    critic_review_id: str | None = None


class FindingPipeline:
    def __init__(self, workspace: Workspace, evidence_store: EvidenceStore, critic: Critic | None = None):
        self.workspace = workspace
        self.evidence_store = evidence_store
        self.hypothesis_engine = HypothesisEngine(workspace)
        self.verifier = FindingVerifier()
        self.dedup = FindingDeduplicator(workspace)
        self.critic = critic

    async def finalize(
        self, hypothesis_id: str, *, category: str | None = None,
        affected_endpoints: list[str] | None = None,
    ) -> FindingPipelineResult:
        hypothesis = self.hypothesis_engine.get(hypothesis_id)
        if hypothesis is None:
            raise ValueError(f"no hypothesis '{hypothesis_id}'")

        evidence = self.evidence_store.for_hypothesis(hypothesis_id)
        decision = self.verifier.evaluate(hypothesis, evidence)
        category = category or hypothesis.category or "uncategorized"
        endpoints = affected_endpoints or []

        if decision.status == VerificationStatus.REJECTED:
            self._safe_transition(hypothesis_id, HypothesisStatus.REJECTED)
            return FindingPipelineResult(HypothesisStatus.REJECTED, None, decision)

        if decision.status == VerificationStatus.SUPPORTED:
            finding_id = self._create_or_merge_finding(hypothesis, evidence, category, endpoints, decision, "supported")
            return FindingPipelineResult(hypothesis.status, finding_id, decision)

        # CONFIRMED-eligible — run the critic before actually confirming, if one is configured.
        self._safe_transition(hypothesis_id, HypothesisStatus.VALIDATING)

        if self.critic is not None:
            summaries = [e.summary for e in evidence]
            review = await self.critic.review(hypothesis.title, category, summaries)
            critic_review_id = self.workspace.record_critic_review(
                hypothesis_id=hypothesis_id, decision=review.decision.value,
                concerns_json=json.dumps(review.concerns),
                additional_validation_needed_json=json.dumps(review.additional_validation_needed),
                confidence_adjustment=review.confidence_adjustment,
            )
            if review.decision == CriticDecision.NEEDS_MORE_EVIDENCE:
                current = self.hypothesis_engine.get(hypothesis_id)
                return FindingPipelineResult(
                    current.status, None, decision, review.decision, critic_review_id,
                )
            if review.decision == CriticDecision.REJECT:
                self._safe_transition(hypothesis_id, HypothesisStatus.REJECTED)
                return FindingPipelineResult(
                    HypothesisStatus.REJECTED, None, decision, review.decision, critic_review_id,
                )
            # ACCEPT falls through to confirmation below
            self._safe_transition(hypothesis_id, HypothesisStatus.CONFIRMED)
            finding_id = self._create_or_merge_finding(hypothesis, evidence, category, endpoints, decision, "confirmed")
            return FindingPipelineResult(
                HypothesisStatus.CONFIRMED, finding_id, decision, review.decision, critic_review_id,
            )

        # no critic configured (e.g. no LLM provider) — confirm directly from
        # deterministic evidence; still gated by the FindingVerifier above.
        self._safe_transition(hypothesis_id, HypothesisStatus.CONFIRMED)
        finding_id = self._create_or_merge_finding(hypothesis, evidence, category, endpoints, decision, "confirmed")
        return FindingPipelineResult(HypothesisStatus.CONFIRMED, finding_id, decision)

    def _safe_transition(self, hypothesis_id: str, target: HypothesisStatus) -> None:
        try:
            self.hypothesis_engine.transition(hypothesis_id, target)
        except InvalidHypothesisTransitionError:
            pass  # already there, or a terminal state reached a different way — not fatal

    def _create_or_merge_finding(
        self, hypothesis, evidence, category: str, affected_endpoints: list[str],
        decision: VerificationDecision, status: str,
    ) -> str:
        evidence_ids = [e.id for e in evidence]
        existing = self.dedup.find_duplicate(category, affected_endpoints) if affected_endpoints else None

        if existing:
            self.dedup.merge_evidence(existing.id, evidence_ids)
            if status == "confirmed" and existing.status != "confirmed":
                self.workspace.update_finding(existing.id, status="confirmed", hypothesis_id=hypothesis.id)
            return existing.id

        impact, remediation = _CATEGORY_GUIDANCE.get(
            category, ("Impact not yet characterized for this category.", "Review and remediate as appropriate.")
        )
        severity = severity_for_category(category)

        finding_id = self.workspace.create_finding(
            title=hypothesis.title, category=category, severity=severity.value,
            confidence=hypothesis.confidence, status=status, summary=hypothesis.title,
            impact=impact, remediation=remediation,
            evidence_ids_json=json.dumps(evidence_ids),
            affected_endpoints_json=json.dumps(affected_endpoints),
            hypothesis_id=hypothesis.id,
            validation_summary="; ".join(decision.reasons),
        )
        for evidence_id in evidence_ids:
            self.workspace.link_evidence_to_finding(evidence_id, finding_id)
        return finding_id
