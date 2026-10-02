"""Explainability and evidence-trace rendering.

Deliberately NOT an LLM call. Every answer here is built by reading
Core's already-persisted structured state (`ActionRecord.reason_summary`/
`.scope_reason`, `CriticReviewRecord`, `Hypothesis`/`Finding` linkage,
`ToolRegistry` fallback order) — "explain" surfaces facts Adi already
recorded, it never invents a justification after the fact or exposes
hidden chain-of-thought that was never stored.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from adi.knowledge.workspace import Workspace


@dataclass
class TraceStep:
    label: str
    detail: str


@dataclass
class EvidenceTrace:
    finding_id: str
    steps: list[TraceStep] = field(default_factory=list)

    def render_lines(self) -> list[str]:
        return [f"{i + 1}. {s.label}: {s.detail}" for i, s in enumerate(self.steps)]


def build_evidence_trace(workspace: Workspace, finding_id: str) -> EvidenceTrace | None:
    """finding -> hypothesis -> validation actions -> observations ->
    tool/HTTP/source evidence -> scope decision, per the spec's
    differentiator: a navigable chain from a confirmed finding all the
    way back to the scope decision that permitted the evidence-gathering
    action."""
    finding = workspace.get_finding(finding_id)
    if finding is None:
        return None

    trace = EvidenceTrace(finding_id=finding_id)
    trace.steps.append(TraceStep("Finding", f"{finding.title} [{finding.severity}, status={finding.status}]"))

    hypothesis = None
    if finding.hypothesis_id:
        hypothesis = next((h for h in workspace.list_hypotheses() if h.id == finding.hypothesis_id), None)
    if hypothesis is not None:
        trace.steps.append(TraceStep("Hypothesis", f"{hypothesis.id}: {hypothesis.title} (confidence={hypothesis.confidence})"))
        validations = workspace.list_validation_actions(hypothesis.id)
        for v in validations:
            trace.steps.append(TraceStep(
                "Validation action",
                f"{v.action_type} -> outcome={v.outcome} scope_allowed={v.scope_allowed}",
            ))
        supporting_ids = json.loads(hypothesis.supporting_observation_ids_json or "[]")
        if supporting_ids:
            observations = {o.id: o for o in workspace.list_observations()}
            for obs_id in supporting_ids:
                obs = observations.get(obs_id)
                if obs is not None:
                    trace.steps.append(TraceStep("Observation", f"{obs.type}: {obs.subject}"))

    if finding.critic_review_id:
        review = workspace.get_critic_review(finding.critic_review_id)
        if review is not None:
            trace.steps.append(TraceStep(
                "Critic review",
                f"{review.decision} (confidence_adjustment={review.confidence_adjustment})",
            ))

    evidence_ids = json.loads(finding.evidence_ids_json or "[]")
    for evidence_id in evidence_ids:
        evidence = workspace.get_evidence(evidence_id)
        if evidence is not None:
            trace.steps.append(TraceStep("Evidence", f"[{evidence.type}] {evidence.sanitized_preview[:120]}"))

    return trace


def explain_why(workspace: Workspace, subject_id: str) -> str:
    """Answer 'why did you run this / why is this High / why rejected /
    why this tool' style questions for one id — an action id, a
    hypothesis id, or a finding id — from stored state only."""
    for action in workspace.list_actions():
        if action.id == subject_id:
            lines = [f"Action {action.id}: {action.action_type} (capability={action.capability or '-'})"]
            lines.append(f"Reason: {action.reason_summary or '(none recorded)'}")
            lines.append(f"Scope decision: allowed={action.scope_allowed} — {action.scope_reason}")
            return "\n".join(lines)

    for hyp in workspace.list_hypotheses():
        if hyp.id == subject_id:
            lines = [f"Hypothesis {hyp.id}: {hyp.title} — status={hyp.status}, confidence={hyp.confidence}"]
            reviews = workspace.list_critic_reviews(hyp.id)
            for review in reviews:
                lines.append(
                    f"Critic: {review.decision} (concerns: {json.loads(review.concerns_json or '[]')})"
                )
            validations = workspace.list_validation_actions(hyp.id)
            if validations:
                lines.append(f"{len(validations)} validation action(s) recorded; "
                              f"outcomes: {', '.join(v.outcome for v in validations)}")
            return "\n".join(lines)

    finding = workspace.get_finding(subject_id)
    if finding is not None:
        lines = [f"Finding {finding.id}: {finding.title} — severity={finding.severity}"]
        lines.append(f"Validation summary: {finding.validation_summary or '(none recorded)'}")
        if finding.hypothesis_id:
            lines.append(f"Derived from hypothesis {finding.hypothesis_id} — see '/trace {finding.id}' for the full chain.")
        return "\n".join(lines)

    return f"No action, hypothesis, or finding with id '{subject_id}' is recorded for this assessment."
