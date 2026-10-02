"""The Critic: a second-pass, bounded-evidence review before a hypothesis
is allowed to become a confirmed Finding (spec Phase 4 sections 24–26).

The critic cannot execute tools or validations itself — it can only ask for
specific additional validation, which the orchestrator decides whether and
how to run. Its input is a small, structured summary, never the whole
assessment history or raw evidence bodies.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from adi.llm.base import LLMMessage, LLMProvider

_SYSTEM_PROMPT = """\
You are the critic in Adi, an autonomous security assessment agent. Your \
only job is to challenge a hypothesis that validation evidence appears to \
support, before it is allowed to become a confirmed finding.

Ask yourself the kinds of questions a skeptical senior security reviewer \
would ask:
- Do we actually know who owns the affected resource, or are we assuming it?
- Could this endpoint be intentionally public?
- Does the response actually contain sensitive information, or only a \
generic/empty response that merely looks similar?
- Could caching, a stale session, or redirect behavior explain this \
instead of a real security failure?
- Is there a more mundane explanation for the observed difference?

You cannot run any tool or validation yourself. If you believe the \
evidence is close but incomplete, name EXACTLY what additional validation \
would resolve your doubt in `additional_validation_needed` — do not just \
say "more testing is needed."

Be specific and evidence-grounded. Do not invent facts not present in the \
summary you were given.
"""


class CriticDecision(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"


class CriticReview(BaseModel):
    decision: CriticDecision
    concerns: list[str] = Field(default_factory=list)
    additional_validation_needed: list[str] = Field(default_factory=list)
    confidence_adjustment: float = 0.0  # applied to the hypothesis's confidence, can be negative


class Critic:
    def __init__(self, llm: LLMProvider):
        self.llm = llm

    async def review(self, hypothesis_title: str, hypothesis_category: str,
                      evidence_summaries: list[str]) -> CriticReview:
        bounded_evidence = "\n".join(f"- {s}" for s in evidence_summaries[:15])
        prompt = (
            f"Hypothesis: {hypothesis_title}\n"
            f"Category: {hypothesis_category}\n\n"
            f"Supporting evidence summaries:\n{bounded_evidence or '(none)'}\n\n"
            "Review this and return your decision."
        )
        messages = [
            LLMMessage(role="system", content=_SYSTEM_PROMPT),
            LLMMessage(role="user", content=prompt),
        ]
        return await self.llm.structured(messages, CriticReview)
