"""Validation budgets and stop conditions (spec Phase 4 sections 42–43).

Each hypothesis gets its own validation budget so one speculative
hypothesis can never consume the whole assessment's action budget, and
validation stops the instant a hypothesis reaches a terminal state —
continuing to collect evidence after proof is already established wastes
budget and risks unnecessary impact.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from adi.knowledge.hypotheses import HypothesisStatus, is_terminal

DEFAULT_MAX_VALIDATION_ACTIONS_PER_HYPOTHESIS = 8


@dataclass
class ValidationBudget:
    max_actions_per_hypothesis: int = DEFAULT_MAX_VALIDATION_ACTIONS_PER_HYPOTHESIS
    _counts: dict[str, int] = field(default_factory=dict)

    def used(self, hypothesis_id: str) -> int:
        return self._counts.get(hypothesis_id, 0)

    def exhausted(self, hypothesis_id: str) -> bool:
        return self.used(hypothesis_id) >= self.max_actions_per_hypothesis

    def record(self, hypothesis_id: str) -> None:
        self._counts[hypothesis_id] = self.used(hypothesis_id) + 1


def should_stop_validating(status: HypothesisStatus) -> bool:
    """Once a hypothesis reaches a terminal state, further validation is
    wasted effort (and, for CONFIRMED, unnecessary additional impact)."""
    return is_terminal(status)
