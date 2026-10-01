"""Explicit hypothesis model and state machine.

A scanner alert or a suspicious observation becomes a `Hypothesis`, never
directly a `Finding` — see docs/agent-loop.md. The planner can target an
action specifically at investigating one (`related_hypothesis_id` on
`PlannedAction`).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from adi.knowledge.db import HypothesisRecord


class HypothesisStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    SUPPORTED = "supported"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    DUPLICATE = "duplicate"


# Valid status transitions. A hypothesis can also be left in place (no-op),
# which is not modeled here since that is not a transition.
_VALID_TRANSITIONS: dict[HypothesisStatus, set[HypothesisStatus]] = {
    HypothesisStatus.NEW: {
        HypothesisStatus.INVESTIGATING,
        HypothesisStatus.REJECTED,
        HypothesisStatus.DUPLICATE,
        HypothesisStatus.BLOCKED,
    },
    HypothesisStatus.INVESTIGATING: {
        HypothesisStatus.SUPPORTED,
        HypothesisStatus.CONFIRMED,
        HypothesisStatus.REJECTED,
        HypothesisStatus.BLOCKED,
        HypothesisStatus.DUPLICATE,
    },
    HypothesisStatus.SUPPORTED: {
        HypothesisStatus.CONFIRMED,
        HypothesisStatus.REJECTED,
        HypothesisStatus.INVESTIGATING,
        HypothesisStatus.BLOCKED,
    },
    HypothesisStatus.BLOCKED: {
        HypothesisStatus.INVESTIGATING,
        HypothesisStatus.REJECTED,
    },
    # Terminal states: no further transitions.
    HypothesisStatus.CONFIRMED: set(),
    HypothesisStatus.REJECTED: set(),
    HypothesisStatus.DUPLICATE: set(),
}


class InvalidHypothesisTransitionError(ValueError):
    def __init__(self, current: HypothesisStatus, target: HypothesisStatus):
        super().__init__(f"cannot transition hypothesis from {current.value} to {target.value}")
        self.current = current
        self.target = target


class Hypothesis(BaseModel):
    id: str | None = None
    title: str
    category: str = ""
    status: HypothesisStatus = HypothesisStatus.NEW
    confidence: float = 0.3
    supporting_observation_ids: list[str] = Field(default_factory=list)
    contradicting_observation_ids: list[str] = Field(default_factory=list)
    validation_plan: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @classmethod
    def from_record(cls, record: HypothesisRecord) -> Hypothesis:
        import json

        return cls(
            id=record.id,
            title=record.title,
            category=record.category,
            status=HypothesisStatus(record.status),
            confidence=record.confidence,
            supporting_observation_ids=json.loads(record.supporting_observation_ids_json),
            contradicting_observation_ids=json.loads(record.contradicting_observation_ids_json),
            validation_plan=json.loads(record.validation_plan_json),
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    def can_transition_to(self, target: HypothesisStatus) -> bool:
        if target == self.status:
            return True
        return target in _VALID_TRANSITIONS.get(self.status, set())

    def transition(self, target: HypothesisStatus) -> Hypothesis:
        if not self.can_transition_to(target):
            raise InvalidHypothesisTransitionError(self.status, target)
        return self.model_copy(update={"status": target})


def is_terminal(status: HypothesisStatus) -> bool:
    return not _VALID_TRANSITIONS.get(status)
