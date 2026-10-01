"""HypothesisEngine: the only path that creates or transitions a Hypothesis.

Enforces the state machine in `adi.knowledge.hypotheses` so neither the
planner nor a bug elsewhere can jump a hypothesis straight from `new` to
`confirmed`, or resurrect a terminal one.
"""

from __future__ import annotations

import json

from adi.knowledge.hypotheses import Hypothesis, HypothesisStatus, InvalidHypothesisTransitionError
from adi.knowledge.workspace import Workspace


class HypothesisEngine:
    def __init__(self, workspace: Workspace):
        self.workspace = workspace

    def list(self) -> list[Hypothesis]:
        return [Hypothesis.from_record(r) for r in self.workspace.list_hypotheses()]

    def get(self, hypothesis_id: str) -> Hypothesis | None:
        for h in self.list():
            if h.id == hypothesis_id:
                return h
        return None

    def create(self, title: str, category: str = "", confidence: float = 0.3,
               validation_plan: list[str] | None = None) -> Hypothesis:
        hyp_id = self.workspace.upsert_hypothesis(
            None,
            title=title,
            category=category,
            status=HypothesisStatus.NEW.value,
            confidence=confidence,
            validation_plan_json=json.dumps(validation_plan or []),
        )
        return self.get(hyp_id)  # type: ignore[return-value]

    def transition(
        self, hypothesis_id: str, target: HypothesisStatus, *,
        confidence: float | None = None,
        new_supporting_observation_ids: list[str] | None = None,
        new_contradicting_observation_ids: list[str] | None = None,
    ) -> Hypothesis:
        current = self.get(hypothesis_id)
        if current is None:
            raise ValueError(f"no hypothesis '{hypothesis_id}'")
        updated = current.transition(target)  # raises InvalidHypothesisTransitionError

        supporting = list(current.supporting_observation_ids)
        for obs_id in new_supporting_observation_ids or []:
            if obs_id not in supporting:
                supporting.append(obs_id)
        contradicting = list(current.contradicting_observation_ids)
        for obs_id in new_contradicting_observation_ids or []:
            if obs_id not in contradicting:
                contradicting.append(obs_id)

        self.workspace.upsert_hypothesis(
            hypothesis_id,
            status=updated.status.value,
            confidence=confidence if confidence is not None else current.confidence,
            supporting_observation_ids_json=json.dumps(supporting),
            contradicting_observation_ids_json=json.dumps(contradicting),
        )
        return self.get(hypothesis_id)  # type: ignore[return-value]

    def rejected(self) -> list[Hypothesis]:
        return [h for h in self.list() if h.status == HypothesisStatus.REJECTED]

    def active(self) -> list[Hypothesis]:
        inactive = {HypothesisStatus.REJECTED, HypothesisStatus.DUPLICATE, HypothesisStatus.CONFIRMED}
        return [h for h in self.list() if h.status not in inactive]


__all__ = ["HypothesisEngine", "InvalidHypothesisTransitionError"]
