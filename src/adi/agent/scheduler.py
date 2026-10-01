"""Loop prevention: fingerprints every attempted action and enforces the
budgets that keep an autonomous assessment from running forever or hammering
the same failing action.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from adi.actions import PlannedAction


def fingerprint(action: PlannedAction) -> str:
    """A stable fingerprint for an action: same tool + target + parameters
    is the same action, regardless of reasoning text attached to it."""
    payload = {
        "action_type": action.action_type.value,
        "tool": action.tool,
        "target": action.target,
        "capability": action.capability,
        "parameters": action.parameters,
    }
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


@dataclass
class ActionBudget:
    max_actions: int = 150
    max_consecutive_failures: int = 5
    max_retries_per_action: int = 2

    actions_taken: int = 0
    consecutive_failures: int = 0
    _attempt_counts: dict[str, int] = field(default_factory=dict)
    _completed_fingerprints: set[str] = field(default_factory=set)

    def exhausted(self) -> bool:
        return self.actions_taken >= self.max_actions

    def too_many_consecutive_failures(self) -> bool:
        return self.consecutive_failures >= self.max_consecutive_failures

    def is_duplicate(self, action: PlannedAction) -> bool:
        """True if this exact action already completed successfully — it
        would add no new information."""
        return fingerprint(action) in self._completed_fingerprints

    def retry_limit_reached(self, action: PlannedAction) -> bool:
        return self._attempt_counts.get(fingerprint(action), 0) >= self.max_retries_per_action

    def record_attempt(self, action: PlannedAction) -> None:
        fp = fingerprint(action)
        self._attempt_counts[fp] = self._attempt_counts.get(fp, 0) + 1
        self.actions_taken += 1

    def record_outcome(self, action: PlannedAction, *, succeeded: bool) -> None:
        if succeeded:
            self.consecutive_failures = 0
            self._completed_fingerprints.add(fingerprint(action))
        else:
            self.consecutive_failures += 1
