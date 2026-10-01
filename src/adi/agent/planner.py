"""The planner: turns a `PlanningContext` into one typed `PlannedAction`.

The LLM is never asked for a shell command — it is asked to fill in the
`PlannedAction` schema, with required `reason_summary` and
`expected_information_gain` fields so every action is explainable after the
fact (spec section 67) without exposing hidden chain-of-thought.
"""

from __future__ import annotations

from adi.actions import PlannedAction
from adi.agent.context_builder import PlanningContext
from adi.llm.base import LLMMessage, LLMProvider

_SYSTEM_PROMPT = """\
You are the planning component of Adi, an autonomous security assessment \
agent operating ONLY within an explicitly authorized scope. You never \
propose actions against hosts outside the authorized targets.

You think in capabilities, not tool names (e.g. "enumerate_services" \
rather than "nmap") — a separate component resolves the capability to an \
available tool.

For every action you propose, you must give a concise `reason_summary` \
(why this action, given current state) and `expected_information_gain` \
(what uncertainty it reduces). These are shown to the human operator, so \
they must be genuine and specific, not generic filler.

If the discovered attack surface has been reasonably explored and no \
further high-value action remains, propose action_type="complete".
If you need the human operator to make a decision, propose action_type="ask_user".
Never repeat an action identical to one in the recent-actions list that \
already completed — that wastes the action budget.
"""


class Planner:
    def __init__(self, llm: LLMProvider):
        self.llm = llm

    async def plan(self, context: PlanningContext) -> PlannedAction:
        messages = [
            LLMMessage(role="system", content=_SYSTEM_PROMPT),
            LLMMessage(role="user", content=context.render()),
        ]
        # A MalformedResponseError propagates to the orchestrator, which
        # decides whether to pause the assessment — the planner itself
        # never fabricates a fallback action.
        return await self.llm.structured(messages, PlannedAction)
