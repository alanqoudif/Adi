"""The autonomous assessment loop.

    context = context_builder.build(workspace)
    action = planner.plan(context)
    authorization = scope_engine.authorize(action)   # inside executor.run for run_tool
    if blocked: record + replan
    result = execute(action)
    observations = deterministic_parser(result)      # inside executor.run
    workspace.apply(observations)                     # inside executor.run
    hypothesis_engine.update(...)                      # for hypothesis actions
    continue

This module only sequences the pieces built elsewhere (`ContextBuilder`,
`Planner`, `ToolExecutor`, `HypothesisEngine`, `ActionBudget`) — it does not
duplicate their logic.
"""

from __future__ import annotations

import json

from pydantic import BaseModel

from adi.actions import ActionType, PlannedAction
from adi.agent.context_builder import ContextBuilder
from adi.agent.planner import Planner
from adi.agent.reasoner import HypothesisEngine, InvalidHypothesisTransitionError
from adi.agent.scheduler import ActionBudget
from adi.knowledge.hypotheses import HypothesisStatus
from adi.knowledge.workspace import Workspace
from adi.llm.base import LLMError, MalformedResponseError
from adi.tools.executor import ScopeViolationError, ToolExecutionError, ToolExecutor

_TERMINAL_ACTION_TYPES = {ActionType.COMPLETE, ActionType.ASK_USER}


class StepOutcome(BaseModel):
    action: PlannedAction | None = None
    status: str  # completed | blocked | failed | skipped_duplicate | skipped_retry_limit | stopped | completed_assessment | paused
    detail: str = ""

    model_config = {"arbitrary_types_allowed": True}


class Orchestrator:
    def __init__(
        self,
        workspace: Workspace,
        executor: ToolExecutor,
        planner: Planner,
        context_builder: ContextBuilder,
        budget: ActionBudget | None = None,
    ):
        self.workspace = workspace
        self.executor = executor
        self.planner = planner
        self.context_builder = context_builder
        self.hypothesis_engine = HypothesisEngine(workspace)
        self.budget = budget or ActionBudget()

    async def run(self, max_iterations: int | None = None) -> list[StepOutcome]:
        outcomes: list[StepOutcome] = []
        iterations = 0
        while True:
            if max_iterations is not None and iterations >= max_iterations:
                outcomes.append(StepOutcome(status="stopped", detail="max_iterations reached"))
                break
            if self.budget.exhausted():
                outcomes.append(StepOutcome(status="stopped", detail="action budget exhausted"))
                break
            if self.budget.too_many_consecutive_failures():
                outcomes.append(
                    StepOutcome(status="stopped", detail="too many consecutive failed actions")
                )
                break

            iterations += 1
            context = self.context_builder.build(consecutive_failures=self.budget.consecutive_failures)

            try:
                action = await self.planner.plan(context)
            except MalformedResponseError as exc:
                outcomes.append(StepOutcome(status="stopped", detail=f"planner returned an invalid action: {exc}"))
                break
            except LLMError as exc:
                outcomes.append(StepOutcome(status="stopped", detail=f"LLM provider failure: {exc}"))
                break

            if action.action_type == ActionType.COMPLETE:
                outcomes.append(StepOutcome(action=action, status="completed_assessment", detail=action.reason_summary))
                break
            if action.action_type == ActionType.ASK_USER:
                outcomes.append(StepOutcome(action=action, status="paused", detail=action.reason_summary))
                break

            if self.budget.is_duplicate(action):
                outcomes.append(StepOutcome(action=action, status="skipped_duplicate",
                                             detail="identical action already completed successfully"))
                continue
            if self.budget.retry_limit_reached(action):
                outcomes.append(StepOutcome(action=action, status="skipped_retry_limit",
                                             detail="this exact action has already failed too many times"))
                continue

            self.budget.record_attempt(action)
            outcome = await self._dispatch(action)
            self.budget.record_outcome(action, succeeded=outcome.status == "completed")
            outcomes.append(outcome)

        return outcomes

    async def _dispatch(self, action: PlannedAction) -> StepOutcome:
        if action.action_type == ActionType.RUN_TOOL:
            return await self._dispatch_run_tool(action)
        if action.action_type in (ActionType.UPDATE_HYPOTHESIS, ActionType.INVESTIGATE_HYPOTHESIS):
            return self._dispatch_hypothesis(action)
        return self._dispatch_unsupported(action)

    async def _dispatch_run_tool(self, action: PlannedAction) -> StepOutcome:
        if not action.tool or not action.target:
            return StepOutcome(action=action, status="failed", detail="run_tool action missing tool/target")
        try:
            observations = await self.executor.run(
                action.tool, action.target, action.parameters,
                capability=action.capability, reason_summary=action.reason_summary,
            )
            return StepOutcome(action=action, status="completed",
                                detail=f"{len(observations)} observation(s) recorded")
        except ScopeViolationError as exc:
            return StepOutcome(action=action, status="blocked", detail=exc.reason)
        except ToolExecutionError as exc:
            return StepOutcome(action=action, status="failed", detail=str(exc))

    def _dispatch_hypothesis(self, action: PlannedAction) -> StepOutcome:
        params = action.parameters or {}
        try:
            if action.related_hypothesis_id:
                status_value = params.get("status", HypothesisStatus.INVESTIGATING.value)
                target_status = HypothesisStatus(status_value)
                hyp = self.hypothesis_engine.transition(
                    action.related_hypothesis_id, target_status,
                    confidence=params.get("confidence"),
                    new_supporting_observation_ids=params.get("supporting_observation_ids"),
                    new_contradicting_observation_ids=params.get("contradicting_observation_ids"),
                )
                detail = f"hypothesis {hyp.id} -> {hyp.status.value}"
            else:
                title = params.get("title")
                if not title:
                    return StepOutcome(action=action, status="failed",
                                        detail="hypothesis action missing 'title' to create one")
                hyp = self.hypothesis_engine.create(
                    title=title, category=params.get("category", ""),
                    confidence=params.get("confidence", 0.3),
                    validation_plan=params.get("validation_plan"),
                )
                detail = f"hypothesis {hyp.id} created: {hyp.title}"
        except (InvalidHypothesisTransitionError, ValueError) as exc:
            return StepOutcome(action=action, status="failed", detail=str(exc))

        self.workspace.record_action(
            action_type=action.action_type.value, capability=action.capability,
            tool="", target="", parameters_json=json.dumps(params),
            reason_summary=action.reason_summary, scope_allowed=True,
            scope_reason="internal action", status="completed",
        )
        return StepOutcome(action=action, status="completed", detail=detail)

    def _dispatch_unsupported(self, action: PlannedAction) -> StepOutcome:
        self.workspace.record_action(
            action_type=action.action_type.value, capability=action.capability,
            tool=action.tool or "", target=action.target or "",
            parameters_json=json.dumps(action.parameters), reason_summary=action.reason_summary,
            scope_allowed=True, scope_reason="not yet implemented in this phase",
            status="unsupported",
        )
        return StepOutcome(action=action, status="failed",
                            detail=f"action type '{action.action_type.value}' is not implemented yet")
