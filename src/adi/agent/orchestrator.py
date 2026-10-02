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
from pathlib import Path

from pydantic import BaseModel

from adi.actions import ActionType, PlannedAction
from adi.agent.context_builder import ContextBuilder
from adi.agent.planner import Planner
from adi.agent.reasoner import HypothesisEngine, InvalidHypothesisTransitionError
from adi.agent.scheduler import ActionBudget
from adi.findings.pipeline import ConfirmationInvariantError, FindingPipeline
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.hypotheses import HypothesisStatus
from adi.knowledge.workspace import Workspace
from adi.llm.base import LLMError, MalformedResponseError
from adi.tools.executor import ScopeViolationError, ToolExecutionError, ToolExecutor
from adi.validation.engine import (
    HypothesisAlreadyResolvedError,
    ValidationBudgetExhaustedError,
    ValidationEngine,
)
from adi.validation.models import ValidationAction, ValidationActionType

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
        http_workspace: HTTPWorkspace | None = None,
        validation_engine: ValidationEngine | None = None,
        finding_pipeline: FindingPipeline | None = None,
        report_directory: Path | None = None,
    ):
        self.workspace = workspace
        self.executor = executor
        self.planner = planner
        self.context_builder = context_builder
        self.hypothesis_engine = HypothesisEngine(workspace)
        self.budget = budget or ActionBudget()
        self.http_workspace = http_workspace
        self.validation_engine = validation_engine
        self.finding_pipeline = finding_pipeline
        self.report_directory = report_directory

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
                self.workspace.set_assessment_status("completed")
                outcomes.append(StepOutcome(action=action, status="completed_assessment", detail=action.reason_summary))
                break
            if action.action_type == ActionType.ASK_USER:
                self.workspace.set_assessment_status("paused")
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
        if action.action_type == ActionType.HTTP_REQUEST:
            return await self._dispatch_http_request(action)
        if action.action_type in (ActionType.UPDATE_HYPOTHESIS, ActionType.INVESTIGATE_HYPOTHESIS):
            return self._dispatch_hypothesis(action)
        if action.action_type == ActionType.VERIFY_FINDING:
            return await self._dispatch_verify_finding(action)
        if action.action_type == ActionType.GENERATE_REPORT:
            from adi.reporting.builder import ReportBuilder
            from adi.reporting.json_report import write_reports
            if self.report_directory is None:
                return StepOutcome(action=action, status="failed", detail="no report directory configured")
            paths = write_reports(ReportBuilder(self.workspace).build(), self.report_directory)
            self.workspace.record_action(
                action_type=action.action_type.value, parameters_json="{}",
                reason_summary=action.reason_summary, scope_allowed=True,
                scope_reason="internal report from persisted facts", status="completed")
            return StepOutcome(action=action, status="completed",
                               detail=", ".join(str(p) for p in paths.values()))
        return self._dispatch_unsupported(action)

    async def _dispatch_run_tool(self, action: PlannedAction) -> StepOutcome:
        if not action.target:
            return StepOutcome(action=action, status="failed", detail="run_tool action missing a target")

        tool_name = action.tool
        if not tool_name:
            # Phase 3I: capability-first selection — the planner asked for a
            # capability, not a specific binary. Resolve the best available
            # tool deterministically; the planner never needs to know or
            # care which one actually ran.
            if not action.capability:
                return StepOutcome(action=action, status="failed",
                                    detail="run_tool action has neither a tool nor a capability to resolve")
            resolved = self.executor.registry.resolve(action.capability)
            if resolved is None:
                return StepOutcome(action=action, status="failed",
                                    detail=f"no available tool provides capability '{action.capability}'")
            tool_name = resolved.metadata.name

        try:
            observations = await self.executor.run(
                tool_name, action.target, action.parameters,
                capability=action.capability, reason_summary=action.reason_summary,
            )
            return StepOutcome(action=action, status="completed",
                                detail=f"[{tool_name}] {len(observations)} observation(s) recorded")
        except ScopeViolationError as exc:
            return StepOutcome(action=action, status="blocked", detail=exc.reason)
        except ToolExecutionError as exc:
            return StepOutcome(action=action, status="failed", detail=str(exc))

    async def _dispatch_http_request(self, action: PlannedAction) -> StepOutcome:
        if self.http_workspace is None:
            return StepOutcome(action=action, status="failed",
                                detail="no HTTP workspace configured for this assessment")
        params = action.parameters or {}
        url = params.get("url") or action.target
        if not url:
            return StepOutcome(action=action, status="failed", detail="http_request action missing a url")

        if action.capability == "discover_robots_sitemap":
            # Phase 3E: a distinct, low-cost discovery capability — never
            # run unconditionally, only when the planner chooses it.
            observations = await self.http_workspace.discover_robots_and_sitemap(
                url, session_id=params.get("session_id", "anonymous"),
            )
            self.workspace.record_action(
                action_type=action.action_type.value, capability=action.capability,
                tool="", target=url, parameters_json=json.dumps(params),
                reason_summary=action.reason_summary, scope_allowed=True,
                scope_reason="within scope", status="completed",
            )
            return StepOutcome(action=action, status="completed",
                                detail=f"{len(observations)} observation(s) from robots.txt/sitemap.xml")

        method = params.get("method", "GET")
        session_id = params.get("session_id", "anonymous")

        exchange, observations = await self.http_workspace.fetch_with_exchange(
            method, url, session_id=session_id, body=params.get("body"),
            follow_redirects=params.get("follow_redirects", False),
            source="autonomous_http_request",
        )

        blocked = exchange.error is not None and "not within the authorized scope" in exchange.error
        status_text = (
            f"status {exchange.response.status}" if exchange.response else (exchange.error or "no response")
        )
        self.workspace.record_action(
            action_type=action.action_type.value, capability=action.capability,
            tool="", target=url, parameters_json=json.dumps(params),
            reason_summary=action.reason_summary,
            scope_allowed=not blocked, scope_reason=exchange.error or "within scope",
            status="blocked" if blocked else ("failed" if exchange.error else "completed"),
        )

        if blocked:
            return StepOutcome(action=action, status="blocked", detail=exchange.error)
        if exchange.error:
            return StepOutcome(action=action, status="failed", detail=exchange.error)
        return StepOutcome(action=action, status="completed",
                            detail=f"{status_text}, {len(observations)} observation(s) recorded")

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
            tool="", target=hyp.id, parameters_json=json.dumps(params),
            reason_summary=action.reason_summary, scope_allowed=True,
            scope_reason="internal action", status="completed",
        )
        return StepOutcome(action=action, status="completed", detail=detail)

    async def _dispatch_verify_finding(self, action: PlannedAction) -> StepOutcome:
        """Phase 4 section 20: the real `verify_finding` action. Two modes,
        selected by `parameters.mode`:

        - "validate" (default): execute one typed `ValidationAction` via
          the `ValidationEngine` — e.g. CHECK_OBJECT_AUTHORIZATION.
        - "finalize": run the `FindingPipeline` (verifier -> critic ->
          dedup -> severity) to turn a sufficiently-validated hypothesis
          into a Finding, or reject it.
        """
        if self.validation_engine is None or self.finding_pipeline is None:
            return StepOutcome(action=action, status="failed",
                                detail="no validation engine configured for this assessment")

        params = action.parameters or {}
        hypothesis_id = action.related_hypothesis_id or params.get("hypothesis_id")
        if not hypothesis_id:
            return StepOutcome(action=action, status="failed",
                                detail="verify_finding action missing a hypothesis_id")

        mode = params.get("mode", "validate")
        try:
            if mode == "finalize":
                result = await self.finding_pipeline.finalize(
                    hypothesis_id, category=params.get("category"),
                    affected_endpoints=params.get("affected_endpoints"),
                )
                detail = f"hypothesis -> {result.hypothesis_status.value}"
                if result.finding_id:
                    detail += f", finding {result.finding_id}"
                if result.critic_decision:
                    detail += f" (critic: {result.critic_decision.value})"
                self.workspace.record_action(
                    action_type=action.action_type.value, capability="finalize_finding",
                    tool="", target=hypothesis_id, parameters_json=json.dumps(params),
                    reason_summary=action.reason_summary, scope_allowed=True,
                    scope_reason="internal action", status="completed",
                )
                return StepOutcome(action=action, status="completed", detail=detail)

            validation_action = ValidationAction(
                action_type=ValidationActionType(params["validation_action_type"]),
                hypothesis_id=hypothesis_id, parameters=params.get("validation_parameters", {}),
                reason_summary=action.reason_summary,
            )
            result = await self.validation_engine.execute(validation_action)
            self.workspace.record_action(
                action_type=action.action_type.value, capability=validation_action.action_type.value,
                tool="", target=params.get("validation_parameters", {}).get("url", ""),
                parameters_json=json.dumps(params), reason_summary=action.reason_summary,
                scope_allowed=True, scope_reason="within scope", status="completed",
            )
            return StepOutcome(action=action, status="completed",
                                detail=f"[{result.outcome.value}] {result.detail}")
        except HypothesisAlreadyResolvedError as exc:
            return StepOutcome(action=action, status="failed", detail=str(exc))
        except (ValidationBudgetExhaustedError, ConfirmationInvariantError) as exc:
            return StepOutcome(action=action, status="failed", detail=str(exc))
        except (KeyError, ValueError) as exc:
            return StepOutcome(action=action, status="failed",
                                detail=f"malformed verify_finding action: {exc}")

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
