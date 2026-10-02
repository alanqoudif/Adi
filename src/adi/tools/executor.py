"""ToolExecutor: the only place that actually runs a security tool.

Flow: scope authorization -> argv construction via the skill's adapter ->
execution inside the configured runtime -> raw output persisted to disk ->
deterministic parsing into Observations -> stored in the Workspace.
"""

from __future__ import annotations

import json
from pathlib import Path

from adi.actions import ActionType, PlannedAction, RiskLevel
from adi.knowledge.observations import Observation, ObservationType
from adi.knowledge.workspace import Workspace
from adi.runtime.process import ExecutionResult, ExecutionRuntime
from adi.scope.engine import ScopeEngine
from adi.scope.rate_limiter import RateLimiter
from adi.tools.loader import load_adapter, load_parser
from adi.tools.registry import RegisteredTool, ToolRegistry


class ToolExecutionError(RuntimeError):
    pass


class ScopeViolationError(ToolExecutionError):
    def __init__(self, reason: str):
        super().__init__(f"blocked by scope engine: {reason}")
        self.reason = reason


class ToolExecutor:
    def __init__(
        self,
        registry: ToolRegistry,
        runtime: ExecutionRuntime,
        scope_engine: ScopeEngine,
        workspace: Workspace,
        raw_output_dir: Path,
        rate_limiter: RateLimiter | None = None,
    ):
        self.registry = registry
        self.runtime = runtime
        self.scope_engine = scope_engine
        self.workspace = workspace
        self.raw_output_dir = raw_output_dir
        self.raw_output_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limiter = rate_limiter

    async def run(self, tool_name: str, target: str, parameters: dict | None = None,
                   capability: str = "", reason_summary: str = "") -> list[Observation]:
        parameters = parameters or {}
        tool = self.registry.get(tool_name)
        if tool is None:
            raise ToolExecutionError(f"unknown tool '{tool_name}' — is its skill registered?")

        action = PlannedAction(
            action_type=ActionType.RUN_TOOL,
            capability=capability or (tool.metadata.capabilities[0] if tool.metadata.capabilities else ""),
            reason_summary=reason_summary,
            target=target,
            tool=tool_name,
            parameters=parameters,
            risk=RiskLevel(tool.metadata.risk_level) if tool.metadata.risk_level in
            ("low", "moderate", "elevated", "high") else RiskLevel.LOW,
        )
        decision = self.scope_engine.authorize(action)

        action_id = self.workspace.record_action(
            action_type=action.action_type.value,
            capability=action.capability,
            tool=tool_name,
            target=target,
            parameters_json=json.dumps(parameters),
            reason_summary=reason_summary,
            scope_allowed=decision.allowed,
            scope_reason=decision.reason,
            status="blocked" if not decision.allowed else "running",
        )

        if not decision.allowed:
            raise ScopeViolationError(decision.reason)

        if not tool.available:
            raise ToolExecutionError(
                f"tool '{tool_name}' is not installed/available on this runtime"
            )

        try:
            argv = self._build_argv(tool, target, parameters)
        except Exception as exc:
            self.workspace.update_action_result(
                action_id, exit_code=1, timed_out=False, stdout_path=None, stderr_path=None,
                status="failed",
            )
            raise ToolExecutionError(f"could not build command for '{tool_name}': {exc}") from exc

        if self.rate_limiter is not None:
            async with self.rate_limiter.concurrency_guard():
                await self.rate_limiter.acquire()
                result = await self.runtime.execute(
                    argv, timeout=tool.metadata.execution.timeout_seconds
                )
        else:
            result = await self.runtime.execute(
                argv, timeout=tool.metadata.execution.timeout_seconds
            )
        self._persist_raw(action_id, result)
        self._update_action_result(action_id, result)

        observations = self._parse(tool, result, target)
        if observations:
            self.workspace.record_observations(observations)
        return observations

    def _build_argv(self, tool: RegisteredTool, target: str, parameters: dict) -> list[str]:
        assert tool.metadata.skill_dir is not None
        adapter = load_adapter(tool.metadata.skill_dir)
        binary = tool.binary_path or tool.metadata.execution.binary or tool.metadata.name
        return adapter.build_argv(target=target, parameters=parameters, binary=binary)

    def _parse(self, tool: RegisteredTool, result: ExecutionResult, target: str) -> list[Observation]:
        assert tool.metadata.skill_dir is not None
        parser = load_parser(tool.metadata.skill_dir)
        try:
            return parser.parse(stdout=result.stdout, stderr=result.stderr,
                                 context={"target": target, "exit_code": result.exit_code})
        except Exception as exc:  # noqa: BLE001 - third-party parser boundary
            return [Observation(
                type=ObservationType.TOOL_ERROR,
                subject=target,
                value={"tool": tool.metadata.name, "error": str(exc)},
                source=tool.metadata.name,
                confidence=1.0,
            )]

    def _persist_raw(self, action_id: str, result: ExecutionResult) -> None:
        stdout_path = self.raw_output_dir / f"{action_id}.stdout.txt"
        stderr_path = self.raw_output_dir / f"{action_id}.stderr.txt"
        stdout_path.write_text(result.stdout)
        stderr_path.write_text(result.stderr)
        result.stdout_path = str(stdout_path)
        result.stderr_path = str(stderr_path)

    def _update_action_result(self, action_id: str, result: ExecutionResult) -> None:
        self.workspace.update_action_result(
            action_id,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            stdout_path=result.stdout_path,
            stderr_path=result.stderr_path,
            status="completed" if result.succeeded else "failed",
        )
