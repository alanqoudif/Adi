"""Expert command/capability console.

This is the *reviewed* manual-execution path for the human operator —
distinct from the autonomous `ProductController._drive` loop, but it goes
through exactly the same Core choke points:

    operator request
      -> ToolRegistry (resolve capability -> ranked tools) / direct tool
      -> sanitized preview (no secrets, no raw shell string)
      -> ScopeEngine.authorize (via ToolExecutor.run/run_capability)
      -> reviewed adapter -> argv -> Runtime
      -> deterministic parser -> Evidence/Observations

There is no separate "expert execution" code path in Core: `preview()`
only *describes* what `ToolExecutor.run_capability`/`run` would do, and
`execute()` calls those same methods. A `ScopeViolationError` from Core is
surfaced as-is — this module never retries past a scope decision except
for the one Core-supported elevated-approval mechanism
(`Scope.approval_mode` + `Scope.approved_elevated_actions`), and even then
only after the operator explicitly confirms, and the grant is revoked
again immediately after use ("approve once").
"""

from __future__ import annotations

from dataclasses import dataclass

from adi.actions import ActionType, PlannedAction, RiskLevel
from adi.assessment import Assessment
from adi.reporting.redaction import known_secrets, redact_text
from adi.tools.executor import ScopeViolationError, ToolExecutionError


@dataclass
class CommandPreview:
    capability: str
    target: str
    parameters: dict
    candidate_tools: list[str]
    runtime: str
    risk: str
    rate_limit_rps: float
    concurrent_tools: int
    requires_approval: bool
    scope_reason: str

    def render_lines(self) -> list[str]:
        lines = [
            f"Capability:   {self.capability}",
            f"Target:       {self.target}",
            f"Candidates:   {', '.join(self.candidate_tools) or '(none available)'}",
            f"Runtime:      {self.runtime}",
            f"Risk:         {self.risk}",
            f"Rate:         {self.rate_limit_rps}/s, {self.concurrent_tools} concurrent",
        ]
        if self.parameters:
            lines.append(f"Parameters:   {self.parameters}")
        if self.requires_approval:
            lines.append("Approval:     REQUIRED before execution")
        lines.append(f"Scope check:  {self.scope_reason}")
        return lines


@dataclass
class CommandResult:
    ok: bool
    detail: str
    observation_count: int = 0


class ExpertConsole:
    def __init__(self, assessment: Assessment):
        self.assessment = assessment

    def _secrets(self) -> tuple[str, ...]:
        return known_secrets(self.assessment.workspace.load_scope())

    def _sanitize(self, text: str) -> str:
        return redact_text(text, self._secrets())

    # -- browsing -----------------------------------------------------------

    def list_tools(self) -> list[dict]:
        out = []
        for tool in sorted(self.assessment.registry.all(), key=lambda t: t.metadata.name):
            out.append({
                "name": tool.metadata.name,
                "available": tool.available,
                "runtime": tool.runtime,
                "risk": tool.metadata.risk_level,
                "trust": tool.metadata.trust_level.value,
                "capabilities": list(tool.metadata.capabilities),
            })
        return out

    def describe_tool(self, name: str) -> dict | None:
        tool = self.assessment.registry.get(name)
        if tool is None:
            return None
        meta = tool.metadata
        return {
            "name": meta.name,
            "capabilities": list(meta.capabilities),
            "categories": list(meta.category),
            "risk": meta.risk_level,
            "trust": meta.trust_level.value,
            "runtime": tool.runtime,
            "available": tool.available,
            "version": tool.version if tool.available else None,
            "timeout_seconds": meta.execution.timeout_seconds,
        }

    def list_capabilities(self) -> list[dict]:
        scope = self.assessment.workspace.load_scope()
        out = []
        for cap in self.assessment.registry.capabilities():
            allowed = all(getattr(scope.permissions, p) for p in cap.required_scope_permissions)
            providers = self.assessment.registry.by_capability(cap.id)
            out.append({
                "id": cap.id,
                "risk": cap.risk_level,
                "permission": allowed,
                "available_tools": [p.metadata.name for p in providers if p.available],
                "blocked_tools": [p.metadata.name for p in providers if not p.available],
            })
        return out

    def describe_capability(self, name: str) -> dict | None:
        match = next((c for c in self.assessment.registry.capabilities() if c.id == name), None)
        if match is None:
            return None
        scope = self.assessment.workspace.load_scope()
        allowed = all(getattr(scope.permissions, p) for p in match.required_scope_permissions)
        ranked = self.assessment.registry.ranked(name)
        return {
            "id": match.id,
            "risk": match.risk_level,
            "current_scope_permission": allowed,
            "fallback_order": [t.metadata.name for t in ranked],
        }

    # -- preview / execution --------------------------------------------

    def preview(self, capability: str, target: str, parameters: dict | None = None) -> CommandPreview:
        parameters = parameters or {}
        ranked = self.assessment.registry.ranked(capability)
        candidate_tools = [t.metadata.name for t in ranked]
        risk = ranked[0].metadata.risk_level if ranked else "unknown"
        action = PlannedAction(
            action_type=ActionType.RUN_TOOL, capability=capability, target=target,
            parameters=parameters, risk=RiskLevel(risk) if risk in RiskLevel._value2member_map_ else RiskLevel.LOW,
            reason_summary="operator expert-console request",
        )
        decision = self.assessment.scope_engine.authorize(action)
        scope = self.assessment.workspace.load_scope()
        return CommandPreview(
            capability=capability, target=target, parameters=self._sanitize_params(parameters),
            candidate_tools=candidate_tools,
            runtime=ranked[0].runtime if ranked else "unknown",
            risk=risk,
            rate_limit_rps=scope.rate_limits.requests_per_second,
            concurrent_tools=scope.rate_limits.concurrent_tools,
            requires_approval=(not decision.allowed and "approval" in decision.reason),
            scope_reason=decision.reason,
        )

    def _sanitize_params(self, parameters: dict) -> dict:
        return {k: (self._sanitize(str(v)) if isinstance(v, str) else v) for k, v in parameters.items()}

    async def execute(
        self, capability: str, target: str, parameters: dict | None = None,
        *, grant_elevated_approval: bool = False,
    ) -> CommandResult:
        parameters = parameters or {}
        approval_key = f"{capability}:{target}"
        granted_here = False
        try:
            if grant_elevated_approval:
                scope = self.assessment.workspace.load_scope()
                if approval_key not in scope.approved_elevated_actions:
                    scope = scope.model_copy(update={
                        "approval_mode": True,
                        "approved_elevated_actions": [*scope.approved_elevated_actions, approval_key],
                    })
                    self.assessment.workspace.update_scope(scope)
                    granted_here = True
            observations = await self.assessment.executor.run_capability(
                capability, target, parameters, reason_summary="operator expert-console execution",
            )
            return CommandResult(ok=True, detail=f"{len(observations)} observation(s) recorded",
                                  observation_count=len(observations))
        except ScopeViolationError as exc:
            return CommandResult(ok=False, detail=self._sanitize(str(exc)))
        except ToolExecutionError as exc:
            return CommandResult(ok=False, detail=self._sanitize(str(exc)))
        finally:
            if granted_here:
                # "approve once": revoke the grant immediately after use.
                scope = self.assessment.workspace.load_scope()
                scope = scope.model_copy(update={
                    "approved_elevated_actions": [
                        k for k in scope.approved_elevated_actions if k != approval_key
                    ],
                })
                self.assessment.workspace.update_scope(scope)
