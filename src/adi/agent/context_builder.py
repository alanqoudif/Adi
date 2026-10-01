"""Builds the bounded context handed to the planner on every iteration.

Never serializes the entire assessment database into the prompt — see spec
section 49. Only a capped number of recent/important observations, active
hypotheses, recent actions, and available capabilities are included.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from adi.agent.reasoner import HypothesisEngine
from adi.knowledge.hypotheses import Hypothesis
from adi.knowledge.workspace import Workspace
from adi.scope.models import Scope
from adi.tools.registry import ToolRegistry

MAX_RECENT_OBSERVATIONS = 20
MAX_RECENT_ACTIONS = 10


class AssetSummary(BaseModel):
    address: str
    open_ports: list[int] = Field(default_factory=list)


class EndpointSummary(BaseModel):
    path: str
    methods: list[str] = Field(default_factory=list)
    requires_auth: bool = False


class SessionSummary(BaseModel):
    name: str
    authenticated: bool = False


class ActionSummary(BaseModel):
    tool: str
    target: str
    status: str
    capability: str = ""


class PlanningContext(BaseModel):
    """Everything the planner is allowed to see. Kept small and typed so it
    can be rendered into a compact prompt deterministically."""

    goal: str
    scope_name: str
    scope_mode: str
    targets: list[str]
    assets: list[AssetSummary]
    endpoints: list[EndpointSummary] = Field(default_factory=list)
    sessions: list[SessionSummary] = Field(default_factory=list)
    active_hypotheses: list[Hypothesis]
    rejected_hypothesis_titles: list[str]
    recent_actions: list[ActionSummary]
    recent_observation_summaries: list[str]
    consecutive_failures: int
    actions_used: int
    actions_remaining: int
    available_capabilities: list[str]

    def render(self) -> str:
        """A deterministic, human-readable rendering for the LLM prompt."""
        lines = [
            f"Assessment goal: {self.goal}",
            f"Scope: {self.scope_name} (mode: {self.scope_mode})",
            f"Authorized targets: {', '.join(self.targets) or 'none'}",
            f"Action budget: {self.actions_used} used, {self.actions_remaining} remaining",
        ]
        if self.consecutive_failures:
            lines.append(f"Consecutive failed actions: {self.consecutive_failures}")

        lines.append("\nKnown assets:")
        if self.assets:
            for asset in self.assets:
                ports = ", ".join(str(p) for p in asset.open_ports) or "none known"
                lines.append(f"  - {asset.address}: open ports [{ports}]")
        else:
            lines.append("  (none discovered yet)")

        if self.endpoints:
            lines.append("\nKnown web endpoints:")
            for ep in self.endpoints:
                methods = "/".join(ep.methods) or "?"
                auth = " [requires auth]" if ep.requires_auth else ""
                lines.append(f"  - {methods} {ep.path}{auth}")

        if self.sessions:
            lines.append("\nTest identities/sessions:")
            for s in self.sessions:
                state = "authenticated" if s.authenticated else "unauthenticated"
                lines.append(f"  - {s.name} ({state})")

        lines.append("\nActive hypotheses:")
        if self.active_hypotheses:
            for h in self.active_hypotheses:
                lines.append(f"  - [{h.status.value}] {h.title} (confidence {h.confidence:.2f}, id={h.id})")
        else:
            lines.append("  (none)")

        if self.rejected_hypothesis_titles:
            lines.append("\nRejected hypotheses (do not re-investigate):")
            for title in self.rejected_hypothesis_titles:
                lines.append(f"  - {title}")

        lines.append("\nRecent actions:")
        if self.recent_actions:
            for a in self.recent_actions:
                lines.append(f"  - {a.tool} -> {a.target} [{a.status}]")
        else:
            lines.append("  (none yet)")

        if self.recent_observation_summaries:
            lines.append("\nRecent observations:")
            for summary in self.recent_observation_summaries:
                lines.append(f"  - {summary}")

        lines.append(f"\nAvailable capabilities: {', '.join(self.available_capabilities) or 'none'}")
        return "\n".join(lines)


class ContextBuilder:
    def __init__(self, workspace: Workspace, scope: Scope, registry: ToolRegistry, goal: str):
        self.workspace = workspace
        self.scope = scope
        self.registry = registry
        self.goal = goal

    def build(self, *, consecutive_failures: int = 0) -> PlanningContext:
        hosts = self.workspace.list_hosts()
        services = self.workspace.list_services()
        endpoints = self.workspace.list_endpoints()
        sessions = self.workspace.list_sessions()
        actions = self.workspace.list_actions()
        hyp_engine = HypothesisEngine(self.workspace)

        assets = [
            AssetSummary(
                address=h.address,
                open_ports=sorted(s.port for s in services if s.host_id == h.id),
            )
            for h in hosts
        ]

        endpoint_summaries = [
            EndpointSummary(path=ep.path, methods=json.loads(ep.methods_json),
                             requires_auth=ep.requires_auth)
            for ep in endpoints
        ]
        session_summaries = [
            SessionSummary(name=s.name, authenticated=s.authenticated) for s in sessions
        ]

        recent_actions = [
            ActionSummary(tool=a.tool, target=a.target, status=a.status, capability=a.capability)
            for a in actions[-MAX_RECENT_ACTIONS:]
        ]

        active = hyp_engine.active()
        rejected_titles = [h.title for h in hyp_engine.rejected()]

        recent_observations = self.workspace.list_observations()[-MAX_RECENT_OBSERVATIONS:]
        observation_summaries = [
            f"[{o.type}] {o.subject}" for o in recent_observations
        ]

        capabilities = sorted(
            {cap for t in self.registry.all() if t.available for cap in t.metadata.capabilities}
        )

        return PlanningContext(
            goal=self.goal,
            scope_name=self.scope.name,
            scope_mode=self.scope.mode.value,
            targets=self.scope.targets,
            assets=assets,
            endpoints=endpoint_summaries,
            sessions=session_summaries,
            active_hypotheses=active,
            rejected_hypothesis_titles=rejected_titles,
            recent_actions=recent_actions,
            recent_observation_summaries=observation_summaries,
            consecutive_failures=consecutive_failures,
            actions_used=len(actions),
            actions_remaining=max(0, self.scope.max_actions - len(actions)),
            available_capabilities=capabilities,
        )
