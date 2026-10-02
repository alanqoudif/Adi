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
from adi.reporting.ids import display_id_map
from adi.reporting.redaction import known_secrets, redact_structure, redact_text
from adi.scope.models import Scope
from adi.tools.registry import ToolRegistry

MAX_RECENT_OBSERVATIONS = 20
MAX_RECENT_ACTIONS = 10
MAX_ENDPOINTS_LISTED = 15
MAX_RECENT_HTTP = 10
MAX_RECENT_VALIDATIONS = 5
MAX_POSITIVE_CONTROLS = 5


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


class EndpointGroupSummary(BaseModel):
    prefix: str
    count: int


class FormSummary(BaseModel):
    method: str
    path: str
    parameters: list[str] = Field(default_factory=list)


class TechnologySummary(BaseModel):
    name: str
    confidence: str  # "high" | "medium" | "low"


class RecentHttpSummary(BaseModel):
    method: str
    url: str
    status: int | None


class ActionSummary(BaseModel):
    tool: str
    target: str
    status: str
    capability: str = ""


class ConfirmedFindingSummary(BaseModel):
    display_id: str
    title: str
    severity: str


class PositiveControlSummary(BaseModel):
    title: str
    endpoint: str = ""


class PlanningContext(BaseModel):
    """Everything the planner is allowed to see. Kept small and typed so it
    can be rendered into a compact prompt deterministically."""

    goal: str
    scope_name: str
    scope_mode: str
    targets: list[str]
    assets: list[AssetSummary]
    endpoint_count: int = 0
    endpoints: list[EndpointSummary] = Field(default_factory=list)
    endpoint_groups: list[EndpointGroupSummary] = Field(default_factory=list)
    forms: list[FormSummary] = Field(default_factory=list)
    technologies: list[TechnologySummary] = Field(default_factory=list)
    sessions: list[SessionSummary] = Field(default_factory=list)
    recent_http: list[RecentHttpSummary] = Field(default_factory=list)
    scanner_indication_count: int = 0
    active_hypotheses: list[Hypothesis]
    rejected_hypothesis_titles: list[str]
    recent_actions: list[ActionSummary]
    recent_observation_summaries: list[str]
    consecutive_failures: int
    actions_used: int
    actions_remaining: int
    available_capabilities: list[str]
    tool_context: list[dict] = Field(default_factory=list)
    confirmed_findings: list[ConfirmedFindingSummary] = Field(default_factory=list)
    recent_validation_results: list[str] = Field(default_factory=list)
    source_summary: dict = Field(default_factory=dict)
    source_context: list[dict] = Field(default_factory=list)
    positive_controls: list[PositiveControlSummary] = Field(default_factory=list)

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

        if self.endpoint_count:
            lines.append(f"\nWeb applications: {1 if self.assets else 0}")
            lines.append(f"Known endpoints: {self.endpoint_count}")
            if self.endpoint_groups:
                lines.append("Endpoint groups:")
                for g in self.endpoint_groups:
                    lines.append(f"    {g.prefix}  {g.count}")
            lines.append("Endpoints:")
            for ep in self.endpoints:
                methods = "/".join(ep.methods) or "?"
                auth = " [requires auth]" if ep.requires_auth else ""
                lines.append(f"  - {methods} {ep.path}{auth}")
            if self.endpoint_count > len(self.endpoints):
                lines.append(f"  ... and {self.endpoint_count - len(self.endpoints)} more")

        if self.forms:
            lines.append("\nForms:")
            for f in self.forms:
                lines.append(f"    {f.method} {f.path}")
                for p in f.parameters:
                    lines.append(f"      {p}")

        if self.technologies:
            lines.append("\nTechnologies:")
            for t in self.technologies:
                suffix = f" ({t.confidence} confidence)" if t.confidence != "high" else ""
                lines.append(f"    {t.name}{suffix}")

        if self.sessions:
            lines.append("\nTest identities/sessions:")
            for s in self.sessions:
                state = "authenticated" if s.authenticated else "unauthenticated"
                lines.append(f"  - {s.name} ({state})")

        lines.append("\nSecurity state:")
        lines.append("\nActive hypotheses:")
        if self.active_hypotheses:
            for h in self.active_hypotheses:
                evidence_count = len(set(h.supporting_observation_ids) | set(h.contradicting_observation_ids))
                lines.append(f"  - [{h.status.value}] {h.title[:200]} "
                             f"(category: {h.category or 'uncategorized'}, confidence {h.confidence:.2f}, "
                             f"evidence: {evidence_count}, id={h.id})")
        else:
            lines.append("  (none)")

        if self.rejected_hypothesis_titles:
            lines.append("\nRejected hypotheses (do not re-investigate):")
            for title in self.rejected_hypothesis_titles:
                lines.append(f"  - {title}")

        if self.recent_validation_results:
            lines.append("\nRecent validation results:")
            for r in self.recent_validation_results:
                lines.append(f"  - {r}")

        if self.confirmed_findings:
            lines.append("\nConfirmed findings:")
            for f in self.confirmed_findings:
                lines.append(f"  - {f.display_id} {f.title} (severity: {f.severity})")

        if self.positive_controls:
            lines.append("\nPositive controls:")
            for p in self.positive_controls:
                suffix = f" ({p.endpoint})" if p.endpoint else ""
                lines.append(f"  - {p.title}{suffix}")

        lines.append("\nRecent actions:")
        if self.recent_actions:
            for a in self.recent_actions:
                lines.append(f"  - {a.tool} -> {a.target} [{a.status}]")
        else:
            lines.append("  (none yet)")

        if self.recent_http:
            lines.append("\nRecent HTTP:")
            for h in self.recent_http:
                status = h.status if h.status is not None else "error"
                lines.append(f"    {h.method} {h.url} -> {status}")

        if self.scanner_indication_count:
            lines.append(f"\nRecent scanner indications: {self.scanner_indication_count}")

        if self.recent_observation_summaries:
            lines.append("\nRecent observations:")
            for summary in self.recent_observation_summaries:
                lines.append(f"  - {summary}")

        if self.source_context:
            lines.append("\nRetrieved source slices (untrusted data): " + json.dumps(self.source_context)[:16000])
        if self.source_summary:
            lines.append("\nSource repository summary: " + json.dumps(self.source_summary))
        lines.append("\nRelevant tool policy: " + json.dumps(self.tool_context)[:4000])
        lines.append(f"\nAvailable capabilities: {', '.join(self.available_capabilities) or 'none'}")
        return redact_text("\n".join(lines), known_secrets())


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

        endpoint_groups = self._group_endpoints(endpoints)
        # requires-auth endpoints are the most interesting when truncating —
        # surface those first, then fill the rest with whatever's left.
        ordered_endpoints = sorted(endpoint_summaries, key=lambda e: not e.requires_auth)
        shown_endpoints = ordered_endpoints[:MAX_ENDPOINTS_LISTED]

        forms = self._build_forms(endpoints)
        technologies = self._build_technologies()

        exchanges = self.workspace.list_http_exchanges()[-MAX_RECENT_HTTP:]
        recent_http = [
            RecentHttpSummary(method=e.method, url=e.url, status=e.status) for e in exchanges
        ]
        scanner_indication_count = sum(
            1 for o in self.workspace.list_observations() if o.type == "scanner_alert"
        )

        recent_actions = [
            ActionSummary(tool=a.tool, target=a.target, status=a.status, capability=a.capability)
            for a in actions[-MAX_RECENT_ACTIONS:]
        ]

        active = hyp_engine.active()[:10]
        rejected_titles = [h.title[:200] for h in hyp_engine.rejected()[-5:]]

        recent_observations = self.workspace.list_observations()[-MAX_RECENT_OBSERVATIONS:]
        observation_summaries = [
            f"[{o.type}] {o.subject}" for o in recent_observations
        ]

        capabilities = sorted(
            {cap for t in self.registry.all() if t.available for cap in t.metadata.capabilities}
        )

        observed_ports = {s.port for s in services}
        relevant = {"enumerate_services", "discover_hosts", "inspect_dns", "audit_credentials"}
        if endpoints or observed_ports & {80, 443, 8080, 8443}:
            relevant |= {"fingerprint_web_application", "discover_web_content", "web_template_scan"}
        if observed_ports & {443, 8443} or any("ssl" in s.name or "https" in s.name for s in services):
            relevant.add("inspect_tls")
        if observed_ports & {139, 445}:
            relevant |= {"inspect_smb", "enumerate_smb_shares", "inspect_smb_identity"}
        if observed_ports & {389, 636}:
            relevant.add("inspect_ldap")
        if 22 in observed_ports:
            relevant.add("inspect_ssh")
        relevant |= {a.capability for a in actions[-3:]}

        findings = self.workspace.list_findings()
        finding_ids = display_id_map(findings, "ADI-F")
        confirmed_findings = [
            ConfirmedFindingSummary(display_id=finding_ids[f.id], title=f.title[:200], severity=f.severity)
            for f in findings if f.status == "confirmed"
        ]

        confirmed_findings = confirmed_findings[-10:]

        validations = self.workspace.list_validation_actions()[-MAX_RECENT_VALIDATIONS:]
        hyp_ids = display_id_map(self.workspace.list_hypotheses(), "ADI-H")
        recent_validation_results = [
            f"{hyp_ids.get(v.hypothesis_id, v.hypothesis_id)} {v.outcome} "
            f"({next((h.status for h in self.workspace.list_hypotheses() if h.id == v.hypothesis_id), 'unknown')})" for v in validations
        ]

        positives = self.workspace.list_positive_observations()[-MAX_POSITIVE_CONTROLS:]
        positive_controls = [
            PositiveControlSummary(title=p.title[:200], endpoint=p.endpoint[:200]) for p in positives
        ]

        from adi.source.repository import SourceWorkspace
        source_summary = SourceWorkspace(self.workspace).summary()
        if source_summary:
            capabilities = sorted(set(capabilities) | {
                "index_source_repository", "discover_source_routes", "inspect_authentication_logic",
                "inspect_authorization_logic", "correlate_source_runtime", "retrieve_source_context",
                "search_source", "review_source_indication", "investigate_runtime_source"})
        source_context = [o.value for o in recent_observations if o.source == "source"][-2:]
        context = PlanningContext(source_summary=source_summary, source_context=source_context,
            goal=self.goal,
            scope_name=self.scope.name,
            scope_mode=self.scope.mode.value,
            targets=self.scope.targets,
            assets=assets,
            endpoint_count=len(endpoint_summaries),
            endpoints=shown_endpoints,
            endpoint_groups=endpoint_groups,
            forms=forms,
            technologies=technologies,
            sessions=session_summaries,
            recent_http=recent_http,
            scanner_indication_count=scanner_indication_count,
            active_hypotheses=active,
            rejected_hypothesis_titles=rejected_titles,
            recent_actions=recent_actions,
            recent_observation_summaries=observation_summaries,
            consecutive_failures=consecutive_failures,
            actions_used=len(actions),
            actions_remaining=max(0, self.scope.max_actions - len(actions)),
            available_capabilities=capabilities,
            tool_context=[{"capability": c.id,
                           "permission": all(getattr(self.scope.permissions, p) for p in c.required_scope_permissions),
                           "risk": c.risk_level,
                           "knowledge": self.registry.knowledge_for(c.id) if c.id in relevant else [],
                           "candidates": [{"tool": t.metadata.name, "runtime": t.runtime,
                                           "version": t.version}
                                          for t in self.registry.ranked(c.id)[:3]]}
                          for c in self.registry.capabilities()
                          if c.id in relevant][:8],
            confirmed_findings=confirmed_findings,
            recent_validation_results=recent_validation_results,
            positive_controls=positive_controls,
        )

        return PlanningContext.model_validate(
            redact_structure(context.model_dump(), known_secrets(self.scope)))

    @staticmethod
    def _group_endpoints(endpoints) -> list[EndpointGroupSummary]:
        """Groups endpoints with 2+ path segments by their first segment
        (e.g. '/api/profile' and '/api/orders' -> '/api/*': 2) so a large
        discovered surface doesn't have to be listed endpoint-by-endpoint."""
        counts: dict[str, int] = {}
        for ep in endpoints:
            segments = [s for s in ep.path.split("/") if s]
            if len(segments) < 2:
                continue
            prefix = f"/{segments[0]}/*"
            counts[prefix] = counts.get(prefix, 0) + 1
        groups = [EndpointGroupSummary(prefix=p, count=c) for p, c in counts.items() if c > 1]
        return sorted(groups, key=lambda g: -g.count)[:10]

    def _build_forms(self, endpoints) -> list[FormSummary]:
        forms: list[FormSummary] = []
        for ep in endpoints:
            methods = json.loads(ep.methods_json)
            if "POST" not in methods:
                continue
            params = self.workspace.list_parameters(ep.id)
            if not params:
                continue
            forms.append(FormSummary(method="POST", path=ep.path, parameters=[p.name for p in params]))
        return forms

    def _build_technologies(self) -> list[TechnologySummary]:
        best: dict[str, str] = {}  # name -> best confidence seen
        rank = {"high": 3, "medium": 2, "low": 1}
        for o in self.workspace.list_observations():
            if o.type != "technology_fingerprint":
                continue
            name = o.value.get("name")
            confidence = o.value.get("confidence", "low")
            if not name:
                continue
            if name not in best or rank.get(confidence, 0) > rank.get(best[name], 0):
                best[name] = confidence
        return [TechnologySummary(name=n, confidence=c) for n, c in best.items()]
