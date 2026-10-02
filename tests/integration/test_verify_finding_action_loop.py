"""Proves `ActionType.VERIFY_FINDING` actually drives validation and finding
finalization through the real `Orchestrator` loop — not just through the
`ValidationEngine`/`FindingPipeline` directly (see test_phase4_mandatory_validation.py
for those). The planner (MockLLM) only ever chooses actions; everything
downstream (scope, HTTP, evidence, verifier, dedup) is production code.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures" / "webapp"))
from app import DemoApp

from adi.actions import ActionType, PlannedAction
from adi.agent.context_builder import ContextBuilder
from adi.agent.critic import Critic, CriticDecision, CriticReview
from adi.agent.orchestrator import Orchestrator
from adi.agent.planner import Planner
from adi.agent.reasoner import HypothesisEngine
from adi.agent.scheduler import ActionBudget
from adi.evidence.store import EvidenceStore
from adi.findings.pipeline import FindingPipeline
from adi.http.client import HTTPClient
from adi.http.sessions import SessionJarRegistry
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.hypotheses import HypothesisStatus
from adi.knowledge.workspace import Workspace
from adi.llm.mock import MockLLM
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.tools.executor import ToolExecutor
from adi.tools.registry import ToolRegistry
from adi.validation.context import ValidationContext
from adi.validation.engine import ValidationEngine

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"


@pytest.fixture()
def demo_app():
    app = DemoApp().start()
    yield app
    app.stop()


def _action(**kwargs) -> PlannedAction:
    defaults = {"action_type": ActionType.VERIFY_FINDING, "reason_summary": "r", "expected_information_gain": "g"}
    defaults.update(kwargs)
    return PlannedAction(**defaults)


@pytest.mark.asyncio
async def test_verify_finding_action_validates_and_confirms_through_the_orchestrator(tmp_path, demo_app):
    scope = Scope(name="verify-finding-loop", targets=["127.0.0.1"], max_actions=10)
    workspace = Workspace.create(tmp_path / "state.db", scope)
    scope_engine = ScopeEngine(scope)
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()

    from adi.runtime.mock import MockRuntime
    tool_executor = ToolExecutor(registry, MockRuntime(), scope_engine, workspace, tmp_path / "raw")
    http_client = HTTPClient(scope_engine, SessionJarRegistry())
    http_ws = HTTPWorkspace(http_client, workspace, tmp_path / "evidence")

    # log user_a and user_b in before the orchestrator loop starts, exactly
    # as a prior autonomous step would have done
    await http_ws.fetch("POST", demo_app.base_url + "/api/login", session_id="user_a", body="username=user_a")
    await http_ws.fetch("POST", demo_app.base_url + "/api/login", session_id="user_b", body="username=user_b")

    hyp_engine = HypothesisEngine(workspace)
    hyp = hyp_engine.create(
        title="possible broken object authorization on /api/orders-broken/1",
        category="broken_object_authorization",
    )

    evidence_store = EvidenceStore(workspace)
    validation_engine = ValidationEngine(ValidationContext(http_ws, evidence_store, workspace))
    critic_llm = MockLLM()
    critic_llm.script_structured(CriticReview(decision=CriticDecision.ACCEPT, concerns=[]))
    finding_pipeline = FindingPipeline(workspace, evidence_store, critic=Critic(critic_llm))

    context_builder = ContextBuilder(workspace, scope, registry, goal=scope.goal)
    llm = MockLLM()
    llm.script_structured(
        _action(
            related_hypothesis_id=hyp.id,
            parameters={
                "mode": "validate", "validation_action_type": "check_object_authorization",
                "validation_parameters": {
                    "url": demo_app.base_url + "/api/orders-broken/1",
                    "owner_session": "user_a", "other_session": "user_b",
                },
            },
        ),
        _action(
            related_hypothesis_id=hyp.id,
            parameters={"mode": "finalize", "category": "broken_object_authorization",
                        "affected_endpoints": ["/api/orders-broken/1"]},
        ),
        PlannedAction(action_type=ActionType.COMPLETE, reason_summary="done", expected_information_gain="none"),
    )
    planner = Planner(llm)
    orchestrator = Orchestrator(
        workspace, tool_executor, planner, context_builder, ActionBudget(max_actions=10),
        http_workspace=http_ws, validation_engine=validation_engine, finding_pipeline=finding_pipeline,
    )

    outcomes = await orchestrator.run()

    assert outcomes[0].status == "completed"
    assert "supports" in outcomes[0].detail
    assert outcomes[1].status == "completed"
    assert "confirmed" in outcomes[1].detail
    assert outcomes[2].status == "completed_assessment"

    findings = workspace.list_findings()
    assert len(findings) == 1
    assert findings[0].status == "confirmed"
    assert findings[0].severity == "high"

    final_hyp = hyp_engine.get(hyp.id)
    assert final_hyp.status == HypothesisStatus.CONFIRMED

    # the planner's own action log shows both validation steps, auditable
    actions = workspace.list_actions()
    verify_actions = [a for a in actions if a.action_type == "verify_finding"]
    assert len(verify_actions) == 2
