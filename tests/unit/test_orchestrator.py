from pathlib import Path

import pytest

from adi.actions import ActionType, PlannedAction
from adi.agent.context_builder import ContextBuilder
from adi.agent.orchestrator import Orchestrator
from adi.agent.planner import Planner
from adi.agent.scheduler import ActionBudget
from adi.knowledge.workspace import Workspace
from adi.llm.base import LLMError, MalformedResponseError
from adi.llm.mock import MockLLM
from adi.runtime.mock import MockRuntime
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.tools.executor import ToolExecutor
from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"
NMAP_XML_FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "nmap" / "scan.xml"
).read_text()


def make_action(**overrides) -> PlannedAction:
    defaults = {"action_type": ActionType.RUN_TOOL, "tool": "nmap", "target": "lab.local",
                     "capability": "enumerate_services", "parameters": {},
                     "reason_summary": "r", "expected_information_gain": "g"}
    defaults.update(overrides)
    return PlannedAction(**defaults)


def build_orchestrator(tmp_path, llm, *, max_actions=150, max_consecutive_failures=5):
    scope = Scope(name="orch-test", targets=["lab.local"], max_actions=max_actions,
                  max_consecutive_failures=max_consecutive_failures)
    workspace = Workspace.create(tmp_path / "state.db", scope)
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    tool = registry.get("nmap")
    tool.available = True
    tool.binary_path = "/usr/bin/nmap"

    runtime = MockRuntime()
    runtime.script(["/usr/bin/nmap"], stdout=NMAP_XML_FIXTURE)

    scope_engine = ScopeEngine(scope)
    executor = ToolExecutor(registry, runtime, scope_engine, workspace, tmp_path / "raw")
    context_builder = ContextBuilder(workspace, scope, registry, goal=scope.goal)
    planner = Planner(llm)
    budget = ActionBudget(max_actions=max_actions, max_consecutive_failures=max_consecutive_failures)
    return Orchestrator(workspace, executor, planner, context_builder, budget), workspace, runtime


@pytest.mark.asyncio
async def test_blocked_scope_action_then_replan(tmp_path):
    llm = MockLLM()
    llm.script_structured(
        make_action(target="evil.example.com"),  # out of scope -> blocked
        make_action(action_type=ActionType.COMPLETE, tool=None, target=None,
                    reason_summary="nothing more to do"),
    )
    orchestrator, workspace, runtime = build_orchestrator(tmp_path, llm)

    outcomes = await orchestrator.run()

    assert outcomes[0].status == "blocked"
    assert outcomes[1].status == "completed_assessment"
    assert runtime.calls == []  # the blocked action must never reach the runtime
    # the blocked attempt is still in the audit trail
    actions = workspace.list_actions()
    assert any(a.status == "blocked" for a in actions)


@pytest.mark.asyncio
async def test_duplicate_action_is_skipped_not_reexecuted(tmp_path):
    llm = MockLLM()
    llm.script_structured(
        make_action(),
        make_action(),  # identical -> should be skipped, not re-run
        make_action(action_type=ActionType.COMPLETE, tool=None, target=None),
    )
    orchestrator, _workspace, runtime = build_orchestrator(tmp_path, llm)

    outcomes = await orchestrator.run()

    assert outcomes[0].status == "completed"
    assert outcomes[1].status == "skipped_duplicate"
    assert outcomes[2].status == "completed_assessment"
    assert len(runtime.calls) == 1  # nmap only actually executed once


@pytest.mark.asyncio
async def test_budget_exhaustion_stops_loop_without_further_planning(tmp_path):
    llm = MockLLM()
    llm.script_structured(make_action())
    orchestrator, _workspace, _runtime = build_orchestrator(tmp_path, llm, max_actions=1)

    outcomes = await orchestrator.run()

    assert outcomes[0].status == "completed"
    assert outcomes[1].status == "stopped"
    assert "budget" in outcomes[1].detail
    assert len(llm.calls) == 1  # no second planning call once budget is exhausted


@pytest.mark.asyncio
async def test_malformed_planner_response_stops_assessment(tmp_path):
    llm = MockLLM()
    llm.script_structured(MalformedResponseError("the model returned garbage"))
    orchestrator, _, _ = build_orchestrator(tmp_path, llm)

    outcomes = await orchestrator.run()

    assert outcomes[-1].status == "stopped"
    assert "invalid action" in outcomes[-1].detail


@pytest.mark.asyncio
async def test_provider_failure_stops_assessment_cleanly(tmp_path):
    llm = MockLLM()
    llm.script_structured(LLMError("connection refused"))
    orchestrator, _, _ = build_orchestrator(tmp_path, llm)

    outcomes = await orchestrator.run()

    assert outcomes[-1].status == "stopped"
    assert "provider failure" in outcomes[-1].detail


@pytest.mark.asyncio
async def test_consecutive_failures_halts_assessment(tmp_path):
    llm = MockLLM()
    # an action targeting a tool that isn't registered fails every time without
    # ever succeeding, so consecutive failures should trip the breaker
    bad_action = make_action(tool="nonexistent-tool")
    llm.script_structured(bad_action, bad_action, bad_action)
    orchestrator, _, _ = build_orchestrator(tmp_path, llm, max_consecutive_failures=2)

    outcomes = await orchestrator.run()

    assert outcomes[-1].status == "stopped"
    assert "consecutive" in outcomes[-1].detail


@pytest.mark.asyncio
async def test_hypothesis_creation_and_investigation_via_orchestrator(tmp_path):
    llm = MockLLM()
    llm.script_structured(
        make_action(action_type=ActionType.UPDATE_HYPOTHESIS, tool=None, target=None,
                    capability="", parameters={"title": "possible IDOR", "category": "authorization"}),
        make_action(action_type=ActionType.COMPLETE, tool=None, target=None),
    )
    orchestrator, workspace, _ = build_orchestrator(tmp_path, llm)

    outcomes = await orchestrator.run()

    assert outcomes[0].status == "completed"
    assert "created" in outcomes[0].detail
    hyps = workspace.list_hypotheses()
    assert len(hyps) == 1
    assert hyps[0].title == "possible IDOR"
