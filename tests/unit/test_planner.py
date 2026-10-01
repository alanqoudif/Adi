import pytest

from adi.actions import ActionType, PlannedAction
from adi.agent.context_builder import PlanningContext
from adi.agent.planner import Planner
from adi.llm.base import MalformedResponseError
from adi.llm.mock import MockLLM


def make_context(**overrides) -> PlanningContext:
    defaults = dict(
        goal="find the flag", scope_name="lab", scope_mode="lab", targets=["lab.local"],
        assets=[], endpoints=[], sessions=[], active_hypotheses=[], rejected_hypothesis_titles=[],
        recent_actions=[], recent_observation_summaries=[], consecutive_failures=0,
        actions_used=0, actions_remaining=150, available_capabilities=["enumerate_services"],
    )
    defaults.update(overrides)
    return PlanningContext(**defaults)


@pytest.mark.asyncio
async def test_planner_returns_scripted_action():
    llm = MockLLM()
    action = PlannedAction(action_type=ActionType.RUN_TOOL, tool="nmap", target="lab.local",
                            capability="enumerate_services", reason_summary="r", expected_information_gain="g")
    llm.script_structured(action)
    planner = Planner(llm)

    result = await planner.plan(make_context())
    assert result.tool == "nmap"
    assert len(llm.calls) == 1


@pytest.mark.asyncio
async def test_planner_propagates_malformed_response():
    llm = MockLLM()
    llm.script_structured(MalformedResponseError("bad json"))
    planner = Planner(llm)

    with pytest.raises(MalformedResponseError):
        await planner.plan(make_context())


def test_context_renders_without_crashing():
    context = make_context()
    rendered = context.render()
    assert "find the flag" in rendered
    assert "lab.local" in rendered
