"""The most important Phase 2 test: proves the full agent loop wiring.

MockLLM + MockRuntime + the REAL tool registry + the REAL nmap parser + the
REAL Workspace. No mocking of anything in between planner output and
workspace state — this is what makes it an integration test rather than a
unit test of any single piece.

    planner returns a run_tool action
    -> executor runs it (through the real scope engine)
    -> the real nmap parser turns the (scripted) XML into observations
    -> the workspace is updated with typed Host/Service rows
    -> the planner's SECOND call receives a context that reflects that
       update (the new host/port appear in the rendered context)
    -> the planner returns 'complete' and the loop ends
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adi.actions import ActionType, PlannedAction
from adi.agent.context_builder import ContextBuilder
from adi.agent.orchestrator import Orchestrator
from adi.agent.planner import Planner
from adi.agent.scheduler import ActionBudget
from adi.knowledge.workspace import Workspace
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


@pytest.mark.asyncio
async def test_full_agent_loop_plan_execute_parse_update_replan(tmp_path):
    scope = Scope(name="integration-lab", targets=["10.10.10.15"], max_actions=10,
                  goal="Enumerate services and report what is found.")
    workspace = Workspace.create(tmp_path / "state.db", scope)

    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    nmap_tool = registry.get("nmap")
    assert nmap_tool is not None, "nmap skill must be discoverable from the real skills/ dir"
    nmap_tool.available = True
    nmap_tool.binary_path = "/usr/bin/nmap"

    runtime = MockRuntime()
    runtime.script(["/usr/bin/nmap"], stdout=NMAP_XML_FIXTURE)

    scope_engine = ScopeEngine(scope)
    executor = ToolExecutor(registry, runtime, scope_engine, workspace, tmp_path / "raw")
    context_builder = ContextBuilder(workspace, scope, registry, goal=scope.goal)

    llm = MockLLM()
    first_action = PlannedAction(
        action_type=ActionType.RUN_TOOL, tool="nmap", target="10.10.10.15",
        capability="enumerate_services",
        reason_summary="No service knowledge yet for this host.",
        expected_information_gain="Establishes the open ports and services.",
    )
    second_action = PlannedAction(
        action_type=ActionType.COMPLETE,
        reason_summary="Services enumerated; stopping here for Phase 2.",
        expected_information_gain="none — concluding.",
    )
    llm.script_structured(first_action, second_action)

    planner = Planner(llm)
    orchestrator = Orchestrator(workspace, executor, planner, context_builder, ActionBudget(max_actions=10))

    # Pre-condition: nothing known about the target yet.
    pre_context = context_builder.build()
    assert pre_context.assets == []

    outcomes = await orchestrator.run()

    # The planner was called exactly twice, and the loop terminated cleanly.
    assert len(outcomes) == 2
    assert outcomes[0].status == "completed"
    assert outcomes[1].status == "completed_assessment"

    # The real nmap parser actually ran: host + 2 open services persisted.
    hosts = workspace.list_hosts()
    services = workspace.list_services()
    assert len(hosts) == 1
    assert hosts[0].address == "10.10.10.15"
    assert {s.port for s in services} == {22, 80}

    # The SECOND planner call saw the updated attack surface, proving the
    # loop actually threads workspace state back into planning context.
    assert len(llm.calls) == 2
    second_call_prompt = llm.calls[1][-1].content  # last message = rendered context
    assert "10.10.10.15" in second_call_prompt
    assert "80" in second_call_prompt

    # And the audit trail recorded both the tool execution and its result.
    actions = workspace.list_actions()
    assert len(actions) == 1  # only the run_tool action hits the audit trail; COMPLETE doesn't
    assert actions[0].status == "completed"
    assert actions[0].reason_summary == "No service knowledge yet for this host."
