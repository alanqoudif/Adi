"""Phase 3B: the `http_request` PlannedAction actually executes through the
full orchestrator loop — planner -> ScopeEngine -> HTTP client -> HTTPExchange
-> deterministic extraction -> Observations -> Workspace -> ContextBuilder ->
planner again — using the real local demo app, not a mock.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures" / "webapp"))
from app import DemoApp

from adi.actions import ActionType, PlannedAction
from adi.agent.context_builder import ContextBuilder
from adi.agent.orchestrator import Orchestrator
from adi.agent.planner import Planner
from adi.agent.scheduler import ActionBudget
from adi.http.client import HTTPClient
from adi.http.sessions import SessionJarRegistry
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.workspace import Workspace
from adi.llm.mock import MockLLM
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.tools.executor import ToolExecutor
from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"


@pytest.fixture()
def demo_app():
    app = DemoApp().start()
    yield app
    app.stop()


@pytest.mark.asyncio
async def test_planner_driven_http_request_discovers_links_and_replans(tmp_path, demo_app):
    scope = Scope(name="http-loop-test", targets=["127.0.0.1"], max_actions=10,
                  goal="Discover the web attack surface.")
    workspace = Workspace.create(tmp_path / "state.db", scope)
    scope_engine = ScopeEngine(scope)
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()

    from adi.runtime.mock import MockRuntime
    tool_executor = ToolExecutor(registry, MockRuntime(), scope_engine, workspace, tmp_path / "raw")

    http_client = HTTPClient(scope_engine, SessionJarRegistry())
    http_workspace = HTTPWorkspace(http_client, workspace, tmp_path / "evidence")

    context_builder = ContextBuilder(workspace, scope, registry, goal=scope.goal)

    llm = MockLLM()
    llm.script_structured(
        PlannedAction(
            action_type=ActionType.HTTP_REQUEST, capability="http_fetch",
            parameters={"url": demo_app.base_url + "/", "method": "GET"},
            reason_summary="No knowledge of the web app yet — fetch the root page.",
            expected_information_gain="Discovers initial links and technology.",
        ),
        PlannedAction(action_type=ActionType.COMPLETE, reason_summary="done", expected_information_gain="none"),
    )
    planner = Planner(llm)
    orchestrator = Orchestrator(workspace, tool_executor, planner, context_builder,
                                 ActionBudget(max_actions=10), http_workspace=http_workspace)

    outcomes = await orchestrator.run()

    assert outcomes[0].status == "completed"
    assert outcomes[1].status == "completed_assessment"

    endpoints = {e.path for e in workspace.list_endpoints()}
    assert "/login" in endpoints
    assert "/dashboard" in endpoints

    exchanges = workspace.list_http_exchanges()
    assert len(exchanges) == 1
    assert exchanges[0].status == 200

    # the SECOND planner call must have seen the discovered endpoints
    second_prompt = llm.calls[1][-1].content
    assert "/login" in second_prompt


@pytest.mark.asyncio
async def test_http_request_to_out_of_scope_host_is_blocked_not_crashed(tmp_path, demo_app):
    scope = Scope(name="http-loop-blocked", targets=["10.0.0.0/8"], max_actions=5)
    workspace = Workspace.create(tmp_path / "state.db", scope)
    scope_engine = ScopeEngine(scope)
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()

    from adi.runtime.mock import MockRuntime
    tool_executor = ToolExecutor(registry, MockRuntime(), scope_engine, workspace, tmp_path / "raw")
    http_client = HTTPClient(scope_engine, SessionJarRegistry())
    http_workspace = HTTPWorkspace(http_client, workspace, tmp_path / "evidence")
    context_builder = ContextBuilder(workspace, scope, registry, goal=scope.goal)

    llm = MockLLM()
    llm.script_structured(
        PlannedAction(action_type=ActionType.HTTP_REQUEST, capability="http_fetch",
                      parameters={"url": demo_app.base_url + "/"}),
        PlannedAction(action_type=ActionType.COMPLETE),
    )
    planner = Planner(llm)
    orchestrator = Orchestrator(workspace, tool_executor, planner, context_builder,
                                 ActionBudget(max_actions=5), http_workspace=http_workspace)

    outcomes = await orchestrator.run()

    assert outcomes[0].status == "blocked"
    assert workspace.list_endpoints() == []
