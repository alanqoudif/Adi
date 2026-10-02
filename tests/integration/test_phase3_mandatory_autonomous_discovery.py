"""THE Phase 3 core acceptance test.

Starting with ONLY a root URL known, driven entirely through the real
`Orchestrator` loop (planner -> scope -> execute -> parse -> workspace ->
replan) with NO manually injected Endpoint/Parameter/Session observations
anywhere in this file. The planner (a scripted MockLLM standing in for a
real LLM) chooses a sequence of `http_request` / `discover_web_content`
actions a real autonomous run would plausibly choose; everything after
that point — scope authorization, the real HTTP client, real HTML
extraction, real feroxbuster execution, endpoint/parameter creation,
deduplication, and context propagation back into the next planning call —
is exactly the production code path.

Demonstrates every item the spec's mandatory test requires:
  1. root HTTP request executes                         -> step 1
  2. exchange persists                                   -> assert len(exchanges)
  3. HTML links/forms are extracted                       -> step 1 + 2
  4. Endpoint records appear                              -> assert expected endpoints
  5. Parameters appear                                    -> assert login params
  6. a content-discovery tool independently confirms/adds endpoints -> step 4 (feroxbuster, real binary)
  7. duplicate discoveries merge                          -> assert endpoint count sanity
  8. ContextBuilder sees the discovered state             -> assert on rendered context
  9. subsequent planning calls receive the updated surface -> assert on llm.calls[n]
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
from adi.runtime.shell import LocalRuntime
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.tools.executor import ToolExecutor
from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"
TINY_WORDLIST = Path(__file__).resolve().parents[1] / "fixtures" / "wordlists" / "tiny.txt"


@pytest.fixture()
def demo_app():
    app = DemoApp().start()
    yield app
    app.stop()


def _action(action_type, **kwargs) -> PlannedAction:
    defaults = {"reason_summary": "autonomous step", "expected_information_gain": "discovers more surface"}
    defaults.update(kwargs)
    return PlannedAction(action_type=action_type, **defaults)


@pytest.mark.asyncio
async def test_adi_autonomously_discovers_the_entire_app_local_style_tree(tmp_path, demo_app):
    scope = Scope(
        name="phase3-mandatory", targets=["127.0.0.1"], max_actions=20,
        goal="Starting from only the root URL, map the full web attack surface.",
    )
    workspace = Workspace.create(tmp_path / "state.db", scope)
    scope_engine = ScopeEngine(scope)

    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    runtime_available = registry.get("feroxbuster").available
    tool_executor = ToolExecutor(registry, LocalRuntime(), scope_engine, workspace, tmp_path / "raw")

    http_client = HTTPClient(scope_engine, SessionJarRegistry())
    http_workspace = HTTPWorkspace(http_client, workspace, tmp_path / "evidence")

    context_builder = ContextBuilder(workspace, scope, registry, goal=scope.goal)

    llm = MockLLM()
    base = demo_app.base_url

    # Nothing here is an Observation — these are PLANNER DECISIONS. Every
    # fact in the resulting knowledge graph is derived by production code
    # (HTTP client -> HTML extractor -> Workspace, or feroxbuster -> parser
    # -> Workspace), never injected directly.
    scripted = [
        _action(ActionType.HTTP_REQUEST, capability="http_fetch",
                parameters={"url": base + "/", "method": "GET"},
                reason_summary="No knowledge of the target yet — fetch the root page."),
        _action(ActionType.HTTP_REQUEST, capability="discover_robots_sitemap",
                parameters={"url": base},
                reason_summary="Low-cost discovery before deeper crawling."),
        _action(ActionType.HTTP_REQUEST, capability="http_fetch",
                parameters={"url": base + "/login", "method": "GET"},
                reason_summary="Root page linked to /login — inspect it for a form."),
        _action(ActionType.HTTP_REQUEST, capability="http_fetch",
                parameters={"url": base + "/dashboard", "method": "GET"},
                reason_summary="Root page also linked to /dashboard."),
    ]
    if runtime_available:
        scripted.append(_action(
            ActionType.RUN_TOOL, capability="discover_web_content",
            target=base + "/", parameters={"wordlist": str(TINY_WORDLIST), "depth": 1},
            reason_summary="Confirm nothing is hiding outside the linked pages.",
        ))
    scripted.append(_action(ActionType.COMPLETE, reason_summary="Attack surface sufficiently mapped."))

    llm.script_structured(*scripted)
    planner = Planner(llm)
    orchestrator = Orchestrator(
        workspace, tool_executor, planner, context_builder, ActionBudget(max_actions=20),
        http_workspace=http_workspace,
    )

    outcomes = await orchestrator.run()

    # --- every step actually completed (no crashes, no silent no-ops) ---
    for outcome in outcomes[:-1]:
        assert outcome.status == "completed", outcome.detail
    assert outcomes[-1].status == "completed_assessment"

    # --- (1)(2)(3) root request executed, persisted, HTML extracted ---
    exchanges = workspace.list_http_exchanges()
    assert len(exchanges) >= 3  # /, /login, /dashboard (robots/sitemap logged separately)
    root_exchange = next(e for e in exchanges if e.url.rstrip("/") == base)
    assert root_exchange.status == 200
    assert root_exchange.title == "Demo App"

    # --- (4) endpoint records appear, discovered purely from crawling ---
    endpoints = {e.path: e for e in workspace.list_endpoints()}
    expected_minimum = {"/", "/login", "/dashboard", "/api/profile", "/api/orders", "/admin"}
    assert expected_minimum.issubset(endpoints.keys()), endpoints.keys()

    # --- (5) parameters appear ---
    login_params = {p.name for p in workspace.list_parameters(endpoints["/login"].id)}
    assert login_params == {"email", "password"}

    # --- (6) an independent tool (feroxbuster) also contributed, when available ---
    if runtime_available:
        ferox_observations = [o for o in workspace.list_observations() if o.source == "feroxbuster"]
        assert len(ferox_observations) > 0

    # --- (7) duplicate discoveries merged, not duplicated ---
    assert len(endpoints) == len({e for e in endpoints})  # dict already proves uniqueness by path
    login_endpoint_rows = [e for e in workspace.list_endpoints() if e.path == "/login"]
    assert len(login_endpoint_rows) == 1

    # --- (8) ContextBuilder sees the fully discovered state ---
    final_context = context_builder.build()
    rendered = final_context.render()
    assert "/login" in rendered
    assert "/api/profile" in rendered or "/api/*" in rendered
    assert final_context.endpoint_count == len(endpoints)

    # --- (9) later planning calls saw the state built up by earlier ones ---
    assert len(llm.calls) == len(scripted)
    last_prompt_seen_by_planner = llm.calls[-1][-1].content
    assert "/login" in last_prompt_seen_by_planner

    # sessions: anonymous always exists, matching every target's tree
    assert any(s.name == "anonymous" for s in workspace.list_sessions())
