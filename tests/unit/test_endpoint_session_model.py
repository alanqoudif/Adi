"""Models the exact attack-surface tree below as Observations and verifies
the knowledge model folds it correctly:

    app.local
    ├── React application
    ├── /
    ├── /login
    │   └── POST form
    │       ├── email
    │       └── password
    ├── /dashboard
    │   ├── GET /api/profile
    │   └── GET /api/orders
    ├── /api
    │   ├── /profile
    │   └── /orders
    ├── Session
    │   └── anonymous
    └── Technologies
        ├── React
        └── nginx
"""

from pathlib import Path

import pytest

from adi.agent.context_builder import ContextBuilder
from adi.knowledge.observations import Observation, ObservationType
from adi.knowledge.workspace import Workspace
from adi.scope.models import Scope
from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"
HOST = "app.local"


@pytest.fixture()
def workspace(tmp_path) -> Workspace:
    scope = Scope(name="app-local-audit", targets=[HOST], goal="Map the attack surface.")
    return Workspace.create(tmp_path / "state.db", scope)


def test_default_anonymous_session_exists_on_creation(workspace):
    sessions = workspace.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].name == "anonymous"
    assert sessions[0].authenticated is False


def test_folds_the_app_local_tree_into_typed_state(workspace):
    # nginx fronting the app (service-level observation, Phase 1 model)
    workspace.record_observation(Observation(
        type=ObservationType.OPEN_PORT, subject=f"{HOST}:80",
        value={"host": HOST, "port": 80, "protocol": "tcp", "service": "http", "product": "nginx"},
        source="nmap",
    ))

    # React SPA root
    workspace.record_observation(Observation(
        type=ObservationType.WEB_ENDPOINT, subject=f"{HOST}/",
        value={"host": HOST, "path": "/", "methods": ["GET"], "requires_auth": False,
               "technology": "React"},
        source="httpx",
    ))

    # /login (POST form: email + password) — unauthenticated by design
    workspace.record_observation(Observation(
        type=ObservationType.WEB_ENDPOINT, subject=f"{HOST}/login",
        value={"host": HOST, "path": "/login", "methods": ["POST"], "requires_auth": False},
        source="httpx",
    ))
    login_endpoint = next(e for e in workspace.list_endpoints() if e.path == "/login")
    workspace.record_observation(Observation(
        type=ObservationType.ENDPOINT_PARAMETER, subject="email",
        value={"endpoint_id": login_endpoint.id, "name": "email", "location": "body", "required": True},
        source="httpx",
    ))
    workspace.record_observation(Observation(
        type=ObservationType.ENDPOINT_PARAMETER, subject="password",
        value={"endpoint_id": login_endpoint.id, "name": "password", "location": "body", "required": True},
        source="httpx",
    ))

    # /dashboard (authenticated) which itself calls two authenticated API endpoints
    for path in ("/dashboard", "/api/profile", "/api/orders"):
        workspace.record_observation(Observation(
            type=ObservationType.WEB_ENDPOINT, subject=f"{HOST}{path}",
            value={"host": HOST, "path": path, "methods": ["GET"], "requires_auth": True},
            source="browser",
        ))

    # --- assertions ---------------------------------------------------

    hosts = workspace.list_hosts()
    assert len(hosts) == 1
    assert hosts[0].address == HOST

    services = workspace.list_services()
    assert len(services) == 1
    assert services[0].product == "nginx"

    endpoints = {e.path: e for e in workspace.list_endpoints()}
    assert set(endpoints) == {"/", "/login", "/dashboard", "/api/profile", "/api/orders"}
    assert endpoints["/"].technology == "React"
    assert endpoints["/login"].requires_auth is False
    assert endpoints["/dashboard"].requires_auth is True
    assert endpoints["/api/orders"].requires_auth is True

    login_params = {p.name: p for p in workspace.list_parameters(login_endpoint.id)}
    assert set(login_params) == {"email", "password"}
    assert all(p.location == "body" for p in login_params.values())

    # parameters are scoped to their endpoint, not leaked onto others
    assert workspace.list_parameters(endpoints["/dashboard"].id) == []

    sessions = {s.name for s in workspace.list_sessions()}
    assert sessions == {"anonymous"}


def test_repeated_observation_merges_methods_instead_of_duplicating(workspace):
    workspace.record_observation(Observation(
        type=ObservationType.WEB_ENDPOINT, subject=f"{HOST}/api/orders",
        value={"host": HOST, "path": "/api/orders", "methods": ["GET"]}, source="httpx",
    ))
    workspace.record_observation(Observation(
        type=ObservationType.WEB_ENDPOINT, subject=f"{HOST}/api/orders",
        value={"host": HOST, "path": "/api/orders", "methods": ["POST"], "requires_auth": True},
        source="browser",
    ))

    endpoints = workspace.list_endpoints()
    assert len(endpoints) == 1  # no duplicate row for the same (host, path)
    import json
    assert json.loads(endpoints[0].methods_json) == ["GET", "POST"]
    assert endpoints[0].requires_auth is True  # once true, stays true


def test_session_can_become_authenticated_via_observation(workspace):
    workspace.record_observation(Observation(
        type=ObservationType.SESSION_OBSERVED, subject="user_a",
        value={"name": "user_a", "role": "user", "authenticated": True,
               "test_account_name": "user_a"},
        source="browser",
    ))
    sessions = {s.name: s for s in workspace.list_sessions()}
    assert set(sessions) == {"anonymous", "user_a"}
    assert sessions["user_a"].authenticated is True
    assert sessions["user_a"].role == "user"


def test_context_builder_surfaces_endpoints_and_sessions(workspace):
    workspace.record_observation(Observation(
        type=ObservationType.WEB_ENDPOINT, subject=f"{HOST}/dashboard",
        value={"host": HOST, "path": "/dashboard", "methods": ["GET"], "requires_auth": True},
        source="browser",
    ))
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    scope = workspace.load_scope()
    builder = ContextBuilder(workspace, scope, registry, goal=scope.goal)

    context = builder.build()
    assert len(context.endpoints) == 1
    assert context.endpoints[0].path == "/dashboard"
    assert context.endpoints[0].requires_auth is True
    assert any(s.name == "anonymous" for s in context.sessions)

    rendered = context.render()
    assert "/dashboard" in rendered
    assert "requires auth" in rendered
    assert "anonymous" in rendered
