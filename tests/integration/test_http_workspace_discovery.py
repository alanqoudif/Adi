"""The Phase 3 core acceptance test: starting with ONLY a root URL, Adi must
autonomously derive the demo app's attack surface — no manually injected
endpoint observations anywhere in this file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures" / "webapp"))
from app import DemoApp

from adi.http.client import HTTPClient
from adi.http.sessions import SessionJarRegistry
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.workspace import Workspace
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope


@pytest.fixture()
def demo_app():
    app = DemoApp().start()
    yield app
    app.stop()


@pytest.fixture()
def http_workspace(tmp_path, demo_app):
    scope = Scope(name="discovery-test", targets=["127.0.0.1"], max_actions=50)
    workspace = Workspace.create(tmp_path / "state.db", scope)
    scope_engine = ScopeEngine(scope)
    client = HTTPClient(scope_engine, SessionJarRegistry())
    http_ws = HTTPWorkspace(client, workspace, tmp_path / "evidence")
    return http_ws, workspace


@pytest.mark.asyncio
async def test_root_request_alone_discovers_links(http_workspace, demo_app):
    http_ws, workspace = http_workspace

    observations = await http_ws.fetch("GET", demo_app.base_url + "/")

    assert len(observations) > 0
    endpoints = {e.path for e in workspace.list_endpoints()}
    # discovered purely from <a href> tags on the home page — nothing injected
    assert "/" in endpoints
    assert "/login" in endpoints
    assert "/dashboard" in endpoints


@pytest.mark.asyncio
async def test_visiting_login_discovers_the_form_and_its_parameters(http_workspace, demo_app):
    http_ws, workspace = http_workspace

    await http_ws.fetch("GET", demo_app.base_url + "/login")

    endpoints = {e.path: e for e in workspace.list_endpoints()}
    assert "/login" in endpoints
    login_endpoint = endpoints["/login"]
    assert "POST" in login_endpoint.methods_json

    params = {p.name for p in workspace.list_parameters(login_endpoint.id)}
    assert params == {"email", "password"}


@pytest.mark.asyncio
async def test_visiting_dashboard_discovers_js_fetch_api_endpoints(http_workspace, demo_app):
    http_ws, workspace = http_workspace

    await http_ws.fetch("GET", demo_app.base_url + "/dashboard")

    endpoints = {e.path for e in workspace.list_endpoints()}
    # found via static JS extraction of fetch() calls, not hardcoded
    assert "/api/profile" in endpoints
    assert "/api/orders" in endpoints


@pytest.mark.asyncio
async def test_technology_fingerprint_observed_from_headers_and_cookies(http_workspace, demo_app):
    http_ws, workspace = http_workspace

    await http_ws.fetch("GET", demo_app.base_url + "/")

    tech_observations = [
        o for o in workspace.list_observations() if o.type == "technology_fingerprint"
    ]
    names = {o.value["name"] for o in tech_observations}
    assert any("nginx" in n for n in names)
    assert "Express" in names  # from the connect.sid cookie


@pytest.mark.asyncio
async def test_duplicate_discovery_merges_instead_of_duplicating(http_workspace, demo_app):
    http_ws, workspace = http_workspace

    await http_ws.fetch("GET", demo_app.base_url + "/")
    await http_ws.fetch("GET", demo_app.base_url + "/")  # same page again

    login_endpoints = [e for e in workspace.list_endpoints() if e.path == "/login"]
    assert len(login_endpoints) == 1  # not duplicated


@pytest.mark.asyncio
async def test_robots_and_sitemap_feed_the_same_endpoint_model(http_workspace, demo_app):
    http_ws, workspace = http_workspace

    await http_ws.discover_robots_and_sitemap(demo_app.base_url)

    endpoints = {e.path for e in workspace.list_endpoints()}
    assert "/admin" in endpoints  # from robots.txt Disallow
    assert "/dashboard" in endpoints  # from sitemap.xml


@pytest.mark.asyncio
async def test_http_exchange_is_persisted_with_redacted_headers(http_workspace, demo_app):
    http_ws, workspace = http_workspace

    await http_ws.fetch("GET", demo_app.base_url + "/")

    exchanges = workspace.list_http_exchanges()
    assert len(exchanges) == 1
    assert exchanges[0].status == 200
    assert exchanges[0].title == "Demo App"


@pytest.mark.asyncio
async def test_full_autonomous_style_crawl_discovers_the_whole_tree(http_workspace, demo_app):
    """The mandatory Phase 3 acceptance scenario: simulate the planner
    choosing to visit the pages a real autonomous loop would reach, with NO
    manually injected Endpoint/Parameter observations anywhere."""
    http_ws, workspace = http_workspace

    await http_ws.fetch("GET", demo_app.base_url + "/")
    await http_ws.discover_robots_and_sitemap(demo_app.base_url)
    await http_ws.fetch("GET", demo_app.base_url + "/login")
    await http_ws.fetch("GET", demo_app.base_url + "/dashboard")

    endpoints = {e.path: e for e in workspace.list_endpoints()}
    expected = {"/", "/login", "/dashboard", "/api/profile", "/api/orders", "/admin"}
    assert expected.issubset(endpoints.keys())

    login_params = {p.name for p in workspace.list_parameters(endpoints["/login"].id)}
    assert login_params == {"email", "password"}

    sessions = {s.name for s in workspace.list_sessions()}
    assert "anonymous" in sessions

    exchanges = workspace.list_http_exchanges()
    assert len(exchanges) >= 4
