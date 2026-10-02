"""Phase 3K/3L: browser-driven discovery feeds the SAME canonical Endpoint
model as HTTP-driven discovery. Skipped automatically when `playwright` (or
its browser binaries) isn't installed — this environment doesn't have it;
see the Phase 3 report for exactly what that means.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures" / "webapp"))
from app import DemoApp

from adi.http.workspace import HTTPWorkspace
from adi.knowledge.workspace import Workspace
from adi.runtime.browser import BrowserRuntime
from adi.scope.models import Scope


async def _playwright_ready() -> bool:
    runtime = BrowserRuntime()
    return await runtime.is_available()


@pytest.fixture()
def demo_app():
    app = DemoApp().start()
    yield app
    app.stop()


@pytest.mark.asyncio
async def test_browser_network_capture_merges_into_http_endpoint_model(tmp_path, demo_app):
    if not await _playwright_ready():
        pytest.skip("playwright is not installed/configured in this environment "
                    "(pip install adi[browser] && playwright install chromium)")

    scope = Scope(name="browser-test", targets=["127.0.0.1"])
    workspace = Workspace.create(tmp_path / "state.db", scope)
    http_ws = HTTPWorkspace(client=None, workspace=workspace, evidence_dir=tmp_path / "evidence")  # type: ignore[arg-type]

    runtime = BrowserRuntime()
    await runtime.start()
    try:
        result = await runtime.visit(demo_app.base_url + "/dashboard")
    finally:
        await runtime.stop()

    # the dashboard's inline <script> fires two real fetch() calls — the
    # browser observes them directly, no static regex guessing involved.
    xhr_or_fetch_urls = {r.url for r in result.network_requests if r.resource_type in ("xhr", "fetch")}
    assert any("/api/profile" in u for u in xhr_or_fetch_urls)
    assert any("/api/orders" in u for u in xhr_or_fetch_urls)

    http_ws.record_browser_visit(result)

    endpoints = {e.path for e in workspace.list_endpoints()}
    assert "/api/profile" in endpoints
    assert "/api/orders" in endpoints
