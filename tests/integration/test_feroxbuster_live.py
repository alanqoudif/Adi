"""A real, live run of the feroxbuster binary (when installed) against the
local demo app — not a fixture. Skipped automatically if feroxbuster isn't
on PATH, so this suite still passes on machines without it (per
docs/safety-model.md: never fake a tool's success)."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures" / "webapp"))
from app import DemoApp

from adi.knowledge.workspace import Workspace
from adi.runtime.shell import LocalRuntime
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.tools.executor import ToolExecutor
from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"
TINY_WORDLIST = Path(__file__).resolve().parents[1] / "fixtures" / "wordlists" / "tiny.txt"

pytestmark = pytest.mark.skipif(
    shutil.which("feroxbuster") is None, reason="feroxbuster is not installed on this machine"
)


@pytest.fixture()
def demo_app():
    app = DemoApp().start()
    yield app
    app.stop()


@pytest.mark.asyncio
async def test_real_feroxbuster_discovers_the_demo_app_endpoints(tmp_path, demo_app):
    scope = Scope(name="ferox-live", targets=["127.0.0.1"])
    workspace = Workspace.create(tmp_path / "state.db", scope)
    scope_engine = ScopeEngine(scope)
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    assert registry.get("feroxbuster").available

    executor = ToolExecutor(registry, LocalRuntime(), scope_engine, workspace, tmp_path / "raw")
    observations = await executor.run(
        "feroxbuster", demo_app.base_url + "/",
        parameters={"wordlist": str(TINY_WORDLIST), "depth": 1},
        capability="discover_web_content",
    )

    assert len(observations) > 0
    endpoints = {e.path for e in workspace.list_endpoints()}
    assert "/login" in endpoints
    assert "/dashboard" in endpoints
    assert "/api/profile" in endpoints
