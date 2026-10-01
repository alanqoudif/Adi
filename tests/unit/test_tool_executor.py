from pathlib import Path

import pytest

from adi.knowledge.workspace import Workspace
from adi.runtime.mock import MockRuntime
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.tools.executor import ScopeViolationError, ToolExecutionError, ToolExecutor
from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"
NMAP_XML_FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "nmap" / "scan.xml"
).read_text()


def _force_available(registry: ToolRegistry, name: str) -> None:
    tool = registry.get(name)
    tool.available = True
    tool.binary_path = "/usr/bin/nmap"


@pytest.fixture()
def workspace(tmp_path) -> Workspace:
    scope = Scope(name="test-exec", targets=["lab.local"])
    return Workspace.create(tmp_path / "state.db", scope)


@pytest.fixture()
def registry() -> ToolRegistry:
    reg = ToolRegistry(SKILLS_DIR)
    reg.discover()
    _force_available(reg, "nmap")
    return reg


@pytest.mark.asyncio
async def test_executor_runs_nmap_and_records_observations(tmp_path, workspace, registry):
    runtime = MockRuntime()
    runtime.script(["/usr/bin/nmap"], stdout=NMAP_XML_FIXTURE)
    scope_engine = ScopeEngine(workspace.load_scope())
    executor = ToolExecutor(registry, runtime, scope_engine, workspace, tmp_path / "raw")

    observations = await executor.run("nmap", "lab.local", capability="discover_hosts")

    assert len(observations) >= 2
    hosts = workspace.list_hosts()
    services = workspace.list_services()
    assert len(hosts) == 1
    assert len(services) == 2  # ssh + http (closed mysql port excluded)

    actions = workspace.list_actions()
    assert len(actions) == 1
    assert actions[0].status == "completed"
    assert actions[0].scope_allowed is True


@pytest.mark.asyncio
async def test_executor_blocks_out_of_scope_target(tmp_path, workspace, registry):
    runtime = MockRuntime()
    scope_engine = ScopeEngine(workspace.load_scope())
    executor = ToolExecutor(registry, runtime, scope_engine, workspace, tmp_path / "raw")

    with pytest.raises(ScopeViolationError):
        await executor.run("nmap", "evil.example.com")

    actions = workspace.list_actions()
    assert len(actions) == 1
    assert actions[0].status == "blocked"
    assert runtime.calls == []  # must never execute a blocked action


@pytest.mark.asyncio
async def test_executor_rejects_unknown_tool(tmp_path, workspace, registry):
    runtime = MockRuntime()
    scope_engine = ScopeEngine(workspace.load_scope())
    executor = ToolExecutor(registry, runtime, scope_engine, workspace, tmp_path / "raw")

    with pytest.raises(ToolExecutionError):
        await executor.run("nonexistent-tool", "lab.local")
