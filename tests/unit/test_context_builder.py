from pathlib import Path

from adi.agent.context_builder import ContextBuilder
from adi.knowledge.observations import Observation, ObservationType
from adi.knowledge.workspace import Workspace
from adi.scope.models import Scope
from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"


def test_context_builder_reflects_workspace_state(tmp_path):
    scope = Scope(name="ctx-test", targets=["lab.local"], max_actions=10, goal="find stuff")
    workspace = Workspace.create(tmp_path / "state.db", scope)
    workspace.record_observation(Observation(
        type=ObservationType.OPEN_PORT, subject="lab.local:80",
        value={"host": "lab.local", "port": 80, "protocol": "tcp", "service": "http"},
        source="nmap",
    ))
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()

    builder = ContextBuilder(workspace, scope, registry, goal=scope.goal)
    context = builder.build()

    assert context.goal == "find stuff"
    assert context.actions_remaining == 10
    assert len(context.assets) == 1
    assert context.assets[0].address == "lab.local"
    assert context.assets[0].open_ports == [80]
    assert "lab.local:80" in " ".join(context.recent_observation_summaries)


def test_context_builder_caps_action_budget_at_zero_not_negative(tmp_path):
    scope = Scope(name="ctx-test2", targets=["lab.local"], max_actions=1)
    workspace = Workspace.create(tmp_path / "state.db", scope)
    for _ in range(3):
        workspace.record_action(action_type="run_tool", tool="nmap", target="lab.local",
                                 scope_allowed=True, status="completed")
    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    builder = ContextBuilder(workspace, scope, registry, goal=scope.goal)
    context = builder.build()
    assert context.actions_remaining == 0
    assert context.actions_used == 3
