from __future__ import annotations

import pytest

from adi.actions import ActionType, PlannedAction
from adi.config.models import AdiConfig, RuntimeConfig
from adi.product.controller import ControllerState
from adi.product.models import ProviderProfile
from adi.product.nlu import interpret_scope_command
from adi.product.plain_shell import PlainShell
from adi.scope.models import Scope


def test_nlu_only_host_proposes_target_restriction():
    scope = Scope(name="x", targets=["a", "b"])
    proposal = interpret_scope_command("only localhost", scope)
    assert proposal is not None
    assert proposal.fields["targets"] == ["localhost"]


def test_nlu_disable_auth_testing():
    scope = Scope(name="x")
    proposal = interpret_scope_command("don't perform authentication testing", scope)
    assert proposal is not None
    assert proposal.fields["permissions"].authentication_testing is False


def test_nlu_no_match_returns_none():
    scope = Scope(name="x")
    assert interpret_scope_command("hello there", scope) is None


@pytest.mark.asyncio
async def test_plain_shell_new_status_findings_commands(tmp_path):
    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    shell = PlainShell(config, project_root=tmp_path)
    shell.controller.models.add_profile(ProviderProfile(name="m", kind="mock", locality="local"))

    assert await shell._handle("/new 127.0.0.1") is False
    assert shell.controller.assessment is not None

    await shell._handle("/status")
    await shell._handle("/scope")
    await shell._handle("/findings")
    await shell._handle("/hypotheses")
    await shell._handle("/evidence")
    await shell._handle("/providers")
    await shell._handle("/sessions")
    await shell._handle("/help")
    await shell._handle("/unknown-cmd")


@pytest.mark.asyncio
async def test_plain_shell_chat_sets_goal_and_runs_to_completion(tmp_path):
    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    shell = PlainShell(config, project_root=tmp_path)
    shell.controller.models.add_profile(ProviderProfile(name="m", kind="mock", locality="local"))
    await shell._handle("/new 127.0.0.1")

    llm = shell.controller.models.provider_for("planner")
    llm.script_structured(PlannedAction(action_type=ActionType.COMPLETE, reason_summary="done"))

    await shell._handle("focus on authorization")
    await shell.controller.wait_idle()
    assert shell.controller.state == ControllerState.COMPLETED


@pytest.mark.asyncio
async def test_plain_shell_expert_console_commands(tmp_path, monkeypatch):
    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    shell = PlainShell(config, project_root=tmp_path)
    shell.controller.models.add_profile(ProviderProfile(name="m", kind="mock", locality="local"))
    await shell._handle("/new 127.0.0.1")

    await shell._handle("/tools")
    await shell._handle("/capabilities")
    await shell._handle("/attack-surface")
    await shell._handle("/source")

    # Rejecting the preview must not execute anything.
    import builtins

    monkeypatch.setattr(builtins, "input", lambda prompt="": "n")
    await shell._handle("/run enumerate_services 127.0.0.1")


@pytest.mark.asyncio
async def test_plain_shell_pause_continue_stop_commands(tmp_path):
    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    shell = PlainShell(config, project_root=tmp_path)
    shell.controller.models.add_profile(ProviderProfile(name="m", kind="mock", locality="local"))
    await shell._handle("/new 127.0.0.1")
    await shell._handle("/pause")
    assert shell.controller.state == ControllerState.PAUSED
    await shell._handle("/continue")
    await shell._handle("/stop")
    assert shell.controller.state == ControllerState.STOPPED
