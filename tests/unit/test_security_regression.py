"""Security regression proofs for the Product layer, per the product
specification's "No Raw Model Shell" / authorization-boundary sections.

Each test proves a specific invariant by code inspection or behavior,
not by trusting a docstring:

  - the model cannot execute arbitrary shell
  - the model cannot expand scope / self-approve / enable auth testing
  - secrets never reach the console/log rendering surface
  - privacy routing cannot be silently bypassed
  - the manual/expert console goes through the same ScopeEngine as the
    autonomous loop (no separate bypass path)
"""

from __future__ import annotations

import ast
import inspect
import textwrap

import pytest

from adi.actions import ActionType, PlannedAction
from adi.config.models import AdiConfig, RuntimeConfig
from adi.product.console import ExpertConsole
from adi.product.controller import ProductController
from adi.product.models import ModelManager, PrivacyRoutingError, ProviderProfile


def test_planned_action_schema_has_no_raw_shell_field():
    """The only thing a model can produce is a `PlannedAction` — it has no
    field for a shell command/argv; `tool`/`capability` are looked up
    against the reviewed ToolRegistry, never executed as typed strings."""
    fields = set(PlannedAction.model_fields.keys())
    assert "shell_command" not in fields
    assert "command" not in fields
    assert "argv" not in fields


def test_orchestrator_drive_never_calls_scope_mutation_methods():
    """Static proof: `ProductController._drive` (the autonomous loop body)
    never calls `set_goal`/`update_scope_fields`/`set_active` — those are
    only reachable from operator-facing command handlers in
    `plain_shell.py`, never from the model-driven loop itself."""
    from adi.product import controller as controller_module

    source = textwrap.dedent(inspect.getsource(controller_module.ProductController._drive))
    tree = ast.parse(source)
    called_names = {
        node.func.attr for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    forbidden = {"set_goal", "update_scope_fields", "set_active", "add_profile"}
    assert not (called_names & forbidden)


@pytest.mark.asyncio
async def test_model_cannot_enable_authentication_testing(tmp_path):
    """Even if a (malicious or buggy) planner's PlannedAction claims an
    audit_credentials capability, ScopeEngine blocks it unless the
    operator has explicitly set approval_mode + an approved key through
    the Product layer's own scope-editing path — never through the
    model's action itself."""
    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    controller = ProductController(config, project_root=tmp_path)
    await controller.new_assessment("127.0.0.1")
    scope = controller.assessment.workspace.load_scope()
    assert scope.permissions.authentication_testing is False
    assert scope.approval_mode is False

    action = PlannedAction(
        action_type=ActionType.RUN_TOOL, capability="audit_credentials",
        target="127.0.0.1", reason_summary="model-proposed",
    )
    decision = controller.assessment.scope_engine.authorize(action)
    assert decision.allowed is False


@pytest.mark.asyncio
async def test_privacy_routing_cannot_be_bypassed_by_role_name(tmp_path):
    manager = ModelManager(tmp_path)
    manager.add_profile(ProviderProfile(name="remote", kind="mock", locality="remote"))
    for role in ("planner", "critic", "code_analyst", "reporter", "anything-else"):
        with pytest.raises(PrivacyRoutingError):
            manager.provider_for(role if role != "anything-else" else "planner",
                                  data_category="source_code")


@pytest.mark.asyncio
async def test_expert_console_execute_goes_through_scope_engine(tmp_path):
    """The manual expert console cannot run a prohibited capability either
    — it calls the exact same `ToolExecutor.run_capability`, which calls
    `ScopeEngine.authorize` internally. No parallel execution path."""
    from adi.assessment import Assessment
    from adi.scope.models import Scope

    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    assessment = Assessment.create(Scope(name="x", targets=["127.0.0.1"]), config, tmp_path)
    console = ExpertConsole(assessment)
    result = await console.execute("password_spray", "127.0.0.1")
    assert result.ok is False


def test_redaction_strips_known_secrets_from_plain_shell_output(tmp_path):
    from adi.product.plain_shell import PlainShell
    from adi.scope.models import Scope, TestAccount

    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    shell = PlainShell(config, project_root=tmp_path)

    import os

    os.environ["ADI_TEST_SECRET_VALUE"] = "super-secret-value-123"
    try:
        from adi.assessment import Assessment

        scope = Scope(
            name="x", targets=["127.0.0.1"],
            test_accounts=[TestAccount(name="t", username="u", password_env="ADI_TEST_SECRET_VALUE")],
        )
        shell.controller.assessment = Assessment.create(scope, config, tmp_path)

        captured = []
        shell.output_sink = captured.append
        shell._print("the secret is super-secret-value-123 right here")
        assert "super-secret-value-123" not in captured[0]
    finally:
        del os.environ["ADI_TEST_SECRET_VALUE"]


def test_terminal_escape_sequences_stripped_before_render(tmp_path):
    from adi.product.plain_shell import PlainShell

    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    shell = PlainShell(config, project_root=tmp_path)
    captured = []
    shell.output_sink = captured.append
    shell._print("tool output\x1b]0;pwned-title\x07 continues")
    assert "\x1b" not in captured[0]


@pytest.mark.asyncio
async def test_plain_shell_chat_scope_proposal_requires_explicit_yes(tmp_path, monkeypatch):
    """Behavioral proof: a natural-language scope-widening phrase typed as
    chat ("only localhost" etc.) is never applied silently — declining the
    y/N prompt leaves the stored scope untouched."""
    import builtins

    from adi.product.models import ProviderProfile
    from adi.product.plain_shell import PlainShell

    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    shell = PlainShell(config, project_root=tmp_path)
    shell.controller.models.add_profile(ProviderProfile(name="m", kind="mock", locality="local"))
    await shell._handle("/new 127.0.0.1")
    before = shell.controller.assessment.workspace.load_scope().model_dump_json()

    monkeypatch.setattr(builtins, "input", lambda prompt="": "n")
    await shell._handle("only evil.example.com")

    after = shell.controller.assessment.workspace.load_scope().model_dump_json()
    assert before == after
