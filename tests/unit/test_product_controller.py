"""Vertical-slice test: ProductController -> real Assessment/Orchestrator
-> MockRuntime, driven by a scripted MockLLM through ModelManager. Proves
the Product layer adds no new execution path and narrates the existing
one via typed events."""

from __future__ import annotations

import pytest

from adi.actions import ActionType, PlannedAction
from adi.config.models import AdiConfig, RuntimeConfig
from adi.product.controller import ControllerState, ProductController
from adi.product.events import EventType
from adi.product.models import ModelManager, ProviderProfile


@pytest.fixture
def config() -> AdiConfig:
    return AdiConfig(runtime=RuntimeConfig(type="mock"))


@pytest.mark.asyncio
async def test_controller_drives_real_orchestrator_to_completion(tmp_path, config):
    controller = ProductController(config, project_root=tmp_path)
    controller.models.add_profile(ProviderProfile(name="test-mock", kind="mock", locality="local"))

    seen = []
    controller.events.subscribe(lambda e: seen.append(e))

    await controller.new_assessment("127.0.0.1")
    assert controller.assessment is not None

    llm = controller.models.provider_for("planner")
    llm.script_structured(
        PlannedAction(action_type=ActionType.COMPLETE, reason_summary="nothing left to explore")
    )

    await controller.start()
    await controller.wait_idle()

    assert controller.state == ControllerState.COMPLETED
    assert any(e.type == EventType.ASSESSMENT_COMPLETED for e in seen)
    assert any(e.type == EventType.ASSESSMENT_STARTED for e in seen)


@pytest.mark.asyncio
async def test_controller_pause_continue_stop(tmp_path, config):
    controller = ProductController(config, project_root=tmp_path)
    controller.models.add_profile(ProviderProfile(name="test-mock", kind="mock", locality="local"))
    await controller.new_assessment("127.0.0.1")

    llm = controller.models.provider_for("planner")
    # Script enough COMPLETE-eventually actions; pause before starting so
    # the loop blocks immediately on the pause gate.
    llm.script_structured(
        PlannedAction(action_type=ActionType.COMPLETE, reason_summary="done")
    )

    await controller.pause()
    await controller.start()
    assert controller.state in (ControllerState.PAUSED,)

    await controller.continue_()
    await controller.wait_idle()
    assert controller.state == ControllerState.COMPLETED


def test_session_registry_roundtrip(tmp_path):
    from adi.product.sessions import SessionRegistry

    reg = SessionRegistry(tmp_path)
    record = reg.register("abc123", "localhost:3000", name="orders-api")
    assert record.name == "orders-api"

    reg2 = SessionRegistry(tmp_path)
    assert reg2.get("orders-api").assessment_id == "abc123"
    assert reg2.most_recent().name == "orders-api"


@pytest.mark.asyncio
async def test_model_manager_privacy_routing_blocks_remote_source(tmp_path):
    manager = ModelManager(tmp_path)
    manager.add_profile(ProviderProfile(name="remote", kind="mock", locality="remote"))

    from adi.product.models import PrivacyRoutingError

    with pytest.raises(PrivacyRoutingError):
        manager.provider_for("planner", data_category="source_code")

    # general planning is allowed to remote by default
    manager.provider_for("planner", data_category="general_planning")


def test_model_manager_profile_switching(tmp_path):
    manager = ModelManager(tmp_path)
    manager.add_profile(ProviderProfile(name="a", kind="mock", locality="local"))
    manager.add_profile(ProviderProfile(name="b", kind="mock", locality="local"))
    assert manager.active_profile().name == "a"
    manager.set_active("b")

    manager2 = ModelManager(tmp_path)
    assert manager2.active_profile().name == "b"


@pytest.mark.asyncio
async def test_events_bus_isolates_listener_failures():
    from adi.product.events import EventBus

    bus = EventBus()
    bus.subscribe(lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
    received = []
    bus.subscribe(lambda e: received.append(e))
    await bus.emit(EventType.NOTICE, msg="hi")
    assert len(received) == 1
