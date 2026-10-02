from __future__ import annotations

import pytest

from adi.config.models import AdiConfig, RuntimeConfig
from adi.product.controller import ProductController
from adi.product.events import EventType


@pytest.mark.asyncio
async def test_resume_marks_dangling_planned_action_interrupted(tmp_path):
    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    controller = ProductController(config, project_root=tmp_path)
    await controller.new_assessment("127.0.0.1")
    session_name = controller.session_name
    assessment_id = controller.assessment.id

    # Simulate a crash mid-tool-execution: an action recorded as
    # 'planned' that never reached update_action_result.
    controller.assessment.workspace.record_action(
        action_type="run_tool", capability="enumerate_services", target="127.0.0.1",
        parameters_json="{}", reason_summary="in-flight when the process died",
        scope_allowed=True, scope_reason="within scope", status="planned",
    )
    controller.assessment.workspace.set_assessment_status("running")

    # A brand new controller/process attaches via resume — this is what
    # happens on `adi shell` restart after an unexpected termination.
    controller2 = ProductController(config, project_root=tmp_path)
    seen = []
    controller2.events.subscribe(lambda e: seen.append(e))
    await controller2.resume_assessment(session_name)

    actions = controller2.assessment.workspace.list_actions()
    assert any(a.status == "interrupted" for a in actions)
    assert controller2.assessment.workspace.assessment_status() == "interrupted"
    assert any(e.type == EventType.NOTICE and "interrupted" in e.data.get("detail", "") for e in seen)


@pytest.mark.asyncio
async def test_resume_with_no_dangling_actions_is_silent(tmp_path):
    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    controller = ProductController(config, project_root=tmp_path)
    await controller.new_assessment("127.0.0.1")
    session_name = controller.session_name

    controller2 = ProductController(config, project_root=tmp_path)
    seen = []
    controller2.events.subscribe(lambda e: seen.append(e))
    await controller2.resume_assessment(session_name)

    assert not any(e.type == EventType.NOTICE for e in seen)
