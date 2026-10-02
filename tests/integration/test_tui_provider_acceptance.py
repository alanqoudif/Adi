"""Onboarding to HTTP planner to real Core, runtime, evidence and TUI events."""
import importlib.util
import json
from pathlib import Path

import pytest

from adi.config.models import AdiConfig, RuntimeConfig
from adi.product import credentials
from adi.product.controller import ControllerState
from adi.product.events import EventType
from adi.product.tui.app import AdiApp


def _load_demo_module():
    path = Path(__file__).parents[2] / 'examples' / 'phase4_lab.py'
    spec = importlib.util.spec_from_file_location('tui_provider_demo', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_tui_setup_to_orchestrator_runtime_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv('ADI_CONFIG_HOME', str(tmp_path / 'keys'))
    monkeypatch.setattr(credentials, 'keyring_available', lambda: False)
    demo = _load_demo_module()
    target = demo.DemoApp().start()
    prefix = [demo.action('run_tool', 'Fingerprint the controlled local target through capability resolution.',
                          capability='fingerprint_web_application', target=target.base_url)]
    try:
        with demo.PlannerFixture(target.base_url, prefix_actions=prefix) as provider_url:
            app = AdiApp(AdiConfig(runtime=RuntimeConfig(type='mock')), tmp_path)
            async with app.run_test() as pilot:
                widget = app.query_one('#input')
                async def submit(value):
                    widget.value = value
                    await pilot.press('enter')
                    await pilot.pause()
                await submit('/provider')
                await submit('/provider add')
                for value in ['7', 'fixture', provider_url, 'fixture-secret-private', '1', 'y']:
                    await submit(value)
                assert app.shell.controller.models.active_profile().name == 'fixture'
                await submit('/provider')
                await submit('/models')
                await submit('/model fixture-alternate')
                assert 'fixture-alternate' in str(app.query_one('#side').render())
                await submit('/new ' + target.base_url)
                assessment = app.shell.controller.assessment
                assessment.registry.get('whatweb').available = True
                fixture = Path(__file__).parents[1] / 'fixtures' / 'whatweb' / 'scan.json'
                assessment.runtime.script(['whatweb'], stdout=fixture.read_text())
                await submit('Inspect the controlled application and its authorization boundaries')
                await app.shell.controller.wait_idle()
                await pilot.pause()
                assert app.shell.controller.state == ControllerState.COMPLETED
                assert assessment.runtime.calls, 'CapabilityResolver selected a real runtime adapter'
                assert assessment.workspace.list_evidence()
                assert len(assessment.workspace.list_findings()) == 1
                assert any(e.type == EventType.TOOL_COMPLETED for e in app.shell.controller.events.history)
                assert any(e.type == EventType.ASSESSMENT_COMPLETED for e in app.shell.controller.events.history)
                await submit('/report')
                secret = b'fixture-secret-private'
                assert secret.decode() not in repr(app.shell.controller.events.history)
                for file in assessment.directory.rglob('*'):
                    if file.is_file():
                        assert secret not in file.read_bytes(), file
                assert secret not in app.shell.controller.models.path.read_bytes()
                assert json.loads(app.shell.controller.models.path.read_text())['profiles']['fixture']['credential_ref'] == 'keyring'
    finally:
        target.stop()
