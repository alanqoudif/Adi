from __future__ import annotations

from adi.config.models import AdiConfig, RuntimeConfig
from adi.product.console import ExpertConsole
from adi.scope.models import Scope


def _assessment(tmp_path):
    from adi.assessment import Assessment

    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    scope = Scope(name="x", targets=["127.0.0.1"])
    return Assessment.create(scope, config, tmp_path)


def test_list_tools_and_capabilities(tmp_path):
    assessment = _assessment(tmp_path)
    console = ExpertConsole(assessment)
    tools = console.list_tools()
    assert isinstance(tools, list) and len(tools) > 0
    assert all("capabilities" in t for t in tools)

    caps = console.list_capabilities()
    assert isinstance(caps, list) and len(caps) > 0
    assert all("id" in c for c in caps)


def test_describe_unknown_tool_and_capability_return_none(tmp_path):
    assessment = _assessment(tmp_path)
    console = ExpertConsole(assessment)
    assert console.describe_tool("nonexistent-tool-xyz") is None
    assert console.describe_capability("nonexistent-capability-xyz") is None


def test_preview_enumerate_services(tmp_path):
    assessment = _assessment(tmp_path)
    console = ExpertConsole(assessment)
    preview = console.preview("enumerate_services", "127.0.0.1")
    assert preview.capability == "enumerate_services"
    assert preview.target == "127.0.0.1"
    lines = preview.render_lines()
    assert any("Capability:" in l for l in lines)


def test_preview_out_of_scope_host_is_reported(tmp_path):
    assessment = _assessment(tmp_path)
    console = ExpertConsole(assessment)
    preview = console.preview("enumerate_services", "evil.example.com")
    assert "not within the authorized scope" in preview.scope_reason


async def test_execute_prohibited_capability_blocked(tmp_path):
    assessment = _assessment(tmp_path)
    console = ExpertConsole(assessment)
    result = await console.execute("password_spray", "127.0.0.1")
    assert result.ok is False
