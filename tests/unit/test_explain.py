from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from adi.config.models import AdiConfig, RuntimeConfig
from adi.product.controller import ControllerState, ProductController
from adi.product.explain import build_evidence_trace, explain_why
from adi.product.models import ProviderProfile

ROOT = Path(__file__).resolve().parents[2]


def _load_demo_module():
    spec = importlib.util.spec_from_file_location("phase4_demo_explain", ROOT / "examples" / "phase4_lab.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_trace_and_why_over_a_real_confirmed_finding(tmp_path):
    demo = _load_demo_module()
    app = demo.DemoApp().start()
    config = AdiConfig(runtime=RuntimeConfig(type="mock"))

    with demo.PlannerFixture(app.base_url) as fixture_url:
        controller = ProductController(config, project_root=tmp_path)
        controller.models.add_profile(ProviderProfile(
            name="fixture", kind="openai-compatible", base_url=fixture_url,
            model="deterministic-phase4-fixture", locality="local",
        ))
        await controller.new_assessment(app.base_url, max_actions=60)
        await controller.start()
        await controller.wait_idle()
        assert controller.state == ControllerState.COMPLETED

        ws = controller.assessment.workspace
        finding = ws.list_findings()[0]

        trace = build_evidence_trace(ws, finding.id)
        assert trace is not None
        lines = trace.render_lines()
        assert any("Finding" in l for l in lines)
        assert any("Hypothesis" in l for l in lines)
        assert any("Evidence" in l for l in lines)

        explanation = explain_why(ws, finding.id)
        assert finding.title in explanation

        hyp = next(h for h in ws.list_hypotheses() if h.status == "rejected")
        rejected_explanation = explain_why(ws, hyp.id)
        assert "rejected" in rejected_explanation.lower() or hyp.status in rejected_explanation

        assert "No action" in explain_why(ws, "nonexistent-id")


def test_build_evidence_trace_unknown_finding_returns_none(tmp_path):
    from adi.assessment import Assessment
    from adi.scope.models import Scope

    config = AdiConfig(runtime=RuntimeConfig(type="mock"))
    assessment = Assessment.create(Scope(name="x", targets=["127.0.0.1"]), config, tmp_path)
    assert build_evidence_trace(assessment.workspace, "nonexistent") is None
