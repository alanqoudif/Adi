"""Deterministic, local, headless Product Shell acceptance test.

No public target, no external provider. Reuses the exact Phase 4 fixtures
(`DemoApp` — a local controlled web app; `PlannerFixture` — a scripted,
HTTP-served, OpenAI-compatible-shaped LLM fixture, not a real model) but
drives them through the *Product layer* (`ProductController`,
`ExpertConsole`, `PlainShell`) instead of the bare CLI/Orchestrator, to
prove the product sits transparently above the real Core rather than
duplicating it.

Flow (mirrors the spec's "Full Product Acceptance Test"):
  fresh profile -> configure fixture provider -> attach project -> new
  assessment against the local fixture app -> ProductController drives
  the real Orchestrator -> source/runtime correlation N/A (no bound repo
  here; covered separately) -> hypothesis created -> one rejected, one
  confirmed (controlled broken-object-authorization fixture) -> finding
  visible via /findings -> evidence trace visible via /evidence -> report
  generated -> process "restarts" (new ProductController instance) ->
  resume by session name -> same finding/evidence restored.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from adi.config.models import AdiConfig, RuntimeConfig
from adi.product.console import ExpertConsole
from adi.product.controller import ControllerState, ProductController
from adi.product.models import ProviderProfile

ROOT = Path(__file__).resolve().parents[2]


def _load_demo_module():
    spec = importlib.util.spec_from_file_location("phase4_demo_product", ROOT / "examples" / "phase4_lab.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_full_product_shell_acceptance_flow(tmp_path):
    demo = _load_demo_module()
    app = demo.DemoApp().start()

    config = AdiConfig(runtime=RuntimeConfig(type="mock"))

    with demo.PlannerFixture(app.base_url) as fixture_url:
        controller = ProductController(config, project_root=tmp_path)
        controller.models.add_profile(
            ProviderProfile(
                name="fixture", kind="openai-compatible", base_url=fixture_url,
                model="deterministic-phase4-fixture", locality="local",
            )
        )

        # -- new assessment against the local fixture target --------------
        await controller.new_assessment(app.base_url, max_actions=60)
        session_name = controller.session_name
        assert controller.assessment is not None

        await controller.start()
        await controller.wait_idle()

        assert controller.state == ControllerState.COMPLETED

        ws = controller.assessment.workspace
        findings = ws.list_findings()
        hypotheses = ws.list_hypotheses()
        assert len(findings) == 1
        assert findings[0].severity == "high"
        rejected = [h for h in hypotheses if h.status == "rejected"]
        assert len(rejected) == 1

        # -- findings/evidence/hypotheses visible through the Product layer
        evidence_items = ws.list_evidence()
        assert len(evidence_items) >= 1
        linked_evidence_ids = json.loads(findings[0].evidence_ids_json)
        assert linked_evidence_ids, "confirmed finding must carry an evidence trace"
        evidence = ws.get_evidence(linked_evidence_ids[0])
        assert evidence is not None
        assert evidence.sanitized_preview is not None  # trace is inspectable, not opaque

        # -- expert console surfaces the same tool/capability data ----------
        console = ExpertConsole(controller.assessment)
        tools = console.list_tools()
        assert len(tools) > 0
        caps = console.list_capabilities()
        assert any(c["id"] for c in caps)

        # -- report generation ------------------------------------------
        from adi.reporting.builder import ReportBuilder
        from adi.reporting.json_report import write_reports

        report = ReportBuilder(controller.assessment.workspace).build()
        paths = write_reports(report, controller.assessment.directory / "reports")
        report_data = json.loads(Path(paths["json"]).read_text())
        assert len(report_data["findings"]) == 1
        assert len(report_data["rejected_hypotheses"]) == 1

        assessment_id = controller.assessment.id

    # -- "process restart": a brand-new controller resumes by session name
    controller2 = ProductController(config, project_root=tmp_path)
    await controller2.resume_assessment(session_name)
    assert controller2.assessment.id == assessment_id

    ws2 = controller2.assessment.workspace
    assert len(ws2.list_findings()) == 1
    assert ws2.list_findings()[0].id == findings[0].id
    assert len(ws2.list_evidence()) == len(evidence_items)

    # The session registry survived the "restart" too.
    assert controller2.sessions.get(session_name).assessment_id == assessment_id
