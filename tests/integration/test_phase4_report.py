"""Mandatory Phase 4 report test (spec section 12): a confirmed finding
appears, a rejected hypothesis is never listed as confirmed, a positive
security observation appears, severity/remediation/evidence/critic are
present, secrets are redacted, JSON parses, and files are actually written.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures" / "webapp"))
from app import DemoApp

from adi.agent.critic import Critic, CriticDecision, CriticReview
from adi.evidence.store import EvidenceStore
from adi.findings.pipeline import FindingPipeline
from adi.http.client import HTTPClient
from adi.http.sessions import SessionJarRegistry
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.workspace import Workspace
from adi.llm.mock import MockLLM
from adi.reporting.builder import ReportBuilder
from adi.reporting.json_report import write_reports
from adi.reporting.models import Report
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.validation.context import ValidationContext
from adi.validation.engine import ValidationEngine
from adi.validation.models import ValidationAction, ValidationActionType


@pytest.fixture()
def demo_app():
    app = DemoApp().start()
    yield app
    app.stop()


async def _login(http_ws, base, username):
    await http_ws.fetch("POST", base + "/api/login", session_id=username, body=f"username={username}")


@pytest.mark.asyncio
async def test_mandatory_report_reflects_confirmed_rejected_and_positive_controls(tmp_path, demo_app):
    scope = Scope(name="phase4-report-test", targets=["127.0.0.1"])
    workspace = Workspace.create(tmp_path / "state.db", scope)
    scope_engine = ScopeEngine(scope)
    http_ws = HTTPWorkspace(HTTPClient(scope_engine, SessionJarRegistry()), workspace, tmp_path / "evidence")
    store = EvidenceStore(workspace)
    engine = ValidationEngine(ValidationContext(http_ws, store, workspace))

    llm = MockLLM()
    llm.script_structured(CriticReview(decision=CriticDecision.ACCEPT))
    pipeline = FindingPipeline(workspace, store, critic=Critic(llm))

    await _login(http_ws, demo_app.base_url, "user_a")
    await _login(http_ws, demo_app.base_url, "user_b")

    # CONFIRMED: broken object authorization
    broken_hyp = engine.hypothesis_engine.create(
        title="possible broken object authorization on /api/orders-broken/1",
        category="broken_object_authorization",
    )
    await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=broken_hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-broken/1",
                    "owner_session": "user_a", "other_session": "user_b"},
    ))
    confirmed = await pipeline.finalize(broken_hyp.id, affected_endpoints=["/api/orders-broken/1"])
    assert confirmed.finding_id is not None

    # REJECTED: the safe endpoint, correctly denied
    safe_hyp = engine.hypothesis_engine.create(
        title="possible broken object authorization on /api/orders-safe/1",
        category="broken_object_authorization",
    )
    safe_result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=safe_hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-safe/1",
                    "owner_session": "user_a", "other_session": "user_b"},
    ))
    assert safe_result.outcome.value == "refutes"
    rejected = await pipeline.finalize(safe_hyp.id, affected_endpoints=["/api/orders-safe/1"])
    assert rejected.finding_id is None

    # a sensitive, insecure cookie for the redaction check
    await http_ws.fetch("POST", demo_app.base_url + "/api/login", session_id="user_c", body="username=admin",
                         headers={"Authorization": "Bearer sk-supersecrettoken1234567890"})

    # --- build and write the report ---
    report = ReportBuilder(workspace).build()
    out_dir = tmp_path / "reports"
    paths = write_reports(report, out_dir)

    assert paths["markdown"].exists()
    assert paths["json"].exists()
    md = paths["markdown"].read_text()
    raw_json = paths["json"].read_text()

    # JSON parses and round-trips through the schema
    parsed = json.loads(raw_json)
    Report.model_validate(parsed)

    # confirmed finding appears, with severity + remediation + evidence + critic
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.severity == "high"
    assert f.remediation
    assert f.evidence_ids
    assert set(f.evidence_ids) <= {e.display_id for e in report.evidence_index}
    assert f.validation_ids
    assert "accept" in f.critic_summary.lower()
    assert f.display_id in md
    assert "Broken object authorization" not in [h.title for h in report.rejected_hypotheses]  # sanity

    # the rejected hypothesis is NOT listed among confirmed findings
    confirmed_titles = [x.title for x in report.findings]
    assert safe_hyp.title not in confirmed_titles
    assert any(h.title == safe_hyp.title for h in report.rejected_hypotheses)
    assert "/api/orders-safe/1" in md  # appears in the rejected section, not findings

    # positive security observation recorded and rendered
    assert len(report.positive_security_observations) >= 1
    assert any("denied" in p.summary.lower() for p in report.positive_security_observations)
    assert report.positive_security_observations[0].display_id in md

    # secrets never appear unredacted anywhere in either rendered file
    for blob in (md, raw_json):
        assert "sk-supersecrettoken1234567890" not in blob
        assert "user_a" in blob or "user_b" in blob  # session NAMES are fine, not secrets
