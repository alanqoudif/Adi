"""Phase 4 completion gates: real CLI processes, local HTTP and durable state."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from adi.assessment import Assessment
from adi.cli import app
from adi.config.models import AdiConfig, RuntimeConfig
from adi.evidence.models import EvidenceType
from adi.evidence.store import EvidenceStore
from adi.findings.pipeline import ConfirmationInvariantError, FindingPipeline
from adi.http.client import HTTPClient
from adi.http.sessions import SessionJarRegistry
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.hypotheses import HypothesisStatus
from adi.knowledge.workspace import Workspace
from adi.reporting.builder import ReportBuilder
from adi.reporting.json_report import write_reports
from adi.reporting.redaction import redact_structure, redact_text
from adi.reporting.teach import explain_hypothesis
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.scope.models import TestAccount as Account
from adi.validation.context import ValidationContext
from adi.validation.engine import (
    HypothesisAlreadyResolvedError,
    ValidationBudgetExhaustedError,
    ValidationEngine,
)
from adi.validation.models import ValidationAction, ValidationActionType
from adi.validation.policies import ValidationBudget

ROOT = Path(__file__).resolve().parents[2]


def load_demo():
    spec = importlib.util.spec_from_file_location("phase4_demo", ROOT / "examples" / "phase4_lab.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_complete_autonomous_cli_lab_resume_and_report_regeneration(tmp_path):
    result = load_demo().run_demo(tmp_path)
    report_dir = Path(result["report_directory"])
    ws = Workspace.open(report_dir.parent / "state.db")
    f = ws.list_findings()[0]
    h = next(h for h in ws.list_hypotheses() if h.status == "rejected")
    assert len(ws.list_endpoints()) >= 4
    assert f.confidence == pytest.approx(0.95)
    evidence = ws.get_evidence(json.loads(f.evidence_ids_json)[0])
    exchanges = json.loads(evidence.metadata_json)["http_exchange_ids"]
    assert len(exchanges) == 2
    assert set(exchanges) <= {e.id for e in ws.list_http_exchanges()}
    statuses = {e.session_id: e.status for e in ws.list_http_exchanges() if e.id in exchanges}
    assert statuses == {"user_a": 200, "user_b": 200}
    hashes = {e.body_hash for e in ws.list_http_exchanges() if e.id in exchanges}
    assert len(hashes) == 1  # equivalent protected object, not merely matching status
    teach = explain_hypothesis(ws, h.id)
    assert teach["Result"] == "Rejected"
    assert "403" in teach["Why"]
    assert "Discovery exposes" in teach["Observed"]
    assert "Compare owner" in teach["Validation"]
    report = ReportBuilder(Workspace.open(report_dir.parent / "state.db")).build()
    assert report.findings[0].evidence_ids == result["findings"][0]["evidence_ids"]
    assert report.findings[0].validation_ids
    assert len(report.positive_security_observations) == 1
    write_reports(report, report_dir)
    assert json.loads((report_dir / "report.json").read_text())["findings"][0]["remediation"]
    config = AdiConfig(runtime=RuntimeConfig(type="local", allow_local=True))
    assessment = Assessment.resume(ws.assessment_id, config, project_root=tmp_path)
    engine = assessment.build_orchestrator(__import__("adi.llm.mock", fromlist=["MockLLM"]).MockLLM()).validation_engine
    assert engine.budget.used(f.hypothesis_id) == 1
    assert engine.budget.used(h.id) == 1


@pytest.mark.parametrize("text,secret", [
    ("Authorization: Basic abcdef", "abcdef"),
    ("Cookie: arbitrary_cookie=hidden-cookie", "hidden-cookie"),
    ("Set-Cookie: custom=hidden-set-cookie; HttpOnly", "hidden-set-cookie"),
    ("Bearer tinysecret", "tinysecret"),
    ('{"api_key": "hidden-api-key"}', "hidden-api-key"),
    ('{"password": "hidden-password"}', "hidden-password"),
    ("sk-abcdefghijklmnop", "sk-abcdefghijklmnop"),
])
def test_redaction_quality_gate(text, secret):
    assert secret not in redact_text(text)
    assert secret not in json.dumps(redact_structure({"summary": text, "Authorization": secret}))
    assert "check_object_authorization: supports" == redact_text("check_object_authorization: supports")


def test_cli_and_reports_redact_all_surfaces_and_known_account_password(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LAB_CREDENTIAL", "unique-known-account-value")
    config = AdiConfig(runtime=RuntimeConfig(type="local", allow_local=True))
    scope = Scope(name="redaction", targets=["127.0.0.1"], test_accounts=[
        Account(name="user", username="user", password_env="LAB_CREDENTIAL")])
    assessment = Assessment.create(scope, config)
    secret = 'Authorization: Bearer hiddenbearervalue\nCookie: custom=hiddencookie\nSet-Cookie: custom=hiddensetcookie\napi_key=hiddenapikey\npassword=hiddenpassword\nunique-known-account-value'
    ws = assessment.workspace
    h = FindingPipeline(ws, EvidenceStore(ws)).hypothesis_engine.create(title=secret, category="missing_security_header")
    ev = EvidenceStore(ws).create(EvidenceType.CONFIGURATION, source="test", summary=secret,
                                  subject=secret, raw_text=secret, related_hypothesis_ids=[h.id])
    ws.create_finding(title=secret, status="supported", summary=secret, hypothesis_id=h.id,
                      evidence_ids_json=json.dumps([ev.id]), remediation=secret)
    runner = CliRunner()
    for args in (("status",), ("resume",), ("evidence",), ("evidence", "EV-001"),
                 ("hypotheses",), ("hypothesis", "ADI-H-001"), ("findings",),
                 ("finding", "ADI-F-001"), ("teach", "ADI-H-001"), ("report",)):
        command = [args[0], assessment.id, *args[1:]]
        rendered = runner.invoke(app, command)
        assert rendered.exit_code == 0, rendered.output
        for value in ("hiddenbearervalue", "hiddencookie", "hiddensetcookie", "hiddenapikey", "hiddenpassword", "unique-known-account-value"):
            assert value not in rendered.output
    for path in (assessment.directory / "reports").iterdir():
        for value in ("hiddenbearervalue", "hiddencookie", "hiddensetcookie", "hiddenapikey", "hiddenpassword", "unique-known-account-value"):
            assert value not in path.read_text()
    assert runner.invoke(app, ["report", assessment.id, "--format", "bad"]).exit_code != 0


@pytest.mark.asyncio
async def test_no_orphan_confirmation_without_authorized_validation(tmp_path):
    ws = Workspace.create(tmp_path / "state.db", Scope(name="orphan", targets=["127.0.0.1"]))
    store = EvidenceStore(ws)
    pipeline = FindingPipeline(ws, store)
    h = pipeline.hypothesis_engine.create(title="critical model claim", category="broken_object_authorization")
    ev = store.create(EvidenceType.HTTP_EXCHANGE, source="test", summary="claim", related_hypothesis_ids=[h.id])
    pipeline.hypothesis_engine.transition(h.id, HypothesisStatus.INVESTIGATING,
                                         new_supporting_observation_ids=[ev.id])
    with pytest.raises(ConfirmationInvariantError):
        await pipeline.finalize(h.id)
    assert not ws.list_findings()


@pytest.mark.asyncio
async def test_validation_budget_survives_restart_and_scope_permission_is_required(tmp_path):
    demo = load_demo().DemoApp().start()
    try:
        ws = Workspace.create(tmp_path / "state.db", Scope(name="budget", targets=["127.0.0.1"]))
        store = EvidenceStore(ws)
        http = HTTPWorkspace(HTTPClient(ScopeEngine(ws.load_scope()), SessionJarRegistry()), ws, tmp_path / "evidence")
        engine = ValidationEngine(ValidationContext(http, store, ws), ValidationBudget(max_actions_per_hypothesis=1))
        h = engine.hypothesis_engine.create(title="safe auth", category="missing_authentication")
        action = ValidationAction(action_type=ValidationActionType.CHECK_AUTH_BOUNDARY, hypothesis_id=h.id,
                                  parameters={"url": demo.base_url + "/api/private"})
        await engine.execute(action)
        resumed_ws = Workspace.open(tmp_path / "state.db")
        resumed = ValidationEngine(ValidationContext(http, EvidenceStore(resumed_ws), resumed_ws))
        assert resumed.budget.used(h.id) == 1
        with pytest.raises(ValidationBudgetExhaustedError):
            await resumed.execute(action)
        assert len(resumed_ws.list_validation_actions()) == 1
        await FindingPipeline(resumed_ws, EvidenceStore(resumed_ws)).finalize(h.id)
        with pytest.raises(HypothesisAlreadyResolvedError):
            await resumed.execute(action)
        other = resumed.hypothesis_engine.create(title="outside scope")
        with pytest.raises(ValueError, match="outside scope"):
            await resumed.execute(action.model_copy(update={"hypothesis_id": other.id, "parameters": {"url": "http://example.invalid"}}))
    finally:
        demo.stop()


@pytest.mark.asyncio
async def test_severity_gate_hardening_and_model_critical_claim(tmp_path):
    demo = load_demo().DemoApp().start()
    try:
        ws = Workspace.create(tmp_path / "state.db", Scope(name="severity", targets=["127.0.0.1"]))
        store = EvidenceStore(ws)
        http = HTTPWorkspace(HTTPClient(ScopeEngine(ws.load_scope()), SessionJarRegistry()), ws, tmp_path / "evidence")
        engine = ValidationEngine(ValidationContext(http, store, ws))
        h = engine.hypothesis_engine.create(title="CRITICAL!!! Missing security headers", category="missing_security_header", confidence=1.0)
        await engine.execute(ValidationAction(action_type=ValidationActionType.CHECK_SECURITY_HEADER,
                                             hypothesis_id=h.id, parameters={"url": demo.base_url}))
        pipeline = FindingPipeline(ws, store)
        first = await pipeline.finalize(h.id, affected_endpoints=["/"])
        f = ws.get_finding(first.finding_id)
        assert f.severity in ("info", "low")
        again = await pipeline.finalize(h.id)
        assert again.finding_id == first.finding_id
        assert len(ws.list_findings()) == 1
        assert len(ws.list_validation_actions()) == 1
    finally:
        demo.stop()


def test_checkpoint_database_additive_upgrade_is_conservative(tmp_path):
    import sqlite3
    ws = Workspace.create(tmp_path / "state.db", Scope(name="checkpoint", targets=["127.0.0.1"]))
    h = FindingPipeline(ws, EvidenceStore(ws)).hypothesis_engine.create(title="legacy record")
    ws.record_validation_action(hypothesis_id=h.id, action_type="check_auth_boundary", outcome="supports")
    with sqlite3.connect(tmp_path / "state.db") as connection:
        connection.execute("ALTER TABLE validation_action DROP COLUMN scope_allowed")
        connection.execute("DROP TABLE positive_observation")
        connection.execute("DROP TABLE validation_budget")
    resumed = Workspace.open(tmp_path / "state.db")
    assert resumed.list_validation_actions()[0].scope_allowed is False
    assert resumed.list_positive_observations() == []
    assert resumed.validation_limit(h.id) == 8
