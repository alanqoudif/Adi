"""Phase 5 acceptance: real loopback HTTP, bounded source and honest tool fixtures."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'examples'))
from phase5_lab import FIXTURE, Phase5Lab

from adi.actions import ActionType, PlannedAction
from adi.agent.critic import Critic, CriticDecision, CriticReview
from adi.assessment import Assessment, discover_skills_dir
from adi.cli import app
from adi.config.models import AdiConfig
from adi.evidence.store import EvidenceStore
from adi.findings.pipeline import FindingPipeline
from adi.http.client import HTTPClient
from adi.http.sessions import SessionJarRegistry
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.workspace import Workspace
from adi.llm.mock import MockLLM
from adi.reporting.builder import ReportBuilder
from adi.reporting.json_report import write_reports
from adi.reporting.teach import explain_hypothesis
from adi.scope.engine import ScopeEngine
from adi.scope.models import Permissions, Scope
from adi.scope.models import TestAccount as Account
from adi.source.repository import SourceWorkspace
from adi.source.scanners import SourceScanner
from adi.tools.registry import ToolRegistry
from adi.validation.context import ValidationContext
from adi.validation.engine import ValidationEngine
from adi.validation.models import ValidationAction, ValidationActionType


@pytest.fixture
def lab():
    pytest.importorskip('fastapi')
    pytest.importorskip('uvicorn')
    with Phase5Lab() as lab:
        yield lab


def stack(tmp_path, base):
    scope = Scope(name='phase5', targets=[base], permissions=Permissions(authentication_testing=True),
        test_accounts=[Account(name=n, username=n) for n in ('user_a', 'user_b')],
        notes=['Local controlled object 1 is owned by user_a; object 2 by user_b.'])
    ws = Workspace.create(tmp_path / 'state.db', scope)
    http = HTTPWorkspace(HTTPClient(ScopeEngine(scope), SessionJarRegistry()), ws, tmp_path / 'evidence')
    store = EvidenceStore(ws)
    engine = ValidationEngine(ValidationContext(http, store, ws))
    source = SourceWorkspace(ws)
    source.index(FIXTURE, base)
    llm = MockLLM()
    llm.script_structured(CriticReview(decision=CriticDecision.ACCEPT))
    return ws, http, source, engine, FindingPipeline(ws, store, Critic(llm))


async def login(http, base):
    for name in ('user_a', 'user_b'):
        await http.fetch('POST', base + '/api/login?username=' + name, session_id=name)


@pytest.mark.asyncio
async def test_source_runtime_confirm_safe_reject_trace_report_resume(tmp_path, lab):
    ws, http, source, engine, pipeline = stack(tmp_path, lab.base_url)
    await login(http, lab.base_url)
    for path in ('/api/orders/1', '/api/orders-safe/1'):
        await http.fetch('GET', lab.base_url + path, session_id='user_a')
    correlations = source.correlate()
    assert len(correlations) == 3
    assert all(c.confidence >= 0.95 for c in correlations)
    assert sum(c.method == 'GET' for c in correlations) == 2
    snapshot = source.require_current()
    assert snapshot.repository.frameworks[0].name == 'FastAPI'
    results = {}
    for source_h in snapshot.hypotheses:
        route = next(r for r in snapshot.routes if r.id == source_h.route_id)
        path = route.path.replace('{id}', '1')
        result = await engine.execute(ValidationAction(
            action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION,
            hypothesis_id=source_h.hypothesis_id,
            parameters={'url': lab.base_url + path, 'owner_session': 'user_a', 'other_session': 'user_b'},
        ))
        finalized = await pipeline.finalize(source_h.hypothesis_id, affected_endpoints=[path])
        results[path] = (result, finalized)
    assert results['/api/orders/1'][0].outcome.value == 'supports'
    assert results['/api/orders/1'][1].critic_decision == CriticDecision.ACCEPT
    assert results['/api/orders-safe/1'][0].outcome.value == 'refutes'
    assert results['/api/orders-safe/1'][1].hypothesis_status.value == 'rejected'
    findings = ws.list_findings()
    assert len(findings) == 1 and findings[0].status == 'confirmed'
    finding = findings[0]
    assert finding.severity == 'high'
    assert finding.critic_review_id
    assert 'get_order' in finding.remediation
    evidence = [ws.get_evidence(eid) for eid in json.loads(finding.evidence_ids_json)]
    assert all(e is not None and finding.hypothesis_id in json.loads(e.related_hypothesis_ids_json) for e in evidence)
    assert any(e.type == 'source_snippet' for e in evidence)
    runtime = [e for e in evidence if e.type == 'http_exchange']
    assert runtime and all(json.loads(e.metadata_json)['http_exchange_ids'] for e in runtime)
    validation = ws.list_validation_actions(finding.hypothesis_id)[0]
    assert validation.scope_allowed and validation.outcome == 'supports'
    assert ws.get_critic_review(finding.critic_review_id).decision == 'accept'
    assert ws.list_positive_observations()
    before = source.require_current().repository.indexed_at
    resumed = SourceWorkspace(Workspace.open(tmp_path / 'state.db', ws.assessment_id))
    assert resumed.index(FIXTURE, lab.base_url).repository.indexed_at == before
    assert len(resumed.require_current().correlations) == 3
    assert resumed.require_current().root_causes[0].source_locations
    report = ReportBuilder(ws).build()
    paths = write_reports(report, tmp_path / 'reports')
    text = paths['markdown'].read_text()
    for fragment in ('Root Cause', 'Source Evidence', 'Runtime Evidence', 'Remediation', 'src/routes/orders.py', 'src/services/orders.py'):
        assert fragment in text
    assert report.findings[0].source_locations
    lesson = explain_hypothesis(ws, finding.hypothesis_id)
    assert lesson['Source pattern'] and '/api/orders/1' in lesson['Runtime mapping']


@pytest.mark.asyncio
async def test_real_semgrep_false_positive_secret_dependency_and_redaction(tmp_path, lab):
    ws, _http, source, _engine, _pipeline = stack(tmp_path, lab.base_url)
    registry = ToolRegistry(discover_skills_dir())
    registry.discover()
    scanner = SourceScanner(ws, registry)
    tool = registry.get('semgrep')
    if tool.available:
        result = await scanner.scan('scan_source_patterns')
        assert result['status'] == 'completed', source.load().diagnostics
        assert result['results'] == 1
        before = len(ws.list_actions())
        assert await scanner.scan('scan_source_patterns') == result
        assert len(ws.list_actions()) == before
    else:
        scanner.import_result('semgrep', json.loads((discover_skills_dir() / 'semgrep/fixtures/result.json').read_text()), provenance='acceptance_fixture')
    snapshot = source.require_current()
    assert len(snapshot.indications) == 1
    reviewed = scanner.review_indication(snapshot.indications[0].evidence_id)
    assert reviewed.status == 'rejected'
    assert not ws.list_findings()
    for name in ('gitleaks', 'osv-scanner', 'trivy'):
        scanner.import_result(name, json.loads((discover_skills_dir() / name / 'fixtures/result.json').read_text()), provenance='acceptance_fixture')
    snapshot = source.require_current()
    assert len(snapshot.secrets) == 1
    secret = snapshot.secrets[0]
    assert secret.status.value == 'confirmed_present' and secret.fingerprint and secret.test_only
    assert len(snapshot.vulnerabilities) == 1
    dep = snapshot.vulnerabilities[0]
    assert dep.status == 'KNOWN_AFFECTED_DEPENDENCY' and dep.runtime_exploitability == 'not_validated'
    assert dep.fixed_version == '1.0.1'
    assert not ws.list_findings()
    report = ReportBuilder(ws).build()
    paths = write_reports(report, tmp_path / 'reports')
    raw_secret = (FIXTURE / '.env.example').read_text().split('"')[1]
    assert raw_secret not in (tmp_path / 'state.db').read_bytes().decode('utf-8', errors='ignore')
    assert all(raw_secret not in p.read_text() for p in paths.values())
    assert raw_secret not in snapshot.model_dump_json()
    assert 'Known Affected Dependencies' in paths['markdown'].read_text()
    assert 'ADI-TEST-001' in paths['markdown'].read_text()


@pytest.mark.asyncio
async def test_autonomous_source_actions_and_cli(tmp_path, lab, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = AdiConfig.model_validate({'runtime': {'type': 'mock'}})
    assessment = Assessment.create(Scope(name='source loop', targets=[lab.base_url]), config)
    source = SourceWorkspace(assessment.workspace)
    source.index(FIXTURE, lab.base_url)
    llm = MockLLM()
    llm.script_structured(
        PlannedAction(action_type=ActionType.SOURCE_ACTION, capability='retrieve_source_context',
                      parameters={'path': '/api/orders/{id}'}),
        PlannedAction(action_type=ActionType.HTTP_REQUEST, target=lab.base_url + '/api/orders/1'),
        PlannedAction(action_type=ActionType.SOURCE_ACTION, capability='correlate_source_runtime'),
        PlannedAction(action_type=ActionType.GENERATE_REPORT),
        PlannedAction(action_type=ActionType.COMPLETE),
    )
    outcomes = await assessment.build_orchestrator(llm).run()
    assert all(o.status in ('completed', 'completed_assessment') for o in outcomes)
    assert source.require_current().correlations
    assert 'Retrieved source slices' in assessment.build_orchestrator(MockLLM()).context_builder.build().render()
    monkeypatch.setattr('adi.cli.load_config', lambda: config)
    runner = CliRunner()
    for args in (['source', assessment.id], ['routes', assessment.id], ['source-search', assessment.id, 'find_order'],
                 ['correlations', assessment.id], ['status', assessment.id]):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
        assert 'adi_fake_test_secret_not_a_valid_external_credential_12345' not in result.output


@pytest.mark.asyncio
async def test_runtime_to_source_investigation_preserves_runtime_hypothesis(tmp_path, lab):
    ws, http, source, engine, pipeline = stack(tmp_path, lab.base_url)
    await login(http, lab.base_url)
    runtime_h = engine.hypothesis_engine.create('Runtime BOLA suspicion', category='broken_object_authorization')
    await engine.execute(ValidationAction(action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION,
        hypothesis_id=runtime_h.id, parameters={'url': lab.base_url + '/api/orders/1',
                                               'owner_session': 'user_a', 'other_session': 'user_b'}))
    source.correlate()
    result = await pipeline.finalize(runtime_h.id, affected_endpoints=['/api/orders/1'])
    finding = ws.get_finding(result.finding_id)
    assert finding.hypothesis_id == runtime_h.id
    root = source.require_current().root_causes[0]
    assert root.finding_id == finding.id
    assert any(loc.file == 'src/services/orders.py' for loc in root.source_locations)
    assert any(e.type == 'source_snippet' and runtime_h.id in json.loads(e.related_hypothesis_ids_json)
               for e in ws.list_evidence())


@pytest.mark.asyncio
async def test_source_suspicion_alone_cannot_confirm(tmp_path, lab):
    ws, _http, source, engine, pipeline = stack(tmp_path, lab.base_url)
    hyp = source.require_current().hypotheses[0]
    with pytest.raises(ValueError, match='authorized test accounts'):
        await engine.execute(ValidationAction(action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION,
            hypothesis_id=hyp.hypothesis_id, parameters={'url': lab.base_url + '/api/orders/1',
                                                       'owner_session': 'user_a', 'other_session': 'unapproved'}))
    assert not ws.list_http_exchanges()
    result = await pipeline.finalize(hyp.hypothesis_id, affected_endpoints=['/api/orders/1'])
    assert result.hypothesis_status.value != 'confirmed'
    assert not ws.list_findings()
