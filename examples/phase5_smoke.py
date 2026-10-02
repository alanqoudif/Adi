"""Full local Phase 5 demo. Real HTTP/Semgrep, scripted LLM, labeled scanner fixtures."""
from __future__ import annotations

import asyncio
import json

from phase5_lab import FIXTURE, Phase5Lab

from adi.actions import ActionType, PlannedAction
from adi.agent.critic import CriticDecision, CriticReview
from adi.assessment import Assessment, discover_skills_dir
from adi.config.models import AdiConfig
from adi.config.settings import load_config
from adi.llm.mock import MockLLM
from adi.llm.router import ProviderNotConfiguredError, build_provider
from adi.reporting.builder import ReportBuilder
from adi.reporting.ids import display_id_map
from adi.reporting.json_report import write_reports
from adi.scope.models import Permissions, Scope
from adi.scope.models import TestAccount as Account
from adi.source.repository import SourceWorkspace
from adi.source.scanners import SourceScanner


def source_action(capability, parameters=None):
    return PlannedAction(action_type=ActionType.SOURCE_ACTION, capability=capability,
        parameters=parameters or {}, reason_summary='Inspect bounded operator-owned local source evidence.')


async def demo(lab):
    config = AdiConfig.model_validate({'runtime': {'type': 'mock'}})
    scope = Scope(name='Phase 5 source/runtime acceptance', targets=[lab.base_url],
        permissions=Permissions(authentication_testing=True),
        test_accounts=[Account(name=n, username=n) for n in ('user_a', 'user_b')],
        notes=['Fixture mapping: user_a owns order 1; user_b owns order 2. Local-only fake credentials.'])
    assessment = Assessment.create(scope, config)
    source = SourceWorkspace(assessment.workspace)
    snapshot = source.index(FIXTURE, lab.base_url)
    scanner = SourceScanner(assessment.workspace, assessment.registry)
    scan = await scanner.scan('scan_source_patterns')
    if scan['status'] != 'completed':
        scanner.import_result('semgrep', json.loads((discover_skills_dir() / 'semgrep/fixtures/result.json').read_text()), provenance='acceptance_fixture')
    for name in ('gitleaks', 'osv-scanner', 'trivy'):
        scanner.import_result(name, json.loads((discover_skills_dir() / name / 'fixtures/result.json').read_text()), provenance='acceptance_fixture')
    indication = source.require_current().indications[0]
    actions = [source_action('discover_source_routes'),
        source_action('retrieve_source_context', {'path': '/api/orders/{id}'}),
        source_action('review_source_indication', {'evidence_id': indication.evidence_id})]
    for name in ('user_a', 'user_b'):
        actions.append(PlannedAction(action_type=ActionType.HTTP_REQUEST,
            target=lab.base_url + '/api/login?username=' + name,
            parameters={'method': 'POST', 'session_id': name}, reason_summary='Authenticate authorized local test identity.'))
    for path in ('/api/orders/1', '/api/orders-safe/1'):
        actions.append(PlannedAction(action_type=ActionType.HTTP_REQUEST,
            target=lab.base_url + path, parameters={'session_id': 'user_a'},
            reason_summary='Observe the explicitly controlled object owned by user_a.'))
    actions.append(source_action('correlate_source_runtime'))
    for h in snapshot.hypotheses:
        route = next(r for r in snapshot.routes if r.id == h.route_id)
        path = route.path.replace('{id}', '1')
        actions.append(PlannedAction(action_type=ActionType.VERIFY_FINDING, related_hypothesis_id=h.hypothesis_id,
            parameters={'validation_action_type': 'check_object_authorization',
                'validation_parameters': {'url': lab.base_url + path, 'owner_session': 'user_a', 'other_session': 'user_b'}},
            reason_summary='Compare controlled object 1 across two authenticated local identities.'))
        actions.append(PlannedAction(action_type=ActionType.VERIFY_FINDING, related_hypothesis_id=h.hypothesis_id,
            parameters={'mode': 'finalize', 'affected_endpoints': [path]},
            reason_summary='Accept or reject source suspicion using runtime proof and critic review.'))
        if 'safe' not in path:
            actions.append(CriticReview(decision=CriticDecision.ACCEPT))
    actions += [PlannedAction(action_type=ActionType.GENERATE_REPORT), PlannedAction(action_type=ActionType.COMPLETE)]
    llm = MockLLM()
    llm.script_structured(*actions)
    outcomes = await assessment.build_orchestrator(llm).run()
    assert all(o.status in ('completed', 'completed_assessment') for o in outcomes), [(o.status, o.detail) for o in outcomes]
    ws = assessment.workspace
    findings = ws.list_findings()
    assert len(findings) == 1 and findings[0].status == 'confirmed'
    finding = findings[0]
    assert ws.get_critic_review(finding.critic_review_id).decision == 'accept'
    assert any(h.status == 'rejected' for h in ws.list_hypotheses())
    report = ReportBuilder(ws).build()
    assert report.findings[0].source_evidence and report.findings[0].runtime_evidence
    assert report.findings[0].root_cause
    report_paths = write_reports(report, assessment.directory / 'reports')
    raw_secret = (FIXTURE / '.env.example').read_text().split('"')[1]
    assert raw_secret not in (assessment.directory / 'state.db').read_bytes().decode('utf-8', errors='ignore')
    assert all(raw_secret not in p.read_text() for p in report_paths.values())
    # Configuration inspection only: this demo never invokes an external model.
    try:
        build_provider(load_config(), role='critic')
        real_model = {'status': 'not_run', 'reason': 'provider configured; local demo does not transmit evidence'}
    except ProviderNotConfiguredError:
        real_model = {'status': 'unavailable', 'reason': 'no configured provider'}
    ids = display_id_map(findings, 'ADI-F')
    output = {'assessment_id': assessment.id, 'finding': ids[finding.id], 'finding_id': finding.id,
        'severity': finding.severity, 'critic': 'accept', 'source_summary': source.summary(),
        'source_locations': report.findings[0].source_locations,
        'broken_runtime': 'GET /api/orders/1: owner 200, other 200, same protected object',
        'safe_runtime': 'GET /api/orders-safe/1: owner 200, other 403; hypothesis rejected',
        'sast': scan, 'sast_false_positive': 'AST literal parser indication rejected',
        'secret': 'fake test secret presence confirmed; value redacted; SHA256 fingerprint retained',
        'dependency': 'ADI-TEST-001 synthetic fixture, known affected dependency; runtime not validated',
        'tools': {t.metadata.name: t.available for t in assessment.registry.all() if 'source' in t.metadata.category},
        'real_model': real_model, 'report_paths': {k: str(v.resolve()) for k,v in report_paths.items()}}
    (assessment.directory / 'acceptance.json').write_text(json.dumps(output, indent=2))
    print(json.dumps(output, indent=2))
    return output


if __name__ == '__main__':
    with Phase5Lab() as lab:
        asyncio.run(demo(lab))
