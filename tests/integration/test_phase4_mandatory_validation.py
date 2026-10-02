"""The Phase 4 mandatory acceptance tests (spec sections 57–62), driven
against the real local demo app (tests/fixtures/webapp/app.py) — no mocked
HTTP, only the LLM-facing Critic is ever scripted (MockLLM).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures" / "webapp"))
from app import DemoApp

from adi.agent.critic import Critic, CriticDecision, CriticReview
from adi.evidence.models import EvidenceType
from adi.evidence.store import EvidenceStore
from adi.findings.pipeline import FindingPipeline
from adi.findings.verifier import VerificationStatus
from adi.http.client import HTTPClient
from adi.http.sessions import SessionJarRegistry
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.hypotheses import HypothesisStatus
from adi.knowledge.workspace import Workspace
from adi.llm.mock import MockLLM
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.validation.context import ValidationContext
from adi.validation.engine import HypothesisAlreadyResolvedError, ValidationEngine
from adi.validation.models import ValidationAction, ValidationActionType


@pytest.fixture()
def demo_app():
    app = DemoApp().start()
    yield app
    app.stop()


def build_stack(tmp_path, db_path=None):
    scope = Scope(name="phase4-mandatory", targets=["127.0.0.1"])
    workspace = Workspace.create(db_path or tmp_path / "state.db", scope)
    scope_engine = ScopeEngine(scope)
    http_client = HTTPClient(scope_engine, SessionJarRegistry())
    http_ws = HTTPWorkspace(http_client, workspace, tmp_path / "evidence")
    store = EvidenceStore(workspace)
    ctx = ValidationContext(http_ws, store, workspace)
    engine = ValidationEngine(ctx)
    return workspace, http_ws, store, engine


async def _login(http_ws, base, username):
    await http_ws.fetch("POST", base + "/api/login", session_id=username, body=f"username={username}")


# ===========================================================================
# #57 MANDATORY AUTHORIZATION TEST
# ===========================================================================

@pytest.mark.asyncio
async def test_57_broken_object_authorization_confirmed_and_safe_one_rejected(tmp_path, demo_app):
    workspace, http_ws, store, engine = build_stack(tmp_path)
    await _login(http_ws, demo_app.base_url, "user_a")
    await _login(http_ws, demo_app.base_url, "user_b")
    pipeline = FindingPipeline(workspace, store)  # no critic — deterministic path

    # --- the BROKEN endpoint: expect CONFIRMED ---
    broken_hyp = engine.hypothesis_engine.create(
        title="possible broken object authorization on /api/orders-broken/1",
        category="broken_object_authorization",
    )
    broken_result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=broken_hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-broken/1",
                    "owner_session": "user_a", "other_session": "user_b"},
    ))
    assert broken_result.outcome.value == "supports"
    broken_pipeline_result = await pipeline.finalize(
        broken_hyp.id, affected_endpoints=["/api/orders-broken/1"],
    )
    assert broken_pipeline_result.hypothesis_status == HypothesisStatus.CONFIRMED
    assert broken_pipeline_result.finding_id is not None

    # --- the SAFE endpoint: expect REJECTED ---
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
    safe_pipeline_result = await pipeline.finalize(
        safe_hyp.id, affected_endpoints=["/api/orders-safe/1"],
    )
    assert safe_pipeline_result.hypothesis_status == HypothesisStatus.REJECTED
    assert safe_pipeline_result.finding_id is None

    confirmed = [f for f in workspace.list_findings() if f.status == "confirmed"]
    assert len(confirmed) == 1
    assert confirmed[0].id == broken_pipeline_result.finding_id


# ===========================================================================
# #58 MANDATORY FALSE-POSITIVE TEST
# ===========================================================================

@pytest.mark.asyncio
async def test_58_false_positive_scanner_indication_is_rejected(tmp_path, demo_app):
    """A scanner claims the SAFE endpoint is broken (it isn't). Adi must
    validate the claim and reject it — confirmed finding count must not move."""
    workspace, http_ws, store, engine = build_stack(tmp_path)
    await _login(http_ws, demo_app.base_url, "user_a")
    await _login(http_ws, demo_app.base_url, "user_b")
    pipeline = FindingPipeline(workspace, store)

    before = len([f for f in workspace.list_findings() if f.status == "confirmed"])

    # a fabricated scanner indication claiming a vulnerability that is NOT real
    scanner_evidence = store.create(
        EvidenceType.SCANNER_INDICATION, source="nuclei",
        summary="nuclei: possible IDOR on /api/orders-safe/1 (unverified)",
        raw_text="template: idor-guess\nseverity: medium\nmatched-at: /api/orders-safe/1",
    )
    hyp = engine.hypothesis_engine.create(
        title="scanner-reported possible IDOR on /api/orders-safe/1",
        category="broken_object_authorization",
    )
    # link the scanner evidence as "supporting" pending independent validation
    engine.hypothesis_engine.transition(
        hyp.id, HypothesisStatus.INVESTIGATING, new_supporting_observation_ids=[scanner_evidence.id],
    )
    store.link_to_finding  # (not used — evidence isn't linked to a finding until confirmed)

    # independent validation — this is what actually determines truth
    result = await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-safe/1",
                    "owner_session": "user_a", "other_session": "user_b"},
    ))
    assert result.outcome.value == "refutes"

    pipeline_result = await pipeline.finalize(hyp.id, affected_endpoints=["/api/orders-safe/1"])
    assert pipeline_result.hypothesis_status == HypothesisStatus.REJECTED
    assert pipeline_result.finding_id is None

    after = len([f for f in workspace.list_findings() if f.status == "confirmed"])
    assert after == before  # unchanged


# ===========================================================================
# #59 MANDATORY CRITIC TEST
# ===========================================================================

@pytest.mark.asyncio
async def test_59_critic_requests_more_evidence_then_confirms(tmp_path, demo_app):
    workspace, http_ws, store, engine = build_stack(tmp_path)
    await _login(http_ws, demo_app.base_url, "user_a")
    await _login(http_ws, demo_app.base_url, "user_b")

    llm = MockLLM()
    llm.script_structured(
        CriticReview(
            decision=CriticDecision.NEEDS_MORE_EVIDENCE,
            concerns=["ownership of object 1 by user_a was never independently confirmed"],
            additional_validation_needed=["re-check with a second controlled object"],
        ),
        CriticReview(decision=CriticDecision.ACCEPT, concerns=[]),
    )
    pipeline = FindingPipeline(workspace, store, critic=Critic(llm))

    hyp = engine.hypothesis_engine.create(
        title="possible broken object authorization on /api/orders-broken/1",
        category="broken_object_authorization",
    )
    await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-broken/1",
                    "owner_session": "user_a", "other_session": "user_b"},
    ))

    # first pass: critic is not satisfied yet
    first = await pipeline.finalize(hyp.id, affected_endpoints=["/api/orders-broken/1"])
    assert first.critic_decision == CriticDecision.NEEDS_MORE_EVIDENCE
    assert first.finding_id is None
    mid_hyp = engine.hypothesis_engine.get(hyp.id)
    assert mid_hyp.status not in (HypothesisStatus.CONFIRMED, HypothesisStatus.REJECTED)

    # Adi performs ONE additional controlled validation (a second object)
    await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-broken/2",
                    "owner_session": "user_b", "other_session": "user_a"},
    ))

    # second pass: critic is now satisfied
    second = await pipeline.finalize(
        hyp.id, affected_endpoints=["/api/orders-broken/1", "/api/orders-broken/2"],
    )
    assert second.critic_decision == CriticDecision.ACCEPT
    assert second.hypothesis_status == HypothesisStatus.CONFIRMED
    assert second.finding_id is not None

    # prove the critic review was actually persisted, twice
    reviews = workspace.list_critic_reviews(hypothesis_id=hyp.id)
    assert len(reviews) == 2
    assert reviews[0].decision == "needs_more_evidence"
    assert reviews[1].decision == "accept"


# ===========================================================================
# #60 MANDATORY EVIDENCE TRACE TEST
# ===========================================================================

@pytest.mark.asyncio
async def test_60_confirmed_finding_has_a_complete_evidence_chain(tmp_path, demo_app):
    workspace, http_ws, store, engine = build_stack(tmp_path)
    await _login(http_ws, demo_app.base_url, "user_a")
    await _login(http_ws, demo_app.base_url, "user_b")
    pipeline = FindingPipeline(workspace, store)

    hyp = engine.hypothesis_engine.create(
        title="possible broken object authorization on /api/orders-broken/1",
        category="broken_object_authorization",
    )
    await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-broken/1",
                    "owner_session": "user_a", "other_session": "user_b"},
    ))
    result = await pipeline.finalize(hyp.id, affected_endpoints=["/api/orders-broken/1"])
    finding_id = result.finding_id
    assert finding_id is not None

    # finding -> hypothesis
    finding = workspace.get_finding(finding_id)
    assert finding.hypothesis_id == hyp.id

    # finding -> evidence
    import json
    evidence_ids = json.loads(finding.evidence_ids_json)
    assert len(evidence_ids) > 0
    for evidence_id in evidence_ids:
        evidence = workspace.get_evidence(evidence_id)
        assert evidence is not None  # no orphan evidence reference
        assert hyp.id in json.loads(evidence.related_hypothesis_ids_json)

        # evidence -> real HTTP exchange (not a fabricated claim)
        matching_exchanges = [
            e for e in workspace.list_http_exchanges()
            if e.url.rstrip("/") in evidence.subject or evidence.subject in e.url
        ]
        assert len(matching_exchanges) > 0, f"evidence {evidence_id} has no matching HTTP exchange"

    # hypothesis -> validation action history
    actions = workspace.list_validation_actions(hypothesis_id=hyp.id)
    assert len(actions) >= 1
    assert actions[0].outcome == "supports"


# ===========================================================================
# #61 MANDATORY DEDUP TEST
# ===========================================================================

@pytest.mark.asyncio
async def test_61_scanner_and_validator_agree_produce_one_finding(tmp_path, demo_app):
    workspace, http_ws, store, engine = build_stack(tmp_path)
    pipeline = FindingPipeline(workspace, store)
    endpoint = "/"

    # source 1: a (simulated) nuclei indication about the missing header
    nuclei_hyp = engine.hypothesis_engine.create(
        title="missing security headers (nuclei)", category="missing_security_header",
    )
    scanner_evidence = store.create(
        EvidenceType.SCANNER_INDICATION, source="nuclei", subject=endpoint,
        summary="nuclei: missing Content-Security-Policy header",
        related_hypothesis_ids=[nuclei_hyp.id],
    )
    engine.hypothesis_engine.transition(
        nuclei_hyp.id, HypothesisStatus.INVESTIGATING,
        new_supporting_observation_ids=[scanner_evidence.id],
    )
    # scanner-only evidence keeps it at SUPPORTED, never CONFIRMED on its own
    nuclei_result = await pipeline.finalize(nuclei_hyp.id, affected_endpoints=[endpoint])
    assert nuclei_result.verification.status == VerificationStatus.SUPPORTED
    assert nuclei_result.finding_id is not None
    first_finding_id = nuclei_result.finding_id

    # source 2: Adi's own deterministic header validator independently finds the same thing
    header_hyp = engine.hypothesis_engine.create(
        title="missing security headers (validator)", category="missing_security_header",
    )
    await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_SECURITY_HEADER, hypothesis_id=header_hyp.id,
        parameters={"url": demo_app.base_url + endpoint},
    ))
    header_result = await pipeline.finalize(header_hyp.id, affected_endpoints=[endpoint])

    # same category + same endpoint -> merged into the SAME finding, not a new one
    assert header_result.finding_id == first_finding_id

    all_findings = [f for f in workspace.list_findings() if f.category == "missing_security_header"]
    assert len(all_findings) == 1

    import json
    merged_evidence = json.loads(all_findings[0].evidence_ids_json)
    assert scanner_evidence.id in merged_evidence
    assert len(merged_evidence) >= 2  # both sources' evidence present


# ===========================================================================
# #62 MANDATORY RESUME TEST
# ===========================================================================

@pytest.mark.asyncio
async def test_62_findings_and_evidence_survive_resume(tmp_path, demo_app):
    db_path = tmp_path / "state.db"
    workspace, http_ws, store, engine = build_stack(tmp_path, db_path=db_path)
    await _login(http_ws, demo_app.base_url, "user_a")
    await _login(http_ws, demo_app.base_url, "user_b")
    pipeline = FindingPipeline(workspace, store)

    hyp = engine.hypothesis_engine.create(
        title="possible broken object authorization on /api/orders-broken/1",
        category="broken_object_authorization",
    )
    await engine.execute(ValidationAction(
        action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=hyp.id,
        parameters={"url": demo_app.base_url + "/api/orders-broken/1",
                    "owner_session": "user_a", "other_session": "user_b"},
    ))
    result = await pipeline.finalize(hyp.id, affected_endpoints=["/api/orders-broken/1"])
    assert result.hypothesis_status == HypothesisStatus.CONFIRMED
    assessment_id = workspace.assessment_id

    # --- simulate closing and resuming the assessment ---
    resumed_workspace = Workspace.open(db_path, assessment_id)

    resumed_findings = resumed_workspace.list_findings()
    assert len(resumed_findings) == 1
    assert resumed_findings[0].status == "confirmed"

    resumed_hyp = next(h for h in resumed_workspace.list_hypotheses() if h.id == hyp.id)
    assert resumed_hyp.status == "confirmed"

    resumed_evidence = resumed_workspace.list_evidence()
    assert len(resumed_evidence) > 0

    resumed_actions = resumed_workspace.list_validation_actions(hypothesis_id=hyp.id)
    assert len(resumed_actions) == 1  # not re-run

    # resuming must not allow re-validating an already-confirmed hypothesis
    resumed_store = EvidenceStore(resumed_workspace)
    resumed_scope_engine = ScopeEngine(resumed_workspace.load_scope())
    resumed_http = HTTPWorkspace(
        HTTPClient(resumed_scope_engine, SessionJarRegistry()), resumed_workspace, tmp_path / "evidence2",
    )
    resumed_ctx = ValidationContext(resumed_http, resumed_store, resumed_workspace)
    resumed_engine = ValidationEngine(resumed_ctx)

    with pytest.raises(HypothesisAlreadyResolvedError):
        await resumed_engine.execute(ValidationAction(
            action_type=ValidationActionType.CHECK_OBJECT_AUTHORIZATION, hypothesis_id=hyp.id,
            parameters={"url": demo_app.base_url + "/api/orders-broken/1",
                        "owner_session": "user_a", "other_session": "user_b"},
        ))
