"""Phase 4 section 5: ContextBuilder surfaces a bounded security-state
summary — active hypotheses with evidence counts, recent validation
results, confirmed findings, and positive controls — without dumping raw
evidence payloads, cookies, or every historical hypothesis."""

from pathlib import Path

from adi.agent.context_builder import ContextBuilder
from adi.evidence.models import EvidenceType
from adi.evidence.store import EvidenceStore
from adi.findings.pipeline import FindingPipeline
from adi.knowledge.hypotheses import HypothesisStatus
from adi.knowledge.workspace import Workspace
from adi.scope.models import Scope
from adi.tools.registry import ToolRegistry

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"


def test_security_summary_reflects_confirmed_findings_and_positive_controls(tmp_path):
    scope = Scope(name="ctx-sec-test", targets=["lab.local"])
    workspace = Workspace.create(tmp_path / "state.db", scope)
    store = EvidenceStore(workspace)
    pipeline = FindingPipeline(workspace, store)

    hyp = pipeline.hypothesis_engine.create(
        title="broken object authorization on /api/x", category="broken_object_authorization",
    )
    ev = store.create(EvidenceType.HTTP_EXCHANGE, source="test", summary="user_b got user_a's object",
                       related_hypothesis_ids=[hyp.id])
    pipeline.hypothesis_engine.transition(
        hyp.id, HypothesisStatus.INVESTIGATING, new_supporting_observation_ids=[ev.id])
    pipeline.hypothesis_engine.transition(
        hyp.id, HypothesisStatus.SUPPORTED, new_supporting_observation_ids=[ev.id])

    workspace.record_validation_action(
        hypothesis_id=hyp.id, action_type="check_object_authorization",
        outcome="supports", detail="user_b received object", evidence_ids_json="[]",
    )
    workspace.record_positive_observation(
        category="authorization", title="Cross-user object access correctly denied on /api/orders-safe",
        summary="user_b was denied", endpoint="/api/orders-safe/1", evidence_ids_json="[]",
    )

    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    builder = ContextBuilder(workspace, scope, registry, goal="map it")
    context = builder.build()

    assert len(context.active_hypotheses) == 1
    assert len(context.recent_validation_results) == 1
    assert "supports" in context.recent_validation_results[0]
    assert len(context.positive_controls) == 1
    assert context.positive_controls[0].endpoint == "/api/orders-safe/1"

    rendered = context.render()
    assert "Positive controls:" in rendered
    assert "Recent validation results:" in rendered
    assert "evidence: 1" in rendered  # evidence count shown, not the raw evidence body
    assert "user_b got user_a's object" not in rendered  # raw evidence summary not dumped into hypothesis line


def test_security_summary_shows_confirmed_finding(tmp_path):
    scope = Scope(name="ctx-sec-test-2", targets=["lab.local"])
    workspace = Workspace.create(tmp_path / "state.db", scope)
    store = EvidenceStore(workspace)
    pipeline = FindingPipeline(workspace, store)  # no critic -> deterministic confirm path

    hyp = pipeline.hypothesis_engine.create(
        title="broken auth", category="missing_authentication",
    )
    ev = store.create(EvidenceType.HTTP_EXCHANGE, source="test", summary="anon got data",
                       related_hypothesis_ids=[hyp.id])
    pipeline.hypothesis_engine.transition(
        hyp.id, HypothesisStatus.INVESTIGATING, new_supporting_observation_ids=[ev.id])
    workspace.record_validation_action(
        hypothesis_id=hyp.id, action_type="check_auth_boundary",
        outcome="supports", scope_allowed=True, detail="anon got data", evidence_ids_json=f'["{ev.id}"]',
    )

    import asyncio
    result = asyncio.run(pipeline.finalize(hyp.id, affected_endpoints=["/api/leaky"]))
    assert result.finding_id is not None

    registry = ToolRegistry(SKILLS_DIR)
    registry.discover()
    context = ContextBuilder(workspace, scope, registry, goal="g").build()

    assert len(context.confirmed_findings) == 1
    assert context.confirmed_findings[0].severity == "high"
    assert "Confirmed findings:" in context.render()
