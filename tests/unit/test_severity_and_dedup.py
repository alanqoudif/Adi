from adi.evidence.models import EvidenceType
from adi.evidence.store import EvidenceStore
from adi.findings.deduplicator import FindingDeduplicator
from adi.findings.severity import (
    SeverityFactors,
    SeverityLevel,
    compute_severity,
    severity_for_category,
)
from adi.knowledge.workspace import Workspace
from adi.scope.models import Scope


def test_no_impact_is_info():
    assert compute_severity(SeverityFactors()) == SeverityLevel.INFO


def test_strong_combination_reaches_critical():
    factors = SeverityFactors(
        confidentiality_impact="high", integrity_impact="high", availability_impact="high",
        requires_authentication=False, requires_privileges=False, user_interaction=False,
        scope_changed=True, exploitability_confidence=1.0,
    )
    assert compute_severity(factors) == SeverityLevel.CRITICAL


def test_missing_header_is_conservatively_low():
    assert severity_for_category("missing_security_header") in (SeverityLevel.INFO, SeverityLevel.LOW)


def test_broken_object_authorization_is_high_not_critical():
    # strong real-world issue, but per spec CRITICAL should require an even
    # stronger combination (e.g. unauthenticated + integrity + availability)
    assert severity_for_category("broken_object_authorization") == SeverityLevel.HIGH


def test_low_confidence_exploitability_pulls_severity_down():
    high_conf = SeverityFactors(confidentiality_impact="high", integrity_impact="high",
                                 exploitability_confidence=1.0)
    low_conf = SeverityFactors(confidentiality_impact="high", integrity_impact="high",
                                exploitability_confidence=0.1)
    assert compute_severity(low_conf) != compute_severity(high_conf)


def test_deduplicator_merges_instead_of_duplicating(tmp_path):
    scope = Scope(name="dedup-test", targets=["lab.local"])
    workspace = Workspace.create(tmp_path / "state.db", scope)
    store = EvidenceStore(workspace)
    dedup = FindingDeduplicator(workspace)

    ev1 = store.create(EvidenceType.CONFIGURATION, source="test", summary="first")
    finding_id = workspace.create_finding(
        title="Missing security header", category="missing_security_header", severity="low",
        confidence=0.5, status="indicated", affected_endpoints_json='["/"]',
        evidence_ids_json=f'["{ev1.id}"]',
    )

    duplicate = dedup.find_duplicate("missing_security_header", ["/"])
    assert duplicate is not None
    assert duplicate.id == finding_id

    ev2 = store.create(EvidenceType.CONFIGURATION, source="test", summary="second")
    ev3 = store.create(EvidenceType.CONFIGURATION, source="test", summary="third")
    dedup.merge_evidence(finding_id, [ev2.id, ev3.id])
    updated = workspace.get_finding(finding_id)
    import json
    assert set(json.loads(updated.evidence_ids_json)) == {ev1.id, ev2.id, ev3.id}

    no_match = dedup.find_duplicate("missing_security_header", ["/other"])
    assert no_match is None
