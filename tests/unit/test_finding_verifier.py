from adi.evidence.models import Evidence, EvidenceType
from adi.findings.verifier import FindingVerifier, VerificationStatus
from adi.knowledge.hypotheses import Hypothesis, HypothesisStatus


def _hyp(supporting=None, contradicting=None) -> Hypothesis:
    return Hypothesis(
        id="hyp-1", title="t", status=HypothesisStatus.VALIDATING, confidence=0.5,
        supporting_observation_ids=supporting or [], contradicting_observation_ids=contradicting or [],
    )


def _ev(id_, type_=EvidenceType.HTTP_EXCHANGE) -> Evidence:
    return Evidence(id=id_, type=type_, source="test")


def test_no_evidence_is_rejected():
    decision = FindingVerifier().evaluate(_hyp(), [])
    assert decision.status == VerificationStatus.REJECTED


def test_only_contradicting_evidence_is_rejected():
    hyp = _hyp(contradicting=["e1"])
    decision = FindingVerifier().evaluate(hyp, [_ev("e1")])
    assert decision.status == VerificationStatus.REJECTED


def test_scanner_only_evidence_stays_supported_not_confirmed():
    hyp = _hyp(supporting=["e1"])
    decision = FindingVerifier().evaluate(hyp, [_ev("e1", EvidenceType.SCANNER_INDICATION)])
    assert decision.status == VerificationStatus.SUPPORTED


def test_contradiction_alongside_support_stays_supported():
    hyp = _hyp(supporting=["e1"], contradicting=["e2"])
    decision = FindingVerifier().evaluate(hyp, [_ev("e1"), _ev("e2")])
    assert decision.status == VerificationStatus.SUPPORTED


def test_clean_reproducible_evidence_confirms():
    hyp = _hyp(supporting=["e1"])
    decision = FindingVerifier().evaluate(hyp, [_ev("e1", EvidenceType.HTTP_EXCHANGE)])
    assert decision.status == VerificationStatus.CONFIRMED


def test_non_reproducible_evidence_type_stays_supported():
    hyp = _hyp(supporting=["e1"])
    decision = FindingVerifier().evaluate(hyp, [_ev("e1", EvidenceType.MANUAL_NOTE)])
    assert decision.status == VerificationStatus.SUPPORTED
