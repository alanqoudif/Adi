import pytest

from adi.agent.reasoner import HypothesisEngine, InvalidHypothesisTransitionError
from adi.knowledge.hypotheses import HypothesisStatus
from adi.knowledge.workspace import Workspace
from adi.scope.models import Scope


@pytest.fixture()
def workspace(tmp_path) -> Workspace:
    scope = Scope(name="hyp-test", targets=["lab.local"])
    return Workspace.create(tmp_path / "state.db", scope)


def test_create_hypothesis_starts_new(workspace):
    engine = HypothesisEngine(workspace)
    hyp = engine.create(title="Possible IDOR on /api/orders/:id", category="authorization")
    assert hyp.status == HypothesisStatus.NEW
    assert hyp.id is not None


def test_valid_transition_chain(workspace):
    engine = HypothesisEngine(workspace)
    hyp = engine.create(title="IDOR hypothesis")
    hyp = engine.transition(hyp.id, HypothesisStatus.INVESTIGATING)
    assert hyp.status == HypothesisStatus.INVESTIGATING
    hyp = engine.transition(hyp.id, HypothesisStatus.SUPPORTED, confidence=0.7)
    assert hyp.status == HypothesisStatus.SUPPORTED
    assert hyp.confidence == 0.7
    hyp = engine.transition(hyp.id, HypothesisStatus.CONFIRMED)
    assert hyp.status == HypothesisStatus.CONFIRMED


def test_cannot_skip_new_to_confirmed(workspace):
    engine = HypothesisEngine(workspace)
    hyp = engine.create(title="IDOR hypothesis")
    with pytest.raises(InvalidHypothesisTransitionError):
        engine.transition(hyp.id, HypothesisStatus.CONFIRMED)


def test_terminal_states_cannot_transition_out(workspace):
    engine = HypothesisEngine(workspace)
    hyp = engine.create(title="dead end")
    hyp = engine.transition(hyp.id, HypothesisStatus.REJECTED)
    assert hyp.status == HypothesisStatus.REJECTED
    with pytest.raises(InvalidHypothesisTransitionError):
        engine.transition(hyp.id, HypothesisStatus.INVESTIGATING)


def test_rejection_is_not_a_failure_it_is_tracked(workspace):
    engine = HypothesisEngine(workspace)
    h1 = engine.create(title="false lead one")
    h2 = engine.create(title="false lead two")
    engine.transition(h1.id, HypothesisStatus.REJECTED)
    engine.transition(h2.id, HypothesisStatus.REJECTED)
    assert len(engine.rejected()) == 2
    assert engine.active() == []


def test_observation_ids_accumulate_without_duplicates(workspace):
    engine = HypothesisEngine(workspace)
    hyp = engine.create(title="h")
    engine.transition(hyp.id, HypothesisStatus.INVESTIGATING,
                       new_supporting_observation_ids=["obs-1", "obs-2"])
    hyp = engine.transition(hyp.id, HypothesisStatus.SUPPORTED,
                             new_supporting_observation_ids=["obs-2", "obs-3"])
    assert hyp.supporting_observation_ids == ["obs-1", "obs-2", "obs-3"]
