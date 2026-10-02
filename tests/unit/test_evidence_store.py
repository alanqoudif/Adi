from adi.evidence.models import EvidenceType
from adi.evidence.redaction import redact_secrets, sanitize_for_evidence
from adi.evidence.store import EvidenceStore
from adi.knowledge.workspace import Workspace
from adi.scope.models import Scope


def test_redact_secrets_masks_bearer_token():
    text = "Authorization: Bearer sk-abcdef1234567890"
    redacted = redact_secrets(text)
    assert "abcdef1234567890" not in redacted
    assert "<redacted>" in redacted


def test_redact_secrets_masks_password_field():
    text = "body: password=hunter2verysecret&user=alice"
    redacted = redact_secrets(text)
    assert "hunter2verysecret" not in redacted


def test_redact_secrets_leaves_normal_text_alone():
    text = "The server returned a 200 OK response with a JSON body."
    assert redact_secrets(text) == text


def test_sanitize_for_evidence_truncates_and_redacts():
    text = "api_key=supersecretvalue12345 " + "x" * 2000
    sanitized = sanitize_for_evidence(text)
    assert "supersecretvalue12345" not in sanitized
    assert len(sanitized) < 1200


def test_evidence_store_creates_and_retrieves(tmp_path):
    scope = Scope(name="ev-test", targets=["lab.local"])
    workspace = Workspace.create(tmp_path / "state.db", scope)
    store = EvidenceStore(workspace)

    evidence = store.create(
        EvidenceType.HTTP_EXCHANGE, source="http_client", subject="GET /api/orders/1",
        summary="user_b received user_a's order", raw_text="Authorization: Bearer secrettoken123\nstatus 200",
        related_hypothesis_ids=["hyp-1"],
    )

    assert evidence.id is not None
    assert evidence.hash  # non-empty, deterministic
    assert "secrettoken123" not in evidence.sanitized_preview

    fetched = store.get(evidence.id)
    assert fetched.subject == "GET /api/orders/1"

    for_hyp = store.for_hypothesis("hyp-1")
    assert len(for_hyp) == 1


def test_evidence_can_be_linked_to_a_finding(tmp_path):
    scope = Scope(name="ev-link-test", targets=["lab.local"])
    workspace = Workspace.create(tmp_path / "state.db", scope)
    store = EvidenceStore(workspace)

    evidence = store.create(EvidenceType.MANUAL_NOTE, source="test", summary="note")
    store.link_to_finding(evidence.id, "find-1")

    linked = store.for_finding("find-1")
    assert len(linked) == 1
    assert linked[0].id == evidence.id
