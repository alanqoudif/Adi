from adi.evidence.comparison import ResponseSnapshot, compare_responses


def _snap(label, status=200, body="hello", content_type="text/html", headers=None):
    return ResponseSnapshot(label=label, status=status, headers=headers or {},
                             content_type=content_type, body=body)


def test_identical_responses_are_equivalent():
    a = _snap("user_a")
    b = _snap("user_b")
    comparison = compare_responses(a, b)
    assert comparison.responses_equivalent
    assert comparison.status_match
    assert comparison.body_hash_match


def test_different_status_is_not_equivalent():
    a = _snap("anonymous", status=401, body="unauthorized")
    b = _snap("user_a", status=200, body="order details")
    comparison = compare_responses(a, b)
    assert not comparison.responses_equivalent
    assert not comparison.status_match


def test_same_status_different_body_is_not_equivalent():
    a = _snap("user_a", body="order 1 details")
    b = _snap("user_b", body="order 2 details")
    comparison = compare_responses(a, b)
    assert comparison.status_match
    assert not comparison.body_hash_match
    assert not comparison.responses_equivalent


def test_whitespace_only_body_differences_still_equivalent():
    a = _snap("user_a", body="  order details  \n")
    b = _snap("user_b", body="order details")
    comparison = compare_responses(a, b)
    assert comparison.responses_equivalent
