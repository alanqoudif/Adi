from adi.http.redaction import redact_headers, safe_body_preview


def test_authorization_header_is_redacted():
    out = redact_headers({"Authorization": "Bearer sk-supersecrettoken1234"})
    assert "supersecrettoken1234" not in out["Authorization"]
    assert "<redacted>" in out["Authorization"]


def test_cookie_and_set_cookie_redacted_case_insensitively():
    out = redact_headers({"cookie": "session=abc123", "Set-Cookie": "session=abc123; Path=/"})
    assert "abc123" not in out["cookie"]
    assert "abc123" not in out["Set-Cookie"]


def test_non_sensitive_headers_pass_through_unchanged():
    out = redact_headers({"Content-Type": "application/json", "Server": "nginx"})
    assert out == {"Content-Type": "application/json", "Server": "nginx"}


def test_safe_body_preview_truncates_long_text():
    body = "x" * 2000
    preview = safe_body_preview(body)
    assert len(preview) < 1000
    assert "truncated" in preview


def test_safe_body_preview_marks_binary_content_as_binary():
    preview = safe_body_preview(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50, content_type="image/png")
    assert "binary content" in preview


def test_safe_body_preview_decodes_text_content_type():
    preview = safe_body_preview(b'{"a": 1}', content_type="application/json")
    assert preview == '{"a": 1}'
