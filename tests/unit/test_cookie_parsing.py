from adi.http.cookies import parse_set_cookie_header


def test_parses_all_flags():
    meta = parse_set_cookie_header("session=abc123; Path=/; Domain=example.com; HttpOnly; Secure; SameSite=Lax")
    assert meta.name == "session"
    assert meta.domain == "example.com"
    assert meta.path == "/"
    assert meta.http_only is True
    assert meta.secure is True
    assert meta.same_site == "Lax"


def test_missing_flags_default_false():
    meta = parse_set_cookie_header("session=abc123; Path=/")
    assert meta.http_only is False
    assert meta.secure is False
    assert meta.same_site == ""


def test_never_captures_the_cookie_value():
    meta = parse_set_cookie_header("session=supersecretvalue; Path=/")
    assert "supersecretvalue" not in meta.model_dump_json()
