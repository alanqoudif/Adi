from adi.http.fingerprints import fingerprint_response, normalize_body_for_hash


def test_identical_bodies_hash_identically():
    a = fingerprint_response(200, {"Content-Type": "text/html"}, "<html>hi</html>")
    b = fingerprint_response(200, {"Content-Type": "text/html"}, "<html>hi</html>")
    assert a.normalized_body_hash == b.normalized_body_hash


def test_whitespace_only_differences_still_hash_identically():
    a = fingerprint_response(200, {}, "line1\nline2")
    b = fingerprint_response(200, {}, "  line1  \n  line2  \n\n")
    assert a.normalized_body_hash == b.normalized_body_hash


def test_different_bodies_hash_differently():
    a = fingerprint_response(200, {}, "body A")
    b = fingerprint_response(200, {}, "body B")
    assert a.normalized_body_hash != b.normalized_body_hash


def test_header_fingerprint_reflects_selected_headers_only():
    a = fingerprint_response(200, {"Server": "nginx", "Date": "Mon"}, "x")
    b = fingerprint_response(200, {"Server": "nginx", "Date": "Tue"}, "x")
    assert a.header_fingerprint == b.header_fingerprint  # Date isn't fingerprinted


def test_header_fingerprint_changes_when_server_changes():
    a = fingerprint_response(200, {"Server": "nginx"}, "x")
    b = fingerprint_response(200, {"Server": "apache"}, "x")
    assert a.header_fingerprint != b.header_fingerprint


def test_normalize_body_strips_blank_lines_and_indentation():
    assert normalize_body_for_hash("  a  \n\n  b  \n") == "a\nb"
