from adi.http.extractors import extract_html, fingerprint_from_cookies, fingerprint_from_headers


def test_extracts_title_links_and_forms():
    html = """
    <html><head><title>  Demo App  </title></head>
    <body>
      <a href="/login">Login</a>
      <a href="https://other.example.com/x">external</a>
      <form method="POST" action="/login">
        <input name="email" type="email" required>
        <input name="password" type="password" required>
      </form>
    </body></html>
    """
    result = extract_html("http://host/", html)
    assert result.title == "Demo App"
    assert "http://host/login" in result.links
    assert "https://other.example.com/x" in result.links
    assert len(result.forms) == 1
    form = result.forms[0]
    assert form.method == "POST"
    assert form.action == "http://host/login"
    assert {f.name for f in form.fields} == {"email", "password"}
    assert all(f.required for f in form.fields)


def test_extracts_inline_js_fetch_calls():
    html = """
    <html><body><script>
      fetch('/api/profile').then(r => r.json());
      fetch("/api/orders");
    </script></body></html>
    """
    result = extract_html("http://host/dashboard", html)
    assert "http://host/api/profile" in result.js_fetch_calls
    assert "http://host/api/orders" in result.js_fetch_calls


def test_extracts_external_script_src():
    html = '<html><head><script src="/static/app.js"></script></head><body></body></html>'
    result = extract_html("http://host/", html)
    assert "http://host/static/app.js" in result.scripts


def test_meta_generator_hint():
    html = '<html><head><meta name="generator" content="WordPress 6.4"></head><body></body></html>'
    result = extract_html("http://host/", html)
    assert any(h.name == "WordPress 6.4" for h in result.tech_hints)


def test_form_get_method_defaults_and_get_without_method_attr():
    html = '<form action="/search"><input name="q"></form>'
    result = extract_html("http://host/", html)
    assert result.forms[0].method == "GET"


def test_fingerprint_from_headers_is_high_confidence():
    hints = fingerprint_from_headers({"Server": "nginx/1.18.0", "X-Powered-By": "Express"})
    names = {h.name for h in hints}
    assert "nginx/1.18.0" in names
    assert "Express" in names
    assert all(h.confidence == "high" for h in hints)


def test_fingerprint_from_cookies_known_names():
    hints = fingerprint_from_cookies(["connect.sid", "unrelated_cookie"])
    assert len(hints) == 1
    assert hints[0].name == "Express"
    assert hints[0].confidence == "medium"


def test_fingerprint_from_cookies_no_false_positive():
    assert fingerprint_from_cookies(["random_session_xyz"]) == []
