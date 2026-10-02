"""A minimal, deterministic local web application used to prove Adi can
autonomously discover a realistic attack surface (spec Phase 3T) and, for
Phase 4, validate real security properties against it.

This is NOT a general vulnerability lab — it exposes exactly the handful of
controlled scenarios Phase 3/4 acceptance tests need:

Phase 3 (discovery): links, a login form, "authenticated" API routes
reached via an inline JS fetch, robots.txt, sitemap.xml, a cookie, and an
out-of-scope redirect.

Phase 4 (validation), per spec section 56:
  A. correct authentication:     GET /api/private           (401 anon)
  B. broken auth boundary:       GET /api/leaky-profile      (200 regardless)
  C. correct object authz:       GET /api/orders-safe/<id>   (403 wrong owner)
  D. broken object authz:        GET /api/orders-broken/<id> (200 any session)
  E. cookie hardening issue:     POST /api/login cookie lacks HttpOnly/Secure
  F. permissive CORS:            GET /api/cors-test reflects Origin + credentials
  G. debug info disclosure:      GET /api/debug-error        (fake stack trace)

Pure standard library — no extra test dependency to install.
"""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# owner mapping for the object-authorization scenarios (C/D) — user_a owns
# object 1, user_b owns object 2; "admin" may access either.
_ORDERS = {
    "1": {"owner": "user_a", "data": "Order #1: 2x widget, shipped to user_a's address"},
    "2": {"owner": "user_b", "data": "Order #2: 1x gadget, shipped to user_b's address"},
}
_VALID_SESSIONS = {"user_a", "user_b", "admin"}

_HOME_HTML = """<!doctype html><html><head><title>Demo App</title></head>
<body>
<a href="/login">Login</a>
<a href="/dashboard">Dashboard</a>
</body></html>"""

_LOGIN_HTML = """<!doctype html><html><head><title>Login</title></head>
<body>
<form method="POST" action="/login">
  <input name="email" type="email" required>
  <input name="password" type="password" required>
</form>
</body></html>"""

_DASHBOARD_HTML = """<!doctype html><html><head><title>Dashboard</title></head>
<body>
<h1>Dashboard</h1>
<script>
  fetch('/api/profile').then(r => r.json());
  fetch('/api/orders').then(r => r.json());
</script>
</body></html>"""

_ROBOTS_TXT_TEMPLATE = "User-agent: *\nDisallow: /admin\nSitemap: http://{host}/sitemap.xml\n"

_SITEMAP_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://{host}/</loc></url>
  <url><loc>http://{host}/dashboard</loc></url>
</urlset>"""


class DemoAppHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.18.0"  # exercises Server-header tech fingerprinting

    def log_message(self, format, *args):
        pass  # keep test output quiet

    def _send(self, status: int, body: str, content_type: str = "text/html",
              extra_headers: dict | None = None):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(encoded)

    def _adi_session(self) -> str | None:
        """The Phase 4 test-session cookie (distinct from Phase 3's
        `connect.sid` fingerprinting cookie)."""
        cookie_header = self.headers.get("Cookie", "")
        match = re.search(r"adi_session=([^;]+)", cookie_header)
        if match and match.group(1) in _VALID_SESSIONS:
            return match.group(1)
        return None

    def do_GET(self):
        host = self.headers.get("Host", f"127.0.0.1:{self.server.server_port}")
        order_match = re.match(r"^/api/orders-(safe|broken)/(\w+)$", self.path)

        if self.path == "/api/private":
            # A. correct authentication boundary
            session = self._adi_session()
            if session is None:
                self._send(401, '{"error": "unauthorized"}', content_type="application/json")
            else:
                self._send(200, f'{{"user": "{session}", "data": "private account info"}}',
                            content_type="application/json")
            return

        if self.path == "/api/leaky-profile":
            # B. BROKEN authentication boundary — returns protected-looking
            # data regardless of whether any session cookie was sent.
            self._send(200, '{"profile": "full profile data including private fields"}',
                        content_type="application/json")
            return

        if order_match:
            mode, order_id = order_match.groups()
            order = _ORDERS.get(order_id)
            if order is None:
                self._send(404, '{"error": "not found"}', content_type="application/json")
                return
            session = self._adi_session()
            if session is None:
                self._send(401, '{"error": "unauthorized"}', content_type="application/json")
                return
            if mode == "safe":
                # C. CORRECT object-level authorization
                if session == order["owner"] or session == "admin":
                    self._send(200, f'{{"id": "{order_id}", "data": "{order["data"]}"}}',
                                content_type="application/json")
                else:
                    self._send(403, '{"error": "forbidden"}', content_type="application/json")
            else:
                # D. BROKEN object-level authorization — any authenticated
                # session can read any order, regardless of ownership.
                self._send(200, f'{{"id": "{order_id}", "data": "{order["data"]}"}}',
                            content_type="application/json")
            return

        if self.path == "/api/cors-test":
            # F. permissive CORS: reflects the Origin AND allows credentials
            # — a genuinely risky combination for a validator to flag.
            origin = self.headers.get("Origin", "*")
            self._send(200, '{"ok": true}', content_type="application/json", extra_headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            })
            return

        if self.path == "/api/debug-error":
            # G. information disclosure via a verbose framework-style error
            trace = (
                "Traceback (most recent call last):\n"
                '  File "/app/src/handlers/orders.py", line 42, in get_order\n'
                "    return db.query(order_id)\n"
                "ValueError: invalid literal for int() with base 10: 'abc'\n"
            )
            self._send(500, trace, content_type="text/plain")
            return

        if self.path == "/phase4":
            self._send(200, '<html><body>Controlled lab: user_a owns order 1; user_b owns order 2.'
                       '<a href="/api/orders-broken/1">Order comparison A</a>'
                       '<a href="/api/orders-safe/1">Order comparison B</a></body></html>')
        elif self.path == "/":
            self._send(200, _HOME_HTML, extra_headers={"Set-Cookie": "connect.sid=s%3Afake.sig; Path=/"})
        elif self.path == "/login":
            self._send(200, _LOGIN_HTML)
        elif self.path == "/dashboard":
            self._send(200, _DASHBOARD_HTML)
        elif self.path == "/api/profile":
            self._send(200, '{"user": "demo"}', content_type="application/json")
        elif self.path == "/api/orders":
            self._send(200, '{"orders": []}', content_type="application/json")
        elif self.path == "/robots.txt":
            self._send(200, _ROBOTS_TXT_TEMPLATE.format(host=host), content_type="text/plain")
        elif self.path == "/sitemap.xml":
            self._send(200, _SITEMAP_TEMPLATE.format(host=host), content_type="application/xml")
        elif self.path == "/external-redirect":
            self.send_response(302)
            self.send_header("Location", "http://external.example.com/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(404, "<html><body>not found</body></html>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")

        if self.path == "/api/login":
            match = re.search(r"username=(\w+)", body)
            username = match.group(1) if match else ""
            if username not in _VALID_SESSIONS:
                self._send(401, '{"error": "invalid credentials"}', content_type="application/json")
                return
            # E. cookie hardening issue — intentionally missing HttpOnly and
            # Secure, for the cookie-attribute validator to catch.
            self._send(200, f'{{"logged_in_as": "{username}"}}', content_type="application/json",
                       extra_headers={"Set-Cookie": f"adi_session={username}; Path=/"})
            return

        if self.path == "/api/logout":
            self._send(200, '{"logged_out": true}', content_type="application/json",
                       extra_headers={"Set-Cookie": "adi_session=; Path=/; Max-Age=0"})
            return

        if self.path == "/login":
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", "connect.sid=s%3Aauthenticated.sig; Path=/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(404, "<html><body>not found</body></html>")


class DemoApp:
    """Runs `DemoAppHandler` on a background thread on an OS-assigned port."""

    def __init__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), DemoAppHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_port

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> DemoApp:
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
