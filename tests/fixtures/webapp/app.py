"""A minimal, deterministic local web application used to prove Adi can
autonomously discover a realistic attack surface (spec Phase 3T).

This is NOT primarily a vulnerability lab — its only purpose is to expose a
realistic shape (links, a login form, "authenticated" API routes reached via
an inline JS fetch, robots.txt, sitemap.xml, a cookie, and an out-of-scope
redirect) for the HTTP/HTML discovery pipeline to find on its own.

Pure standard library — no extra test dependency to install.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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

    def do_GET(self):
        host = self.headers.get("Host", f"127.0.0.1:{self.server.server_port}")
        if self.path == "/":
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
        self.rfile.read(length)
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
