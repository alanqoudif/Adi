import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures" / "webapp"))
from app import DemoApp

from adi.http.client import HTTPClient
from adi.http.sessions import SessionJarRegistry
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope


@pytest.fixture()
def demo_app():
    app = DemoApp().start()
    yield app
    app.stop()


def make_client(targets: list[str]) -> HTTPClient:
    scope = Scope(name="http-client-test", targets=targets)
    return HTTPClient(ScopeEngine(scope), SessionJarRegistry())


@pytest.mark.asyncio
async def test_basic_get_request(demo_app):
    client = make_client(["127.0.0.1"])
    exchange, body = await client.request("GET", demo_app.base_url + "/")
    assert exchange.response is not None
    assert exchange.response.status == 200
    assert "Login" in body


@pytest.mark.asyncio
async def test_headers_are_redacted_on_the_exchange(demo_app):
    client = make_client(["127.0.0.1"])
    exchange, _ = await client.request("GET", demo_app.base_url + "/")
    # the home page sets a session cookie; it must never appear unredacted
    set_cookie = exchange.response.headers.get("Set-Cookie", "")
    assert "fake.sig" not in set_cookie


@pytest.mark.asyncio
async def test_out_of_scope_target_is_never_requested(demo_app):
    client = make_client(["10.0.0.0/8"])  # does not cover 127.0.0.1
    exchange, body = await client.request("GET", demo_app.base_url + "/")
    assert exchange.response is None
    assert "not within the authorized scope" in exchange.error
    assert body == ""


@pytest.mark.asyncio
async def test_redirect_to_out_of_scope_host_is_not_followed(demo_app):
    client = make_client(["127.0.0.1"])
    exchange, _ = await client.request(
        "GET", demo_app.base_url + "/external-redirect", follow_redirects=True,
    )
    assert len(exchange.redirects) == 1
    hop = exchange.redirects[0]
    assert hop.to_url == "http://external.example.com/"
    assert hop.authorized is False
    # the final response is still the 302 itself — Adi never actually
    # requested external.example.com
    assert exchange.response.status == 302


@pytest.mark.asyncio
async def test_redirect_to_in_scope_host_is_followed(demo_app):
    client = make_client(["127.0.0.1"])
    # POST /login 302s to /dashboard on the same host — this hop must be followed
    exchange, body = await client.request(
        "POST", demo_app.base_url + "/login", follow_redirects=True, body="email=a&password=b",
    )
    assert len(exchange.redirects) == 1
    assert exchange.redirects[0].authorized is True
    assert exchange.response.status == 200
    assert "Dashboard" in body


@pytest.mark.asyncio
async def test_session_cookie_jar_persists_across_requests(demo_app):
    client = make_client(["127.0.0.1"])
    await client.request("POST", demo_app.base_url + "/login", session_id="user_a",
                          follow_redirects=True, body="email=a&password=b")
    names = client.session_jars.cookie_names("user_a")
    assert "connect.sid" in names
