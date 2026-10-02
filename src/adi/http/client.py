"""The internal HTTP client (spec Phase 3B/3F).

Every redirect hop is authorized against the `ScopeEngine` individually —
`httpx`'s own `follow_redirects=True` is never used blindly, because that
would let a single authorized request silently pull the agent onto an
unauthorized host. An unauthorized hop is recorded, never followed.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import httpx

from adi.http.cookies import parse_set_cookie_headers
from adi.http.models import (
    HTTPExchange,
    HTTPMethod,
    HTTPRequest,
    HTTPResponse,
    RedirectHop,
)
from adi.http.redaction import redact_headers, safe_body_preview
from adi.http.sessions import SessionJarRegistry
from adi.scope.engine import ScopeEngine
from adi.scope.rate_limiter import RateLimiter

MAX_BODY_BYTES = 2 * 1024 * 1024  # never buffer unbounded response bodies


def _utcnow() -> datetime:
    return datetime.now(UTC)


class HTTPClient:
    def __init__(
        self,
        scope_engine: ScopeEngine,
        session_jars: SessionJarRegistry,
        rate_limiter: RateLimiter | None = None,
        timeout: float = 20.0,
    ):
        self.scope_engine = scope_engine
        self.session_jars = session_jars
        self.rate_limiter = rate_limiter
        self.timeout = timeout

    async def request(
        self,
        method: HTTPMethod | str,
        url: str,
        *,
        session_id: str = "anonymous",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        follow_redirects: bool = False,
        max_redirects: int = 5,
        source: str = "http_client",
    ) -> tuple[HTTPExchange, str]:
        """Returns (exchange, raw_response_body_text). The body is kept out
        of the persisted `HTTPExchange` model (only a redacted preview/hash
        is) so callers (HTTPWorkspace) can run HTML extraction on it without
        the full body ever round-tripping through planner context."""
        method = HTTPMethod(method) if isinstance(method, str) else method
        headers = headers or {}
        started_at = _utcnow()
        current_url = url
        redirects: list[RedirectHop] = []
        jar = self.session_jars.get(session_id)

        host = urlsplit(current_url).hostname or ""
        if not self.scope_engine.is_host_authorized(host):
            return (
                HTTPExchange(
                    request=HTTPRequest(method=method, url=url, headers=redact_headers(headers),
                                         body_size=len(body or ""), session_id=session_id),
                    response=None,
                    error=f"host '{host}' is not within the authorized scope",
                    source=source, started_at=started_at, completed_at=_utcnow(),
                ),
                "",
            )

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=False, cookies=jar,
        ) as client:
            hop = 0
            current_method = method
            current_body = body
            response: httpx.Response | None = None
            error: str | None = None
            while True:
                if self.rate_limiter is not None:
                    await self.rate_limiter.acquire()
                try:
                    response = await client.request(
                        current_method.value, current_url, headers=headers,
                        content=current_body.encode() if current_body else None,
                    )
                except httpx.HTTPError as exc:
                    error = str(exc)
                    break

                is_redirect = response.is_redirect and "location" in response.headers
                if not is_redirect or not follow_redirects or hop >= max_redirects:
                    break

                next_url = urljoin(current_url, response.headers["location"])
                next_host = urlsplit(next_url).hostname or ""
                authorized = self.scope_engine.is_host_authorized(next_host)
                redirects.append(RedirectHop(
                    from_url=current_url, to_url=next_url, status=response.status_code,
                    authorized=authorized,
                    reason="" if authorized else f"host '{next_host}' is outside the authorized scope",
                ))
                if not authorized:
                    break
                current_url = next_url
                # Per RFC 7231: a 301/302/303 to a non-GET/HEAD request is
                # conventionally re-issued as GET (standard browser
                # behavior); 307/308 preserve the original method and body.
                if response.status_code in (301, 302, 303) and current_method not in (
                    HTTPMethod.GET, HTTPMethod.HEAD
                ):
                    current_method = HTTPMethod.GET
                    current_body = None
                hop += 1

            # httpx.AsyncClient(cookies=jar) copies `jar` into its own
            # internal Cookies instance rather than mutating it in place, so
            # Set-Cookie responses never reach the session's persistent jar
            # on their own. `Cookies.update()` only ever ADDS cookies, so it
            # can't express a Max-Age=0/expiry removal (e.g. a logout
            # response) — replace the jar's contents outright instead so
            # removals are honored too.
            jar.jar.clear()
            for cookie in client.cookies.jar:
                jar.jar.set_cookie(cookie)

        completed_at = _utcnow()

        if error is not None or response is None:
            return (
                HTTPExchange(
                    request=HTTPRequest(method=method, url=url, headers=redact_headers(headers),
                                         body_size=len(body or ""), session_id=session_id),
                    response=None, redirects=redirects, error=error,
                    source=source, started_at=started_at, completed_at=completed_at,
                ),
                "",
            )

        raw_bytes = response.content[:MAX_BODY_BYTES]
        content_type = response.headers.get("content-type", "")
        body_text = safe_body_preview(raw_bytes, content_type, max_len=10**9)  # full text if decodable
        body_hash = hashlib.sha256(raw_bytes).hexdigest()

        # Parsed from the raw header, not the cookie jar — the jar loses
        # Secure/HttpOnly/SameSite flags, which the cookie-hardening
        # validator (Phase 4) needs.
        cookies_meta = parse_set_cookie_headers(response.headers.get_list("set-cookie"))

        http_response = HTTPResponse(
            status=response.status_code,
            headers=redact_headers(dict(response.headers)),
            content_type=content_type,
            content_length=len(raw_bytes),
            body_hash=body_hash,
            body_preview=safe_body_preview(raw_bytes, content_type),
            cookies=cookies_meta,
        )

        exchange = HTTPExchange(
            request=HTTPRequest(method=method, url=current_url, headers=redact_headers(headers),
                                 body_size=len(body or ""), session_id=session_id),
            response=http_response, redirects=redirects, source=source,
            started_at=started_at, completed_at=completed_at,
        )
        return exchange, body_text
