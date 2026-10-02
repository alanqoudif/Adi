"""Raw `Set-Cookie` header parsing.

httpx's cookie jar (used for session continuity — sending cookies back on
later requests) does not reliably preserve `Secure`/`HttpOnly`/`SameSite`
flags. Phase 4's cookie-hardening validator needs those flags, so they are
parsed directly from the raw header value here instead.
"""

from __future__ import annotations

from adi.http.models import CookieMetadata


def parse_set_cookie_header(raw: str) -> CookieMetadata:
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return CookieMetadata(name="")
    name = parts[0].split("=", 1)[0].strip()

    secure = False
    http_only = False
    domain = ""
    path = "/"
    same_site = ""

    for attr in parts[1:]:
        if "=" in attr:
            key, value = attr.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
        else:
            key, value = attr.strip().lower(), ""

        if key == "secure":
            secure = True
        elif key == "httponly":
            http_only = True
        elif key == "domain":
            domain = value
        elif key == "path":
            path = value or "/"
        elif key == "samesite":
            same_site = value

    return CookieMetadata(
        name=name, domain=domain, path=path, secure=secure, http_only=http_only,
        same_site=same_site,
    )


def parse_set_cookie_headers(raw_values: list[str]) -> list[CookieMetadata]:
    return [parse_set_cookie_header(v) for v in raw_values]
