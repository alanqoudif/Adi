"""Canonical URL handling (spec Phase 3C).

Endpoint deduplication depends entirely on this being deterministic: the
same logical endpoint must always normalize to the same string, and two
endpoints that only *look* similar must never collapse into one.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def canonicalize_url(url: str) -> str:
    """Normalize a URL for storage/comparison:

    - lowercase scheme and host
    - drop the default port for the scheme (http:80, https:443)
    - drop the fragment (fragments are client-side only, never a distinct
      server-side endpoint)
    - collapse an empty path to "/"
    - sort query parameters by key (stable, safe — values are never merged
      or deduplicated, so semantically different query strings never
      collapse into the same endpoint)
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = parts.hostname.lower() if parts.hostname else ""
    port = parts.port
    if port is not None and _DEFAULT_PORTS.get(scheme) == port:
        port = None
    netloc = host if port is None else f"{host}:{port}"
    if parts.username:
        userinfo = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{userinfo}@{netloc}"

    path = parts.path or "/"

    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    query = urlencode(sorted(query_pairs))

    return urlunsplit((scheme, netloc, path, query, ""))


def path_only(url: str) -> str:
    """The canonical path component alone (what `EndpointRecord.path`
    stores) — query strings describe parameters, not distinct endpoints."""
    parts = urlsplit(canonicalize_url(url))
    return parts.path or "/"


def host_of(url: str) -> str:
    parts = urlsplit(url)
    return parts.hostname or ""


def join_url(base: str, link: str) -> str:
    """Resolve a (possibly relative) link against a base URL and canonicalize
    the result. Used for links/forms/script srcs extracted from HTML."""
    from urllib.parse import urljoin

    return canonicalize_url(urljoin(base, link))
