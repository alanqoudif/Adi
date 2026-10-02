"""General-purpose evidence redaction — distinct from `adi.http.redaction`
(which only handles HTTP header names). This scans arbitrary text (a
response body excerpt, a tool output snippet, a manual note) for common
secret-shaped patterns before it's stored as a `sanitized_preview`.

Defense in depth, not a guarantee: callers should still prefer passing only
the minimal text needed rather than relying solely on pattern matching.
"""

from __future__ import annotations

import re

from adi.http.redaction import MAX_BODY_PREVIEW, safe_body_preview

_SECRET_PATTERNS = [
    re.compile(r"(Bearer\s+)[A-Za-z0-9\-_\.]{10,}", re.IGNORECASE),
    re.compile(r"(Basic\s+)[A-Za-z0-9+/=]{10,}", re.IGNORECASE),
    re.compile(r"((?:api[_-]?key|apikey|secret|token)\s*[=:]\s*[\"']?)([A-Za-z0-9\-_\.]{8,})",
               re.IGNORECASE),
    re.compile(r"(password\s*[=:]\s*[\"']?)([^\s\"']{3,})", re.IGNORECASE),
    re.compile(r"(set-cookie:\s*[A-Za-z0-9_\-]+=)([^;\s]+)", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
]


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS[:-1]:
        redacted = pattern.sub(lambda m: m.group(1) + "<redacted>", redacted)
    redacted = _SECRET_PATTERNS[-1].sub("<redacted private key>", redacted)
    return redacted


def sanitize_for_evidence(text: str, content_type: str = "", max_len: int = MAX_BODY_PREVIEW) -> str:
    """The one function evidence creation should call: truncates/binary-guards
    (reusing the same logic HTTP responses already go through) and then
    scrubs secret-shaped substrings from what remains."""
    preview = safe_body_preview(text, content_type=content_type, max_len=max_len)
    return redact_secrets(preview)
