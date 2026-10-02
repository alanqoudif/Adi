"""Header/body redaction — nothing secret reaches planner context, logs, the
database, or reports. See docs/safety-model.md."""

from __future__ import annotations

_SENSITIVE_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "x-api-key", "api-key",
    "x-auth-token", "proxy-authorization", "x-csrf-token",
}

MAX_BODY_PREVIEW = 600


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted = {}
    for key, value in headers.items():
        if key.lower() in _SENSITIVE_HEADER_NAMES:
            redacted[key] = _redact_value(value)
        else:
            redacted[key] = value
    return redacted


def _redact_value(value: str) -> str:
    if not value:
        return value
    visible = value[:6]
    return f"{visible}...<redacted>"


def safe_body_preview(body: bytes | str, content_type: str = "", max_len: int = MAX_BODY_PREVIEW) -> str:
    """A truncated, best-effort-safe preview of a response/request body for
    display in logs or planner context. Binary content is never decoded."""
    if isinstance(body, bytes):
        if content_type and not any(
            t in content_type for t in ("text", "json", "xml", "html", "javascript")
        ):
            return f"<binary content, {len(body)} bytes>"
        try:
            text = body.decode("utf-8", errors="replace")
        except UnicodeError:
            return f"<binary content, {len(body)} bytes>"
    else:
        text = body
    text = text.strip()
    if len(text) > max_len:
        return text[:max_len] + f"... <truncated, {len(text)} chars total>"
    return text
