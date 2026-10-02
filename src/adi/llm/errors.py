"""Safe provider errors: never propagate response bodies, URLs or headers."""
import httpx


def provider_error(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException) or 'timeout' in type(exc).__name__.lower():
        return 'Timeout'
    if isinstance(exc, httpx.ConnectError):
        return 'Connection refused or server unreachable'
    if isinstance(exc, (httpx.InvalidURL, httpx.UnsupportedProtocol)):
        return 'Invalid endpoint'
    status = getattr(exc, 'status_code', None)
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
    if status in (401, 403):
        return 'Authentication rejected'
    if status == 404:
        return 'Model not found or invalid endpoint'
    if status == 429:
        return 'Provider rate limit or quota exceeded'
    if status:
        return f'Provider rejected request (HTTP {status})'
    return 'Provider returned malformed response'
