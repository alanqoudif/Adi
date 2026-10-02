"""Maps logical Adi sessions ("anonymous", "user_a", "admin", ...) to HTTP
cookie jars (spec Phase 3M).

Cookie *values* live only in memory for the lifetime of the process — never
persisted to the database or written to disk, since a session cookie is
effectively a live credential. Only cookie *names* (via
`CookieMetadata`) are ever stored, through `HTTPWorkspace`.
"""

from __future__ import annotations

import httpx


class SessionJarRegistry:
    """One `httpx.Cookies` jar per logical session name, scoped to a single
    assessment run (process memory only)."""

    def __init__(self):
        self._jars: dict[str, httpx.Cookies] = {}

    def get(self, session_id: str) -> httpx.Cookies:
        if session_id not in self._jars:
            self._jars[session_id] = httpx.Cookies()
        return self._jars[session_id]

    def cookie_names(self, session_id: str) -> list[str]:
        jar = self._jars.get(session_id)
        if jar is None:
            return []
        return [c.name for c in jar.jar]

    def reset(self, session_id: str) -> None:
        self._jars.pop(session_id, None)
