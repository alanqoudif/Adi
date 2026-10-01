"""A shared, assessment-level rate policy (spec Phase 3P).

Both the internal HTTP client and every external tool (ffuf, feroxbuster,
nuclei, ...) acquire from the same limiter so the configured
`rate_limits.requests_per_second` actually bounds total request volume
against the target, not just one subsystem's share of it.
"""

from __future__ import annotations

import asyncio
import time

from adi.scope.models import RateLimits


class RateLimiter:
    """A simple token-bucket limiter plus a concurrency semaphore."""

    def __init__(self, rate_limits: RateLimits):
        self._min_interval = 1.0 / rate_limits.requests_per_second if rate_limits.requests_per_second > 0 else 0.0
        self._last_request_at = 0.0
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max(1, rate_limits.concurrent_tools))

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_request_at)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at = time.monotonic()

    def concurrency_guard(self):
        return self._semaphore
