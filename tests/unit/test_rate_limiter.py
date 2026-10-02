import time

import pytest

from adi.scope.models import RateLimits
from adi.scope.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_enforces_minimum_interval():
    limiter = RateLimiter(RateLimits(requests_per_second=10))  # 100ms between requests
    start = time.monotonic()
    await limiter.acquire()
    await limiter.acquire()
    await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.2  # two gaps of ~100ms


@pytest.mark.asyncio
async def test_concurrency_guard_limits_parallelism():
    limiter = RateLimiter(RateLimits(requests_per_second=1000, concurrent_tools=2))
    active = 0
    max_active = 0

    async def worker():
        nonlocal active, max_active
        async with limiter.concurrency_guard():
            active += 1
            max_active = max(max_active, active)
            import asyncio
            await asyncio.sleep(0.05)
            active -= 1

    import asyncio
    await asyncio.gather(*(worker() for _ in range(5)))
    assert max_active <= 2
