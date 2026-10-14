import sys
import time

sys.path.insert(0, ".")

import asyncio

from app.backend.rate_limiter import RateLimiter


def _local_limiter():
    rl = RateLimiter()
    rl._enabled = False
    return rl


def test_local_acquire_allows_under_limit():
    rl = _local_limiter()

    async def main():
        assert await rl.acquire("VT", limit=3, window=10) is True
        assert await rl.acquire("VT", limit=3, window=10) is True
        assert await rl.acquire("VT", limit=3, window=10) is True

    asyncio.run(main())


def test_local_acquire_blocks_over_limit():
    rl = _local_limiter()

    async def main():
        for _ in range(3):
            assert await rl.acquire("VT", limit=3, window=10) is True
        assert await rl.acquire("VT", limit=3, window=10) is False

    asyncio.run(main())


def test_local_acquire_window_expiry():
    rl = _local_limiter()
    rl._local_counters["VT"] = [1.0]  # old timestamp far outside any window

    async def main():
        assert await rl.acquire("VT", limit=1, window=3600) is True

    asyncio.run(main())


def test_local_acquire_per_source_independent():
    rl = _local_limiter()

    async def main():
        for _ in range(3):
            assert await rl.acquire("VT", limit=3, window=10) is True
        assert await rl.acquire("OTX", limit=3, window=10) is True

    asyncio.run(main())


def test_acquire_blocking_succeeds():
    rl = _local_limiter()

    async def main():
        assert await rl.acquire_blocking("VT", limit=2, window=10, timeout=2.0) is True

    asyncio.run(main())


def test_acquire_blocking_times_out():
    rl = _local_limiter()

    async def main():
        for _ in range(2):
            await rl.acquire("VT", limit=2, window=3600)
        ok = await rl.acquire_blocking("VT", limit=2, window=3600, timeout=0.2)
        assert ok is False

    asyncio.run(main())


def test_close_resets_state():
    rl = _local_limiter()

    async def main():
        await rl.acquire("VT", limit=1, window=10)
        await rl.close()
        assert rl._redis is None

    asyncio.run(main())


def test_degraded_when_redis_unavailable(monkeypatch):
    rl = RateLimiter(redis_url="redis://localhost:6399/0")

    async def boom():
        raise ConnectionError("no redis")

    monkeypatch.setattr(rl, "_connect", boom)

    async def main():
        assert await rl.acquire("VT", limit=5, window=10) is True
        assert rl._enabled is False
        assert rl._redis is None

    asyncio.run(main())


class _FakeRedisLimiter:
    def __init__(self):
        self.sorted = {}
        self.expires = {}

    async def zremrangebyscore(self, key, mn, mx):
        if key not in self.sorted:
            return 0
        lo = float("-inf") if mn in ("-inf", "-INF") else mn
        hi = float("inf") if mx in ("inf", "+inf") else mx
        before = len(self.sorted[key])
        self.sorted[key] = [v for v in self.sorted[key] if not (lo <= v <= hi)]
        return before - len(self.sorted[key])

    async def zcard(self, key):
        return len(self.sorted.get(key, []))

    async def zadd(self, key, mapping):
        self.sorted.setdefault(key, []).append(list(mapping.values())[0])

    async def expire(self, key, ttl):
        self.expires[key] = ttl


class TestRateLimiterRedis:
    def test_redis_acquire_under_limit(self):
        rl = RateLimiter()
        rl._redis = _FakeRedisLimiter()

        async def main():
            assert await rl.acquire("VT", limit=2, window=10) is True
            assert await rl.acquire("VT", limit=2, window=10) is True

        asyncio.run(main())

    def test_redis_acquire_blocks_over_limit(self):
        rl = RateLimiter()
        rl._redis = _FakeRedisLimiter()

        async def main():
            assert await rl.acquire("VT", limit=2, window=10) is True
            assert await rl.acquire("VT", limit=2, window=10) is True
            assert await rl.acquire("VT", limit=2, window=10) is False

        asyncio.run(main())

    def test_redis_prunes_old_scores(self):
        rl = RateLimiter()
        rl._redis = _FakeRedisLimiter()
        rl._redis.sorted["ratelimit:VT"] = [0.0, 0.0]  # very old entries

        async def main():
            assert await rl.acquire("VT", limit=1, window=3600) is True

        asyncio.run(main())

    def test_redis_error_falls_back_to_local(self):
        rl = RateLimiter()
        rl._enabled = True

        class Broken:
            async def zremrangebyscore(self, *a):
                raise ConnectionError("down")

            async def zcard(self, *a):
                raise ConnectionError("down")

            async def zadd(self, *a):
                raise ConnectionError("down")

            async def expire(self, *a):
                raise ConnectionError("down")

        rl._redis = Broken()

        async def main():
            assert await rl.acquire("VT", limit=2, window=10) is True

        asyncio.run(main())

    def test_redis_acquire_blocking_succeeds(self):
        rl = RateLimiter()
        rl._redis = _FakeRedisLimiter()

        async def main():
            assert await rl.acquire_blocking("VT", limit=2, window=10, timeout=2.0) is True

        asyncio.run(main())

    def test_redis_provider_quota_reservation_does_not_leak_minute_token(self):
        rl = RateLimiter()
        rl._redis = _FakeRedisLimiter()

        async def main():
            now = time.time()
            rl._redis.sorted["ratelimit:Provider:day"] = [now]
            denied = await rl.acquire_provider("Provider", 1, 1)
            assert denied.allowed is False
            assert denied.reason == "daily_quota_exhausted"
            assert rl._redis.sorted.get("ratelimit:Provider", []) == []

        asyncio.run(main())

    def test_close_with_redis(self):
        rl = RateLimiter()
        rl._redis = _FakeRedisLimiter()

        async def main():
            await rl.close()
            assert rl._redis is None
            assert rl._enabled is True

        asyncio.run(main())
