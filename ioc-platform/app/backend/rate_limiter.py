import asyncio
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from app.backend.logger import get_logger

logger = get_logger("rate_limiter")

# Provider pacing windows.  Module-level so tests can shrink them; the
# production values match the per-minute / per-day quotas the adapters declare
# in their ``RateLimitConfig``.
PROVIDER_WINDOW_SECONDS = 60.0
PROVIDER_DAY_SECONDS = 86400.0
# Upper bound for a provider-supplied Retry-After we will honor.
MAX_PROVIDER_PENALTY_SECONDS = 86400.0


@dataclass
class RateLimitDecision:
    allowed: bool
    retry_count: int = 0
    retry_after_seconds: float | None = None
    reason: str = ""


@dataclass
class SlotReservation:
    """Outcome of asking the provider scheduler for a request slot.

    ``granted`` reservations carry the monotonic ``slot_time`` at which the
    request may be sent; ``wait_seconds`` is how long the caller waited (or has
    to wait) for it.  A denied reservation reports ``retry_after_seconds``: the
    wait that would have been required, which did not fit the caller's budget.
    """

    granted: bool
    wait_seconds: float = 0.0
    retry_after_seconds: float | None = None
    reason: str = ""
    slot_time: float | None = None


@dataclass
class _ProviderSchedule:
    # Sorted monotonic send times (past requests and future reservations).
    minute: list[float] = field(default_factory=list)
    day: list[float] = field(default_factory=list)
    last_slot: float = float("-inf")
    # Provider-requested back-off (Retry-After / 429) shared by all lookups.
    blocked_until: float = 0.0


class RateLimiter:
    _PROVIDER_RESERVATION_SCRIPT = """
local minute_key = KEYS[1]
local daily_key = KEYS[2]
local now = tonumber(ARGV[1])
local minute_cutoff = tonumber(ARGV[2])
local daily_cutoff = tonumber(ARGV[3])
local minute_limit = tonumber(ARGV[4])
local daily_limit = tonumber(ARGV[5])
local member = ARGV[6]
redis.call('ZREMRANGEBYSCORE', minute_key, '-inf', minute_cutoff)
redis.call('ZREMRANGEBYSCORE', daily_key, '-inf', daily_cutoff)
if redis.call('ZCARD', minute_key) >= minute_limit then
    return 0
end
if daily_limit > 0 and redis.call('ZCARD', daily_key) >= daily_limit then
    return -1
end
redis.call('ZADD', minute_key, now, member)
redis.call('EXPIRE', minute_key, 65)
if daily_limit > 0 then
    redis.call('ZADD', daily_key, now, member)
    redis.call('EXPIRE', daily_key, 86405)
end
return 1
"""

    def __init__(self, redis_url: str | None = None):
        self.redis_url = redis_url or ""
        self._redis = None
        self._enabled = bool(self.redis_url)
        self._local_counters: dict[str, list[float]] = {}
        self._local_lock = asyncio.Lock()
        self._redis_lock = asyncio.Lock()
        self._slot_lock = asyncio.Lock()
        self._provider_slots: dict[str, asyncio.Semaphore] = {}
        self._provider_slot_limits: dict[str, int] = {}
        self._last_request: dict[str, float] = {}
        self._interval_locks: dict[str, asyncio.Lock] = {}
        self._schedules: dict[str, _ProviderSchedule] = {}

    async def _connect(self):
        import redis.asyncio as aioredis
        self._redis = aioredis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            retry_on_timeout=False,
        )
        await self._redis.ping()

    async def _get_redis(self):
        if self._redis is not None:
            return self._redis
        if not self._enabled or not self.redis_url:
            return None
        if self._redis is None:
            try:
                await self._connect()
            except Exception:
                logger.warning("Redis unavailable — rate limiter degraded to local")
                self._enabled = False
                self._redis = None
        return self._redis

    async def acquire(self, source: str, limit: int, window: int) -> bool:
        r = await self._get_redis()
        if r is None:
            return await self._local_acquire(source, limit, window)
        return await self._redis_acquire(r, source, limit, window)

    async def _redis_acquire(self, r, source: str, limit: int, window: int) -> bool:
        key = f"ratelimit:{source}"
        now = time.time()
        cutoff = now - window
        try:
            # The four commands form one critical section in this process.
            # Redis deployments can replace this with a Lua script, but the
            # lock also makes the bundled/fake Redis implementation race-free.
            async with self._redis_lock:
                await r.zremrangebyscore(key, "-inf", cutoff)
                count = await r.zcard(key)
                if count >= limit:
                    return False
                # A timestamp is not a safe sorted-set member: two requests
                # can arrive in the same clock tick and overwrite each other.
                member = f"{now:.9f}:{random.random():.12f}"
                await r.zadd(key, {member: now})
                await r.expire(key, window + 5)
                return True
        except Exception:
            return await self._local_acquire(source, limit, window)

    async def _local_acquire(self, source: str, limit: int, window: int) -> bool:
        async with self._local_lock:
            now = time.time()
            cutoff = now - window
            timestamps = self._local_counters.get(source, [])
            timestamps = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= limit:
                return False
            timestamps.append(now)
            self._local_counters[source] = timestamps
            return True

    async def acquire_blocking(self, source: str, limit: int, window: int, timeout: float = 30.0) -> bool:
        decision = await self.acquire_with_metadata(source, limit, window, timeout=timeout, max_attempts=3)
        if not decision.allowed:
            logger.warning("Rate limit exceeded for %s after %s attempts", source, decision.retry_count + 1)
        return decision.allowed

    async def acquire_with_metadata(
        self,
        source: str,
        limit: int,
        window: int,
        *,
        timeout: float = 30.0,
        max_attempts: int = 3,
        backoff_factor: float = 0.5,
        max_backoff_seconds: float = 8.0,
    ) -> RateLimitDecision:
        """Acquire a token with a bounded, jittered retry budget.

        A denied token is an availability outcome, never a reputation
        outcome. Callers can choose ``max_attempts=1`` for batch admission so
        a busy provider does not hold all other providers hostage.
        """
        deadline = time.monotonic() + max(0.0, timeout)
        attempts = 0
        while True:
            if await self.acquire(source, limit, window):
                return RateLimitDecision(True, retry_count=attempts)
            if attempts >= max(0, max_attempts - 1) or time.monotonic() >= deadline:
                return RateLimitDecision(
                    False,
                    retry_count=attempts,
                    retry_after_seconds=self.retry_after(source, limit, window),
                    reason="rate_limited",
                )
            attempts += 1
            delay = min(max_backoff_seconds, backoff_factor * (2 ** (attempts - 1)))
            delay *= random.uniform(0.8, 1.2)
            delay = min(delay, max(0.0, deadline - time.monotonic()))
            if delay <= 0:
                break
            await asyncio.sleep(delay)
        return RateLimitDecision(False, retry_count=attempts, reason="rate_limited")

    async def acquire_provider(
        self,
        source: str,
        requests_per_minute: int,
        requests_per_day: int,
        *,
        timeout: float = 0.0,
    ) -> RateLimitDecision:
        """Apply both the short-window and daily provider budgets."""
        # The local implementation reserves both windows under one lock. The
        # Redis implementation uses a Lua transaction when available, so the
        # minute and daily checks/reservations are atomic across app workers.
        redis = await self._get_redis()
        if redis is None:
            return await self._local_acquire_provider(
                source, requests_per_minute, requests_per_day,
            )
        return await self._redis_acquire_provider(
            redis, source, requests_per_minute, requests_per_day,
        )

    async def _redis_acquire_provider(
        self,
        redis,
        source: str,
        requests_per_minute: int,
        requests_per_day: int,
    ) -> RateLimitDecision:
        minute_limit = max(1, int(requests_per_minute or 1))
        daily_limit = max(0, int(requests_per_day or 0))
        now = time.time()
        member = f"{now:.9f}:{random.random():.12f}"
        minute_key = f"ratelimit:{source}"
        daily_key = f"ratelimit:{source}:day"

        try:
            # Redis' Lua execution is atomic across all workers/processes. It
            # also avoids the minute-token leak caused by two independent
            # acquire() calls when the daily quota is already exhausted.
            if hasattr(redis, "eval"):
                result = await redis.eval(
                    self._PROVIDER_RESERVATION_SCRIPT,
                    2,
                    minute_key,
                    daily_key,
                    now,
                    now - 60,
                    now - 86400,
                    minute_limit,
                    daily_limit,
                    member,
                )
                result = int(result)
                if result == 1:
                    return RateLimitDecision(True)
                return RateLimitDecision(
                    False,
                    reason="daily_quota_exhausted" if result == -1 else "rate_limited",
                )

            # Small fake/in-process Redis implementations used by tests may
            # not expose EVAL. Keep their fallback atomic within this process
            # and explicitly roll back a partial reservation on write errors.
            async with self._redis_lock:
                await redis.zremrangebyscore(minute_key, "-inf", now - 60)
                await redis.zremrangebyscore(daily_key, "-inf", now - 86400)
                if await redis.zcard(minute_key) >= minute_limit:
                    return RateLimitDecision(False, reason="rate_limited")
                if daily_limit and await redis.zcard(daily_key) >= daily_limit:
                    return RateLimitDecision(False, reason="daily_quota_exhausted")
                await redis.zadd(minute_key, {member: now})
                try:
                    if daily_limit:
                        await redis.zadd(daily_key, {member: now})
                    await redis.expire(minute_key, 65)
                    if daily_limit:
                        await redis.expire(daily_key, 86405)
                except Exception:
                    if hasattr(redis, "zrem"):
                        await redis.zrem(minute_key, member)
                        if daily_limit:
                            await redis.zrem(daily_key, member)
                    raise
                return RateLimitDecision(True)
        except Exception:
            logger.warning("Redis provider quota unavailable for %s; falling back to local", source)
            return await self._local_acquire_provider(source, minute_limit, daily_limit)

    async def _local_acquire_provider(
        self,
        source: str,
        requests_per_minute: int,
        requests_per_day: int,
    ) -> RateLimitDecision:
        now = time.time()
        minute_limit = max(1, int(requests_per_minute or 1))
        daily_limit = max(0, int(requests_per_day or 0))
        async with self._local_lock:
            minute_values = [
                value for value in self._local_counters.get(source, [])
                if value > now - 60
            ]
            if len(minute_values) >= minute_limit:
                self._local_counters[source] = minute_values
                retry_after = max(0.0, minute_values[0] + 60 - now) if minute_values else None
                return RateLimitDecision(False, retry_after_seconds=retry_after, reason="rate_limited")

            daily_values = [
                value for value in self._local_counters.get(f"{source}:day", [])
                if value > now - 86400
            ]
            if daily_limit and len(daily_values) >= daily_limit:
                self._local_counters[f"{source}:day"] = daily_values
                retry_after = max(0.0, daily_values[0] + 86400 - now) if daily_values else None
                return RateLimitDecision(False, retry_after_seconds=retry_after, reason="daily_quota_exhausted")

            minute_values.append(now)
            self._local_counters[source] = minute_values
            if daily_limit:
                daily_values.append(now)
                self._local_counters[f"{source}:day"] = daily_values
            return RateLimitDecision(True)

    def retry_after(self, source: str, limit: int, window: int) -> float | None:
        """Best-effort local retry-after estimate for a sliding window."""
        timestamps = self._local_counters.get(source, [])
        if not timestamps or limit <= 0:
            return None
        index = max(0, len(timestamps) - limit + 1)
        return max(0.0, timestamps[index] + window - time.time())

    async def wait_for_interval(self, source: str, interval: float, timeout: float = 0.0) -> float:
        """Wait for a provider minimum-request interval and return wait ms."""
        interval = max(0.0, float(interval or 0.0))
        started = time.monotonic()
        if interval:
            # Serialize only requests to the same provider. Holding the
            # shared counter lock while sleeping would accidentally turn a
            # per-provider pacing rule into a global application bottleneck.
            async with self._local_lock:
                interval_lock = self._interval_locks.setdefault(source, asyncio.Lock())
            remaining = max(0.0, timeout - (time.monotonic() - started)) if timeout else None
            if remaining is not None:
                await asyncio.wait_for(interval_lock.acquire(), timeout=remaining)
            else:
                await interval_lock.acquire()
            try:
                last = self._last_request.get(source, 0.0)
                delay = max(0.0, interval - (time.monotonic() - last))
                if delay > 0:
                    remaining = max(0.0, timeout - (time.monotonic() - started)) if timeout else None
                    if remaining is not None and delay > remaining:
                        raise asyncio.TimeoutError
                    await asyncio.sleep(delay)
                self._last_request[source] = time.monotonic()
            finally:
                interval_lock.release()
        return (time.monotonic() - started) * 1000.0

    # --- Provider request scheduler -------------------------------------
    #
    # One schedule per provider, shared by every single lookup and batch in
    # this process.  Instead of rejecting a request as soon as the sliding
    # window is full (which made concurrent lookups fail with rate_limited
    # immediately), a caller *reserves* the earliest send time that respects
    # the provider's per-minute and per-day quota, its minimum interval and
    # any Retry-After back-off the provider asked for.  Reservations are FIFO,
    # so concurrent callers get distinct slots without a thundering herd.  A
    # caller only receives ``rate_limited`` when that slot is further away than
    # the time it can afford to wait (its remaining IOC deadline).
    #
    # The app runs as a single process, so this schedule is process-local by
    # design; the Redis-backed ``acquire``/``acquire_provider`` helpers above
    # remain for request-level limiting.

    def _provider_schedule(self, source: str) -> _ProviderSchedule:
        schedule = self._schedules.get(source)
        if schedule is None:
            schedule = _ProviderSchedule()
            self._schedules[source] = schedule
        return schedule

    def reserve_provider(
        self,
        source: str,
        requests_per_minute: int,
        requests_per_day: int = 0,
        *,
        minimum_interval: float = 0.0,
        max_wait: float = 0.0,
    ) -> SlotReservation:
        """Reserve the earliest permitted send time for one provider request.

        The reservation is recorded only when the required wait fits inside
        ``max_wait``; otherwise nothing is consumed and the required wait is
        returned as ``retry_after_seconds``.  The computation contains no
        ``await``, so it is atomic on the event loop.
        """
        now = time.monotonic()
        window = float(PROVIDER_WINDOW_SECONDS)
        day = float(PROVIDER_DAY_SECONDS)
        schedule = self._provider_schedule(source)
        schedule.minute = [t for t in schedule.minute if t > now - window]
        schedule.day = [t for t in schedule.day if t > now - day]
        minute_limit = max(1, int(requests_per_minute or 1))
        daily_limit = max(0, int(requests_per_day or 0))

        earliest = max(now, schedule.blocked_until)
        reason = "provider_retry_after" if schedule.blocked_until > now else "rate_limited"
        interval = max(0.0, float(minimum_interval or 0.0))
        if interval and schedule.last_slot != float("-inf"):
            earliest = max(earliest, schedule.last_slot + interval)
        if schedule.minute:
            # FIFO: never jump ahead of an existing reservation.
            earliest = max(earliest, schedule.minute[-1])
        if len(schedule.minute) >= minute_limit:
            earliest = max(earliest, schedule.minute[-minute_limit] + window)
        if daily_limit and len(schedule.day) >= daily_limit:
            day_earliest = schedule.day[-daily_limit] + day
            if day_earliest > earliest:
                earliest = day_earliest
                reason = "daily_quota_exhausted"

        wait = max(0.0, earliest - now)
        if wait > max(0.0, float(max_wait or 0.0)):
            return SlotReservation(False, retry_after_seconds=round(wait, 3), reason=reason)
        schedule.minute.append(earliest)
        if daily_limit:
            schedule.day.append(earliest)
        schedule.last_slot = max(schedule.last_slot, earliest)
        return SlotReservation(True, wait_seconds=wait, slot_time=earliest)

    def release_provider(self, source: str, slot_time: float | None) -> None:
        """Return a reservation that was never used (caller cancelled/gave up)."""
        if slot_time is None:
            return
        schedule = self._schedules.get(source)
        if schedule is None or slot_time <= time.monotonic():
            # The slot's send time has passed: treat it as consumed.
            return
        for values in (schedule.minute, schedule.day):
            try:
                values.remove(slot_time)
            except ValueError:
                pass
        if schedule.last_slot == slot_time:
            schedule.last_slot = schedule.minute[-1] if schedule.minute else float("-inf")

    def penalize_provider(self, source: str, retry_after_seconds: float | None) -> None:
        """Honor a provider's Retry-After for every lookup in this process."""
        if retry_after_seconds is None:
            return
        try:
            delay = min(max(0.0, float(retry_after_seconds)), MAX_PROVIDER_PENALTY_SECONDS)
        except (TypeError, ValueError):
            return
        if delay <= 0:
            return
        schedule = self._provider_schedule(source)
        schedule.blocked_until = max(schedule.blocked_until, time.monotonic() + delay)

    def provider_blocked_for(self, source: str) -> float:
        schedule = self._schedules.get(source)
        if schedule is None:
            return 0.0
        return max(0.0, schedule.blocked_until - time.monotonic())

    async def wait_for_reservation(
        self,
        source: str,
        reservation: SlotReservation,
        *,
        max_wait: float,
    ) -> SlotReservation:
        """Sleep until a granted reservation's send time.

        If the provider asked us to back off while we were waiting, the extra
        delay is honored when it still fits ``max_wait`` (measured from the
        start of this call); otherwise the reservation is released and a denied
        reservation is returned.  Cancellation releases the unused slot.
        """
        if not reservation.granted:
            return reservation
        started = time.monotonic()
        try:
            delay = (reservation.slot_time or started) - started
            if delay > 0:
                await asyncio.sleep(delay)
            blocked = self.provider_blocked_for(source)
            if blocked > 0:
                spent = time.monotonic() - started
                if spent + blocked > max(0.0, max_wait):
                    self.release_provider(source, reservation.slot_time)
                    return SlotReservation(
                        False,
                        wait_seconds=spent,
                        retry_after_seconds=round(blocked, 3),
                        reason="provider_retry_after",
                    )
                await asyncio.sleep(blocked)
        except asyncio.CancelledError:
            self.release_provider(source, reservation.slot_time)
            raise
        reservation.wait_seconds = time.monotonic() - started
        return reservation

    @asynccontextmanager
    async def provider_slot(self, source: str, concurrency_limit: int = 2, timeout: float = 0.0):
        """Limit in-flight requests independently for each provider."""
        limit = max(1, int(concurrency_limit or 1))
        async with self._slot_lock:
            slot = self._provider_slots.get(source)
            if slot is None or self._provider_slot_limits.get(source) != limit:
                slot = asyncio.Semaphore(limit)
                self._provider_slots[source] = slot
                self._provider_slot_limits[source] = limit
        if timeout and timeout > 0:
            await asyncio.wait_for(slot.acquire(), timeout=timeout)
        else:
            await slot.acquire()
        try:
            yield
        finally:
            slot.release()

    async def close(self):
        if self._redis is not None:
            try:
                await self._redis.close()
            except Exception:
                pass
            self._redis = None
            self._enabled = True
        self._provider_slots.clear()
        self._provider_slot_limits.clear()
        self._interval_locks.clear()
        self._schedules.clear()
