"""Regression tests for provider fan-out orchestration.

Covers the shared per-provider scheduler (concurrent lookups wait for a slot
instead of failing with rate_limited), Retry-After sharing, the circuit
breaker only counting provider-side failures, slow providers not holding the
lookup, failures never being cached, and not_applicable providers staying out
of task.results.
"""
import asyncio
import time

import httpx
import pytest

from app.backend import pipeline as pipeline_mod
from app.backend import rate_limiter as rate_limiter_mod
from app.backend.adapters.base import EnrichmentData, NormalizedResult, RateLimitConfig, SourceAdapter
from app.backend.cache import CacheLayer, LocalFileCache, cache_key
from app.backend.circuit_breaker import CircuitBreakerState, get_breaker
from app.backend.logger import describe_exception
from app.backend.pipeline import run_analysis
from app.backend.rate_limiter import RateLimiter


def _adapter(name, *, rpm=60, rpd=0, types=("ipv4",), behavior=None, concurrency=4, max_retries=2):
    calls: list[tuple[str, float]] = []

    class FakeAdapter(SourceAdapter):
        public_without_key = True
        api_key = None

        async def lookup(self, ioc_value, ioc_type):
            calls.append((ioc_value, time.monotonic()))
            if behavior is not None:
                return await behavior(self, ioc_value, ioc_type, len(calls))
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="clean", execution_state="success",
            )

    FakeAdapter.name = name
    FakeAdapter.supported_types = list(types)
    FakeAdapter.rate_limit = RateLimitConfig(
        requests_per_minute=rpm, requests_per_day=rpd, concurrency_limit=concurrency,
        max_retries=max_retries, backoff_factor=0.01, max_backoff_seconds=0.02,
    )
    adapter = FakeAdapter()
    get_breaker(name).reset()
    return adapter, calls


@pytest.fixture
def orchestration(monkeypatch):
    async def fake_enrich(value, ioc_type):
        return EnrichmentData()

    limiter = RateLimiter()
    monkeypatch.setattr(pipeline_mod, "enrich", fake_enrich)
    monkeypatch.setattr(pipeline_mod, "cache", None)
    monkeypatch.setattr(pipeline_mod, "rate_limiter", limiter)
    return limiter


async def test_concurrent_lookups_wait_for_shared_provider_slots(orchestration, monkeypatch):
    """9 concurrent lookups vs a 4-per-window provider: all succeed, none is
    reported rate_limited, and the provider never sees more than 4 requests in
    one window."""
    window = 0.4
    monkeypatch.setattr(rate_limiter_mod, "PROVIDER_WINDOW_SECONDS", window)
    adapter, calls = _adapter("Fake Quota4", rpm=4)
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [adapter])

    iocs = [f"8.8.4.{i}" for i in range(1, 10)]
    tasks = await asyncio.gather(*(run_analysis(ioc, ioc_deadline=15) for ioc in iocs))

    states = [task.results[0].execution_state for task in tasks]
    assert states == ["success"] * 9
    assert all(task.status == "done" for task in tasks)
    assert len(calls) == 9
    stamps = sorted(stamp for _, stamp in calls)
    for index in range(len(stamps) - 4):
        # The 5th request after any request is at least one window later.
        assert stamps[index + 4] - stamps[index] >= window - 0.02
    # Later lookups recorded the time they spent waiting for their slot.
    assert max(task.results[0].queue_wait_ms for task in tasks) >= (window * 1000) * 0.9


async def test_slot_beyond_deadline_is_rate_limited_without_calling(orchestration, monkeypatch):
    adapter, calls = _adapter("Fake Quota1", rpm=1)
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [adapter])

    first, second = await asyncio.gather(
        run_analysis("8.8.4.20", ioc_deadline=6),
        run_analysis("8.8.4.21", ioc_deadline=6),
    )
    by_state = sorted([first.results[0], second.results[0]], key=lambda r: r.execution_state)
    limited, success = by_state
    assert success.execution_state == "success"
    assert limited.execution_state == "rate_limited"
    assert limited.request_made is False
    assert limited.retry_after_seconds is not None and limited.retry_after_seconds > 50
    assert len(calls) == 1
    # Throttling by us is not a provider failure.
    assert get_breaker("Fake Quota1").state == CircuitBreakerState.CLOSED
    assert get_breaker("Fake Quota1").failure_count == 0


async def test_provider_retry_after_is_honored_by_later_lookups(orchestration, monkeypatch):
    async def throttled(self, ioc_value, ioc_type, n):
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="unknown",
            execution_state="rate_limited", tags=["rate_limited"], http_status=429,
            retry_after_seconds=120.0,
        )

    adapter, calls = _adapter("Fake RetryAfter", behavior=throttled)
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [adapter])

    first = await run_analysis("8.8.4.30", ioc_deadline=5)
    second = await run_analysis("8.8.4.31", ioc_deadline=5)

    assert len(calls) == 1, "the provider's Retry-After must stop further requests"
    assert first.results[0].execution_state == "rate_limited"
    assert first.results[0].http_status == 429
    assert second.results[0].execution_state == "rate_limited"
    assert second.results[0].request_made is False
    assert "provider_retry_after" in second.results[0].tags
    assert get_breaker("Fake RetryAfter").state == CircuitBreakerState.CLOSED


async def test_transport_errors_count_toward_circuit_but_are_retried(orchestration, monkeypatch):
    async def broken(self, ioc_value, ioc_type, n):
        raise httpx.ConnectError("")

    adapter, calls = _adapter("Fake Broken", behavior=broken, max_retries=1)
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [adapter])

    task = await run_analysis("8.8.4.40", ioc_deadline=10)
    result = task.results[0]
    assert result.execution_state == "error"
    assert "request_error" in result.tags
    assert result.retry_count == 1
    assert len(calls) == 2
    breaker = get_breaker("Fake Broken")
    assert breaker.failure_count == 1  # one failed lookup, not one per attempt


async def test_slow_provider_times_out_without_holding_the_lookup(orchestration, monkeypatch):
    from app.backend.config import settings

    async def slow(self, ioc_value, ioc_type, n):
        await asyncio.sleep(10)

    slow_adapter, _ = _adapter("Fake Slow", behavior=slow)
    fast_adapter, _ = _adapter("Fake Fast")
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [slow_adapter, fast_adapter])
    monkeypatch.setattr(settings, "provider_timeout_seconds", 0.3)

    started = time.monotonic()
    task = await run_analysis("8.8.4.50", ioc_deadline=8)
    elapsed = time.monotonic() - started

    by_source = {r.source: r for r in task.results}
    assert task.status == "done"
    assert elapsed < 3.0
    assert by_source["Fake Slow"].execution_state == "timeout"
    assert by_source["Fake Slow"].request_made is True
    assert by_source["Fake Fast"].execution_state == "success"


async def test_ioc_deadline_keeps_completed_results_and_marks_aborted(orchestration, monkeypatch):
    from app.backend.config import settings

    async def slow(self, ioc_value, ioc_type, n):
        await asyncio.sleep(10)

    slow_adapter, _ = _adapter("Fake Stuck", behavior=slow)
    fast_adapter, _ = _adapter("Fake Quick")
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [slow_adapter, fast_adapter])
    monkeypatch.setattr(settings, "provider_timeout_seconds", 30.0)

    task = await run_analysis("8.8.4.60", ioc_deadline=0.5)
    by_source = {r.source: r for r in task.results}
    assert task.status == "done"
    assert by_source["Fake Quick"].execution_state == "success"
    assert by_source["Fake Stuck"].execution_state in {"timeout", "aborted_due_to_ioc_deadline"}
    assert task.final_assessment is not None
    assert task.enrichment is not None


async def test_not_applicable_providers_are_only_in_the_plan(orchestration, monkeypatch):
    ip_adapter, _ = _adapter("Fake IP Source", types=("ipv4",))
    hash_adapter, hash_calls = _adapter("Fake Hash Source", types=("md5",))
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [ip_adapter, hash_adapter])

    task = await run_analysis("8.8.4.70", ioc_deadline=5)

    assert [r.source for r in task.results] == ["Fake IP Source"]
    assert all(r.execution_state != "not_applicable" for r in task.results)
    plan = {item["provider"]: item["applicable"] for item in task.provider_plan}
    assert plan == {"Fake IP Source": True, "Fake Hash Source": False}
    assert task.final_assessment.evidence_summary["not_applicable_providers"] == 1
    assert hash_calls == []


async def test_success_is_cached_but_failures_are_not(orchestration, monkeypatch, tmp_path):
    async def flaky(self, ioc_value, ioc_type, n):
        if ioc_value.endswith(".81"):
            raise httpx.ReadError("")
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="clean", execution_state="success",
        )

    layer = CacheLayer()
    layer._local = LocalFileCache(str(tmp_path))
    monkeypatch.setattr(pipeline_mod, "cache", layer)
    adapter, calls = _adapter("Fake Cacheable", behavior=flaky, max_retries=0)
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [adapter])

    await run_analysis("8.8.4.80", ioc_deadline=5)
    await run_analysis("8.8.4.81", ioc_deadline=5)
    assert await layer.get(cache_key("Fake Cacheable", "ipv4", "8.8.4.80")) is not None
    assert await layer.get(cache_key("Fake Cacheable", "ipv4", "8.8.4.81")) is None

    again = await run_analysis("8.8.4.80", ioc_deadline=5)
    assert again.results[0].cached is True
    assert len(calls) == 2


async def test_cancelled_analysis_is_terminal_and_propagates(orchestration, monkeypatch):
    async def slow(self, ioc_value, ioc_type, n):
        await asyncio.sleep(10)

    adapter, _ = _adapter("Fake Cancel", behavior=slow)
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [adapter])

    runner = asyncio.create_task(run_analysis("8.8.4.90", task_id="orch-cancel", ioc_deadline=20))
    await asyncio.sleep(0.2)
    runner.cancel()
    with pytest.raises(asyncio.CancelledError):
        await runner
    task = pipeline_mod.get_task("orch-cancel")
    assert task.status == "cancelled"
    assert task.progress == 100.0
    assert "orch-cancel" not in pipeline_mod._running_tasks


async def test_failed_analysis_reports_a_non_empty_error(orchestration, monkeypatch):
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [])

    def explode(*args, **kwargs):
        raise RuntimeError()

    monkeypatch.setattr(pipeline_mod, "aggregate_evidence", explode)
    task = await run_analysis("8.8.4.100", ioc_deadline=5)
    assert task.status == "error"
    assert task.error and "RuntimeError" in task.error


def test_describe_exception_is_never_empty():
    assert describe_exception(httpx.ConnectError("")).startswith("ConnectError")
    assert "TimeoutError" in describe_exception(asyncio.TimeoutError())
    try:
        try:
            raise OSError("connection reset")
        except OSError as inner:
            raise httpx.ReadError("") from inner
    except httpx.ReadError as exc:
        text = describe_exception(exc)
    assert "ReadError" in text and "OSError: connection reset" in text
    assert "secret123" not in describe_exception(ValueError("apikey=secret123"))


def test_scheduler_reservations_are_fifo_and_releasable(monkeypatch):
    monkeypatch.setattr(rate_limiter_mod, "PROVIDER_WINDOW_SECONDS", 10.0)
    limiter = RateLimiter()
    granted = [limiter.reserve_provider("P", 2, max_wait=30) for _ in range(4)]
    assert [g.granted for g in granted] == [True] * 4
    assert granted[0].wait_seconds == pytest.approx(0, abs=0.05)
    assert granted[1].wait_seconds == pytest.approx(0, abs=0.05)
    assert granted[2].wait_seconds == pytest.approx(10, abs=0.1)
    assert granted[3].wait_seconds == pytest.approx(10, abs=0.1)

    denied = limiter.reserve_provider("P", 2, max_wait=5)
    assert not denied.granted
    assert denied.retry_after_seconds == pytest.approx(20, abs=0.1)

    # Releasing an unused future slot frees it for the next caller.
    limiter.release_provider("P", granted[3].slot_time)
    again = limiter.reserve_provider("P", 2, max_wait=15)
    assert again.granted and again.wait_seconds == pytest.approx(10, abs=0.1)

    daily = RateLimiter()
    assert daily.reserve_provider("D", 100, 1, max_wait=1).granted
    exhausted = daily.reserve_provider("D", 100, 1, max_wait=1)
    assert not exhausted.granted and exhausted.reason == "daily_quota_exhausted"
