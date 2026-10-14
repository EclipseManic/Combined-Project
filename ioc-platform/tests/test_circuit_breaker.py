import sys

sys.path.insert(0, ".")

import time

from app.backend.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerState,
    all_breaker_states,
    get_breaker,
)


def test_closed_allows_requests():
    cb = CircuitBreaker("t")
    assert cb.allow_request() is True
    assert cb.total_requests == 1


def test_opens_after_threshold():
    cb = CircuitBreaker("t", failure_threshold=3, recovery_timeout=30)
    for _ in range(2):
        assert cb.allow_request() is True
        cb.record_failure()
    assert cb.state == CircuitBreakerState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitBreakerState.OPEN


def test_open_blocks_requests():
    cb = CircuitBreaker("t", failure_threshold=1, recovery_timeout=100)
    cb.allow_request()
    cb.record_failure()
    assert cb.state == CircuitBreakerState.OPEN
    assert cb.allow_request() is False


def test_open_recovers_to_half_open():
    cb = CircuitBreaker("t", failure_threshold=1, recovery_timeout=-1)
    cb.allow_request()
    cb.record_failure()
    assert cb.state == CircuitBreakerState.OPEN
    assert cb.allow_request() is True  # past recovery window -> half-open probe
    assert cb.state == CircuitBreakerState.HALF_OPEN


def test_half_open_probe_success_resets():
    cb = CircuitBreaker("t", failure_threshold=1, recovery_timeout=-1)
    cb.allow_request()
    cb.record_failure()
    cb.allow_request()  # -> half-open
    cb.record_success()
    assert cb.state == CircuitBreakerState.CLOSED
    assert cb.failure_count == 0


def test_record_success_updates_last_success():
    cb = CircuitBreaker("t")
    cb.record_failure()
    cb.record_success()
    assert cb.state == CircuitBreakerState.CLOSED
    assert cb.last_success_time is not None


def test_reset():
    cb = CircuitBreaker("t", failure_threshold=1)
    cb.allow_request()
    cb.record_failure()
    assert cb.state == CircuitBreakerState.OPEN
    cb.reset()
    assert cb.state == CircuitBreakerState.CLOSED
    assert cb.failure_count == 0
    assert cb.last_failure_time is None


def test_to_dict_fields():
    cb = CircuitBreaker("t", failure_threshold=3, recovery_timeout=30)
    cb.allow_request()
    d = cb.to_dict()
    assert d["name"] == "t"
    assert d["state"] == CircuitBreakerState.CLOSED
    assert d["failure_threshold"] == 3
    assert d["recovery_timeout"] == 30
    assert d["total_requests"] == 1
    assert d["total_failures"] == 0


def test_get_breaker_caches_and_reuses():
    a = get_breaker("shared", failure_threshold=2, recovery_timeout=5)
    b = get_breaker("shared")
    assert a is b
    assert b.failure_threshold == 2


def test_all_breaker_states():
    get_breaker("cb_alpha", failure_threshold=1, recovery_timeout=1)
    states = all_breaker_states()
    names = [s["name"] for s in states]
    assert "cb_alpha" in names
    assert all("state" in s for s in states)
