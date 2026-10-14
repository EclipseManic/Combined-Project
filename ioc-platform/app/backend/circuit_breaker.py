import threading
import time
from typing import Optional


class CircuitBreakerState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 3, recovery_timeout: float = 30.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.total_requests = 0
        self.total_failures = 0
        self.last_success_time: Optional[float] = None
        self._lock = threading.Lock()

    def _now(self) -> float:
        return time.time()

    def allow_request(self) -> bool:
        with self._lock:
            self.total_requests += 1
            if self.state == CircuitBreakerState.CLOSED:
                return True

            if self.state == CircuitBreakerState.OPEN:
                if self.last_failure_time and (self._now() - self.last_failure_time) >= self.recovery_timeout:
                    self.state = CircuitBreakerState.HALF_OPEN
                    return True
                return False

            return True  # HALF_OPEN allows probe

    def record_success(self):
        with self._lock:
            self.failure_count = 0
            self.state = CircuitBreakerState.CLOSED
            self.last_success_time = self._now()

    def record_failure(self):
        with self._lock:
            self.total_failures += 1
            self.failure_count += 1
            self.last_failure_time = self._now()

            if self.failure_count >= self.failure_threshold:
                self.state = CircuitBreakerState.OPEN

    def reset(self):
        with self._lock:
            self.state = CircuitBreakerState.CLOSED
            self.failure_count = 0
            self.last_failure_time = None

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "name": self.name,
                "state": self.state,
                "failure_count": self.failure_count,
                "failure_threshold": self.failure_threshold,
                "recovery_timeout": self.recovery_timeout,
                "total_requests": self.total_requests,
                "total_failures": self.total_failures,
                "last_failure_time": self.last_failure_time,
                "last_success_time": self.last_success_time,
            }


_breakers: dict[str, CircuitBreaker] = {}
_breakers_lock = threading.Lock()


# Consecutive provider-side failures (transport errors, 5xx, provider
# timeouts) before a provider's circuit opens.  The pipeline never reports
# rate limits, local queueing or configuration errors here, but a burst of
# concurrent lookups can still see several simultaneous transport failures
# during one network blip; a threshold of 5 keeps such a blip from blocking
# the provider for every other lookup.
DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_RECOVERY_TIMEOUT = 30.0


def get_breaker(
    name: str,
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    recovery_timeout: float = DEFAULT_RECOVERY_TIMEOUT,
) -> CircuitBreaker:
    with _breakers_lock:
        if name not in _breakers:
            _breakers[name] = CircuitBreaker(name, failure_threshold, recovery_timeout)
        return _breakers[name]


def reset_all_breakers() -> None:
    with _breakers_lock:
        breakers = list(_breakers.values())
    for breaker in breakers:
        breaker.reset()


def all_breaker_states() -> list[dict]:
    with _breakers_lock:
        breakers = list(_breakers.values())
    return [b.to_dict() for b in breakers]
