import sys
sys.path.insert(0, ".")

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.backend import main as main_mod
from app.backend.database import get_db
from app.backend.main import app
from app.backend.models import Base
from app.backend.pipeline import AnalysisTask
from app.backend.adapters.base import CompositeScore, EnrichmentData, NormalizedResult
from app.backend.rate_limiter import RateLimiter
from app.backend.config import settings


@pytest.fixture
async def client(tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            try:
                yield session
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost") as c:
        yield c
    app.dependency_overrides.clear()
    await engine.dispose()


def _make_task(ioc_value="8.8.8.8"):
    return AnalysisTask(
        task_id="t1",
        ioc_value=ioc_value,
        normalized=ioc_value,
        ioc_type="ipv4",
        status="done",
        progress=100.0,
        results=[
            NormalizedResult(
                ioc=ioc_value, ioc_type="ipv4", source="VirusTotal", verdict="malicious",
                raw_score=0.9, confidence="high", tags=["malicious"],
            )
        ],
        composite=CompositeScore(score=90.0, verdict="malicious", confidence="high",
                                 sources_contributing=1, source_breakdown=[]),
        enrichment=EnrichmentData(),
        relationships=[],
        error=None,
    )


@pytest.fixture(autouse=True)
def _monkey_pipeline(monkeypatch):
    from app.backend import batch as batch_mod
    from app.backend import pipeline as pipeline_mod

    async def fake_run_analysis(ioc_value, task_id=None, fp_override=False, ioc_type_override=None, password_prehashed=False):
        task = _make_task(ioc_value)
        task.task_id = task_id or task.task_id
        if ioc_type_override:
            task.ioc_type = ioc_type_override
        with pipeline_mod._dict_lock:
            pipeline_mod._tasks[task.task_id] = task
        return task

    monkeypatch.setattr(main_mod, "run_analysis", fake_run_analysis)
    monkeypatch.setattr(batch_mod, "run_analysis", fake_run_analysis)
    yield


# --- 429 after limit exceeded (IP) ---

async def test_lookup_rate_limited_returns_429(client, monkeypatch):
    class AlwaysLimited:
        async def acquire(self, source, limit, window):
            return False

    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: AlwaysLimited())
    r = await client.post("/api/lookup", json={"ioc": "8.8.8.8"})
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    assert "Rate limit exceeded" in r.text


async def test_lookup_global_rate_limited_returns_429(client, monkeypatch):
    class IpAllowGlobalDeny:
        async def acquire(self, source, limit, window):
            if source.startswith("global:"):
                return False
            return True

    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: IpAllowGlobalDeny())
    r = await client.post("/api/lookup", json={"ioc": "8.8.8.8"})
    assert r.status_code == 429
    assert "Global rate limit" in r.text
    assert r.headers["Retry-After"] == "60"


async def test_lookup_not_rate_limited_when_limiter_none(client, monkeypatch):
    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: None)
    # Should allow request even without limiter, but log warning (verified manually via logs)
    r = await client.post("/api/lookup", json={"ioc": "8.8.8.8"})
    assert r.status_code == 200
    assert "task_id" in r.json()


async def test_lookup_limiter_exception_fails_closed(client, monkeypatch):
    class ExplodingLimiter:
        async def acquire(self, source, limit, window):
            raise RuntimeError("redis down")

    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: ExplodingLimiter())
    r = await client.post("/api/lookup", json={"ioc": "8.8.8.8"})
    assert r.status_code == 503


async def test_batch_polling_not_rate_limited_when_limiter_always_limited(client, monkeypatch):
    class AlwaysLimited:
        async def acquire(self, source, limit, window):
            return False

    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: AlwaysLimited())
    r = await client.get("/api/batch/not-a-real-batch")
    assert r.status_code == 404  # reaches handler, not 429
    # Similarly task polling should not be throttled
    r2 = await client.get("/api/tasks/fake-task-id")
    assert r2.status_code == 404


async def test_tasks_polling_not_rate_limited_for_lookup_flow(client, monkeypatch):
    # Ensure GET /api/tasks/* is not throttled even when lookup POST is throttled
    class AlwaysLimited:
        async def acquire(self, source, limit, window):
            return False

    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: AlwaysLimited())
    # POST lookup should be 429
    r = await client.post("/api/lookup", json={"ioc": "8.8.8.8"})
    assert r.status_code == 429
    # GET task status should not be 429 (even with fake id, expect 404 not 429)
    r2 = await client.get("/api/tasks/any-id")
    assert r2.status_code == 404


# --- X-Forwarded-For handling ---

async def test_lookup_xff_respected_when_trust_proxy(client, monkeypatch):
    captured = {}

    class CaptureLimiter:
        async def acquire(self, source, limit, window):
            if source.startswith("ip:"):
                captured["source"] = source
                captured["limit"] = limit
            # need to allow both ip and global checks
            return True

    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: CaptureLimiter())
    monkeypatch.setattr(settings, "trust_proxy", True)
    monkeypatch.setattr(settings, "trusted_proxy_hosts", "127.0.0.1")

    r = await client.post("/api/lookup", json={"ioc": "8.8.8.8"}, headers={"X-Forwarded-For": "5.6.7.8, 1.1.1.1"})
    assert r.status_code == 200
    # source should contain the XFF first IP
    assert "5.6.7.8" in captured["source"]
    assert captured["source"].startswith("ip:5.6.7.8")

    # Subsequent request with same XFF should use same bucket; verify limit from settings
    assert captured["limit"] == settings.lookup_rate_limit_per_minute


async def test_lookup_xff_ignored_when_trust_proxy_false(client, monkeypatch):
    captured = {}

    class CaptureLimiter:
        async def acquire(self, source, limit, window):
            # capture first ip check only
            if source.startswith("ip:"):
                captured["source"] = source
            return True

    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: CaptureLimiter())
    monkeypatch.setattr(settings, "trust_proxy", False)

    r = await client.post("/api/lookup", json={"ioc": "8.8.8.8"}, headers={"X-Forwarded-For": "5.6.7.8"})
    assert r.status_code == 200
    # When trust_proxy is False, XFF must be ignored – source should NOT contain 5.6.7.8
    assert "5.6.7.8" not in captured["source"]


async def test_lookup_x_real_ip_respected_when_trust_proxy(client, monkeypatch):
    captured = {}

    class CaptureLimiter:
        async def acquire(self, source, limit, window):
            if source.startswith("ip:"):
                captured["source"] = source
            return True

    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: CaptureLimiter())
    monkeypatch.setattr(settings, "trust_proxy", True)
    monkeypatch.setattr(settings, "trusted_proxy_hosts", "127.0.0.1")

    r = await client.post("/api/lookup", json={"ioc": "8.8.8.8"}, headers={"X-Real-IP": "9.9.9.9"})
    assert r.status_code == 200
    assert "9.9.9.9" in captured["source"]


# --- Real limiter 429 after window exceeded ---

async def test_lookup_real_limiter_blocks_after_limit(client, monkeypatch):
    # Use a real local RateLimiter with tiny limit to verify sliding window
    rl = RateLimiter()
    rl._enabled = False  # force local
    # temporarily tighten limit via settings
    monkeypatch.setattr(settings, "lookup_rate_limit_per_minute", 2)
    monkeypatch.setattr(settings, "lookup_rate_window", 60)
    monkeypatch.setattr(settings, "lookup_global_rate_limit_per_minute", 1000)
    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: rl)
    # Ensure XFF not interfering
    monkeypatch.setattr(settings, "trust_proxy", False)

    # First 2 should succeed
    r1 = await client.post("/api/lookup", json={"ioc": "8.8.8.8"})
    assert r1.status_code == 200
    r2 = await client.post("/api/lookup", json={"ioc": "1.1.1.1"})
    assert r2.status_code == 200
    # Third should be 429 (same IP = testclient)
    r3 = await client.post("/api/lookup", json={"ioc": "2.2.2.2"})
    assert r3.status_code == 429
    assert r3.headers["Retry-After"] == "60"


async def test_lookup_per_ip_isolation(client, monkeypatch):
    rl = RateLimiter()
    rl._enabled = False
    monkeypatch.setattr(settings, "lookup_rate_limit_per_minute", 1)
    monkeypatch.setattr(settings, "lookup_rate_window", 60)
    monkeypatch.setattr(settings, "lookup_global_rate_limit_per_minute", 1000)
    monkeypatch.setattr(settings, "trust_proxy", True)
    monkeypatch.setattr(settings, "trusted_proxy_hosts", "127.0.0.1")
    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: rl)

    # IP 1.1.1.1 gets 1 slot
    r1 = await client.post("/api/lookup", json={"ioc": "8.8.8.8"}, headers={"X-Forwarded-For": "1.1.1.1"})
    assert r1.status_code == 200
    # Same IP again -> 429
    r2 = await client.post("/api/lookup", json={"ioc": "8.8.8.9"}, headers={"X-Forwarded-For": "1.1.1.1"})
    assert r2.status_code == 429
    # Different IP should still succeed (per-IP isolation)
    r3 = await client.post("/api/lookup", json={"ioc": "8.8.8.10"}, headers={"X-Forwarded-For": "2.2.2.2"})
    assert r3.status_code == 200


async def test_lookup_rate_limit_configured_via_settings(client, monkeypatch):
    # Verify settings defaults align with middleware tightening
    assert settings.lookup_rate_limit_per_minute == 30
    assert settings.lookup_rate_window == 60
    assert settings.lookup_global_rate_limit_per_minute == 300
    # Middleware class constants should reflect tightening
    assert main_mod.RateLimitMiddleware.RATE_LIMITS["/api/lookup"] == (30, 60)
    assert main_mod.RateLimitMiddleware.GLOBAL_LIMITS["/api/lookup"] == (300, 60)
