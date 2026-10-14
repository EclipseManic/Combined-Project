import sys

sys.path.insert(0, ".")

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.backend import main as main_mod
from app.backend.adapters.base import CompositeScore, EnrichmentData, NormalizedResult
from app.backend.database import get_db
from app.backend.main import app
from app.backend.models import Base
from app.backend.pipeline import AnalysisTask


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
    from app.backend.batch import _batch_runners, _persist_tasks, shutdown_batch_tasks
    # Let background batch work (fake analyses + SQLite persistence) finish
    # inside this test's event loop.  Cancelling it mid-query leaves an
    # aiosqlite worker thread that later calls back into the closed loop
    # ("RuntimeError: Event loop is closed").
    background = [t for t in (*_batch_runners.values(), *_persist_tasks) if not t.done()]
    if background:
        await asyncio.wait(background, timeout=5)
    await shutdown_batch_tasks()
    runners = list(_batch_runners.values())
    for runner in runners:
        if not runner.done():
            runner.cancel()
    if runners:
        await asyncio.gather(*runners, return_exceptions=True)
    _batch_runners.clear()
    await engine.dispose()


def _make_task(ioc_value="8.8.8.8", verdict="malicious", score=90.0, status="done"):
    return AnalysisTask(
        task_id="t1",
        ioc_value=ioc_value,
        normalized=ioc_value,
        ioc_type="ipv4",
        status=status,
        progress=100.0 if status == "done" else 0.0,
        results=[
            NormalizedResult(
                ioc=ioc_value, ioc_type="ipv4", source="VirusTotal", verdict=verdict,
                raw_score=0.9, confidence="high", tags=["malicious"],
                mitre_attck=["T1071"],
                malware_family="", reports_count=3, source_link="https://vt.com",
            )
        ],
        composite=CompositeScore(score=score, verdict=verdict, confidence="high",
                                  sources_contributing=1, source_breakdown=[]),
        enrichment=EnrichmentData(),
        relationships=[],
        error=None,
    )


@pytest.fixture(autouse=True)
def _monkey_pipeline(monkeypatch):
    from app.backend import batch as batch_mod
    from app.backend import pipeline as pipeline_mod

    async def fake_run_analysis(ioc_value, task_id=None, fp_override=False, ioc_type_override=None, bypass_cache=False, password_prehashed=False, ioc_deadline=None):
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


@pytest.fixture(autouse=True)
def _seed_export_task():
    from app.backend import pipeline as pipeline_mod

    task = _make_task()
    with pipeline_mod._dict_lock:
        pipeline_mod._tasks[task.task_id] = task
    yield


async def test_health(client):
    r = await client.get("/api/health")
    assert r.status_code == 200
    assert "status" in r.json()


async def test_rejects_untrusted_host(client):
    response = await client.get("/api/health", headers={"Host": "evil.example"})
    assert response.status_code == 400


async def test_rejects_untrusted_browser_origin(client):
    response = await client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403


async def test_network_mode_fails_closed_without_api_keys(monkeypatch):
    monkeypatch.setattr(main_mod.settings, "allow_network_bind", True)
    monkeypatch.setattr(main_mod.settings, "api_keys", "")
    monkeypatch.setattr(main_mod.settings, "trust_proxy", True)
    monkeypatch.setattr(main_mod.settings, "trusted_proxy_hosts", "203.0.113.10")
    transport = ASGITransport(app=app, client=("203.0.113.10", 40000))
    async with AsyncClient(transport=transport, base_url="http://localhost") as remote:
        response = await remote.get("/api/recent", headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 503
    assert response.text == "Authentication is not configured"


async def test_network_mode_rejects_plain_http(monkeypatch):
    monkeypatch.setattr(main_mod.settings, "allow_network_bind", True)
    monkeypatch.setattr(main_mod.settings, "api_keys", "network-test-key-123456")
    transport = ASGITransport(app=app, client=("203.0.113.10", 40000))
    async with AsyncClient(transport=transport, base_url="http://localhost") as remote:
        response = await remote.get("/api/health")
    assert response.status_code == 400
    assert response.text == "HTTPS is required for network access"


async def test_sensitive_api_responses_are_not_cacheable(client):
    response = await client.get("/api/recent")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"


async def test_screenshot_proxy_is_not_publicly_cacheable(client, monkeypatch):
    class FakeResponse:
        status_code = 200
        content = b"png"

    class FakeClient:
        async def get(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(main_mod, "_get_http_client", lambda: FakeClient())
    response = await client.get("/api/screenshot?scan_id=abcdefghij")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"


async def test_configured_api_key_protects_private_routes_but_not_health(client, monkeypatch):
    monkeypatch.setattr(main_mod.settings, "api_keys", "test-secret")

    health = await client.get("/api/health")
    assert health.status_code == 200

    missing = await client.get("/api/recent")
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "ApiKey"

    wrong = await client.get("/api/recent", headers={"X-API-Key": "wrong"})
    assert wrong.status_code == 401

    valid = await client.get("/api/recent", headers={"X-API-Key": "test-secret"})
    assert valid.status_code == 200


async def test_adapters_health(client):
    r = await client.get("/api/adapters/health")
    assert r.status_code == 200
    assert isinstance(r.json(), dict)
    assert "adapters" in r.json()


async def test_source_inventory_does_not_expose_keys(client):
    r = await client.get("/api/sources")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == len(data["sources"])
    assert data["available_count"] <= data["count"]
    assert all("api_key" not in source for source in data["sources"])
    assert all("enabled_by_policy" in source for source in data["sources"])
    assert all(source["credential_source"] in {".env", "environment", "public_no_key", "not_configured"} for source in data["sources"])
    assert any(source["name"] == "StopForumSpam" for source in data["sources"])


async def test_root(client):
    r = await client.get("/")
    assert r.status_code == 200


async def test_lookup_flow(client):
    r = await client.post("/api/lookup", json={"ioc": "8.8.8.8", "task_id": "t1"})
    assert r.status_code == 200
    data = r.json()
    assert "task_id" in data
    assert data["status"] == "pending"
    assert isinstance(data["stages"], list)

    task_id = data["task_id"]
    await asyncio.sleep(0)
    status_r = await client.get(f"/api/tasks/{task_id}")
    assert status_r.status_code == 200
    assert status_r.json()["status"] == "done"

    result_r = await client.get(f"/api/tasks/{task_id}/result")
    assert result_r.status_code == 200
    assert "composite" in result_r.json()


async def test_lookup_accepts_legacy_input_field(client):
    r = await client.post("/api/lookup", json={"input": "8.8.8.8"})
    assert r.status_code == 200
    assert r.json()["ioc_value"] == "8.8.8.8"


async def test_lookup_accepts_explicit_ioc_type(client):
    r = await client.post("/api/lookup", json={"ioc": "W32Time", "ioc_type": "service_name"})
    assert r.status_code == 200
    assert r.json()["ioc_type"] == "service_name"


async def test_lookup_accepts_prehashed_password_contract(client, monkeypatch):
    captured = {}

    async def capture_run_analysis(ioc_value, task_id=None, fp_override=False, ioc_type_override=None, bypass_cache=False, password_prehashed=False):
        captured["value"] = ioc_value
        captured["type"] = ioc_type_override
        captured["prehashed"] = password_prehashed
        return _make_task(ioc_value)

    monkeypatch.setattr(main_mod, "run_analysis", capture_run_analysis)
    digest = "a" * 40
    response = await client.post("/api/lookup", json={"ioc": digest, "ioc_type": "password_sha1"})
    assert response.status_code == 200
    await asyncio.sleep(0)
    assert captured == {"value": digest, "type": "password", "prehashed": True}


@pytest.mark.parametrize("value", ["abcdefghijkl", r"Global\\MyMutex", r"\\\\host\\pipe\\EvilPipe", r"HKLM\\Software\\Evil"])
async def test_lookup_rejects_untyped_host_artifact(client, value):
    response = await client.post("/api/lookup", json={"ioc": value})
    assert response.status_code == 400
    assert "explicit type" in response.json()["detail"]


async def test_lookup_rejects_invalid_prehashed_password(client):
    response = await client.post("/api/lookup", json={"ioc": "z" * 40, "ioc_type": "password_sha1"})
    assert response.status_code == 400


async def test_password_prefix_with_digest_is_not_double_hashed(client, monkeypatch):
    captured = {}

    async def capture_run_analysis(ioc_value, task_id=None, fp_override=False, ioc_type_override=None, bypass_cache=False, password_prehashed=False):
        captured["value"] = ioc_value
        return _make_task(ioc_value)

    monkeypatch.setattr(main_mod, "run_analysis", capture_run_analysis)
    digest = "d" * 40
    response = await client.post("/api/lookup", json={"ioc": f"password:{digest}"})
    assert response.status_code == 200
    await asyncio.sleep(0)
    assert captured["value"] == digest


async def test_typed_password_sha1_and_result_marker(client, monkeypatch):
    captured = {}

    async def capture_run_analysis(ioc_value, task_id=None, fp_override=False, ioc_type_override=None, bypass_cache=False, password_prehashed=False):
        captured["value"] = ioc_value
        captured["prehashed"] = password_prehashed
        task = _make_task(ioc_value)
        task.task_id = task_id or task.task_id
        task.ioc_type = "password"
        task.password_prehashed = password_prehashed
        from app.backend import pipeline as pipeline_mod
        with pipeline_mod._dict_lock:
            pipeline_mod._tasks[task.task_id] = task
        return task

    monkeypatch.setattr(main_mod, "run_analysis", capture_run_analysis)
    digest = "b" * 40
    response = await client.post("/api/lookup", json={"ioc": f"password_sha1:{digest}"})
    assert response.status_code == 200
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    result = await client.get(f"/api/tasks/{response.json()['task_id']}/result")
    assert result.status_code == 200
    assert captured == {"value": digest, "prehashed": True}
    assert result.json()["ioc_type"] == "password"
    assert result.json()["password_prehashed"] is True


async def test_save_rejects_untyped_host_artifact(client):
    response = await client.post("/api/save", json={"ioc": "abcdefghijkl"})
    assert response.status_code == 400


async def test_save_accepts_explicit_host_artifact_type(client):
    response = await client.post("/api/save", json={"ioc": "service_name:W32Time"})
    assert response.status_code == 200


async def test_save_accepts_typed_prehashed_password(client):
    digest = "c" * 40
    response = await client.post("/api/save", json={"ioc": f"password_sha1:{digest}"})
    assert response.status_code == 200
    recent = await client.get("/api/recent")
    assert any(item["value"] == digest and item["ioc_type"] == "password" for item in recent.json())


async def test_feedback_rejects_untyped_host_artifact(client):
    response = await client.post("/api/feedback", json={"ioc": "abcdefghijkl", "feedback": "false_positive"})
    assert response.status_code == 400


async def test_lookup_refresh_forwards_cache_bypass(client, monkeypatch):
    calls = []

    async def capture_run_analysis(ioc_value, task_id=None, fp_override=False, ioc_type_override=None, bypass_cache=False, password_prehashed=False):
        calls.append(bypass_cache)
        return _make_task(ioc_value)

    monkeypatch.setattr(main_mod, "run_analysis", capture_run_analysis)
    response = await client.post("/api/lookup", json={"ioc": "8.8.8.8", "refresh": True})
    assert response.status_code == 200
    await asyncio.sleep(0)
    assert calls == [True]


async def test_lookup_invalid_ioc(client):
    r = await client.post("/api/lookup", json={"ioc": ""})
    assert r.status_code == 400


async def test_lookup_rejects_url_userinfo(client):
    response = await client.post(
        "/api/lookup",
        json={"ioc": "https://user:password@example.com/path", "ioc_type": "url"},
    )
    assert response.status_code == 400


async def test_save_endpoint(client):
    r = await client.post("/api/save", json={"ioc": "8.8.8.8", "task_id": "t1"})
    assert r.status_code == 200


async def test_recent_endpoint(client):
    r = await client.get("/api/recent")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


async def test_feedback_crud(client):
    post = await client.post("/api/feedback", json={"ioc": "8.8.8.8", "verdict": "malicious", "reason": "test"})
    assert post.status_code == 200
    get = await client.get("/api/feedback/8.8.8.8")
    assert get.status_code == 200
    delete = await client.delete("/api/feedback/8.8.8.8")
    assert delete.status_code == 200


async def test_network_mode_blocks_global_feedback_without_explicit_opt_in(client, monkeypatch):
    monkeypatch.setattr(main_mod.settings, "allow_network_bind", True)
    monkeypatch.setattr(main_mod.settings, "api_keys", "network-test-key-123456")
    monkeypatch.setattr(main_mod.settings, "allow_global_feedback", False)
    monkeypatch.setattr(main_mod.settings, "trust_proxy", True)
    monkeypatch.setattr(main_mod.settings, "trusted_proxy_hosts", "127.0.0.1")
    response = await client.post(
        "/api/feedback",
        json={"ioc": "8.8.8.8", "feedback": "false_positive"},
        headers={
            "X-API-Key": "network-test-key-123456",
            "X-Forwarded-Proto": "https",
        },
    )
    assert response.status_code == 403


async def test_cache_clear(client):
    r = await client.post("/api/cache/clear")
    assert r.status_code == 200


async def test_export_report(client):
    r = await client.post("/api/export/report", json={"ioc": "8.8.8.8", "task_id": "t1"})
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


async def test_export_stix(client):
    r = await client.post("/api/export/stix", json={"ioc": "8.8.8.8", "task_id": "t1"})
    assert r.status_code == 200
    assert r.json()["type"] == "bundle"
    assert "objects" in r.json()


async def test_export_misp(client):
    r = await client.post("/api/export/misp", json={"ioc": "8.8.8.8", "task_id": "t1"})
    assert r.status_code == 200
    assert r.json()["Event"]["uuid"]


async def test_export_siem_ok(client):
    r = await client.post("/api/export/siem", json={"ioc": "8.8.8.8", "task_id": "t1", "format": "splunk"})
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]


async def test_export_siem_bad_format(client):
    r = await client.post("/api/export/siem", json={"ioc": "8.8.8.8", "task_id": "t1", "format": "cef"})
    assert r.status_code == 400


async def test_export_siem_ecs(client):
    r = await client.post("/api/export/siem", json={"ioc": "8.8.8.8", "task_id": "t1", "format": "ecs"})
    assert r.status_code == 200
    assert "application/x-ndjson" in r.headers["content-type"]


async def test_export_csv(client):
    r = await client.post("/api/export/csv", json={"ioc": "8.8.8.8", "task_id": "t1"})
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]


async def test_batch_flow(client):
    r = await client.post("/api/batch", json={"iocs": ["8.8.8.8", "1.1.1.1"]})
    assert r.status_code == 200
    batch_id = r.json()["batch_id"]
    for _ in range(50):
        poll = await client.get(f"/api/batch/{batch_id}")
        assert poll.status_code == 200
        if poll.json().get("status") == "done":
            break
        await asyncio.sleep(0.05)
    result = await client.get(f"/api/batch/{batch_id}/result")
    assert result.status_code == 200
    assert result.json()["total"] == 2


async def test_batch_upload_csv(client):
    r = await client.post(
        "/api/batch/upload",
        files={"file": ("iocs.csv", b"8.8.8.8\ngoogle.com\n1.1.1.1", "text/csv")},
    )
    assert r.status_code == 200
    await asyncio.sleep(0)
    assert r.json()["total"] == 3


async def test_batch_upload_json(client):
    r = await client.post(
        "/api/batch/upload",
        files={"file": ("iocs.json", b'{"iocs": ["8.8.8.8"]}', "application/json")},
    )
    assert r.status_code == 200
    await asyncio.sleep(0)
    assert r.json()["total"] == 1


async def test_batch_status_polling_is_not_rate_limited(client, monkeypatch):
    from app.backend import main as main_mod

    class AlwaysLimited:
        async def acquire(self, source, limit, window):
            return False

    monkeypatch.setattr(main_mod, "get_rate_limiter", lambda: AlwaysLimited())
    r = await client.get("/api/batch/nonexistent_batch_id")
    assert r.status_code == 404


async def test_stored_recent_and_batch_ioc_endpoints(client):
    # 1. Test stored lookup when non-existent
    r_missing = await client.get("/api/lookup/stored?ioc=nonexistent.example.com")
    assert r_missing.status_code == 404

    # 2. Run a batch and test single IOC retrieval from batch
    r_batch = await client.post("/api/batch", json={"iocs": ["1.1.1.1"]})
    assert r_batch.status_code == 200
    batch_id = r_batch.json()["batch_id"]
    await client.get(f"/api/batch/{batch_id}/result")

    r_single = await client.get(f"/api/batch/{batch_id}/ioc/1.1.1.1")
    assert r_single.status_code == 200
    single_data = r_single.json()
    assert single_data["input"] == "1.1.1.1"
    assert "composite" in single_data
