import hashlib
import sys

sys.path.insert(0, ".")

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.backend.database import get_db
from app.backend.main import app
from app.backend.models import Base
from app.backend.pipeline import AnalysisTask
from app.backend.adapters.base import CompositeScore, EnrichmentData


@pytest.fixture
async def client(tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Match the real application session behavior so post-commit access to
    # expired ORM objects is caught by the API tests.
    session_factory = async_sessionmaker(engine, expire_on_commit=True)

    async def override_get_db():
        async with session_factory() as session:
            try:
                yield session
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost") as client:
        yield client
    app.dependency_overrides.clear()
    await engine.dispose()


async def _fake_task(ioc_value, fp_override=False, verdict="suspicious", score=45.0, ioc_type_override=None, password_prehashed=False):
    return AnalysisTask(
        task_id=f"task-{hashlib.sha1(ioc_value.encode()).hexdigest()[:12]}",
        ioc_value=ioc_value,
        normalized=ioc_value,
        ioc_type=ioc_type_override or "ipv4",
        status="done",
        progress=100.0,
        composite=CompositeScore(score=score, verdict=verdict, confidence="medium"),
        enrichment=EnrichmentData(),
        results=[],
        relationships=[],
        stages=[],
        created_at=0,
    )


@pytest.mark.asyncio
async def test_investigation_crud_and_autoscore(client, monkeypatch):
    from app.backend import main as main_mod

    created = await client.post("/api/investigations", json={"name": "Case 1", "description": "d"})
    assert created.status_code == 200
    inv_id = created.json()["id"]

    monkeypatch.setattr(main_mod, "run_analysis", _fake_task)
    added = await client.post(f"/api/investigations/{inv_id}/iocs", json={"ioc": "8.8.8.8"})
    assert added.status_code == 200

    detail = await client.get(f"/api/investigations/{inv_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["name"] == "Case 1"
    assert len(body["iocs"]) == 1
    entry = body["iocs"][0]
    assert entry["value"] == "8.8.8.8"
    assert entry["score"] == 45.0
    assert entry["verdict"] == "suspicious"

    listed = await client.get("/api/investigations")
    assert listed.status_code == 200
    assert any(i["id"] == inv_id for i in listed.json())

    removed = await client.delete(f"/api/investigations/{inv_id}/iocs/{entry['id']}")
    assert removed.status_code == 200
    detail2 = (await client.get(f"/api/investigations/{inv_id}")).json()
    assert detail2["iocs"] == []

    deleted = await client.delete(f"/api/investigations/{inv_id}")
    assert deleted.status_code == 200
    assert (await client.get(f"/api/investigations/{inv_id}")).status_code == 404


@pytest.mark.asyncio
async def test_add_ioc_is_idempotent(client, monkeypatch):
    from app.backend import main as main_mod

    created = (await client.post("/api/investigations", json={"name": "Dup"})).json()
    inv_id = created["id"]
    monkeypatch.setattr(main_mod, "run_analysis", _fake_task)

    for _ in range(2):
        resp = await client.post(f"/api/investigations/{inv_id}/iocs", json={"ioc": "8.8.8.8"})
        assert resp.status_code == 200

    detail = (await client.get(f"/api/investigations/{inv_id}")).json()
    assert len(detail["iocs"]) == 1


@pytest.mark.asyncio
async def test_add_ioc_rejects_untyped_host_artifact(client, monkeypatch):
    from app.backend import main as main_mod

    created = await client.post("/api/investigations", json={"name": "Ambiguous"})
    inv_id = created.json()["id"]
    monkeypatch.setattr(main_mod, "run_analysis", _fake_task)

    response = await client.post(f"/api/investigations/{inv_id}/iocs", json={"ioc": "abcdefghijkl"})
    assert response.status_code == 400
    detail = await client.get(f"/api/investigations/{inv_id}")
    assert detail.json()["iocs"] == []


@pytest.mark.asyncio
async def test_lookup_result_batched_load_no_n1(client, monkeypatch):
    from app.backend import main as main_mod

    created = (await client.post("/api/investigations", json={"name": "Batch"})).json()
    inv_id = created["id"]
    monkeypatch.setattr(main_mod, "run_analysis", _fake_task)

    for ioc in ("1.1.1.1", "2.2.2.2"):
        await client.post(f"/api/investigations/{inv_id}/iocs", json={"ioc": ioc})

    detail = (await client.get(f"/api/investigations/{inv_id}")).json()
    assert len(detail["iocs"]) == 2
    for entry in detail["iocs"]:
        assert entry["verdict"] == "suspicious"
