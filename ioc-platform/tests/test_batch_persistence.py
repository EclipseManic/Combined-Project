import pytest
import json
from httpx import AsyncClient, ASGITransport
from app.backend.main import app
from app.backend.batch import (
    _batch_tasks,
    get_all_batches_from_db,
    get_batch_from_db,
)
from app.backend.models import BatchRecord
from app.backend.database import async_session


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost") as c:
        yield c


@pytest.mark.asyncio
async def test_batch_sqlite_persistence_and_endpoints(client):
    batch_id = "test_persistence_batch_123"

    # 1. Directly insert a BatchRecord to test DB persistence layer
    summary_data = {
        "total": 3,
        "completed": 3,
        "malicious": 1,
        "suspicious": 1,
        "clean": 1,
        "unknown": 0,
    }
    result_data = {
        "batch_id": batch_id,
        "status": "completed",
        "total": 3,
        "completed": 3,
        "summary": summary_data,
        "results": [
            {
                "task_id": "sub_1",
                "input": "1.1.1.1",
                "normalized": "1.1.1.1",
                "ioc_type": "ipv4",
                "composite": {
                    "score": 0.0,
                    "verdict": "clean",
                    "confidence": "high",
                    "breakdown": {},
                },
                "sources": [],
                "enrichment": {},
                "relationships": [],
            },
            {
                "task_id": "sub_2",
                "input": "evil.com",
                "normalized": "evil.com",
                "ioc_type": "domain",
                "composite": {
                    "score": 85.0,
                    "verdict": "malicious",
                    "confidence": "high",
                    "breakdown": {},
                },
                "sources": [],
                "enrichment": {},
                "relationships": [],
            },
        ],
    }

    async with async_session() as session:
        record = BatchRecord(
            id=batch_id,
            status="completed",
            total=3,
            completed=3,
            summary_json=json.dumps(summary_data),
            result_json=json.dumps(result_data),
        )
        session.add(record)
        await session.commit()

    # 2. Test get_all_batches_from_db
    batches = await get_all_batches_from_db()
    matching = [b for b in batches if b["batch_id"] == batch_id]
    assert len(matching) == 1
    assert matching[0]["summary"]["malicious"] == 1
    assert matching[0]["summary"]["suspicious"] == 1

    # 3. Test get_batch_from_db
    db_res = await get_batch_from_db(batch_id)
    assert db_res is not None
    assert db_res["batch_id"] == batch_id
    assert len(db_res["results"]) == 2
    assert db_res["results"][0]["ioc"] == "1.1.1.1"
    assert db_res["results"][0]["source"] == "historical_aggregate"
    assert len(db_res["assessments"]) == 2
    assert db_res["assessments"][0]["final_verdict"] == "clean"
    assert db_res["assessments"][1]["final_verdict"] == "malicious"
    assert db_res["assessments"][1]["normalized_score"] == 85.0

    # 4. Test API GET /api/batches
    r = await client.get("/api/batches")
    assert r.status_code == 200
    api_batches = r.json()
    assert any(b["batch_id"] == batch_id for b in api_batches)

    # 5. Ensure batch is NOT in memory _batch_tasks, then test fallback endpoints
    _batch_tasks.pop(batch_id, None)

    # Test GET /api/batch/{id}/result fallback to DB
    r_result = await client.get(f"/api/batch/{batch_id}/result")
    assert r_result.status_code == 200
    assert r_result.json()["batch_id"] == batch_id

    # Test GET /api/batch/{id}/ioc/{ioc} fallback to DB
    r_ioc = await client.get(f"/api/batch/{batch_id}/ioc/evil.com")
    assert r_ioc.status_code == 200
    assert r_ioc.json()["input"] == "evil.com"
    assert r_ioc.json()["composite"]["verdict"] == "malicious"

    # Test IOC not found in batch
    r_ioc_404 = await client.get(f"/api/batch/{batch_id}/ioc/notfound.com")
    assert r_ioc_404.status_code == 404

    # 6. Test API DELETE /api/batch/{batch_id}
    r_del = await client.delete(f"/api/batch/{batch_id}")
    assert r_del.status_code == 200
    assert r_del.json()["status"] == "deleted"

    # Verify deleted from DB
    assert await get_batch_from_db(batch_id) is None

    # Test DELETE non-existent returns 404
    r_del_404 = await client.delete(f"/api/batch/{batch_id}")
    assert r_del_404.status_code == 404


@pytest.mark.asyncio
async def test_legacy_batch_scalar_rows_are_hydrated():
    from app.backend.batch import _normalize_batch_payload

    payload = _normalize_batch_payload(
        {"batch_id": "scalar", "status": "completed", "total": 2, "completed": 2, "results": ["1.2.3.4", "evil.example"]},
        batch_id="scalar",
        status="completed",
        total=2,
        completed=2,
    )
    assert [row["ioc"] for row in payload["results"]] == ["1.2.3.4", "evil.example"]
    assert len(payload["assessments"]) == 2


@pytest.mark.asyncio
async def test_legacy_batch_payload_gets_complete_api_contract():
    batch_id = "test_legacy_batch_contract_456"
    async with async_session() as session:
        session.add(BatchRecord(
            id=batch_id,
            status="completed",
            total=2,
            completed=1,
            summary_json=json.dumps({"malicious": 1}),
            result_json=json.dumps({
                "batch_id": batch_id,
                "status": "completed",
                "total": 2,
                "completed": 1,
                "summary": {"malicious": 1},
            }),
        ))
        await session.commit()

    result = await get_batch_from_db(batch_id)
    assert result is not None
    assert result["expected_lookups"] == 0
    assert result["results"] == []
    assert result["provider_health"] == []
    assert result["relationships"] == []
    assert result["subtasks"] == []
    assert result["summary"] == {
        "malicious": 1,
        # A legacy stored summary has no `breached` key; the API contract fills
        # it with zero so clients can rely on the shape.
        "breached": 0,
        "suspicious": 0,
        "clean": 0,
        "unknown": 0,
        "error": 0,
    }
    assert result["progress"] == 100.0

    batches = await get_all_batches_from_db()
    summary = next(item["summary"] for item in batches if item["batch_id"] == batch_id)
    assert summary["suspicious"] == 0

    async with async_session() as session:
        record = await session.get(BatchRecord, batch_id)
        if record is not None:
            await session.delete(record)
            await session.commit()


@pytest.mark.asyncio
async def test_progress_persistence_is_debounced(monkeypatch):
    """Debounce fix (unit): _maybe_persist_progress must NOT persist on every
    completed IOC (the "persistence storm"); it flushes only once every
    BATCH_PROGRESS_PERSIST_EVERY completions when the time trigger is disabled."""
    import time
    from app.backend import batch as batch_mod

    bt = batch_mod.BatchTask("dbnc_unit", ["a", "b", "c", "d", "e", "f"])

    calls = {"n": 0}

    async def fake_persist(b, *, required=False):
        calls["n"] += 1

    monkeypatch.setattr(batch_mod, "_persist_batch", fake_persist)
    monkeypatch.setattr(batch_mod, "BATCH_PROGRESS_PERSIST_EVERY", 3)
    monkeypatch.setattr(batch_mod, "BATCH_PROGRESS_PERSIST_INTERVAL", 0.0)  # count-trigger only

    # Baseline exactly as run_batch_analysis sets it before the drive loop.
    bt._last_progress_persist_ts = time.monotonic()
    bt._last_progress_persist_completed = 0

    persist_points = []
    for i in range(1, 7):  # six completions, driven one at a time
        bt.completed = i
        await batch_mod._maybe_persist_progress(bt)
        persist_points.append(calls["n"])

    # No per-completion storm: completions 1,2,4,5 add zero persists.
    assert persist_points == [0, 0, 1, 1, 1, 2]
    # Flushes fire exactly at the configured cadence (after the 3rd and 6th).
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_completed_batch_fully_persisted_despite_debounce(monkeypatch):
    """Debounce fix (integration): even when mid-run persistence is fully
    throttled, the forced terminal persist writes the COMPLETE batch — every
    subtask — to the DB, so the debounce never loses data."""
    from app.backend import batch as batch_mod
    from app.backend.pipeline import AnalysisTask
    from app.backend.adapters.base import CompositeScore

    batch_id = "test_debounce_complete_789"
    batch_mod._batch_tasks.pop(batch_id, None)
    batch_mod._batch_queues.clear()

    # Suppress ALL mid-run persists: an unreachable completion count plus the
    # time trigger disabled means only the forced terminal persist can fire.
    monkeypatch.setattr(batch_mod, "BATCH_PROGRESS_PERSIST_EVERY", 10_000)
    monkeypatch.setattr(batch_mod, "BATCH_PROGRESS_PERSIST_INTERVAL", 0.0)

    persist_calls = {"n": 0}
    real_persist = batch_mod._persist_batch

    async def counting_persist(bt, *, required=False):
        persist_calls["n"] += 1
        await real_persist(bt, required=required)

    monkeypatch.setattr(batch_mod, "_persist_batch", counting_persist)

    async def fake_run(ioc, task_id=None, fp_override=False, **kwargs):
        t = AnalysisTask(task_id=task_id or "x", ioc_value=ioc, normalized=ioc,
                         ioc_type="ipv4", status="done", progress=100.0)
        t.composite = CompositeScore(score=0.0, verdict="clean", confidence="high")
        return t

    monkeypatch.setattr(batch_mod, "run_analysis", fake_run)

    iocs = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"]
    bt = await batch_mod.run_batch_analysis(
        iocs, batch_id=batch_id, prenormalized=True, type_overrides={}
    )

    # Mid-run persistence was fully throttled: the only persist was terminal.
    assert persist_calls["n"] == 1
    assert bt.status == "done"
    assert len(bt.subtasks) == len(iocs)

    # ...and that single terminal persist stored the COMPLETE batch: one
    # per-IOC LookupResult row for every subtask (the debounce loses no data).
    from sqlalchemy import select
    from app.backend.models import LookupResult
    async with async_session() as session:
        rows = (await session.execute(
            select(LookupResult).where(LookupResult.batch_id == batch_id)
        )).scalars().all()
    assert len(rows) == len(iocs)
    assert all(r.composite_verdict == "clean" for r in rows)

    # The consolidated BatchRecord also reflects the full completion count.
    db_res = await get_batch_from_db(batch_id)
    assert db_res is not None
    assert db_res["completed"] == len(iocs)

    # cleanup
    batch_mod._batch_tasks.pop(batch_id, None)
    async with async_session() as session:
        record = await session.get(BatchRecord, batch_id)
        if record is not None:
            await session.delete(record)
            await session.commit()
