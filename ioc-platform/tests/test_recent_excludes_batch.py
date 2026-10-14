"""Batch IOCs must not appear in the single-scan history.

``_persist_batch`` writes every completed subtask to LookupResult tagged with its
batch_id so a batch survives a restart. That is correct, but ``/api/recent`` read
the table unfiltered, so every IOC in a batch showed up in the individual-scan
history as though it had been scanned on its own. A 100-IOC batch injected 100
history entries.

The batch stays fully reachable through /api/batches and
/api/batch/{id}/result; only the single-scan history is scoped.
"""

import sys

sys.path.insert(0, ".")

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.backend.database import get_db
from app.backend.main import app
from app.backend.models import Base, IOC, LookupResult


@pytest.fixture
async def client():
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
    from app.backend.batch import shutdown_batch_tasks

    await shutdown_batch_tasks()


async def _seed(rows):
    """Insert IOC + LookupResult rows through the app's own session dependency.

    rows: (value, ioc_type, batch_id, verdict)

    ``iocs.value`` is UNIQUE and an indicator gets one row with many lookup
    results, so a repeated value reuses the existing IOC. That is the real shape:
    a batch lookup and a later single scan of the same indicator both attach to
    the same IOC row.
    """
    from sqlalchemy import select

    gen = app.dependency_overrides[get_db]()
    session = await gen.__anext__()
    try:
        for value, ioc_type, batch_id, verdict in rows:
            found = (
                await session.execute(select(IOC).where(IOC.value == value))
            ).scalar_one_or_none()
            if found is None:
                found = IOC(value=value, ioc_type=ioc_type)
                session.add(found)
                await session.flush()
            session.add(LookupResult(
                ioc_id=found.id,
                task_id=f"task-{value}-{batch_id or 'single'}",
                batch_id=batch_id,
                composite_verdict=verdict,
                composite_score=50.0,
                composite_confidence="medium",
                full_response="{}",
                source_count=1,
            ))
        await session.commit()
    finally:
        await gen.aclose()


@pytest.mark.asyncio
async def test_batch_results_are_excluded_from_history(client):
    await _seed([
        ("9.9.9.9", "ipv4", "batch-abc", "suspicious"),
        ("1.1.1.1", "ipv4", None, "clean"),
    ])
    response = await client.get("/api/recent")
    assert response.status_code == 200
    values = [item["value"] for item in response.json()]

    assert "9.9.9.9" not in values, "a batch-only IOC must not appear in single-scan history"
    assert "1.1.1.1" in values, "a genuine single scan must still appear"


@pytest.mark.asyncio
async def test_a_later_single_scan_wins_over_an_earlier_batch_result(client):
    """The batch filter has to be applied INSIDE the latest-per-IOC subquery.

    Filtering only the outer join would let an IOC whose most recent stored
    result happened to come from a batch report that batch's verdict, or be
    dropped entirely. The single scan is what history should report.
    """
    await _seed([
        ("8.8.8.8", "ipv4", "batch-xyz", "malicious"),
        ("8.8.8.8", "ipv4", None, "clean"),
    ])
    response = await client.get("/api/recent")
    values = {item["value"]: item for item in response.json()}

    assert "8.8.8.8" in values, "an IOC with a genuine single scan must appear"
    assert values["8.8.8.8"]["verdict"] == "clean", (
        "history must report the single-scan verdict, not the batch's"
    )


@pytest.mark.asyncio
async def test_history_is_empty_when_every_result_came_from_a_batch(client):
    await _seed([
        ("5.5.5.5", "ipv4", "batch-1", "suspicious"),
        ("4.4.4.4", "ipv4", "batch-1", "malicious"),
    ])
    response = await client.get("/api/recent")
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_a_mixed_batch_keeps_only_its_single_scanned_iocs(client):
    await _seed([
        ("3.3.3.3", "ipv4", "batch-mix", "malicious"),
        ("2.2.2.2", "ipv4", "batch-mix", "suspicious"),
        ("2.2.2.2", "ipv4", None, "benign"),
    ])
    values = {item["value"] for item in (await client.get("/api/recent")).json()}
    assert values == {"2.2.2.2"}