"""Request-lifecycle regression tests: queued lookups, cancellation, duplicate
submissions, terminal error states, SSE completion, and history ordering."""
import asyncio
import json

import pytest
from httpx import ASGITransport, AsyncClient

from app.backend import main as main_mod
from app.backend import pipeline as pipeline_mod
from app.backend.adapters.base import CompositeScore, EnrichmentData
from app.backend.main import app
from app.backend.pipeline import AnalysisTask


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost") as c:
        yield c
    tasks = list(main_mod._lookup_tasks)
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    main_mod._inflight_lookups.clear()


@pytest.fixture
async def gated_analysis(monkeypatch):
    """run_analysis stand-in that blocks until the test releases it."""
    gate = asyncio.Event()
    started: list[str] = []

    async def fake_run_analysis(ioc_value, task_id=None, fp_override=False, ioc_type_override=None,
                                bypass_cache=False, password_prehashed=False):
        started.append(ioc_value)
        task = AnalysisTask(task_id=task_id, ioc_value=ioc_value, normalized=ioc_value,
                            ioc_type=ioc_type_override or "ipv4", status="querying")
        with pipeline_mod._dict_lock:
            pipeline_mod._tasks[task_id] = task
        await gate.wait()
        task.composite = CompositeScore(score=0.0, verdict="clean", confidence="high")
        task.enrichment = EnrichmentData()
        task.status = "done"
        task.progress = 100.0
        return task

    monkeypatch.setattr(main_mod, "run_analysis", fake_run_analysis)
    monkeypatch.setattr(main_mod, "_lookup_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(main_mod, "_lookup_semaphore_loop", asyncio.get_running_loop())
    monkeypatch.setattr(main_mod, "_pending_lookups", 0)
    return gate, started


async def test_queued_lookup_is_visible_and_cancellable(client, gated_analysis):
    gate, started = gated_analysis
    first = (await client.post("/api/lookup", json={"ioc": "8.8.8.8"})).json()
    queued = (await client.post("/api/lookup", json={"ioc": "1.1.1.1"})).json()
    await asyncio.sleep(0.05)
    assert started == ["8.8.8.8"]

    # The queued task exists (it used to be 404 "Task not found" until it ran).
    status = await client.get(f"/api/tasks/{queued['task_id']}")
    assert status.status_code == 200
    assert status.json()["status"] == "pending"
    assert (await client.get(f"/api/tasks/{queued['task_id']}/result")).status_code == 425

    cancel = await client.post(f"/api/tasks/{queued['task_id']}/cancel")
    assert cancel.status_code == 200
    await asyncio.sleep(0.05)
    status = (await client.get(f"/api/tasks/{queued['task_id']}")).json()
    assert status["status"] == "cancelled"
    result = await client.get(f"/api/tasks/{queued['task_id']}/result")
    assert result.status_code == 409
    assert "cancelled" in result.json()["detail"]

    gate.set()
    await asyncio.sleep(0.05)
    assert (await client.get(f"/api/tasks/{first['task_id']}/result")).status_code == 200
    assert started == ["8.8.8.8"]


async def test_duplicate_submission_joins_the_running_lookup(client, gated_analysis):
    gate, started = gated_analysis
    first = (await client.post("/api/lookup", json={"ioc": "8.8.8.8"})).json()
    second = (await client.post("/api/lookup", json={"ioc": "8.8.8.8"})).json()
    refresh = (await client.post("/api/lookup", json={"ioc": "8.8.8.8", "refresh": True})).json()
    assert second["task_id"] == first["task_id"]
    assert refresh["task_id"] != first["task_id"]
    gate.set()
    await asyncio.sleep(0.05)
    # Once finished, a new submission starts a new lookup.
    third = (await client.post("/api/lookup", json={"ioc": "8.8.8.8"})).json()
    assert third["task_id"] != first["task_id"]


async def test_failed_task_result_is_terminal_error(client):
    task = AnalysisTask(task_id="orch-failed", ioc_value="8.8.8.8", normalized="8.8.8.8",
                        ioc_type="ipv4", status="error", error="RuntimeError: boom")
    with pipeline_mod._dict_lock:
        pipeline_mod._tasks["orch-failed"] = task
    response = await client.get("/api/tasks/orch-failed/result")
    assert response.status_code == 409
    assert "boom" in response.json()["detail"]


async def test_stream_of_finished_task_sends_done_and_closes(client):
    task = AnalysisTask(task_id="orch-done", ioc_value="8.8.8.8", normalized="8.8.8.8",
                        ioc_type="ipv4", status="done", progress=100.0)
    with pipeline_mod._dict_lock:
        pipeline_mod._tasks["orch-done"] = task
    response = await asyncio.wait_for(client.get("/api/tasks/orch-done/stream"), timeout=5)
    assert response.status_code == 200
    assert "event: done" in response.text
    payload = json.loads(response.text.split("data: ", 1)[1].split("\n", 1)[0])
    assert payload["status"] == "done"

    assert (await client.get("/api/tasks/orch-unknown/stream")).status_code == 404


async def test_stream_closes_after_live_done_event(client):
    task = AnalysisTask(task_id="orch-live", ioc_value="8.8.8.8", normalized="8.8.8.8",
                        ioc_type="ipv4", status="querying")
    with pipeline_mod._dict_lock:
        pipeline_mod._tasks["orch-live"] = task

    async def finish():
        await asyncio.sleep(0.2)
        task.status = "done"
        await pipeline_mod._emit_done_event(task)

    finisher = asyncio.create_task(finish())
    response = await asyncio.wait_for(client.get("/api/tasks/orch-live/stream"), timeout=5)
    await finisher
    assert "event: done" in response.text


async def test_history_orders_by_latest_lookup_and_finds_normalized_values(client):
    from app.backend.database import persist_lookup

    async def store(value, task_id, verdict):
        await persist_lookup(
            value=value, ioc_type="domain", task_id=task_id, composite_score=1.0,
            composite_verdict=verdict, composite_confidence="low",
            full_response=json.dumps({
                "input": value, "task_id": task_id, "normalized": value, "ioc_type": "domain",
                "composite": {"score": 1.0, "verdict": verdict},
            }),
            source_count=0,
        )

    await store("orch-old.example", "orch-h1", "clean")
    await store("orch-new.example", "orch-h2", "clean")
    await store("orch-old.example", "orch-h3", "malicious")  # re-scan of the older IOC

    recent = (await client.get("/api/recent")).json()
    values = [item["value"] for item in recent]
    assert values.index("orch-old.example") < values.index("orch-new.example")
    old = next(item for item in recent if item["value"] == "orch-old.example")
    assert old["verdict"] == "malicious"

    stored = await client.get("/api/lookup/stored", params={"ioc": "ORCH-OLD.example"})
    assert stored.status_code == 200
    assert stored.json()["task_id"] == "orch-h3"
