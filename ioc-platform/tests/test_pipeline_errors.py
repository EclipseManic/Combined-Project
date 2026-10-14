"""Tests for WU-2.5 Error Handling: SSE task_error propagation and cancellation."""

import asyncio

import pytest

from app.backend import pipeline
from app.backend.adapters.base import RateLimitConfig
from app.backend.pipeline import SSE_QUEUE_MAXSIZE, cancel_analysis, get_task_queue, run_analysis


class Boom:
    name = "BoomAdapter"
    supported_types = ["ipv4"]
    api_key = "valid-key-123"
    rate_limit = RateLimitConfig(requests_per_minute=100)

    async def lookup(self, ioc_value, ioc_type):
        raise RuntimeError("boom")

    def _check_circuit(self):
        return True

    def _record_success(self):
        pass

    def _record_failure(self):
        pass


@pytest.mark.asyncio
async def test_adapter_failure_emits_task_error():
    """P-2: adapter exception must emit a task_error SSE event."""
    pipeline._task_queues.clear()

    queue = get_task_queue("err-test")
    events = []

    async def collector():
        while True:
            try:
                event, data = await asyncio.wait_for(queue.get(), timeout=5.0)
                events.append((event, data))
                if event == "done":
                    return
            except asyncio.TimeoutError:
                return

    collector_task = asyncio.create_task(collector())
    await asyncio.sleep(0)

    original_adapters = pipeline.ADAPTERS
    original_enrich = pipeline.enrich
    pipeline.ADAPTERS = [Boom()]
    pipeline.enrich = None
    try:
        async def _fake_enrich(*args, **kwargs):
            return None
        pipeline.enrich = _fake_enrich
        task = await run_analysis("8.8.8.8", task_id="err-test")
    finally:
        pipeline.ADAPTERS = original_adapters
        pipeline.enrich = original_enrich
        pipeline.cleanup_task_queue("err-test")

    await collector_task

    err_events = [e for e in events if e[0] == "task_error"]
    assert err_events, "no task_error event emitted"
    assert "BoomAdapter" in err_events[0][1]["stage"]
    assert task.status == "done"


@pytest.mark.asyncio
async def test_cancel_analysis_cancels_running_task():
    """MAIN-12: cancel_analysis cancels only the registered task for that id."""
    started = asyncio.Event()
    cancelled = []

    async def stub():
        started.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise

    pipeline._running_tasks.clear()
    fake = asyncio.create_task(stub())
    with pipeline._dict_lock:
        pipeline._running_tasks["cancel-test"] = fake
    try:
        await started.wait()
        assert cancel_analysis("cancel-test") is True
        with pytest.raises(asyncio.CancelledError):
            await fake
        assert cancelled
    finally:
        with pipeline._dict_lock:
            pipeline._running_tasks.pop("cancel-test", None)


@pytest.mark.asyncio
async def test_task_queue_has_maxsize_and_drops_oldest():
    """MAIN-4: SSE queue is bounded and _emit_event drops the oldest event when full."""
    pipeline._task_queues.clear()
    queue = get_task_queue("maxsize-test")
    assert queue.maxsize == SSE_QUEUE_MAXSIZE

    for i in range(SSE_QUEUE_MAXSIZE + 50):
        await pipeline._emit_event("maxsize-test", "stage", {"i": i})

    assert queue.qsize() == SSE_QUEUE_MAXSIZE
    first, _ = queue.get_nowait()
    assert first == "stage"
    remaining = queue.qsize() + 1
    assert remaining == SSE_QUEUE_MAXSIZE

    pipeline.cleanup_task_queue("maxsize-test")


@pytest.mark.asyncio
async def test_emit_event_noop_without_queue():
    """_emit_event must not raise when no queue exists for the task."""
    pipeline._task_queues.clear()
    await pipeline._emit_event("ghost-task", "stage", {"x": 1})
    assert "ghost-task" not in pipeline._task_queues
