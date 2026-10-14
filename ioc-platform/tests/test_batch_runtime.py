import sys

sys.path.insert(0, ".")

import asyncio
import time

from app.backend import batch as batch_mod
from app.backend.adapters.base import CompositeScore
from app.backend.pipeline import AnalysisTask


def test_batch_task_to_dict():
    bt = batch_mod.BatchTask("b1", ["8.8.8.8", "google.com"])
    t = AnalysisTask(task_id="t1", ioc_value="8.8.8.8", status="done", progress=100.0)
    t.composite = CompositeScore(score=0.5, verdict="suspicious", confidence="medium")
    bt.subtasks = [t]
    bt.status = "done"
    bt.progress = 100.0
    bt.completed = 1
    d = bt.to_dict()
    assert d["batch_id"] == "b1"
    assert d["status"] == "done"
    assert d["total"] == 2
    assert d["completed"] == 1
    assert d["subtasks"][0]["task_id"] == "t1"
    assert d["subtasks"][0]["ioc_value"] == "8.8.8.8"


def test_get_batch_returns_none_for_missing():
    assert batch_mod.get_batch("nonexistent") is None


def test_get_batch_queue_reuses_existing():
    batch_mod._batch_queues.clear()
    q1 = batch_mod.get_batch_queue("bq")
    q2 = batch_mod.get_batch_queue("bq")
    assert q1 is q2
    assert q1.maxsize == 500
    batch_mod.cleanup_batch_queue("bq")


def test_emit_batch_event_no_queue():
    batch_mod._batch_queues.clear()

    async def main():
        await batch_mod._emit_batch_event("missing", "batch_started", {})  # no queue → noop

    asyncio.run(main())


def test_emit_batch_event_drops_oldest_when_full():
    batch_mod._batch_queues.clear()
    q = batch_mod.get_batch_queue("full")
    for i in range(500):
        q.put_nowait(("e", i))

    async def main():
        await batch_mod._emit_batch_event("full", "progress", {"n": 1})
        assert q.qsize() == 500
        first = q.get_nowait()
        assert first[1] == 1  # oldest dropped

    asyncio.run(main())
    batch_mod.cleanup_batch_queue("full")


def test_remove_oldest_batch_evicts():
    batch_mod._batch_tasks.clear()
    batch_mod._batch_queues.clear()
    batch_mod._BATCH_TASKS_MAX = 2

    bt1 = batch_mod.BatchTask("a", ["1"])
    bt2 = batch_mod.BatchTask("b", ["2"])
    bt3 = batch_mod.BatchTask("c", ["3"])
    bt1.created_at = 1
    bt2.created_at = 2
    bt3.created_at = 3
    batch_mod._batch_tasks = {"a": bt1, "b": bt2, "c": bt3}
    batch_mod._batch_queues = {"a": asyncio.Queue(), "b": asyncio.Queue(), "c": asyncio.Queue()}

    batch_mod._remove_oldest_batch()
    assert "a" not in batch_mod._batch_tasks
    assert "a" not in batch_mod._batch_queues
    assert len(batch_mod._batch_tasks) == 2


def test_run_batch_analysis_success(monkeypatch):
    batch_mod._batch_tasks.clear()
    batch_mod._batch_queues.clear()

    async def fake_run_analysis(ioc, task_id=None, fp_override=False, **kwargs):
        t = AnalysisTask(task_id=task_id or "x", ioc_value=ioc, status="done", progress=100.0)
        t.composite = CompositeScore(score=0.0, verdict="clean", confidence="high")
        return t

    monkeypatch.setattr(batch_mod, "run_analysis", fake_run_analysis)

    async def main():
        bt = await batch_mod.run_batch_analysis(["8.8.8.8", "google.com"])
        assert bt.status == "done"
        assert bt.completed == 2
        assert bt.progress == 100.0
        assert len(bt.subtasks) == 2

    asyncio.run(main())


def test_run_batch_analysis_timeout(monkeypatch):
    batch_mod._batch_tasks.clear()
    batch_mod._batch_queues.clear()

    async def slow_run(ioc, task_id=None, fp_override=False, **kwargs):
        await asyncio.sleep(5)

    monkeypatch.setattr(batch_mod, "run_analysis", slow_run)

    async def main():
        bt = await batch_mod.run_batch_analysis(["8.8.8.8"], timeout=0.05)
        assert bt.subtasks[0].status == "error"
        assert "timed out" in (bt.subtasks[0].error or "")

    asyncio.run(main())


def test_run_batch_analysis_generic_error(monkeypatch):
    batch_mod._batch_tasks.clear()
    batch_mod._batch_queues.clear()

    async def boom_run(ioc, task_id=None, fp_override=False, **kwargs):
        raise ValueError("kaput")

    monkeypatch.setattr(batch_mod, "run_analysis", boom_run)

    async def main():
        bt = await batch_mod.run_batch_analysis(["8.8.8.8"])
        assert bt.subtasks[0].status == "error"
        assert "kaput" in (bt.subtasks[0].error or "")

    asyncio.run(main())


def test_run_batch_analysis_too_long_ioc():
    async def main():
        try:
            await batch_mod.run_batch_analysis(["x" * 3000])
        except ValueError as e:
            return str(e)
        return None

    err = asyncio.run(main())
    assert err is not None
    assert "too long" in err


def test_run_batch_analysis_fp_override(monkeypatch):
    batch_mod._batch_tasks.clear()
    batch_mod._batch_queues.clear()
    captured = []

    async def fake_run(ioc, task_id=None, fp_override=False, **kwargs):
        captured.append((ioc, fp_override))
        t = AnalysisTask(task_id=task_id or "x", ioc_value=ioc, status="done")
        t.composite = CompositeScore(score=0.0, verdict="clean", confidence="high")
        return t

    monkeypatch.setattr(batch_mod, "run_analysis", fake_run)

    async def main():
        await batch_mod.run_batch_analysis(["8.8.8.8", "1.1.1.1"], fp_overrides={"8.8.8.8"})
        assert captured == [("8.8.8.8", True), ("1.1.1.1", False)]

    asyncio.run(main())


def test_consolidate_results_and_relationships():
    bt = batch_mod.BatchTask("b1", ["8.8.8.8"])
    t = AnalysisTask(task_id="t1", ioc_value="8.8.8.8", status="done")
    t.composite = CompositeScore(score=0.8, verdict="malicious", confidence="high")
    t.results = [
        {"source": "VT", "ioc_type": "ipv4", "verdict": "malicious", "raw_score": 0.9,
         "confidence": "high", "tags": ["mal"], "categories": [], "mitre_attck": [],
         "malware_family": "", "reports_count": 3, "source_link": "https://vt"},
    ]
    t.relationships = [{"source_ioc": "8.8.8.8", "target_ioc": "evil.com",
                         "relationship": "resolves_to", "via_source": "reverse_dns"}]
    bt.subtasks = [t]
    bt.completed = 1

    out = batch_mod.consolidate_batch_results(bt)
    assert out["summary"]["malicious"] == 1
    assert out["results"][0].get("ioc") == "8.8.8.8"
    assert len(out["relationships"]) == 1
