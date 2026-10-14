import sys
sys.path.insert(0, ".")

import pytest

from app.backend.batch import BatchTask, consolidate_batch_results, normalize_batch_iocs, normalize_batch_iocs_typed, parse_csv, parse_json, get_batch_queue
from app.backend.adapters.base import CompositeScore
from app.backend.pipeline import AnalysisTask


def test_parse_csv_simple():
    iocs = parse_csv("8.8.8.8\ngoogle.com\n1.1.1.1")
    assert len(iocs) == 3
    assert "8.8.8.8" in iocs
    assert "google.com" in iocs


def test_parse_csv_with_commas():
    iocs = parse_csv("8.8.8.8,google.com,1.1.1.1")
    assert len(iocs) == 3


def test_parse_csv_empty():
    iocs = parse_csv("")
    assert iocs == []


def test_parse_csv_whitespace():
    iocs = parse_csv("  8.8.8.8  \n  google.com  ")
    assert iocs == ["8.8.8.8", "google.com"]


def test_parse_csv_skips_header_row():
    iocs = parse_csv("ioc,verdict,score\n8.8.8.8,clean,0.0\ngoogle.com,unknown,0.1")
    assert iocs == ["8.8.8.8", "google.com"]


def test_parse_csv_single_column_header():
    iocs = parse_csv("ioc\n8.8.8.8\ngoogle.com")
    assert iocs == ["8.8.8.8", "google.com"]


def test_parse_csv_data_row_looks_like_header_keyword():
    iocs = parse_csv("8.8.8.8\nvalue\ngoogle.com")
    assert iocs == ["8.8.8.8", "value", "google.com"]


def test_parse_json_array():
    iocs = parse_json('["8.8.8.8", "google.com", "1.1.1.1"]')
    assert len(iocs) == 3


def test_parse_json_object_with_iocs_key():
    iocs = parse_json('{"iocs": ["8.8.8.8", "google.com"]}')
    assert len(iocs) == 2


def test_parse_json_list_of_dicts():
    iocs = parse_json('[{"value": "8.8.8.8"}, {"value": "google.com"}]')
    assert iocs == ["8.8.8.8", "google.com"]


def test_parse_json_nested_dict_values():
    iocs = parse_json('{"data": {"iocs": ["8.8.8.8", {"value": "google.com"}]}}')
    assert "8.8.8.8" in iocs
    assert "google.com" in iocs


def test_parse_json_numbers_and_bools():
    iocs = parse_json('["8.8.8.8", 123, true]')
    assert "8.8.8.8" in iocs
    assert "123" in iocs
    assert any(v.lower() == "true" for v in iocs)


def test_parse_json_empty_array():
    iocs = parse_json("[]")
    assert iocs == []


def test_parse_json_indicators_key():
    iocs = parse_json('{"indicators": ["8.8.8.8"]}')
    assert iocs == ["8.8.8.8"]


def test_parse_json_mixed_whitespace():
    iocs = parse_json('["  8.8.8.8  ", "google.com"]')
    assert "8.8.8.8" in iocs
    assert "google.com" in iocs


def test_normalize_batch_iocs_handles_markdown_and_escaped_values():
    values = normalize_batch_iocs([
        "[https://example.com/login](https://example.com/login)",
        r"test\@example.com",
        r"attacker\@example.com CVE-2024-3094 T1059.001 AS15169",
    ])
    assert "https://example.com/login" in values
    assert "test@example.com" in values
    assert "attacker@example.com" in values
    assert "CVE-2024-3094" in values
    assert "T1059.001" in values
    assert "AS15169" in values
    assert all("[" not in value and "]" not in value for value in values)


def test_normalize_batch_iocs_deduplicates_values():
    assert normalize_batch_iocs(["example.com", "example.com"]) == ["example.com"]


def test_normalize_batch_rejects_ambiguous_credential_shapes():
    with pytest.raises(ValueError, match="explicit type prefix"):
        normalize_batch_iocs_typed(["user@example.com"])
    assert normalize_batch_iocs_typed(["email:user@example.com"])[0][1] == "email"


def test_normalize_batch_requires_explicit_host_artifact_types():
    with pytest.raises(ValueError, match="explicit type prefix"):
        normalize_batch_iocs_typed(["service_name_probe"])
    assert normalize_batch_iocs_typed(["service_name:service_name_probe"])[0][1] == "service_name"


def test_normalize_batch_requires_prehashed_passwords():
    with pytest.raises(ValueError, match="pre-hashed"):
        normalize_batch_iocs_typed(["password:plaintext"])
    assert normalize_batch_iocs_typed(["password:" + "a" * 40])[0][1] == "password"
    assert normalize_batch_iocs_typed(["password_sha1:" + "b" * 40])[0][1] == "password"


def test_normalize_batch_rejects_invalid_password_sha1():
    import pytest

    with pytest.raises(ValueError, match="40-character SHA-1"):
        normalize_batch_iocs_typed(["password_sha1:not-a-digest"])


def _task(ioc_value, verdict, status="done"):
    t = AnalysisTask(task_id="t", ioc_value=ioc_value, status=status)
    t.composite = CompositeScore(score=0.0, verdict=verdict, confidence="low")
    return t


def test_consolidate_counts_per_ioc_not_per_result():
    bt = BatchTask("b1", ["8.8.8.8", "google.com", "1.1.1.1"])
    t1 = _task("8.8.8.8", "malicious")
    t2 = _task("google.com", "unknown")
    t3 = _task("1.1.1.1", "clean")
    bt.subtasks = [t1, t2, t3]
    bt.completed = 3
    out = consolidate_batch_results(bt)
    assert out["summary"] == {"malicious": 1, "breached": 0, "suspicious": 0, "clean": 1, "unknown": 1, "error": 0}


def test_consolidate_error_subtask_counts_as_error():
    bt = BatchTask("b2", ["8.8.8.8"])
    t = AnalysisTask(task_id="t", ioc_value="8.8.8.8", status="error", error="boom")
    bt.subtasks = [t]
    bt.completed = 1
    out = consolidate_batch_results(bt)
    assert out["summary"]["error"] == 1
    assert out["summary"]["malicious"] == 0


def test_consolidate_reports_not_applicable_and_deadline_counters():
    from app.backend.adapters.base import NormalizedResult

    bt = BatchTask("b3", ["8.8.8.8"])
    t = _task("8.8.8.8", "unknown")
    t.results = [
        NormalizedResult(
            ioc="8.8.8.8", ioc_type="ipv4", source="Censys",
            verdict="unknown", execution_state="not_applicable", request_made=False,
        ),
        NormalizedResult(
            ioc="8.8.8.8", ioc_type="ipv4", source="AlienVault OTX",
            verdict="unknown", execution_state="batch_deadline_exceeded", request_made=False,
        ),
    ]
    bt.subtasks = [t]
    bt.completed = 1
    out = consolidate_batch_results(bt)
    assert out["not_applicable_lookups"] == 1
    assert out["batch_deadline_exceeded"] == 1
    assert out["execution_health"]["not_applicable"] == 1


def test_batch_queue_emits_events_and_cleans_up():
    import asyncio
    from app.backend import batch as batch_mod

    batch_mod._batch_queues.clear()
    q = get_batch_queue("bq1")
    assert q.maxsize == 500

    async def emit():
        await batch_mod._emit_batch_event("bq1", "progress", {"completed": 1, "total": 2})
        await batch_mod._emit_batch_event("bq1", "batch_done", {"progress": 100.0})

    async def collect():
        return await asyncio.wait_for(q.get(), timeout=2.0)

    async def main():
        await emit()
        e1 = await collect()
        e2 = await collect()
        assert e1[0] == "progress"
        assert e2[0] == "batch_done"
        batch_mod.cleanup_batch_queue("bq1")
        assert "bq1" not in batch_mod._batch_queues

    asyncio.run(main())


def test_defaults_from_settings():
    from app.backend.config import settings
    from app.backend.batch import BATCH_SEMAPHORE_LIMIT, IOC_TIMEOUT
    assert BATCH_SEMAPHORE_LIMIT == settings.batch_semaphore_limit
    assert IOC_TIMEOUT == settings.ioc_timeout
    assert IOC_TIMEOUT == 60


def test_run_batch_analysis_rejects_invalid_concurrency():
    import asyncio
    from app.backend import batch as batch_mod

    async def main():
        try:
            await batch_mod.run_batch_analysis([], concurrency=0)
        except ValueError as e:
            return str(e)
        return None

    err = asyncio.run(main())
    assert err is not None
    assert "concurrency" in err


def test_resolve_batch_concurrency_applies_provider_budget(monkeypatch):
    """Fix 3: the shared provider fan-out budget clamps batch concurrency so the
    worst-case simultaneous provider burst stays bounded, without editing
    pipeline.py."""
    from app.backend import batch as batch_mod

    monkeypatch.setattr(batch_mod, "BATCH_SEMAPHORE_LIMIT", 10)
    monkeypatch.setattr(batch_mod, "BATCH_PROVIDER_FANOUT_PER_IOC", 18)
    monkeypatch.setattr(batch_mod, "BATCH_PROVIDER_FANOUT_BUDGET", 90)

    # 90 // 18 = 5, so a request for the full 10 is clamped down to 5 IOCs.
    assert batch_mod._resolve_batch_concurrency(10) == 5
    assert batch_mod._resolve_batch_concurrency(None) == 5
    # A request already under the budget is left alone.
    assert batch_mod._resolve_batch_concurrency(3) == 3

    # Budget of 0 disables the clamp; only the semaphore limit applies.
    monkeypatch.setattr(batch_mod, "BATCH_PROVIDER_FANOUT_BUDGET", 0)
    assert batch_mod._resolve_batch_concurrency(10) == 10
    assert batch_mod._resolve_batch_concurrency(50) == 10  # clamped to the limit

    # Invalid concurrency is still rejected before any budget math.
    with pytest.raises(ValueError):
        batch_mod._resolve_batch_concurrency(0)


def test_run_batch_analysis_normalizes_once(monkeypatch):
    """Fix 2: run_batch_analysis normalizes exactly once on the direct path and
    NOT at all when the caller already normalized (prenormalized=True), so the
    start_batch_analysis -> run_batch_analysis handoff no longer double-normalizes."""
    import asyncio
    from app.backend import batch as batch_mod

    batch_mod._batch_tasks.clear()
    batch_mod._batch_queues.clear()

    calls = {"n": 0}
    original = batch_mod.normalize_batch_iocs_typed

    def counting(values):
        calls["n"] += 1
        return original(values)

    monkeypatch.setattr(batch_mod, "normalize_batch_iocs_typed", counting)

    async def fake_run(ioc, task_id=None, fp_override=False, **kwargs):
        t = AnalysisTask(task_id=task_id or "x", ioc_value=ioc, normalized=ioc,
                         ioc_type="ipv4", status="done", progress=100.0)
        t.composite = CompositeScore(score=0.0, verdict="clean", confidence="high")
        return t

    monkeypatch.setattr(batch_mod, "run_analysis", fake_run)

    async def main():
        # Direct path normalizes once.
        await batch_mod.run_batch_analysis(["8.8.8.8", "1.1.1.1"])
        after_direct = calls["n"]
        # Prenormalized handoff (what start_batch_analysis does) skips it entirely.
        await batch_mod.run_batch_analysis(
            ["8.8.8.8", "1.1.1.1"], type_overrides={}, prenormalized=True
        )
        after_prenormalized = calls["n"]
        return after_direct, after_prenormalized

    after_direct, after_prenormalized = asyncio.run(main())
    assert after_direct == 1
    assert after_prenormalized == 1  # unchanged: the second run added zero calls


def test_batch_timeout_synthetic_task_is_resolvable(monkeypatch):
    """Fix 4: a timed-out IOC's synthetic task carries normalized + ioc_type so
    GET /api/batch/{id}/ioc/{ioc} can resolve it."""
    import asyncio
    from app.backend import batch as batch_mod

    batch_mod._batch_tasks.clear()
    batch_mod._batch_queues.clear()

    async def slow_run(ioc, task_id=None, fp_override=False, **kwargs):
        await asyncio.sleep(5)

    monkeypatch.setattr(batch_mod, "run_analysis", slow_run)

    async def main():
        return await batch_mod.run_batch_analysis(["8.8.8.8"], timeout=0.05)

    bt = asyncio.run(main())
    task = bt.subtasks[0]
    assert task.status == "error"
    assert "timed out" in (task.error or "")
    # The endpoint matches on task.normalized / task.ioc_value; both must be set.
    assert task.normalized == "8.8.8.8"
    assert task.ioc_type  # non-empty (classified as ipv4)

