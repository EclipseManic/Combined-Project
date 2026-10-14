import sys

sys.path.insert(0, ".")

import asyncio

from app.backend import webhooks as webhooks_mod


def _patch_dispatch(monkeypatch, results: list, delay: float = 0.0):
    async def fake_dispatch(task_id, ioc_value, verdict, score):
        if delay:
            await asyncio.sleep(delay)
        results.append((task_id, ioc_value, verdict, score))

    monkeypatch.setattr(webhooks_mod, "dispatch_lookup_complete", fake_dispatch)


def test_spawn_tracks_and_completes(monkeypatch):
    webhooks_mod._pending_dispatch.clear()
    results = []
    _patch_dispatch(monkeypatch, results)

    async def main():
        t = webhooks_mod.spawn_lookup_dispatch("t1", "8.8.8.8", "malicious", 90.0)
        assert t is not None
        assert t in webhooks_mod._pending_dispatch
        await asyncio.sleep(0.05)
        assert results == [("t1", "8.8.8.8", "malicious", 90.0)]
        assert webhooks_mod._pending_dispatch == set()

    asyncio.run(main())


def test_spawn_drops_above_cap(monkeypatch):
    webhooks_mod._pending_dispatch.clear()
    results = []
    _patch_dispatch(monkeypatch, results, delay=0.5)

    async def main():
        created = []
        for i in range(webhooks_mod._MAX_PENDING_DISPATCH + 5):
            t = webhooks_mod.spawn_lookup_dispatch(f"t{i}", "1.1.1.1", "unknown", 0.0)
            if t is not None:
                created.append(t)

        assert len(created) == webhooks_mod._MAX_PENDING_DISPATCH
        assert len(webhooks_mod._pending_dispatch) == webhooks_mod._MAX_PENDING_DISPATCH
        await webhooks_mod.shutdown_webhook_tasks()
        assert webhooks_mod._pending_dispatch == set()

    asyncio.run(main())


def test_shutdown_cancels_pending(monkeypatch):
    webhooks_mod._pending_dispatch.clear()
    results = []
    _patch_dispatch(monkeypatch, results, delay=10.0)

    async def main():
        t = webhooks_mod.spawn_lookup_dispatch("t1", "8.8.8.8", "malicious", 90.0)
        assert t is not None
        await webhooks_mod.shutdown_webhook_tasks()
        assert webhooks_mod._pending_dispatch == set()
        assert results == []

    asyncio.run(main())


def test_queue_skips_when_no_matching_webhook(monkeypatch):
    created = []

    async def fake_list():
        return [{"events": ["other.event"]}]

    def fake_spawn(*args):
        created.append(args)

    monkeypatch.setattr(webhooks_mod, "list_webhooks", fake_list)
    monkeypatch.setattr(webhooks_mod, "spawn_lookup_dispatch", fake_spawn)

    async def main():
        queued = await webhooks_mod.queue_lookup_dispatch("t1", "8.8.8.8", "clean", 0.0)
        assert queued is None

    asyncio.run(main())
    assert created == []


def test_queue_spawns_for_matching_webhook(monkeypatch):
    sentinel = object()

    async def fake_list():
        return [{"events": ["lookup.complete"]}]

    monkeypatch.setattr(webhooks_mod, "list_webhooks", fake_list)
    monkeypatch.setattr(webhooks_mod.settings, "webhooks_enabled", True)
    monkeypatch.setattr(webhooks_mod, "spawn_lookup_dispatch", lambda *args: sentinel)

    async def main():
        queued = await webhooks_mod.queue_lookup_dispatch("t1", "8.8.8.8", "clean", 0.0)
        assert queued is sentinel

    asyncio.run(main())
