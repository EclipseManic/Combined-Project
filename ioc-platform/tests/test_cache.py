import sys

sys.path.insert(0, ".")

import asyncio
from app.backend.cache import CACHE_TTL, CacheLayer, LocalFileCache, cache_key


class TestLocalFileCache:
    def test_set_get_roundtrip(self, tmp_path):
        c = LocalFileCache(str(tmp_path))
        c.set("k1", {"a": 1}, ttl=100)
        assert c.get("k1") == {"a": 1}

    def test_get_missing_returns_none(self, tmp_path):
        c = LocalFileCache(str(tmp_path))
        assert c.get("nope") is None

    def test_get_expired_removes_file(self, tmp_path):
        c = LocalFileCache(str(tmp_path))
        c.set("k1", {"a": 1}, ttl=-10)
        assert c.get("k1") is None
        assert not (tmp_path / "k1.json").exists()

    def test_set_sanitizes_path_chars(self, tmp_path):
        c = LocalFileCache(str(tmp_path))
        c.set("a/b:c?d", {"v": 1}, ttl=100)
        assert (tmp_path / "a_b_c_d.json").exists()

    def test_get_corrupt_file_returns_none(self, tmp_path):
        c = LocalFileCache(str(tmp_path))
        (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
        assert c.get("bad") is None

    def test_delete(self, tmp_path):
        c = LocalFileCache(str(tmp_path))
        c.set("k1", {"a": 1}, ttl=100)
        c.delete("k1")
        assert c.get("k1") is None

    def test_delete_missing_is_noop(self, tmp_path):
        c = LocalFileCache(str(tmp_path))
        c.delete("missing")

    def test_clear(self, tmp_path):
        c = LocalFileCache(str(tmp_path))
        c.set("a", {}, ttl=100)
        c.set("b", {}, ttl=100)
        c.clear()
        assert c.get("a") is None and c.get("b") is None

    def test_list_keys_with_prefix_and_limit(self, tmp_path):
        c = LocalFileCache(str(tmp_path))
        c.set("task:1", {}, ttl=100)
        c.set("task:2", {}, ttl=100)
        c.set("other:3", {}, ttl=100)
        assert sorted(c.list_keys("task:")) == ["task_1", "task_2"]
        assert len(c.list_keys("task:", limit=1)) == 1

    def test_default_dir_falls_back(self):
        c = LocalFileCache()
        assert c.cache_dir.exists()


class TestCacheLayerLocalMode:
    def test_local_fallback_when_disabled(self, tmp_path):
        layer = CacheLayer()
        layer._enabled = False
        layer._local = LocalFileCache(str(tmp_path))

        async def main():
            await layer.set("k1", {"x": 1}, ttl=100)
            assert await layer.get("k1") == {"x": 1}
            assert await layer.get("missing") is None
            await layer.delete("k1")
            assert await layer.get("k1") is None

        asyncio.run(main())

    def test_get_or_compute_caches(self, tmp_path):
        layer = CacheLayer()
        layer._enabled = False
        layer._local = LocalFileCache(str(tmp_path))
        calls = []

        async def fn():
            calls.append(1)
            return {"value": 42}

        async def main():
            assert await layer.get_or_compute("gc", 100, fn) == {"value": 42}
            assert await layer.get_or_compute("gc", 100, fn) == {"value": 42}
            assert len(calls) == 1

        asyncio.run(main())

    def test_get_or_compute_none_not_cached(self, tmp_path):
        layer = CacheLayer()
        layer._enabled = False
        layer._local = LocalFileCache(str(tmp_path))

        async def fn():
            return None

        async def main():
            assert await layer.get_or_compute("gc", 100, fn) is None

        asyncio.run(main())

    def test_task_helpers(self, tmp_path):
        layer = CacheLayer()
        layer._enabled = False
        layer._local = LocalFileCache(str(tmp_path))

        async def main():
            await layer.save_task("t1", {"ioc": "8.8.8.8"}, ttl=100)
            assert await layer.get_task("t1") == {"ioc": "8.8.8.8"}
            assert await layer.get_task("missing") is None
            assert await layer.list_task_ids() == ["task_t1"]
            await layer.delete_task("t1")
            assert await layer.get_task("t1") is None

        asyncio.run(main())

    def test_clear_local(self, tmp_path):
        layer = CacheLayer()
        layer._enabled = False
        layer._local = LocalFileCache(str(tmp_path))

        async def main():
            await layer.set("a", {}, ttl=100)
            await layer.clear()
            assert await layer.get("a") is None

        asyncio.run(main())

    def test_close_resets_state(self):
        layer = CacheLayer()
        layer._enabled = False

        async def main():
            await layer.close()

        asyncio.run(main())


def test_cache_key_normalizes():
    assert cache_key("VirusTotal", "ipv4", " 8.8.8.8 ") == "cache:VirusTotal:ipv4:8.8.8.8"


def test_cache_ttl_constants():
    assert CACHE_TTL["VirusTotal"] == 300
    assert CACHE_TTL["AbuseIPDB"] == 3600


class _FakeRedis:
    def __init__(self):
        self.data = {}
        self.flushed = False

    async def get(self, key):
        return self.data.get(key)

    async def setex(self, key, ttl, value):
        self.data[key] = value

    async def delete(self, key):
        self.data.pop(key, None)

    async def scan(self, cursor=0, match="*", count=10):
        import fnmatch
        keys = [k for k in self.data if fnmatch.fnmatch(k, match)]
        return 0, keys

    async def scan_iter(self, match="*"):
        import fnmatch
        for key in list(self.data):
            if fnmatch.fnmatch(key, match):
                yield key

    async def flushdb(self):
        self.data.clear()
        self.flushed = True

    async def ping(self):
        return True

    async def close(self):
        pass


class TestCacheLayerRedisMode:
    def test_get_set_delete_roundtrip(self, tmp_path):
        layer = CacheLayer()
        layer._redis = _FakeRedis()
        layer._local = LocalFileCache(str(tmp_path))

        async def main():
            await layer.set("k1", {"x": 1}, ttl=100)
            assert await layer.get("k1") == {"x": 1}
            assert await layer.get("missing") is None
            await layer.delete("k1")
            assert await layer.get("k1") is None

        asyncio.run(main())

    def test_redis_exception_falls_back_to_local(self, tmp_path):
        layer = CacheLayer()
        layer._local = LocalFileCache(str(tmp_path))

        class Broken:
            async def get(self, key):
                raise ConnectionError("down")

            async def setex(self, key, ttl, value):
                raise ConnectionError("down")

            async def delete(self, key):
                raise ConnectionError("down")

        layer._redis = Broken()

        async def main():
            await layer.set("k1", {"x": 1}, ttl=100)
            assert await layer.get("k1") == {"x": 1}
            await layer.delete("k1")
            assert await layer.get("k1") is None

        asyncio.run(main())

    def test_connect_failure_disables_redis(self, tmp_path):
        layer = CacheLayer()
        layer._local = LocalFileCache(str(tmp_path))

        async def main():
            assert await layer._get_redis() is None
            assert layer._enabled is False
            await layer.set("k1", {"x": 1}, ttl=100)
            assert await layer.get("k1") == {"x": 1}

        asyncio.run(main())

    def test_save_get_list_delete_task(self, tmp_path):
        layer = CacheLayer()
        layer._redis = _FakeRedis()
        layer._local = LocalFileCache(str(tmp_path))

        async def main():
            await layer.save_task("t9", {"ioc": "1.1.1.1"}, ttl=100)
            assert await layer.get_task("t9") == {"ioc": "1.1.1.1"}
            assert await layer.get_task("nope") is None
            assert await layer.list_task_ids("task:", limit=50) == ["task:t9"]
            await layer.delete_task("t9")
            assert await layer.get_task("t9") is None

        asyncio.run(main())

    def test_task_fallbacks_on_redis_error(self, tmp_path):
        layer = CacheLayer()
        layer._local = LocalFileCache(str(tmp_path))

        class Broken:
            async def get(self, key):
                raise ConnectionError("down")

            async def setex(self, key, ttl, value):
                raise ConnectionError("down")

            async def delete(self, key):
                raise ConnectionError("down")

            async def scan(self, cursor=0, match="*", count=10):
                raise ConnectionError("down")

        layer._redis = Broken()

        async def main():
            await layer.save_task("t1", {"ioc": "x"}, ttl=100)
            assert await layer.get_task("t1") == {"ioc": "x"}
            assert await layer.list_task_ids() == ["task_t1"]
            await layer.delete_task("t1")
            assert await layer.get_task("t1") is None

        asyncio.run(main())

    def test_clear_redis_and_fallback(self, tmp_path):
        layer = CacheLayer()
        layer._redis = _FakeRedis()
        layer._local = LocalFileCache(str(tmp_path))

        async def main():
            await layer.set("cache:a", {"v": 1}, ttl=100)
            await layer.clear()
            assert not layer._redis.flushed
            assert layer._redis.data == {}
            assert await layer.get("cache:a") is None

        asyncio.run(main())

        layer2 = CacheLayer()
        layer2._local = LocalFileCache(str(tmp_path))

        class BrokenScan:
            async def scan_iter(self, match="*"):
                raise ConnectionError("down")
                yield

        layer2._redis = BrokenScan()

        async def main2():
            await layer2.set("b", {"v": 1}, ttl=100)
            await layer2.clear()
            assert await layer2.get("b") is None

        asyncio.run(main2())

    def test_close_with_redis(self):
        layer = CacheLayer()
        layer._redis = _FakeRedis()

        async def main():
            await layer.close()
            assert layer._redis is None
            assert layer._enabled is True

        asyncio.run(main())

    def test_get_or_compute_with_redis(self, tmp_path):
        layer = CacheLayer()
        layer._redis = _FakeRedis()
        layer._local = LocalFileCache(str(tmp_path))
        calls = []

        async def fn():
            calls.append(1)
            return {"value": 7}

        async def main():
            assert await layer.get_or_compute("gc", 100, fn) == {"value": 7}
            assert await layer.get_or_compute("gc", 100, fn) == {"value": 7}
            assert len(calls) == 1

        asyncio.run(main())
