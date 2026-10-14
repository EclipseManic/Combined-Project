import json
import time
import uuid
from uuid import uuid4
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from app.backend.logger import get_logger

logger = get_logger("cache")


class LocalFileCache:
    def __init__(self, cache_dir: str | None = None):
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            from app.backend.config import settings
            self.cache_dir = Path(settings.cache_dir) if settings.cache_dir else Path(__file__).resolve().parent.parent.parent / ".cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _safe_name(self, key: str) -> str:
        return key.replace(":", "_").replace("/", "_").replace("?", "_").replace(" ", "_")[:64]

    def _digest_path(self, key: str) -> Path:
        import hashlib

        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        safe = self._safe_name(key)
        return self.cache_dir / f"{safe}_{digest}.json"

    def _path(self, key: str) -> Path:
        # Preserve the readable filename used by the local-cache API.  When
        # two keys sanitize to the same name, set() transparently falls back
        # to the digest path below and get() checks both forms.
        return self.cache_dir / f"{self._safe_name(key)}.json"

    def _read_path(self, key: str) -> Path | None:
        readable = self._path(key)
        if readable.exists():
            return readable
        digest = self._digest_path(key)
        return digest if digest.exists() else None

    def get(self, key: str) -> dict | None:
        path = self._read_path(key)
        try:
            if path is None:
                return None
            with path.open("r", encoding="utf-8") as f:
                entry = json.load(f)
            if entry.get("expires_at") and time.time() > entry["expires_at"]:
                path.unlink(missing_ok=True)
                return None
            return entry.get("value")
        except Exception:
            return None

    def get_entry(self, key: str) -> tuple[dict, bool] | None:
        """Read a value without deleting an expired entry.

        Normal ``get`` retains its strict-expiry behavior for callers that
        need a cache miss.  The analysis pipeline uses this audit-preserving
        method so stale intelligence can be shown as stale instead of being
        silently relabeled as fresh.
        """
        path = self._read_path(key)
        try:
            if path is None:
                return None
            entry = json.loads(path.read_text(encoding="utf-8"))
            expires_at = float(entry.get("expires_at", 0) or 0)
            return entry.get("value"), bool(expires_at and time.time() > expires_at)
        except Exception:
            return None

    def set(self, key: str, value: dict, ttl: int):
        path = self._path(key)
        try:
            if path.exists():
                try:
                    existing = json.loads(path.read_text(encoding="utf-8"))
                    if existing.get("key") not in (None, key):
                        path = self._digest_path(key)
                except Exception:
                    pass
            entry = {"key": key, "value": value, "expires_at": time.time() + ttl}
            tmp = path.with_suffix(f".tmp.{uuid4().hex}")
            tmp.write_text(json.dumps(entry), encoding="utf-8")
            tmp.replace(path)
        except Exception:
            pass

    def delete(self, key: str):
        try:
            self._path(key).unlink(missing_ok=True)
            self._digest_path(key).unlink(missing_ok=True)
        except Exception:
            pass

    def clear(self):
        try:
            for f in self.cache_dir.glob("*.json"):
                f.unlink(missing_ok=True)
        except Exception:
            pass

    def list_keys(self, prefix: str = "task:", limit: int = 50) -> list[str]:
        try:
            safe = self._safe_name(prefix)
            keys = []
            for path in self.cache_dir.glob("*.json"):
                stem = path.stem
                if not stem.startswith(safe):
                    continue
                # Digest suffixes are an internal collision detail; callers
                # of list_keys should see the same readable key form.
                if len(stem) > 17 and stem[-17] == "_" and all(c in "0123456789abcdef" for c in stem[-16:]):
                    stem = stem[:-17]
                keys.append(stem)
            seen = list(dict.fromkeys(keys))
            return seen[:limit]
        except Exception:
            return []


class CacheLayer:
    def __init__(self, redis_url: str | None = None):
        self.redis_url = redis_url or ""
        self._redis: Any = None
        self._enabled = bool(self.redis_url)
        self._local = LocalFileCache()

    async def _connect(self):
        import redis.asyncio as aioredis
        self._redis = aioredis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            retry_on_timeout=False,
        )
        await self._redis.ping()

    async def _get_redis(self):
        if self._redis is not None:
            return self._redis
        if not self._enabled or not self.redis_url:
            return None
        if self._redis is None:
            try:
                await self._connect()
            except Exception:
                logger.warning("Redis unavailable — cache degraded to local files")
                self._enabled = False
                self._redis = None
        return self._redis

    async def get(self, key: str) -> dict | None:
        r = await self._get_redis()
        if r is None:
            return self._local.get(key)
        try:
            data = await r.get(key)
            if data is not None:
                return json.loads(data)
        except Exception:
            return self._local.get(key)
        return None

    async def get_entry(self, key: str) -> tuple[dict, bool] | None:
        """Return ``(value, stale)`` while preserving expired audit records."""
        r = await self._get_redis()
        if r is None:
            return self._local.get_entry(key)
        try:
            data = await r.get(key)
            if data is None:
                return None
            value = json.loads(data)
            expires_at = value.get("expires_at") if isinstance(value, dict) else None
            if isinstance(expires_at, str):
                try:
                    from datetime import datetime, timezone
                    expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    expires_at = None
            return value, bool(expires_at and time.time() > expires_at)
        except Exception:
            return self._local.get_entry(key)

    async def set(self, key: str, value: dict, ttl: int):
        r = await self._get_redis()
        if r is None:
            self._local.set(key, value, ttl)
            return
        try:
            await r.setex(key, ttl, json.dumps(value))
        except Exception:
            self._local.set(key, value, ttl)

    async def get_or_compute(self, key: str, ttl: int, fn: Callable[[], Awaitable[dict | None]]) -> dict | None:
        cached = await self.get(key)
        if cached is not None:
            return cached
        result = await fn()
        if result is not None:
            await self.set(key, result, ttl)
        return result

    async def delete(self, key: str):
        r = await self._get_redis()
        if r is None:
            self._local.delete(key)
            return
        try:
            await r.delete(key)
        except Exception:
            self._local.delete(key)

    async def save_task(self, task_id: str, task_dict: dict, ttl: int = 3600):
        r = await self._get_redis()
        if r is None:
            self._local.set(f"task:{task_id}", task_dict, ttl)
            return
        try:
            key = f"task:{task_id}"
            await r.setex(key, ttl, json.dumps(task_dict))
        except Exception:
            self._local.set(f"task:{task_id}", task_dict, ttl)

    async def get_task(self, task_id: str) -> dict | None:
        r = await self._get_redis()
        if r is None:
            return self._local.get(f"task:{task_id}")
        try:
            key = f"task:{task_id}"
            data = await r.get(key)
            if data is not None:
                return json.loads(data)
        except Exception:
            return self._local.get(f"task:{task_id}")
        return None

    async def list_task_ids(self, prefix: str = "task:", limit: int = 50) -> list[str]:
        r = await self._get_redis()
        if r is None:
            return self._local.list_keys(prefix, limit)
        try:
            cursor = 0
            keys = []
            while len(keys) < limit:
                cursor, batch = await r.scan(cursor=cursor, match=f"{prefix}*", count=limit)
                keys.extend(batch)
                if cursor == 0:
                    break
            return keys[:limit]
        except Exception:
            return self._local.list_keys(prefix, limit)

    async def delete_task(self, task_id: str):
        r = await self._get_redis()
        if r is None:
            self._local.delete(f"task:{task_id}")
            return
        try:
            key = f"task:{task_id}"
            await r.delete(key)
        except Exception:
            self._local.delete(f"task:{task_id}")

    async def clear(self):
        r = await self._get_redis()
        if r is None:
            self._local.clear()
            return
        try:
            keys = []
            for pattern in ("cache:*", "task:*", "ratelimit:*"):
                async for key in r.scan_iter(match=pattern):
                    keys.append(key)
            if keys:
                await r.delete(*keys)
        except Exception:
            self._local.clear()



    async def close(self):
        if self._redis is not None:
            try:
                await self._redis.close()
            except Exception:
                pass
            self._redis = None
            self._enabled = True


CACHE_TTL = {
    "VirusTotal": 300,
    "AbuseIPDB": 3600,
    "ThreatFox": 1800,
    "MalwareBazaar": 1800,
    "urlscan.io": 3600,
    "Tria.ge": 3600,
    "Hybrid Analysis": 3600,
    "GreyNoise": 3600,
    "AlienVault OTX": 1800,
    "Shodan": 3600,
    "URLhaus": 1800,
    "Tor Exit": 3600,
    "Censys": 3600,
    "IPinfo": 3600,
    "AbstractAPI": 3600,
    "AbstractAPI IP": 3600,
    "AbstractAPI Phone": 3600,
    "IPQualityScore Phone": 3600,
    "IPQualityScore IP": 3600,
    "IPQualityScore Email": 3600,

    "Hunter.io": 3600,
    "Team Cymru": 3600,
    "cve.org": 3600,
    "NVD": 3600,
    "Hashlookup": 3600,
}

CACHE_TTL_BY_TYPE = {
    "cve": {"NVD": 21600, "cve.org": 21600, "CVE": 21600},
    "md5": {"VirusTotal": 900, "MalwareBazaar": 1800, "Hashlookup": 3600},
    "sha1": {"VirusTotal": 900, "MalwareBazaar": 1800, "Hashlookup": 3600},
    "sha256": {"VirusTotal": 900, "MalwareBazaar": 1800, "Hashlookup": 3600},
}

DEFAULT_TTL = 300

TASK_TTL = 3600


def cache_key(source: str, ioc_type: str, value: str) -> str:
    return f"cache:{source}:{ioc_type}:{value.lower().strip()}"


def cache_ttl(source: str, ioc_type: str) -> int:
    return int(CACHE_TTL_BY_TYPE.get(ioc_type, {}).get(source, CACHE_TTL.get(source, DEFAULT_TTL)))
