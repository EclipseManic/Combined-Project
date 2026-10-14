import asyncio
import time
from urllib.parse import urlparse

import httpx

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings
from app.backend.logger import get_logger

logger = get_logger("adapter.openphish")

OPENPHISH_FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"


class OpenPhishAdapter(SourceAdapter):
    name = "OpenPhish"
    supported_types = ["url"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=60)

    _feed: list[str] = []
    _feed_updated: float = 0
    _feed_lock = asyncio.Lock()
    _etag: str = ""
    _last_modified: str = ""

    @staticmethod
    def _normalize_urls(url: str) -> set[str]:
        variants = set()
        stripped = url.strip().rstrip("/")
        parsed = urlparse(stripped)
        if parsed.scheme and parsed.netloc:
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            variants.add(normalized)
            if parsed.scheme == "https":
                variants.add(f"http://{parsed.netloc}{parsed.path}")
            elif parsed.scheme == "http":
                variants.add(f"https://{parsed.netloc}{parsed.path}")
        variants.add(stripped)
        return variants

    async def _ensure_feed(self):
        if time.time() - self._feed_updated < 600:
            return
        async with self._feed_lock:
            if time.time() - self._feed_updated < 600:
                return
            try:
                client = self._get_client()
                headers = {}
                if self._etag:
                    headers["If-None-Match"] = self._etag
                if self._last_modified:
                    headers["If-Modified-Since"] = self._last_modified
                r = await client.get(
                    OPENPHISH_FEED_URL,
                    headers=headers or None,
                    timeout=30,
                )
                if r.status_code == 304:
                    self._feed_updated = time.time()
                    return
                if r.status_code == 200:
                    self._feed = []
                    seen = set()
                    for line in r.text.splitlines():
                        norm_line = line.strip()
                        if norm_line and norm_line not in seen:
                            seen.add(norm_line)
                            self._feed.append(norm_line)
                    self._feed_updated = time.time()
                    self._etag = r.headers.get("ETag", "")
                    self._last_modified = r.headers.get("Last-Modified", "")
                else:
                    logger.warning("OpenPhish feed download failed with status %d", r.status_code)
            except Exception as e:
                logger.warning("OpenPhish feed download error: %s: %r", type(e).__name__, e)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        await self._ensure_feed()

        if not self._feed:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["feed_unavailable"],
            )

        ioc_variants = self._normalize_urls(ioc_value)
        is_phishing = any(v in self._feed for v in ioc_variants)

        if is_phishing:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="malicious", confidence="medium",
                raw_score=0.8, tags=["phishing", "openphish_feed"],
                source_link="https://openphish.com/",
            )

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", confidence="low",
            raw_score=0.0, tags=["not_in_feed"], status="not_found",
        )
