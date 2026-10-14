import asyncio
import socket
import time

from app.backend.adapters._http import describe_exception, failure
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter
from app.backend.logger import get_logger

logger = get_logger("adapter.tor_exit")


_TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_cache: set[str] = set()
_cache_time: float = 0
_CACHE_TTL = 300
# After a failed download, wait before trying again instead of re-downloading
# (serially, under the lock) for every concurrent lookup.
_FAILURE_BACKOFF = 60
_last_failure: float = 0
_cache_lock = asyncio.Lock()


class TorExitAdapter(SourceAdapter):
    """Tor exit-node membership.

    Being a Tor exit is anonymization-infrastructure context: traffic from
    the address may belong to any Tor user.  It is not, by itself, evidence
    that the address is malicious, so the adapter reports membership through
    ``provider_verdict``/tags and leaves the reputation verdict ``unknown``.
    """

    name = "Tor Exit"
    supported_types = ["ipv4"]
    public_without_key = True
    evidence_roles = ("context",)
    direct_threat_evidence = False
    produces_reputation = False
    produces_infrastructure_context = True
    produces_metadata = True
    rate_limit = RateLimitConfig(requests_per_minute=60)

    async def _check_dnsel(self, ioc_value: str) -> bool | None:
        """True/False from the Tor DNS exit list; None when it cannot answer."""
        rev_parts = ioc_value.split(".")
        rev_parts.reverse()
        dnsel_host = ".".join(rev_parts) + ".dnsel.torproject.org"
        try:
            addrinfo = await asyncio.wait_for(
                asyncio.to_thread(
                    socket.getaddrinfo, dnsel_host, 0, type=socket.SOCK_STREAM
                ),
                timeout=5,
            )
        except socket.gaierror as exc:
            # NXDOMAIN is the list's "not an exit" answer.
            if exc.errno in (getattr(socket, "EAI_NONAME", -2), getattr(socket, "EAI_NODATA", -5), 11001, 11004):
                return False
            logger.debug("Tor DNSEL lookup failed: %s", describe_exception(exc))
            return None
        except Exception as exc:
            logger.debug("Tor DNSEL lookup failed: %s", describe_exception(exc))
            return None
        return any(sockaddr[0] == "127.0.0.2" for _family, _stype, _proto, _canon, sockaddr in addrinfo)

    async def _refresh_list(self) -> None:
        global _cache, _cache_time, _last_failure
        async with _cache_lock:
            now = time.time()
            if _cache and now - _cache_time <= _CACHE_TTL:
                return
            if now - _last_failure < _FAILURE_BACKOFF:
                return
            try:
                client = self._get_client()
                resp = await client.get(_TOR_LIST_URL, timeout=15)
                if resp.status_code == 200 and isinstance(resp.text, str):
                    entries = {line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")}
                    if entries:
                        _cache = entries
                        _cache_time = time.time()
                        return
                    logger.warning("Tor exit list download returned an empty list")
                else:
                    logger.warning("Tor exit list download failed with HTTP %s", resp.status_code)
            except Exception as exc:
                logger.warning("Tor exit list download error: %s", describe_exception(exc))
            _last_failure = time.time()

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        await self._refresh_list()
        found = ioc_value in _cache
        method = "bulk_exit_list" if _cache else None
        if not _cache:
            # Without the bulk list only a positive DNS exit-list answer is
            # trusted; a negative (or failed) DNS answer cannot prove absence.
            if await self._check_dnsel(ioc_value) is True:
                found, method = True, "dnsel"
            else:
                return failure(
                    self.name, ioc_value, ioc_type, "unavailable", ["feed_unavailable"],
                    "Tor exit list unavailable; membership could not be checked",
                )

        if found:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="tor_exit_node",
                normalized_verdict="unknown", raw_score=None, confidence="high",
                tags=["tor_exit_node", "anonymization_infrastructure"],
                provider_summary="Listed Tor exit node (anonymization infrastructure, not a maliciousness verdict)",
                source_link="https://metrics.torproject.org/rs.html#search/" + ioc_value,
                raw_data={"tor_exit": True, "method": method},
            )

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", provider_verdict="not_found",
            execution_state="not_found", status="not_found",
            raw_score=None, provider_summary="Not a current Tor exit node",
            raw_data={"tor_exit": False, "method": method},
        )
