import calendar
import time

import httpx

from app.backend.adapters._http import (
    MalformedResponse,
    describe_exception,
    exception_result,
    failure,
    http_failure,
    malformed,
    not_configured,
    read_json,
)
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings
from app.backend.logger import get_logger

logger = get_logger("adapter.shodan")

_MAX_PORTS = 20
_MAX_SERVICES = 30


class ShodanAdapter(SourceAdapter):
    name = "Shodan"
    supported_types = ["ipv4"]
    public_without_key = True
    produces_infrastructure_context = True
    produces_metadata = True
    # This adapter intentionally uses only the free InternetDB dataset. The
    # paid host API is not a fallback: an API key alone does not grant host
    # lookup access and must never cause a paid-plan request.
    rate_limit = RateLimitConfig(requests_per_minute=60)

    SHODAN_MONTHLY_LIMIT = 100
    _monthly_credits_used = 0
    _credit_reset_time = 0.0

    def __init__(self):
        self.api_key = settings.shodan_api_key

    def _check_credits(self) -> bool:
        now = time.time()
        if now > self._credit_reset_time:
            self._monthly_credits_used = 0
            now_dt = time.gmtime(now)
            days_in_month = calendar.monthrange(now_dt.tm_year, now_dt.tm_mon)[1]
            self._credit_reset_time = now + days_in_month * 86400
        return self._monthly_credits_used < self.SHODAN_MONTHLY_LIMIT

    async def _internetdb_lookup(self, ioc_value: str) -> NormalizedResult | None:
        """Key-free InternetDB lookup. ``None`` means it had nothing to say."""
        try:
            client = self._get_client()
            resp = await client.get(f"https://internetdb.shodan.io/{ioc_value}", timeout=10)
            if resp.status_code != 200:
                # 404 = no data for this IP; anything else is not a usable answer.
                return None
            data = read_json(resp)
        except (httpx.HTTPError, MalformedResponse) as exc:
            logger.debug("Shodan InternetDB lookup failed for %s: %s", ioc_value, describe_exception(exc))
            return None
        if not isinstance(data, dict):
            return None
        ports = [p for p in (data.get("ports") or []) if isinstance(p, int)][:_MAX_PORTS]
        vulns = [str(v) for v in (data.get("vulns") or [])][:25]
        hostnames = [str(h) for h in (data.get("hostnames") or [])][:10]
        cpes = [str(c) for c in (data.get("cpes") or [])][:10]
        provider_tags = [str(t) for t in (data.get("tags") or []) if isinstance(t, str) and t.strip()][:10]
        tags = ["internetdb", *provider_tags]
        if vulns:
            tags.append("known_vulnerabilities")
        return NormalizedResult(
            ioc=ioc_value, ioc_type="ipv4", source=self.name,
            verdict="unknown", raw_score=None, tags=tags, status="found",
            provider_summary=f"InternetDB lists {len(ports)} open port(s) and {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}",
            raw_data={
                "source": "internetdb", "ports": ports, "vulns": vulns,
                "hostnames": hostnames, "cpes": cpes,
            },
        )

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        internetdb_result = await self._internetdb_lookup(ioc_value)
        if internetdb_result is not None:
            return internetdb_result
        return failure(
            self.name, ioc_value, ioc_type, "not_found", ["internetdb_no_data"],
            "Shodan InternetDB has no free data for this IP", request_made=False,
        )
