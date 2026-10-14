import time

from app.backend.adapters._http import MalformedResponse, failure, http_failure, malformed, read_json
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


class GreyNoiseAdapter(SourceAdapter):
    name = "GreyNoise"
    supported_types = ["ipv4"]
    public_without_key = True
    # Community API: 50 searches/week anonymously; keyed accounts are governed
    # server-side. Pace requests so a burst cannot trip the 429.
    rate_limit = RateLimitConfig(requests_per_minute=10)

    WEEKLY_LIMIT = 50
    _weekly_requests_used = 0
    _quota_reset_time = 0.0
    _quota_remaining: int | None = None

    def __init__(self):
        self.api_key = settings.greynoise_api_key

    async def _check_weekly_quota(self) -> tuple[bool, str | None]:
        if is_valid_api_key(self.api_key):
            return True, None

        now = time.time()
        if now > GreyNoiseAdapter._quota_reset_time:
            GreyNoiseAdapter._weekly_requests_used = 0
            GreyNoiseAdapter._quota_remaining = None
            GreyNoiseAdapter._quota_reset_time = now + 604800

        if GreyNoiseAdapter._quota_remaining is not None:
            if GreyNoiseAdapter._quota_remaining <= 0:
                return False, "weekly_quota_exhausted"
            return True, None

        # The anonymous community endpoint has a small local budget. API-key
        # requests are governed by GreyNoise's server-side quota instead; a
        # process-wide anonymous counter must not throttle authenticated users.
        if GreyNoiseAdapter._weekly_requests_used >= self.WEEKLY_LIMIT:
            return False, "weekly_quota_exhausted"
        return True, None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        allowed, quota_tag = await self._check_weekly_quota()
        if not allowed:
            return failure(
                self.name, ioc_value, ioc_type, "unavailable", [quota_tag or "weekly_quota_exhausted"],
                f"GreyNoise anonymous weekly quota ({self.WEEKLY_LIMIT} lookups) used up; set GREYNOISE_API_KEY",
                request_made=False,
            )

        client = self._get_client()
        key_sent = is_valid_api_key(self.api_key)
        headers = {"accept": "application/json"}
        if key_sent:
            headers["key"] = self.api_key
        resp = await client.get(
            f"https://api.greynoise.io/v3/community/{ioc_value}",
            headers=headers,
            timeout=10,
        )

        if not key_sent:
            GreyNoiseAdapter._weekly_requests_used += 1
        if GreyNoiseAdapter._quota_remaining is not None:
            GreyNoiseAdapter._quota_remaining = max(GreyNoiseAdapter._quota_remaining - 1, 0)
        if resp.status_code == 429 and not key_sent:
            GreyNoiseAdapter._quota_remaining = 0

        # 404 from the community API means "IP not observed by GreyNoise".
        failed = http_failure(
            self.name, ioc_value, ioc_type, resp, key_sent=key_sent,
            not_found_summary="GreyNoise has not observed this IP",
        )
        if failed is not None:
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type, http_status=resp.status_code)

        classification = str(data.get("classification") or "")
        tags: list[str] = []
        if classification == "noise":
            verdict = "unknown"
            raw_score = None
            tags.append("internet_scanner")
        elif classification == "riot":
            # RIOT = a known, common business service (CDN, public DNS, ...).
            verdict = "clean"
            raw_score = 0.0
            tags.append("known_service")
        elif classification == "unknown":
            verdict = "unknown"
            raw_score = None
            tags.append("greynoise_no_data")
        elif classification == "malicious":
            verdict = "malicious"
            raw_score = 0.5
            tags.append("malicious_scanner")
        else:
            verdict = "unknown"
            raw_score = None

        raw_data = {
            key: data.get(key)
            for key in ("classification", "noise", "riot", "name", "link", "last_seen", "message")
            if data.get(key) not in (None, "")
        }
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=raw_score, tags=tags, raw_data=raw_data,
            source_link=data.get("link") or None, http_status=resp.status_code,
        )
