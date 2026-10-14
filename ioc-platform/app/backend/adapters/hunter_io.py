"""Hunter.io Email Verifier and Footprint Adapter."""

import httpx
from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
    retry_after_seconds,
)
from app.backend.config import settings
from app.backend.logger import describe_exception, get_logger

logger = get_logger("adapter.hunter_io")


class HunterIOAdapter(SourceAdapter):
    """Email verifier, spam detection, and public web footprint intelligence from Hunter.io.

    Provides deliverability verification, confidence score, gibberish/spam bot detection,
    disposable email flags, and public internet OSINT source correlation.
    Free tier allows 25 verifications/month at 10 requests/minute.
    """

    name = "Hunter.io"
    supported_types = ["email"]
    public_without_key = False
    rate_limit = RateLimitConfig(
        requests_per_minute=10,
        requests_per_day=25,
    )

    def __init__(self):
        self.api_key = settings.hunterio_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type != "email":
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                tags=["unsupported_type"],
            )

        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                status="unavailable",
                tags=["no_api_key_configured"],
            )

        client = self._get_client()
        url = "https://api.hunter.io/v2/email-verifier"
        params = {
            "api_key": self.api_key,
            "email": ioc_value,
        }

        try:
            resp = await client.get(url, params=params, timeout=12)
        except httpx.TimeoutException:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["timeout"],
            )
        except httpx.HTTPError as exc:
            logger.warning("Hunter.io request error: %s", describe_exception(exc))
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["http_error"],
            )

        if resp.status_code == 429:
            retry_after = retry_after_seconds(resp)
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                status="rate_limited",
                tags=["rate_limited"],
                retry_after_seconds=retry_after,
            )

        if resp.status_code in (401, 403):
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                status="unavailable",
                tags=["unauthorized", "invalid_api_key"],
            )

        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=[f"http_{resp.status_code}"],
            )

        try:
            payload = resp.json()
            data = payload.get("data") or {}
            if not isinstance(data, dict):
                raise ValueError("unexpected data shape")
        except Exception:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["malformed_response"],
                provider_summary="Hunter.io returned a malformed response",
            )

        status = str(data.get("status") or "").lower()
        result_str = str(data.get("result") or "").lower()
        score = data.get("score")
        if score is not None:
            try:
                score = int(score)
            except (ValueError, TypeError):
                score = None

        is_disposable = bool(data.get("disposable"))
        is_gibberish = bool(data.get("gibberish"))
        is_webmail = bool(data.get("webmail"))
        is_accept_all = bool(data.get("accept_all"))
        sources = data.get("sources") or []

        tags = []
        if result_str:
            tags.append(f"hunter:result:{result_str}")
        if status:
            tags.append(f"hunter:status:{status}")
        if is_disposable:
            tags.append("hunter:disposable")
        if is_gibberish:
            tags.append("hunter:gibberish")
        if is_webmail:
            tags.append("hunter:webmail")
        if is_accept_all:
            tags.append("hunter:accept_all")

        # Verdict assignment
        if is_disposable:
            verdict = "suspicious"
            raw_score = 0.65
            confidence = "high"
        elif is_gibberish:
            verdict = "suspicious"
            raw_score = 0.60
            confidence = "high"
        elif result_str == "undeliverable" or status == "invalid":
            verdict = "suspicious"
            raw_score = 0.35
            confidence = "medium"
        elif result_str == "deliverable" and status == "valid":
            verdict = "clean"
            raw_score = 0.0
            confidence = "medium"
        elif result_str == "risky":
            verdict = "suspicious"
            raw_score = 0.30
            confidence = "low"
        else:
            verdict = "unknown"
            raw_score = None
            confidence = "low"

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            raw_score=raw_score,
            confidence=confidence,
            tags=tags,
            raw_data={**data, "sources_found": len(sources) if isinstance(sources, list) else 0},
            source_link=f"https://hunter.io/verify/{ioc_value}",
        )
