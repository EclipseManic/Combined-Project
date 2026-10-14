import threading
from datetime import datetime, timezone

import httpx

from app.backend.adapters._http import MalformedResponse, failure, http_failure, malformed, not_configured, read_json
from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
)
from app.backend.config import settings


class ChainAbuseAdapter(SourceAdapter):
    """ChainAbuse reports for cryptocurrency wallet addresses."""

    name = "ChainAbuse"
    supported_types = ["btc", "eth"]
    rate_limit = RateLimitConfig(requests_per_minute=2, requests_per_day=10)
    produces_reputation = True
    produces_relationships = True
    MONTHLY_LIMIT = 10
    _monthly_requests_used = 0
    _quota_month = ""
    _quota_lock = threading.Lock()

    def __init__(self):
        self.api_key = settings.chainabuse_api_key

    @classmethod
    def _reserve_quota(cls) -> bool:
        now = datetime.now(timezone.utc)
        month = f"{now.year:04d}-{now.month:02d}"
        with cls._quota_lock:
            if month != cls._quota_month:
                cls._quota_month = month
                cls._monthly_requests_used = 0
            if cls._monthly_requests_used >= cls.MONTHLY_LIMIT:
                return False
            cls._monthly_requests_used += 1
            return True

    @staticmethod
    def _reports(data):
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if not isinstance(data, dict):
            return []
        reports = data.get("reports") or data.get("data") or data.get("results") or []
        if isinstance(reports, dict):
            reports = list(reports.values())
        return [item for item in reports if isinstance(item, dict)] if isinstance(reports, list) else []

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return not_configured(self.name, ioc_value, ioc_type)
        if not self._reserve_quota():
            return failure(
                self.name, ioc_value, ioc_type, "unavailable", ["monthly_quota_exhausted"],
                f"ChainAbuse monthly budget ({self.MONTHLY_LIMIT} requests) used up locally", request_made=False,
            )
        client = self._get_client()
        response = await client.get(
            "https://api.chainabuse.com/v0/reports",
            params={"address": ioc_value},
            auth=httpx.BasicAuth(self.api_key, self.api_key),
            headers={"accept": "application/json"},
            timeout=15,
        )
        failed = http_failure(self.name, ioc_value, ioc_type, response, not_found_summary="No ChainAbuse reports for this address")
        if failed is not None:
            if failed.execution_state == "not_found":
                failed.tags = ["no_reports"]
            return failed
        try:
            data = read_json(response)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, response.status_code)
        raw_data = data if isinstance(data, dict) else {"response": data}
        reports = self._reports(data)
        if not reports:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", status="not_found", tags=["no_reports"], raw_data=raw_data,
                source_link=f"https://www.chainabuse.com/address/{ioc_value}",
            )
        categories: list[str] = []
        for report in reports:
            for key in ("category", "category_name", "scam_type", "type"):
                value = report.get(key)
                if value:
                    categories.append(str(value))
        categories = list(dict.fromkeys(categories))[:30]
        # Report count and category names are typed fields (reports_count,
        # categories); the tag is only the label.
        tags = ["abuse_reports"]
        raw_data = {**raw_data, "report_count": len(reports)}
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="malicious", raw_score=min(1.0, 0.65 + len(reports) * 0.05), confidence="high",
            tags=tags, categories=categories, reports_count=len(reports), reports=reports[:25],
            related_iocs=[(str(item.get("transaction_hash")), "transaction") for item in reports if item.get("transaction_hash")],
            source_link=f"https://www.chainabuse.com/address/{ioc_value}", raw_data=raw_data,
        )
