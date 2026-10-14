import threading
import time

from app.backend.adapters._http import MalformedResponse, failure, http_failure, malformed, not_configured, read_json
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key

from app.backend.config import settings
from app.backend.logger import get_logger

logger = get_logger("adapter.abuseipdb")

# AbuseIPDB integer category IDs → human-readable threat labels
ABUSEIPDB_CATEGORIES: dict[int, str] = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot",
    20: "Exploited Host", 21: "Web App Attack", 22: "SSH Brute-Force",
    23: "IoT Targeted",
}


class AbuseIPDBAdapter(SourceAdapter):
    name = "AbuseIPDB"
    supported_types = ["ipv4", "ipv6"]
    produces_reputation = True
    # Free tier: 1,000 /check requests per day.
    rate_limit = RateLimitConfig(requests_per_minute=30, requests_per_day=1000)

    DAILY_LIMIT = 1000
    _daily_requests_used = 0
    _quota_reset_time = 0.0
    _remaining = 0
    _reset_time = 0

    _daily_quota_lock = threading.Lock()

    def __init__(self):
        self.api_key = settings.abuseipdb_api_key

    def _consume_daily_quota(self) -> bool:
        with AbuseIPDBAdapter._daily_quota_lock:
            now = time.time()
            if now > AbuseIPDBAdapter._quota_reset_time:
                AbuseIPDBAdapter._daily_requests_used = 0
                AbuseIPDBAdapter._quota_reset_time = now + 86400
            if AbuseIPDBAdapter._daily_requests_used >= AbuseIPDBAdapter.DAILY_LIMIT:
                return False
            AbuseIPDBAdapter._daily_requests_used += 1
            return True

    def _check_daily_quota(self) -> bool:
        with AbuseIPDBAdapter._daily_quota_lock:
            now = time.time()
            if now > AbuseIPDBAdapter._quota_reset_time:
                AbuseIPDBAdapter._daily_requests_used = 0
                AbuseIPDBAdapter._quota_reset_time = now + 86400
            return AbuseIPDBAdapter._daily_requests_used < AbuseIPDBAdapter.DAILY_LIMIT

    def _update_rate_headers(self, resp):
        try:
            headers = getattr(resp, "headers", {}) or {}
            remaining = headers.get("X-RateLimit-Remaining", "")
            reset = headers.get("X-RateLimit-Reset", "")
            if remaining:
                self._remaining = int(remaining)
            if reset:
                self._reset_time = int(reset)
        except Exception as exc:
            logger.debug("AbuseIPDB rate-limit header parse failed: %r", exc)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return not_configured(self.name, ioc_value, ioc_type)

        if not self._check_daily_quota():
            return failure(
                self.name, ioc_value, ioc_type, "unavailable", ["daily_quota_exhausted"],
                f"AbuseIPDB daily quota ({self.DAILY_LIMIT} checks) used up locally", request_made=False,
            )

        # One /check request per lookup.  The former /blacklist prefetch
        # (10k rows, separate 5/day quota) was retried on every lookup after
        # a failure and delayed the first lookup by up to 30 s; /check already
        # carries the abuse confidence score.
        client = self._get_client()
        resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={
                    "ipAddress": ioc_value,
                    "maxAgeInDays": 365,
                    "verbose": "",  # verbose flag — unlocks reporter comments and category IDs
                },
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=15,
            )

        failed = http_failure(self.name, ioc_value, ioc_type, resp)
        if failed is not None:
            return failed

        self._update_rate_headers(resp)
        self._consume_daily_quota()
        try:
            payload = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type, http_status=resp.status_code)

        abuse_score = data.get("abuseConfidenceScore", 0)
        abuse_score = int(abuse_score) if isinstance(abuse_score, (int, float)) and not isinstance(abuse_score, bool) else 0
        score = abuse_score / 100.0
        total_reports = data.get("totalReports", 0)
        total_reports = int(total_reports) if isinstance(total_reports, (int, float)) and not isinstance(total_reports, bool) else 0
        last_reported = data.get("lastReportedAt")
        whitelisted = bool(data.get("isWhitelisted"))

        if score >= 0.5:
            verdict = "malicious"
        elif score >= 0.25:
            verdict = "suspicious"
        elif whitelisted:
            verdict = "whitelisted"
        elif total_reports == 0:
            # No reports at all is absence of evidence, not a clean bill.
            verdict = "undetected"
        else:
            verdict = "clean"

        confidence = "high" if total_reports > 10 else "medium" if total_reports > 0 else "low"

        tags = []
        if data.get("isTor", False):
            tags.append("tor_exit_node")
        if whitelisted:
            tags.append("whitelisted")

        reports = data.get("reports", []) or []
        reports_out = []
        category_names: list[str] = []
        for r in reports[:20] if isinstance(reports, list) else []:
            if isinstance(r, dict):
                raw_cats = [c for c in (r.get("categories", []) or []) if isinstance(c, int)]
                cat_names = [ABUSEIPDB_CATEGORIES.get(c, f"Category {c}") for c in raw_cats]
                for name in cat_names:
                    if name not in category_names:
                        category_names.append(name)
                reports_out.append({
                    "categories": raw_cats,
                    "category_names": cat_names,
                    "comment": str(r.get("comment") or "")[:300],
                    "reported_at": r.get("reportedAt", ""),
                    "reporter_country": r.get("reporterCountryCode", ""),
                })

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            confidence=confidence,
            raw_score=round(score, 4),
            tags=tags,
            categories=category_names,
            first_seen=None,
            last_seen=self._parse_dt(last_reported) if last_reported else None,
            source_link=f"https://www.abuseipdb.com/check/{ioc_value}",
            reports_count=total_reports,
            reports=reports_out,
            provider_summary=f"Abuse score {abuse_score}/100 from {total_reports} report{'s' if total_reports != 1 else ''}"
            + (" (whitelisted)" if whitelisted else ""),
            raw_data={
                "abuse_confidence_score": abuse_score,
                "total_reports": total_reports,
                "num_distinct_users": data.get("numDistinctUsers"),
                "last_reported_at": last_reported,
                "is_whitelisted": whitelisted,
                "is_tor": bool(data.get("isTor")),
                "is_public": data.get("isPublic"),
                "ip_version": data.get("ipVersion"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "domain": data.get("domain"),
                "hostnames": list(data.get("hostnames") or [])[:5],
                "country_code": data.get("countryCode"),
                # Same shape as ``reports`` (the UI's AbuseReport type).
                "reports": reports_out,
            },
        )

    def _parse_dt(self, val: str):
        from datetime import datetime
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return None
