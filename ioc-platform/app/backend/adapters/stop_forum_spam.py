"""Free StopForumSpam email reputation lookup."""

import inspect

from app.backend.adapters._http import MalformedResponse, http_failure, malformed, read_json
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter


def _number(value, cast=int) -> float | int:
    try:
        return cast(value or 0)
    except (TypeError, ValueError):
        return cast(0)


class StopForumSpamAdapter(SourceAdapter):
    name = "StopForumSpam"
    supported_types = ["email", "username"]
    public_without_key = True
    # The public API allows 100,000 requests/day per IP.
    rate_limit = RateLimitConfig(requests_per_minute=30)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        client = self._get_client()
        param_key = "username" if ioc_type == "username" else "email"
        response = await client.get(
            "https://api.stopforumspam.org/api",
            params={param_key: ioc_value, "json": ""},
            timeout=15,
        )
        failed = http_failure(self.name, ioc_value, ioc_type, response, key_sent=False)
        if failed is not None:
            return failed

        try:
            data = read_json(response)
            if inspect.isawaitable(data):
                data = await data
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, response.status_code)
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type, http_status=response.status_code)
        if data.get("success") == 0:
            return malformed(self.name, ioc_value, ioc_type, "malformed_response", response.status_code)
        info = data.get(param_key) if isinstance(data.get(param_key), dict) else {}
        appears = _number(info.get("appears"))
        frequency = _number(info.get("frequency"))
        confidence = _number(info.get("confidence"), float)
        if not appears:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=None, status="not_found",
                tags=["not_listed"], provider_summary="Not listed in StopForumSpam",
            )

        # This is abuse/spam reputation, not malware attribution. StopForumSpam
        # reports ``confidence`` as a percentage (0-100). Keep weak sightings
        # suspicious and reserve malicious for a strong (>= 50%) confidence.
        verdict = "malicious" if confidence >= 50 else "suspicious"
        fraction = confidence / 100.0
        score = max(0.2, min(0.9, fraction if confidence > 0 else min(0.8, 0.2 + frequency / 10)))
        last_seen = info.get("lastseen")
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=score,
            confidence="high" if confidence >= 50 else "low",
            tags=["spam_report"], last_seen=last_seen, reports_count=appears,
            provider_summary=f"Listed in StopForumSpam ({frequency} report(s), confidence {confidence:.0f}%)",
            raw_data={
                "appears": appears, "frequency": frequency, "confidence": confidence,
                "lastseen": last_seen,
            },
        )
