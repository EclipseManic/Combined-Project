"""Have I Been Pwned (HIBP) Password Range API adapter.

100% Free and requires NO API KEY.
Uses the official k-Anonymity model for SHA-1 hash lookup:
https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

import math
import re
import httpx

from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    retry_after_seconds,
)
from app.backend.logger import get_logger

logger = get_logger("adapter.hibp")

_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")


class HIBPAdapter(SourceAdapter):
    name = "HIBP Pwned Passwords"
    supported_types = ["password", "sha1"]
    public_without_key = True
    rate_limit = RateLimitConfig(requests_per_minute=60, requests_per_day=10000)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        target_hash = (ioc_value or "").strip()
        if ioc_type not in ("password", "sha1"):
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                tags=["unsupported_type"],
            )

        if not _SHA1_RE.match(target_hash):
            import hashlib
            target_hash = hashlib.sha1(target_hash.encode("utf-8")).hexdigest()

        upper_hash = target_hash.upper()
        prefix = upper_hash[:5]
        suffix = upper_hash[5:]

        client = self._get_client()
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {
            "Add-Padding": "true",
            "User-Agent": "IOC-Lookup-Platform/1.0",
            "Accept": "text/plain",
        }

        try:
            resp = await client.get(url, headers=headers, timeout=12)
        except httpx.TimeoutException:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["timeout"],
            )
        except httpx.HTTPError as exc:
            logger.warning("HIBP request error: %s: %r", type(exc).__name__, exc)
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=["request_error"],
            )

        if resp.status_code == 429:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                tags=["rate_limited"],
                http_status=429,
                retry_after_seconds=retry_after_seconds(resp),
            )

        if resp.status_code != 200:
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="error",
                tags=[f"http_{resp.status_code}"],
                http_status=resp.status_code,
            )

        # Parse k-anonymity response lines: {suffix}:{count}
        match_count = 0
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            h_suffix, count_str = line.split(":", 1)
            if h_suffix.upper() == suffix:
                try:
                    match_count = int(count_str.strip())
                except ValueError:
                    match_count = 1
                break

        if match_count > 0:
            score = min(1.0, 0.70 + (math.log10(max(match_count, 1)) / 10.0))
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                status="found",
                verdict="malicious",
                raw_score=round(score, 3),
                confidence="high",
                reports_count=match_count,
                tags=["compromised_credential", "pwned_password"],
                source_link="https://haveibeenpwned.com/Passwords",
                provider_summary=f"Compromised credential: seen in {match_count:,} breach dumps",
                raw_data={"hash_suffix": suffix, "breach_occurrences": match_count},
            )

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            status="found",
            # Absence from the corpus is "not observed", not proof the
            # credential is safe.
            verdict="undetected",
            raw_score=0.0,
            confidence="low",
            tags=["not_in_pwned_passwords"],
            source_link="https://haveibeenpwned.com/Passwords",
            provider_summary="Hash not observed in public breach databases",
            raw_data={"hash_suffix": suffix, "breach_occurrences": 0},
        )
