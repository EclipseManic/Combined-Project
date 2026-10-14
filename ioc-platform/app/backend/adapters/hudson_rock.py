"""Hudson Rock Cavalier Infostealers API adapter.

Public API - no API key required!
Rate limit: 50 requests per 10 seconds.

Endpoints used:
  - Search by email:  https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=X
  - Search by IP:     https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-ip?ip=X
  - Search by domain: https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=X
  - URLs by domain:   https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain=X

All responses are parsed for infostealer infection data, stealer families, compromised credentials,
and related threat intelligence.

Semantics: an infostealer log that *mentions* an IP or domain (a victim
machine resolved it, a victim logged in to it) is exposure context about that
infrastructure, never evidence that the indicator is malicious.  For an email
or username it is credential exposure.  The adapter therefore never emits a
malicious verdict; exposure is carried by ``provider_verdict``, the
``infostealer_compromised`` tag and the typed counts in ``raw_data``.

HUDSON_API_KEY is not sent: the Cavalier OSINT endpoints above are keyless,
and the keyed ``api.hudsonrock.com/json/v3`` API uses a different request and
response contract.
"""

import asyncio

import httpx

from app.backend.adapters._http import describe_exception, exception_result, failure, http_failure
from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
)
from app.backend.logger import get_logger

logger = get_logger("adapter.hudson_rock")

_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "IOC-Lookup-Platform/1.0",
}


class HudsonRockAdapter(SourceAdapter):
    """Hudson Rock Cavalier — free public infostealer intelligence API."""

    name = "Hudson Rock"
    supported_types = ["email", "ipv4", "domain", "url", "username"]
    # Public API: 50 req / 10s = 300 req/min; we stay conservative at 120/min
    rate_limit = RateLimitConfig(requests_per_minute=120, requests_per_day=10_000)
    public_without_key = True  # No API key needed
    evidence_roles = ("exposure",)
    direct_threat_evidence = False
    produces_reputation = False
    produces_infrastructure_context = True
    produces_metadata = True

    def __init__(self):
        super().__init__()
        self.api_key = None  # Not required for the Cavalier public API

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type not in self.supported_types:
            return failure(
                self.name, ioc_value, ioc_type, "not_applicable", ["unsupported_provider_type"],
                f"Hudson Rock does not support {ioc_type} lookups", request_made=False,
            )

        client = self._get_client()

        # --- Route to correct endpoint ---
        if ioc_type == "email":
            url = f"{_BASE}/search-by-email"
            params = {"email": ioc_value}
        elif ioc_type == "ipv4":
            url = f"{_BASE}/search-by-ip"
            params = {"ip": ioc_value}
        elif ioc_type == "username":
            url = f"{_BASE}/search-by-username"
            params = {"username": ioc_value}
        elif ioc_type in ("domain", "url"):
            # Strip scheme from URL to get the domain
            domain = ioc_value
            if "://" in domain:
                domain = domain.split("://", 1)[1].split("/")[0]
            url = f"{_BASE}/search-by-domain"
            params = {"domain": domain}
        else:
            return failure(
                self.name, ioc_value, ioc_type, "not_applicable", ["unsupported_provider_type"],
                f"Hudson Rock does not support {ioc_type} lookups", request_made=False,
            )

        async def _urls_by_domain() -> dict | None:
            try:
                urls_resp = await client.get(
                    f"{_BASE}/urls-by-domain",
                    params={"domain": params["domain"]},
                    headers=_HEADERS,
                    timeout=10,
                )
                if urls_resp.status_code == 200:
                    urls_data = urls_resp.json()
                    return urls_data if isinstance(urls_data, dict) else None
            except Exception as exc:
                logger.debug("Hudson Rock urls-by-domain failed: %s", describe_exception(exc))
            return None

        # The optional urls-by-domain context request runs concurrently with
        # the main search instead of after it.
        urls_task = asyncio.ensure_future(_urls_by_domain()) if "domain" in params else None
        try:
            resp = await client.get(url, params=params, headers=_HEADERS, timeout=15)
        except (httpx.HTTPError, OSError) as exc:
            if urls_task is not None:
                urls_task.cancel()
            logger.warning("Hudson Rock request failed for %s: %s", ioc_value, describe_exception(exc))
            return exception_result(self.name, ioc_value, ioc_type, exc)

        if resp.status_code == 400:
            if urls_task is not None:
                urls_task.cancel()
            err_text = resp.text if isinstance(getattr(resp, "text", None), str) else ""
            logger.info("Hudson Rock rejected query for %s: %s", ioc_value, err_text[:200])
            return failure(
                self.name, ioc_value, ioc_type, "invalid_request", ["domain_search_restricted", "invalid_request"],
                "Hudson Rock does not search broad public domains; no exposure data for this indicator",
                http_status=400,
            )
        failed = http_failure(
            self.name, ioc_value, ioc_type, resp, key_sent=False,
            not_found_summary="No infostealer record for this indicator",
        )
        if failed is not None:
            if urls_task is not None:
                urls_task.cancel()
            return failed

        try:
            data = resp.json()
        except Exception:
            data = None
        if not isinstance(data, dict):
            if urls_task is not None:
                urls_task.cancel()
            return failure(
                self.name, ioc_value, ioc_type, "error", ["malformed_response"],
                "Hudson Rock returned a malformed response", http_status=resp.status_code,
            )

        if urls_task is not None:
            urls_data = await urls_task
            if urls_data:
                data["_urls_by_domain"] = urls_data

        return self._parse_response(ioc_value, ioc_type, data)

    def _parse_response(self, ioc_value: str, ioc_type: str, data: dict) -> NormalizedResult:
        """Parse Cavalier API response into a NormalizedResult."""

        stealers_list = data.get("stealers") or []
        total_corporate = data.get("total_corporate_services", 0) or 0
        total_user = data.get("total_user_services", 0) or 0
        stealer_families_raw = data.get("stealerFamilies") or {}

        # Count infections and extract stealer family names
        infection_count = len(stealers_list) if stealers_list else 0
        total_credentials = total_corporate + total_user

        # Collect stealer family names from either stealers list or stealerFamilies dict
        families: list[str] = []
        if stealer_families_raw and isinstance(stealer_families_raw, dict):
            families = [
                k for k, v in stealer_families_raw.items()
                if k not in ("total", "UNKNOWN") and isinstance(v, int) and v > 0
            ]
        elif stealers_list:
            seen: set[str] = set()
            for s in stealers_list:
                if isinstance(s, dict):
                    f = s.get("stealer_family") or s.get("malware_family") or ""
                    if f and f not in seen:
                        families.append(f)
                        seen.add(f)

        # Collect interesting metadata from individual stealers
        computers: list[str] = []
        os_list: list[str] = []
        dates: list[str] = []
        for s in stealers_list[:5]:  # Cap at 5 for tags
            if isinstance(s, dict):
                cn = s.get("computer_name")
                if cn and cn != "Not Found":
                    computers.append(cn)
                os_name = s.get("operating_system")
                if os_name:
                    os_list.append(os_name)
                dc = s.get("date_compromised")
                if dc:
                    dates.append(dc[:10])  # date portion only

        # Domain-specific: most exposed services
        top_services: list[str] = []
        if isinstance(data.get("topCorporateServices"), list):
            top_services = [
                s.get("domain", "") for s in data["topCorporateServices"][:5]
                if isinstance(s, dict) and s.get("domain")
            ]

        # External services compromised
        top_external: list[str] = []
        if isinstance(data.get("topExternalServices"), list):
            top_external = [
                s.get("domain", "") for s in data["topExternalServices"][:5]
                if isinstance(s, dict) and s.get("domain")
            ]

        # Password strength stats (when available)
        pwd_stats = data.get("passwordStrength") or {}
        pwd_weak_pct = None
        pwd_strong_pct = None
        if isinstance(pwd_stats, dict):
            total_pwd = pwd_stats.get("total", 0)
            if total_pwd > 0:
                pwd_weak_pct = round((pwd_stats.get("weak", 0) / total_pwd) * 100, 1)
                pwd_strong_pct = round((pwd_stats.get("strong", 0) / total_pwd) * 100, 1)

        # Compromised URLs count from urls-by-domain
        urls_domain_data = data.get("_urls_by_domain", {})
        total_compromised_urls = None
        if isinstance(urls_domain_data, dict):
            urls_list = urls_domain_data.get("urls", [])
            if isinstance(urls_list, list):
                total_compromised_urls = len(urls_list)

        exposed = infection_count > 0 or total_credentials > 0
        credential_target = ioc_type in ("email", "username")
        # Tags are labels only; counts live in raw_data.  The
        # ``infostealer_compromised`` label is the stable exposure marker read
        # by the evidence layer.
        tags: list[str] = []
        if exposed:
            tags.append("infostealer_compromised")
            tags.append("credential_exposure" if credential_target else "infrastructure_exposure")

        if not exposed:
            provider_summary = "No infostealer record for this indicator"
        else:
            noun = "credential exposure" if credential_target else "exposure context"
            parts = [f"{infection_count} infostealer infection{'s' if infection_count != 1 else ''} ({noun})"]
            if total_credentials:
                parts.append(f"{total_credentials} credentials at risk")
            if families:
                parts.append(f"families: {', '.join(families[:4])}")
            provider_summary = "; ".join(parts)

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            # Exposure is never a maliciousness verdict for the indicator.
            verdict="unknown",
            provider_verdict=(
                ("credential_exposure" if credential_target else "infostealer_exposure") if exposed else "not_found"
            ),
            normalized_verdict="unknown" if exposed else "not_found",
            execution_state="success" if exposed else "not_found",
            status="found" if exposed else "not_found",
            raw_score=None,
            confidence=("high" if infection_count >= 3 else "medium") if exposed else "low",
            reports_count=infection_count if infection_count else None,
            malware_family=", ".join(families[:4]) if exposed and families else None,
            tags=tags,
            source_link="https://www.hudsonrock.com/",
            provider_summary=provider_summary,
            raw_data={
                "exposure_type": ("credential" if credential_target else "infrastructure") if exposed else None,
                "credentials_at_risk": total_credentials,
                "total_infections": infection_count,
                "total_corporate_services": total_corporate,
                "total_user_services": total_user,
                "stealer_families": stealer_families_raw if stealer_families_raw else families,
                "sample_computers": computers[:3],
                "sample_os": os_list[:3],
                "dates_compromised": sorted(set(dates))[-3:] if dates else [],
                "top_corporate_services": top_services,
                "top_external_services": top_external,
                "password_strength_weak_pct": pwd_weak_pct,
                "password_strength_strong_pct": pwd_strong_pct,
                "total_compromised_urls": total_compromised_urls,
                "raw_message": data.get("message", ""),
            },
        )
