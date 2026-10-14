import base64
import time

from app.backend.adapters._http import MalformedResponse, failure, http_failure, malformed, not_configured, read_json
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings

_MAX_SERVICES = 30


class CensysAdapter(SourceAdapter):
    name = "Censys"
    supported_types = ["ipv4"]
    produces_infrastructure_context = True
    produces_metadata = True
    # Free (Community) tier: 100 credits/month; the Platform API allows a
    # small burst, so keep well under it.
    rate_limit = RateLimitConfig(requests_per_minute=24)

    CENSYS_MONTHLY_LIMIT = 100
    _monthly_credits_used = 0
    _credit_reset_time = 0.0

    def __init__(self):
        self.api_key = settings.censys_api_key
        self.organization_id = settings.censys_organization_id
        # A Platform Personal Access Token is sufficient for the Free tier.
        # Organization IDs identify paid-organization entitlements and are
        # optional according to the Platform API documentation.
        self._has_credentials = is_valid_api_key(self.api_key)

    def _auth_header(self) -> str:
        if ":" in self.api_key:
            api_id, api_secret = self.api_key.split(":", 1)
            token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
            return f"Basic {token}"
        # Modern Censys personal access tokens (censys_...) use Bearer auth.
        return f"Bearer {self.api_key}"

    def _request_headers(self) -> dict:
        """Platform API headers for a PAT-authenticated host lookup."""
        headers = {
            "Authorization": self._auth_header(),
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        }
        if self.organization_id:
            headers["X-Organization-ID"] = self.organization_id
        return headers

    def _check_credits(self) -> bool:
        now = time.time()
        if now > self._credit_reset_time:
            self._monthly_credits_used = 0
            self._credit_reset_time = now + 2592000
        return self._monthly_credits_used < self.CENSYS_MONTHLY_LIMIT

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not self._has_credentials:
            return not_configured(self.name, ioc_value, ioc_type)

        if not self._check_credits():
            return failure(
                self.name, ioc_value, ioc_type, "unavailable", ["out_of_credits"],
                f"Censys monthly credit budget ({self.CENSYS_MONTHLY_LIMIT}) used up locally",
                request_made=False,
            )

        client = self._get_client()
        resp = await client.get(
            f"https://api.platform.censys.io/v3/global/asset/host/{ioc_value}",
            headers=self._request_headers(),
            timeout=15,
        )

        failed = http_failure(self.name, ioc_value, ioc_type, resp, not_found_summary="Censys has no record of this host")
        if failed is not None:
            return failed

        CensysAdapter._monthly_credits_used += 1

        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type, http_status=resp.status_code)
        result = data.get("result")
        resource = result.get("resource") if isinstance(result, dict) else None
        if not isinstance(resource, dict) or not resource:
            return failure(
                self.name, ioc_value, ioc_type, "not_found", [],
                "Censys has no record of this host", http_status=resp.status_code,
            )

        location = resource.get("location") if isinstance(resource.get("location"), dict) else {}
        asys = resource.get("autonomous_system") if isinstance(resource.get("autonomous_system"), dict) else {}
        raw_services = resource.get("services") if isinstance(resource.get("services"), list) else []

        services = []
        for service in raw_services:
            if not isinstance(service, dict) or service.get("port") is None:
                continue
            software = []
            for item in service.get("software") if isinstance(service.get("software"), list) else []:
                if isinstance(item, dict):
                    label = "/".join(
                        str(part) for part in (item.get("product") or item.get("name"), item.get("version")) if part
                    )
                    if label:
                        software.append(label)
            services.append({
                "port": service.get("port"),
                "service_name": service.get("service_name") or None,
                "transport": service.get("transport_protocol") or None,
                "software": software,
            })
        services = services[:_MAX_SERVICES]

        # Structured values live in raw_data; a host Censys returned is
        # confirmed to exist on the internet, which is the only label needed
        # (it also keeps the result from being demoted to not_found when the
        # host has no location/ASN/services).
        raw_data = {
            "ip": resource.get("ip") or ioc_value,
            "location": {
                key: location.get(key)
                for key in ("city", "province", "country", "country_code", "timezone")
                if location.get(key)
            },
            "autonomous_system": {
                key: asys.get(key) for key in ("asn", "name", "bgp_prefix", "country_code") if asys.get(key)
            },
            "service_count": len(raw_services),
            "ports": [service["port"] for service in services],
            "services": services,
        }
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", raw_score=None, status="found", tags=["active_ip"], raw_data=raw_data,
            provider_summary=f"Host is indexed by Censys with {len(raw_services)} service(s)",
            http_status=resp.status_code,
        )
