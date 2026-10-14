from app.backend.adapters._http import MalformedResponse, failure, http_failure, malformed, read_json
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings


class IPinfoAdapter(SourceAdapter):
    """IP geolocation/ASN context. It is not a reputation source: hosting or
    bogon status describes the network, not whether the address is malicious."""

    name = "IPinfo"
    supported_types = ["ipv4", "ipv6"]
    public_without_key = True
    produces_infrastructure_context = True
    produces_metadata = True
    # Free plan: 50k requests/month.
    rate_limit = RateLimitConfig(requests_per_minute=30)

    def __init__(self):
        self.api_key = settings.ipinfo_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        client = self._get_client()

        if not is_valid_api_key(self.api_key):
            return await self._lite_lookup(client, ioc_value, ioc_type)

        return await self._paid_lookup(client, ioc_value, ioc_type)

    async def _lite_lookup(self, client, ioc_value: str, ioc_type: str) -> NormalizedResult:
        resp = await client.get(
            f"https://ipinfo.io/{ioc_value}/json",
            timeout=10,
        )
        failed = http_failure(self.name, ioc_value, ioc_type, resp, key_sent=False)
        if failed is not None:
            # The key-free endpoint could not answer; say so instead of "no data".
            if "lite_api_unavailable" not in failed.tags and failed.execution_state in {"error", "unavailable", "invalid_request"}:
                failed.tags = [*failed.tags, "lite_api_unavailable"]
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type, http_status=resp.status_code)

        raw_data = {
            "country": data.get("country_code", "") or data.get("country", ""),
            "asn": data.get("asn", ""),
            "as_name": data.get("as_name", "") or data.get("asn_name", ""),
            "source": "lite",
        }
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", raw_score=None, tags=["geo_context"],
            raw_data={k: v for k, v in raw_data.items() if v not in ("", None)},
            status="found", http_status=resp.status_code,
        )

    async def _paid_lookup(self, client, ioc_value: str, ioc_type: str) -> NormalizedResult:
        resp = await client.get(
            f"https://ipinfo.io/{ioc_value}/json",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=10,
        )
        failed = http_failure(self.name, ioc_value, ioc_type, resp)
        if failed is not None:
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type, http_status=resp.status_code)

        asn_info = data.get("asn") if isinstance(data.get("asn"), dict) else {}
        hosting = data.get("hosting") if isinstance(data.get("hosting"), dict) else {}
        is_hosting = bool(hosting.get("is_hosting", False))
        is_bogon = bool(hosting.get("is_bogon", False))
        tags = ["geo_context"]
        if is_hosting:
            tags.append("hosting_provider")
        if is_bogon:
            tags.append("bogon")

        # Structured values live in raw_data; network type is context, never a verdict.
        raw_data = {
            key: data.get(key)
            for key in ("ip", "city", "region", "country", "loc", "postal", "timezone", "org", "hostname")
            if data.get(key)
        }
        if asn_info:
            raw_data["asn"] = asn_info.get("asn")
            raw_data["asn_name"] = asn_info.get("name")
        raw_data["is_hosting"] = is_hosting
        raw_data["is_bogon"] = is_bogon
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", raw_score=None, tags=tags,
            raw_data=raw_data, status="found", http_status=resp.status_code,
        )
