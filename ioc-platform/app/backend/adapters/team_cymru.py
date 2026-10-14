import ipaddress

from app.backend.adapters._http import MalformedResponse, failure, http_failure, malformed, read_json
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter

_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
_IPV4_ZONE = "v4.fullbogons.cymru.com"
_IPV6_ZONE = "v6.fullbogons.cymru.com"


def _reverse_name(ioc_value: str, ioc_type: str) -> str:
    """Build the Team Cymru reversed-octet/nibble DNS query name.

    IPv4: reverse octets, e.g. 192.168.1.1 -> 1.1.168.192.v4.fullbogons.cymru.com
    IPv6: reverse nibbles of the fully-expanded address (no colon compression).
    """
    if ioc_type == "ipv4":
        octets = ioc_value.split(".")
        return ".".join(reversed(octets)) + f".{_IPV4_ZONE}"
    exploded = ipaddress.IPv6Address(ioc_value).exploded.replace(":", "")
    return ".".join(reversed(exploded)) + f".{_IPV6_ZONE}"


class TeamCymruAdapter(SourceAdapter):
    """Team Cymru bogon reference, key-free, queried via Cloudflare DoH TXT.

    A TXT answer means the address is within a bogon prefix (the TXT value is
    the offending prefix). No TXT answer means the address is not a bogon.
    """

    name = "Team Cymru"
    supported_types = ["ipv4", "ipv6"]
    public_without_key = True
    evidence_roles = ("context",)
    direct_threat_evidence = False
    produces_reputation = False
    produces_infrastructure_context = True
    produces_metadata = True
    rate_limit = RateLimitConfig(requests_per_minute=30)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        query_name = _reverse_name(ioc_value, ioc_type)
        client = self._get_client()
        resp = await client.get(
            _DOH_ENDPOINT,
            params={"name": query_name, "type": "TXT"},
            headers={"accept": "application/dns-json"},
            timeout=10,
        )

        failed = http_failure(self.name, ioc_value, ioc_type, resp, key_sent=False)
        if failed is not None:
            if failed.execution_state == "not_found":
                # A DoH endpoint never answers 404 for a valid query.
                failed = failure(self.name, ioc_value, ioc_type, "error", ["http_404"], "DNS-over-HTTPS resolver returned HTTP 404", http_status=404)
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type)
        try:
            doh_status = int(data.get("Status", 0) or 0)
        except (TypeError, ValueError):
            return malformed(self.name, ioc_value, ioc_type)
        if doh_status not in (0, 3):
            return failure(
                self.name, ioc_value, ioc_type, "error", [f"doh_status:{doh_status}"],
                f"Bogon DNS query failed (DNS status {doh_status})",
            )

        prefixes = [
            str(a.get("data", "")).strip().strip('"')
            for a in (data.get("Answer") or [])
            if isinstance(a, dict) and a.get("type") == 16 and a.get("data")
        ]

        if prefixes:
            prefix = prefixes[0]
            # A publicly-seen address inside an unallocated/bogon prefix is an
            # anomaly (spoofing or hijacked space) worth flagging.
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="suspicious", raw_score=0.3, confidence="medium",
                tags=["bogon", f"bogon_prefix:{prefix}"],
                source_link="https://www.team-cymru.com/bogon-reference-dns",
                provider_summary=f"Address is inside bogon prefix {prefix}",
                raw_data={"bogon": True, "bogon_prefix": prefix},
            )

        # Not being a bogon says nothing about reputation.
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", provider_verdict="not_bogon", normalized_verdict="unknown",
            raw_score=None, confidence="low",
            tags=["not_bogon"],
            source_link="https://www.team-cymru.com/bogon-reference-dns",
            provider_summary="Allocated address space (not a bogon)",
            raw_data={"bogon": False},
        )
