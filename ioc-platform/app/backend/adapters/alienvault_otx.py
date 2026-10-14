import asyncio
from datetime import datetime

import httpx

from app.backend.adapters._http import (
    MalformedResponse,
    describe_exception,
    exception_result,
    failure,
    http_failure,
    malformed,
    not_configured,
    read_json,
)
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings
from app.backend.logger import get_logger


logger = get_logger("adapter.alienvault_otx")


_TYPE_TO_SEGMENT = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "domain": "domain",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}
# OTX ``validation`` sources that mean "this indicator is known-good or a
# known false positive".  Popularity rankings (alexa, majestic, ...) are kept
# as context only: popular sites do get compromised.
_BENIGN_VALIDATION_SOURCES = {"whitelist", "false_positive"}
_SUB_REQUEST_TIMEOUT = 8.0


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


class AlienVaultOTXAdapter(SourceAdapter):
    name = "AlienVault OTX"
    supported_types = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]
    public_without_key = False
    produces_reputation = True
    produces_relationships = True
    # Keyed DirectConnect API: 10,000 requests/hour.  One lookup issues the
    # ``general`` request plus up to three concurrent context requests.
    rate_limit = RateLimitConfig(
        requests_per_minute=40, requests_per_day=10000, max_retries=1, timeout_seconds=15.0,
    )

    def __init__(self):
        self.api_key = settings.alienvault_otx_api_key

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key, "Accept": "application/json"}

    async def _sub_request(self, url: str) -> dict | None:
        """Optional context request.  Failures never change the verdict."""
        try:
            resp = await self._get_client().get(url, headers=self._headers(), timeout=_SUB_REQUEST_TIMEOUT)
            if resp.status_code != 200:
                return None
            data = resp.json()
            return data if isinstance(data, dict) else None
        except Exception as exc:
            logger.debug("OTX context request %s failed: %s", url.rsplit("/", 1)[-1], describe_exception(exc))
            return None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        segment = _TYPE_TO_SEGMENT.get(ioc_type)
        if not segment:
            return failure(
                self.name, ioc_value, ioc_type, "not_applicable", ["unsupported_type"],
                f"OTX does not support {ioc_type} lookups", request_made=False,
            )
        # OTX's anonymous endpoint returns 200 responses without usable
        # reputation data, so a key is required for an honest answer.
        if not is_valid_api_key(self.api_key):
            return not_configured(self.name, ioc_value, ioc_type)

        base = f"https://otx.alienvault.com/api/v1/indicators/{segment}/{ioc_value}"
        # ``general`` is the only section that carries pulse membership and
        # validation for every indicator type (``/reputation`` exists for IPs
        # only and has no pulse data).
        try:
            resp = await self._get_client().get(f"{base}/general", headers=self._headers(), timeout=10)
        except httpx.HTTPError as exc:
            logger.warning("OTX request failed for %s: %s", ioc_value, describe_exception(exc))
            return exception_result(self.name, ioc_value, ioc_type, exc)
        failed = http_failure(self.name, ioc_value, ioc_type, resp)
        if failed is not None:
            return failed
        try:
            general = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(general, dict):
            return malformed(self.name, ioc_value, ioc_type)

        pulse_info = general.get("pulse_info") if isinstance(general.get("pulse_info"), dict) else {}
        pulses = [p for p in (pulse_info.get("pulses") or []) if isinstance(p, dict)]
        pulse_count = pulse_info.get("count")
        pulse_count = int(pulse_count) if isinstance(pulse_count, int) else len(pulses)
        validation = [v for v in (general.get("validation") or []) if isinstance(v, dict)]
        benign_validation = [
            v for v in validation
            if str(v.get("source") or "").lower() in _BENIGN_VALIDATION_SOURCES
        ]
        false_positive = [fp for fp in (general.get("false_positive") or []) if fp]

        families: list[str] = []
        mitre: set[str] = set()
        pulse_names: list[str] = []
        last_seen = None
        for pulse in pulses:
            name = str(pulse.get("name") or "").strip()
            if name and len(pulse_names) < 10:
                pulse_names.append(name[:120])
            for family in pulse.get("malware_families") or []:
                label = family.get("display_name") if isinstance(family, dict) else family
                if label and str(label) not in families:
                    families.append(str(label))
            for attack in pulse.get("attack_ids") or []:
                attack_id = attack.get("id") if isinstance(attack, dict) else attack
                if attack_id:
                    mitre.add(str(attack_id))
            modified = _parse_dt(pulse.get("modified") or pulse.get("created"))
            if modified and (last_seen is None or modified > last_seen):
                last_seen = modified

        # Context sections, fetched concurrently and bounded so they cannot
        # push the lookup past its deadline.
        context_sections: list[str] = []
        if ioc_type in ("ipv4", "ipv6", "domain"):
            context_sections = ["passive_dns", "url_list", "malware"]
        sub_results = await asyncio.gather(
            *(self._sub_request(f"{base}/{section}") for section in context_sections)
        ) if context_sections else []
        sections = dict(zip(context_sections, sub_results))

        related = []
        pd_data = sections.get("passive_dns") or {}
        for entry in (pd_data.get("passive_dns") or [])[:10]:
            if isinstance(entry, dict):
                hostname = entry.get("hostname", "")
                address = entry.get("address", "")
                if ioc_type == "domain" and address:
                    related.append((str(address), "resolves_to"))
                elif hostname:
                    related.append((str(hostname), "passive_dns"))
        malware_urls = [
            str(entry.get("url")) for entry in ((sections.get("url_list") or {}).get("url_list") or [])[:25]
            if isinstance(entry, dict) and entry.get("url")
        ]
        associated_hashes = [
            str(entry.get("hash")) for entry in ((sections.get("malware") or {}).get("data") or [])[:10]
            if isinstance(entry, dict) and entry.get("hash")
        ]

        tags: list[str] = []
        if benign_validation or false_positive:
            verdict, confidence, raw_score = "whitelisted", "medium", 0.0
            tags.append("otx_whitelisted")
        elif pulse_count >= 3 and (families or mitre):
            verdict, confidence, raw_score = "malicious", "medium", 0.7
        elif pulse_count > 0:
            verdict, confidence, raw_score = "suspicious", "low" if pulse_count == 1 else "medium", 0.4
        else:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="not_found",
                execution_state="not_found", status="not_found",
                related_iocs=related,
                provider_summary="Indicator is not referenced by any OTX pulse",
                raw_data={
                    "pulse_count": 0,
                    "validation": validation[:5],
                    "malware_urls": malware_urls,
                    "associated_hashes": associated_hashes,
                },
                source_link=f"https://otx.alienvault.com/indicator/{segment.lower()}/{ioc_value}",
            )
        if pulse_count:
            tags.append("otx_pulses")

        summary = f"Referenced by {pulse_count} OTX pulse{'s' if pulse_count != 1 else ''}"
        if verdict == "whitelisted":
            summary += "; OTX validation marks it as known-good/false positive"
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, confidence=confidence, raw_score=raw_score,
            tags=tags, reports_count=pulse_count,
            malware_family=", ".join(families[:5]) or None,
            mitre_attck=sorted(mitre),
            related_iocs=related,
            last_seen=last_seen,
            provider_summary=summary,
            source_link=f"https://otx.alienvault.com/indicator/{segment.lower()}/{ioc_value}",
            raw_data={
                "pulse_count": pulse_count,
                "pulse_names": pulse_names,
                "validation": validation[:5],
                "false_positive": false_positive[:5],
                "malware_urls": malware_urls,
                "associated_hashes": associated_hashes,
            },
        )
