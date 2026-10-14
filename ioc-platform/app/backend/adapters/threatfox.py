from datetime import datetime
import re

from app.backend.adapters._http import MalformedResponse, http_failure, failure, malformed, read_json
from app.backend.adapters._matching import host_of, indicator_equals, ip_port_equals, normalize_domain
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings

# F1 quality gate: submissions that carry junk/test markers are excluded from
# evidence. ThreatFox allows test submissions and low-trust reporters to tag
# entries; treating them as full-strength malicious evidence caused false
# positives on legitimate domains (e.g. example.com flagged by a "test" entry).
_JUNK_TAG_MARKERS = (
    "test", "testing", "benign", "joke", "canary", "sandbox",
    "falsepositive", "false_positive", "poc", "demo", "sample",
)
_JUNK_REPORTERS = ("lenny_3bo", "test", "tester", "junk")
_MIN_CONFIDENCE_LEVEL = 50
_MAX_TAGS = 10
_MAX_RELATED = 15


def _matches_target_ioc(entry_ioc: str, target_ioc: str, ioc_type: str) -> bool:
    """Whether a ThreatFox record is *related* to the queried indicator.

    This is a relationship test (same host, subdomain URL, ``ip:port``), not
    an identity test.  Related records are context only; a verdict requires
    :func:`_is_exact_record`.
    """
    if not entry_ioc:
        return False
    entry = entry_ioc.strip().lower()
    target = target_ioc.strip().lower()
    if entry == target:
        return True
    if ioc_type == "domain":
        host = host_of(entry)
        target = normalize_domain(target)
        return host == target or host.endswith("." + target)
    if ioc_type in ("ipv4", "ipv6"):
        return host_of(entry) == target or ip_port_equals(entry, target)
    if ioc_type in {"md5", "sha1", "sha256"}:
        return entry == target
    if ioc_type == "url":
        return indicator_equals(entry, target, "url")
    return False


def _is_exact_record(entry: dict, target_ioc: str, ioc_type: str) -> bool:
    """A record may carry a verdict only when its indicator IS the query."""
    entry_ioc = str(entry.get("ioc") or "").strip()
    if not entry_ioc:
        return False
    record_type = str(entry.get("ioc_type") or "").strip().lower()
    if ioc_type in ("ipv4", "ipv6"):
        # ThreatFox stores network IOCs as ``ip:port``; the record is about
        # the IP itself.  A URL whose host is the IP is only related.
        if record_type == "url" or "://" in entry_ioc:
            return False
        return ip_port_equals(entry_ioc, target_ioc)
    if ioc_type == "domain":
        if record_type == "url" or "://" in entry_ioc:
            return False
        return indicator_equals(entry_ioc, target_ioc, "domain")
    if ioc_type in ("md5", "sha1", "sha256", "url"):
        return indicator_equals(entry_ioc, target_ioc, ioc_type)
    return False


def _is_junk_entry(entry: dict) -> bool:
    tags = entry.get("tags", "")
    if isinstance(tags, str):
        tag_list = [t.strip().lower() for t in tags.split(",") if t.strip()]
    elif isinstance(tags, list):
        tag_list = [str(t).strip().lower() for t in tags]
    else:
        tag_list = []
    if any(
        re.search(rf"(?:^|[^a-z0-9]){re.escape(marker)}(?:$|[^a-z0-9])", tag)
        for tag in tag_list
        for marker in _JUNK_TAG_MARKERS
    ):
        return True
    reporter = str(entry.get("reporter", "")).lower()
    if any(r in reporter for r in _JUNK_REPORTERS):
        return True
    confidence = entry.get("confidence_level")
    if isinstance(confidence, (int, float)) and confidence < _MIN_CONFIDENCE_LEVEL:
        return True
    return False


def _entry_tags(entry: dict) -> list[str]:
    raw = entry.get("tags") or []
    if isinstance(raw, str):
        raw = raw.split(",")
    return [str(tag).strip() for tag in raw if isinstance(tag, (str, int)) and str(tag).strip()] if isinstance(raw, list) else []


def _compact_record(entry: dict) -> dict:
    malpedia = entry.get("malware_malpedia")
    return {
        "id": entry.get("id") or entry.get("ioc_id"),
        "ioc": entry.get("ioc"),
        "ioc_type": entry.get("ioc_type"),
        "threat_type": entry.get("threat_type"),
        "malware": entry.get("malware"),
        "malware_printable": entry.get("malware_printable"),
        "malware_alias": entry.get("malware_alias"),
        "malpedia": malpedia.get("url") if isinstance(malpedia, dict) else malpedia,
        "confidence_level": entry.get("confidence_level"),
        "first_seen": entry.get("first_seen"),
        "last_seen": entry.get("last_seen"),
        "reporter": entry.get("reporter"),
        "reference": entry.get("reference"),
        "tags": _entry_tags(entry)[:15],
    }


class ThreatFoxAdapter(SourceAdapter):
    name = "ThreatFox"
    supported_types = ["md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url"]
    # ThreatFox currently returns HTTP 401 without an Auth-Key.
    public_without_key = False
    direct_threat_evidence = True
    produces_reputation = True
    produces_relationships = True
    # abuse.ch publishes no hard per-minute quota ("fair use").
    rate_limit = RateLimitConfig(requests_per_minute=60, requests_per_day=5000)

    def __init__(self):
        self.api_key = settings.threatfox_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        client = self._get_client()
        headers = {}
        key_sent = is_valid_api_key(self.api_key)
        if key_sent:
            headers["Auth-Key"] = self.api_key
        resp = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc_value},
            headers=headers or None,
            timeout=15,
        )

        failed = http_failure(self.name, ioc_value, ioc_type, resp, key_sent=key_sent)
        if failed is not None:
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type)
        qs = str(data.get("query_status") or "")

        if qs == "no_result":
            return failure(self.name, ioc_value, ioc_type, "not_found", [], "No matching record")
        if qs != "ok":
            lowered = qs.lower()
            if "auth" in lowered or "key" in lowered:
                return failure(
                    self.name, ioc_value, ioc_type, "unavailable", ["invalid_api_key"],
                    f"ThreatFox rejected the Auth-Key (query_status={qs})",
                )
            if lowered.startswith("illegal") or lowered.startswith("invalid"):
                return failure(
                    self.name, ioc_value, ioc_type, "invalid_request", ["invalid_request"],
                    f"ThreatFox rejected the search term (query_status={qs})",
                )
            return failure(
                self.name, ioc_value, ioc_type, "error", ["unexpected_response"],
                f"ThreatFox returned query_status={qs or 'missing'}",
            )

        entries = data.get("data") or []
        if not isinstance(entries, list):
            entries = [entries]
        entries = [entry for entry in entries if isinstance(entry, dict)]

        exact: list[dict] = []
        related: list[dict] = []
        junk_skipped = 0
        for entry in entries:
            if not _is_exact_record(entry, ioc_value, ioc_type):
                related.append(entry)
                continue
            if _is_junk_entry(entry):
                junk_skipped += 1
                continue
            exact.append(entry)

        related_iocs = [
            (str(entry.get("ioc")), "threatfox_related_record")
            for entry in related[:_MAX_RELATED]
            if entry.get("ioc")
        ]
        raw_data = {
            "query_status": qs,
            "match_count": len(exact),
            "match_type": "exact" if exact else None,
            "related_record_count": len(related),
            "filtered_low_quality_count": junk_skipped,
            "records": [_compact_record(entry) for entry in exact[:10]],
            "related_records": [
                {"ioc": entry.get("ioc"), "ioc_type": entry.get("ioc_type"), "malware_printable": entry.get("malware_printable")}
                for entry in related[:_MAX_RELATED]
            ],
        }

        if not exact:
            parts = ["No record for this exact indicator"]
            if related:
                parts.append(f"{len(related)} related record{'s' if len(related) != 1 else ''} (e.g. URLs on this host) kept as context")
            if junk_skipped:
                parts.append(f"{junk_skipped} low-confidence/test record{'s' if junk_skipped != 1 else ''} ignored")
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="not_found", raw_score=0.0,
                execution_state="not_found", status="not_found",
                tags=["related_records_only"] if related else [],
                related_iocs=related_iocs, reports_count=0,
                provider_summary="; ".join(parts), raw_data=raw_data,
                source_link=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc_value}",
            )

        tags: list[str] = []
        families: list[str] = []
        categories: list[str] = []
        refs: list[str] = []
        mitre: set[str] = set()
        first = last = None
        max_confidence = 0
        for entry in exact:
            for tag in _entry_tags(entry):
                if re.match(r"^(TA\d{4}|T\d{4}(\.\d{3})?)$", tag, re.IGNORECASE):
                    mitre.add(tag.upper())
                elif tag not in tags:
                    tags.append(tag)
            family = str(entry.get("malware_printable") or entry.get("malware") or "").strip()
            if family and family.lower() not in {"unknown malware", "unknown"} and family not in families:
                families.append(family)
            threat_type = str(entry.get("threat_type") or "").strip()
            if threat_type and threat_type not in categories:
                categories.append(threat_type)
            ref = entry.get("reference")
            if ref and ref not in refs:
                refs.append(str(ref))
            confidence_level = entry.get("confidence_level", 0)
            if isinstance(confidence_level, (int, float)) and confidence_level > max_confidence:
                max_confidence = confidence_level
            fs = self._parse_dt(entry.get("first_seen"))
            if fs and (first is None or fs < first):
                first = fs
            ls = self._parse_dt(entry.get("last_seen"))
            if ls and (last is None or ls > last):
                last = ls

        record_id = exact[0].get("id") or exact[0].get("ioc_id")
        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict="malicious",
            confidence="high" if len(exact) >= 2 or max_confidence >= 90 else "medium",
            raw_score=(max_confidence / 100.0) if max_confidence > 0 else 1.0,
            tags=tags[:_MAX_TAGS],
            categories=categories,
            malware_family=", ".join(families) or None,
            mitre_attck=sorted(mitre),
            first_seen=first,
            last_seen=last or first,
            related_iocs=related_iocs,
            source_link=(
                f"https://threatfox.abuse.ch/ioc/{record_id}/" if record_id
                else f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc_value}"
            ),
            reports_count=len(exact),
            references=refs[:10],
            source_record_id=str(record_id) if record_id else None,
            provider_summary=(
                f"{len(exact)} ThreatFox record{'s' if len(exact) != 1 else ''} for this exact indicator"
                + (f" ({', '.join(families[:3])})" if families else "")
            ),
            raw_data=raw_data,
        )

    def _parse_dt(self, val) -> datetime | None:
        if not val:
            return None
        text = str(val).replace(" UTC", "").strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
        return None
