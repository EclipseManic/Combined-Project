from datetime import datetime

from app.backend.adapters._http import MalformedResponse, describe_exception, exception_result, failure, http_failure, malformed, read_json
from app.backend.adapters._matching import indicator_equals
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.logger import get_logger

logger = get_logger("adapter.urlhaus")

_MAX_URLS = 10


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    text = str(value).replace(" UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _compact_urls(urls) -> list[dict]:
    if not isinstance(urls, list):
        return []
    compact = []
    for item in urls[:_MAX_URLS]:
        if isinstance(item, dict):
            compact.append({
                "url": str(item.get("url") or "")[:300],
                "url_status": item.get("url_status"),
                "threat": item.get("threat"),
                "date_added": item.get("date_added") or item.get("firstseen"),
                "reference": item.get("urlhaus_reference"),
            })
    return compact


class URLHausAdapter(SourceAdapter):
    name = "URLhaus"
    # The payload endpoint accepts md5_hash / sha256_hash only.
    supported_types = ["url", "domain", "md5", "sha256"]
    # abuse.ch requires an Auth-Key for every API (URLhaus, ThreatFox,
    # MalwareBazaar); anonymous requests are rejected with HTTP 401.
    public_without_key = False
    direct_threat_evidence = True
    produces_reputation = True
    rate_limit = RateLimitConfig(requests_per_minute=60, requests_per_day=5000)

    def __init__(self):
        super().__init__()
        from app.backend.config import settings
        self.api_key = settings.urlhaus_api_key

    def _auth_headers(self) -> dict:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if is_valid_api_key(self.api_key):
            headers["Auth-Key"] = self.api_key
        return headers

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type == "domain":
            endpoint, form = "https://urlhaus-api.abuse.ch/v1/host/", {"host": ioc_value}
        elif ioc_type in ("md5", "sha256"):
            endpoint, form = "https://urlhaus-api.abuse.ch/v1/payload/", {f"{ioc_type}_hash": ioc_value}
        elif ioc_type not in self.supported_types:
            return failure(
                self.name, ioc_value, ioc_type, "not_applicable", ["unsupported_type"],
                f"URLhaus does not support {ioc_type} lookups", request_made=False,
            )
        else:
            endpoint, form = "https://urlhaus-api.abuse.ch/v1/url/", {"url": ioc_value}

        client = self._get_client()
        try:
            resp = await client.post(endpoint, data=form, headers=self._auth_headers(), timeout=15)
        except Exception as exc:
            logger.warning("URLhaus request failed for %s: %s", ioc_value, describe_exception(exc))
            return exception_result(self.name, ioc_value, ioc_type, exc)

        failed = http_failure(self.name, ioc_value, ioc_type, resp, key_sent=is_valid_api_key(self.api_key))
        if failed is not None:
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type)

        query_status = str(data.get("query_status") or "")
        if query_status == "no_results":
            return failure(self.name, ioc_value, ioc_type, "not_found", [], "No matching record")
        if query_status != "ok":
            lowered = query_status.lower()
            if "auth" in lowered or "key" in lowered:
                return failure(
                    self.name, ioc_value, ioc_type, "unavailable", ["invalid_api_key"],
                    f"URLhaus rejected the Auth-Key (query_status={query_status})",
                )
            if lowered.startswith("invalid") or lowered.startswith("illegal"):
                return failure(
                    self.name, ioc_value, ioc_type, "invalid_request", ["invalid_request"],
                    f"URLhaus rejected the query (query_status={query_status})",
                )
            return failure(
                self.name, ioc_value, ioc_type, "error", ["unexpected_response"],
                f"URLhaus returned query_status={query_status or 'missing'}",
            )

        if ioc_type == "domain":
            return self._host_result(ioc_value, ioc_type, data)
        if ioc_type in ("md5", "sha256"):
            return self._payload_result(ioc_value, ioc_type, data)
        return self._url_result(ioc_value, ioc_type, data)

    def _url_result(self, ioc_value: str, ioc_type: str, data: dict) -> NormalizedResult:
        record_url = str(data.get("url") or "")
        if record_url and not indicator_equals(record_url, ioc_value, "url"):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="not_found",
                execution_state="not_found", status="not_found",
                related_iocs=[(record_url, "urlhaus_related_url")],
                provider_summary="URLhaus returned a different URL; kept as context only",
                raw_data={"query_status": "ok", "returned_url": record_url[:300]},
            )
        url_status = str(data.get("url_status") or "").lower()
        threat = data.get("threat") or ""
        if url_status == "online":
            verdict, raw_score, confidence = "malicious", 1.0, "high"
        else:
            # Offline URLs are historical malware distribution sites.
            verdict, raw_score, confidence = "suspicious", 0.5, "medium"
        tags = ["malware_url"] + [t for t in (data.get("tags") or []) if isinstance(t, str)][:8]
        payloads = data.get("payloads") if isinstance(data.get("payloads"), list) else []
        families = [
            str(p.get("signature")) for p in payloads
            if isinstance(p, dict) and p.get("signature")
        ]
        related = [
            (str(p.get("response_sha256")), "sha256")
            for p in payloads[:10] if isinstance(p, dict) and p.get("response_sha256")
        ]
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=raw_score, confidence=confidence,
            tags=tags, categories=[threat] if threat else [],
            malware_family=", ".join(dict.fromkeys(families)) or None,
            first_seen=_parse_dt(data.get("date_added")),
            last_seen=_parse_dt(data.get("last_online")),
            related_iocs=related,
            source_link=data.get("urlhaus_reference") or None,
            reports_count=1,
            source_record_id=str(data.get("id")) if data.get("id") else None,
            provider_summary=f"Listed malware URL ({url_status or 'status unknown'})",
            raw_data={
                "query_status": "ok",
                "id": data.get("id"),
                "url": record_url[:300],
                "url_status": url_status,
                "threat": threat,
                "host": data.get("host"),
                "date_added": data.get("date_added"),
                "last_online": data.get("last_online"),
                "blacklists": data.get("blacklists"),
                "payload_count": len(payloads),
            },
        )

    def _host_result(self, ioc_value: str, ioc_type: str, data: dict) -> NormalizedResult:
        host = str(data.get("host") or "")
        if host and not indicator_equals(host, ioc_value, "domain"):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="not_found",
                execution_state="not_found", status="not_found",
                related_iocs=[(host, "urlhaus_related_host")],
                provider_summary="URLhaus returned a different host; kept as context only",
                raw_data={"query_status": "ok", "returned_host": host},
            )
        urls = data.get("urls") if isinstance(data.get("urls"), list) else []
        url_count = int(data.get("url_count") or len(urls) or 0)
        online = [u for u in urls if isinstance(u, dict) and str(u.get("url_status")).lower() == "online"]
        blacklists = data.get("blacklists") if isinstance(data.get("blacklists"), dict) else {}
        abused_legit = any(str(value).lower().startswith("abused_legit") for value in blacklists.values())
        # URLhaus lists malware URLs *hosted on* this exact host.  That is
        # evidence about the host, but a legitimate platform abused to host
        # a file (flagged "abused_legit_*" by Spamhaus DBL) is only context.
        if abused_legit or url_count == 0:
            verdict, confidence, raw_score = "unknown", "low", None
        else:
            verdict = "suspicious"
            confidence = "medium" if online else "low"
            raw_score = 0.6 if online else 0.4
        tags = ["malware_hosting"] if url_count else []
        if abused_legit:
            tags.append("abused_legitimate_host")
        summary = f"{url_count} malware URL{'s' if url_count != 1 else ''} recorded on this host ({len(online)} online)"
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=raw_score, confidence=confidence, tags=tags,
            first_seen=_parse_dt(data.get("firstseen")),
            related_iocs=[(u["url"], "hosted_malware_url") for u in _compact_urls(urls) if u.get("url")],
            source_link=data.get("urlhaus_reference") or None,
            reports_count=url_count,
            provider_summary=summary,
            raw_data={
                "query_status": "ok",
                "host": host,
                "url_count": url_count,
                "online_url_count": len(online),
                "blacklists": blacklists,
                "urls": _compact_urls(urls),
            },
        )

    def _payload_result(self, ioc_value: str, ioc_type: str, data: dict) -> NormalizedResult:
        record_hash = str(data.get(f"{ioc_type}_hash") or "")
        if record_hash and not indicator_equals(record_hash, ioc_value, ioc_type):
            return failure(self.name, ioc_value, ioc_type, "not_found", [], "No record for this exact hash")
        urls = data.get("urls") if isinstance(data.get("urls"), list) else []
        signature = data.get("signature") or None
        related = []
        for key, kind in (("md5_hash", "md5"), ("sha256_hash", "sha256")):
            value = data.get(key)
            if value and str(value).lower() != ioc_value.lower():
                related.append((str(value), kind))
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            # URLhaus only records payloads that malware URLs delivered.
            verdict="malicious", raw_score=0.9, confidence="high" if signature else "medium",
            tags=["malware_payload"],
            categories=[str(data.get("file_type"))] if data.get("file_type") else [],
            malware_family=signature,
            first_seen=_parse_dt(data.get("firstseen")),
            last_seen=_parse_dt(data.get("lastseen")),
            related_iocs=related + [(u["url"], "delivered_by_url") for u in _compact_urls(urls) if u.get("url")],
            source_link=f"https://urlhaus.abuse.ch/browse.php?search={ioc_value}",
            reports_count=int(data.get("url_count") or len(urls) or 1),
            provider_summary=(
                f"Malware payload delivered by {int(data.get('url_count') or len(urls) or 0)} URL(s)"
                + (f"; family {signature}" if signature else "")
            ),
            raw_data={
                "query_status": "ok",
                "md5_hash": data.get("md5_hash"),
                "sha256_hash": data.get("sha256_hash"),
                "file_type": data.get("file_type"),
                "file_size": data.get("file_size"),
                "signature": signature,
                "url_count": data.get("url_count"),
                "urls": _compact_urls(urls),
            },
        )
