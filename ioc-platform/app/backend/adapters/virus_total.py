import base64
from datetime import datetime, timezone

from app.backend.adapters._http import MalformedResponse, failure, http_failure, malformed, not_configured, read_json
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings

_MAX_TAGS = 12


class VirusTotalAdapter(SourceAdapter):
    name = "VirusTotal"
    supported_types = ["md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url"]
    direct_threat_evidence = True
    produces_reputation = True
    # Public (free) API: 4 lookups/minute, 500/day, 15.5K/month.
    rate_limit = RateLimitConfig(
        requests_per_minute=4,
        requests_per_day=500,
        minimum_interval_seconds=0.0,
        max_backoff_seconds=10.0,
        max_retries=1,
        concurrency_limit=2,
    )

    def __init__(self):
        self.api_key = settings.virustotal_api_key
        rpm = getattr(settings, "vt_rate_per_minute", None)
        if isinstance(rpm, int) and rpm > 0 and rpm != self.rate_limit.requests_per_minute:
            # Premium keys raise the per-minute quota; keep every other
            # policy field (daily cap, retries, concurrency) intact.
            self.rate_limit = self.rate_limit.model_copy(update={"requests_per_minute": rpm})

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return not_configured(self.name, ioc_value, ioc_type)

        endpoint = self._endpoint(ioc_value, ioc_type)
        if not endpoint:
            return failure(
                self.name, ioc_value, ioc_type, "not_applicable", ["unsupported_type"],
                f"VirusTotal does not support {ioc_type} lookups", request_made=False,
            )

        client = self._get_client()
        resp = await client.get(
                endpoint,
                headers={"x-apikey": self.api_key, "accept": "application/json"},
                timeout=15,
            )

        failed = http_failure(self.name, ioc_value, ioc_type, resp)
        if failed is not None:
            if resp.status_code == 429:
                # VirusTotal answers 429 both for the per-minute limit and for
                # an exhausted daily quota (QuotaExceededError).
                failed.provider_summary = "VirusTotal quota reached (HTTP 429; public API allows 4/min, 500/day)"
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict) or not isinstance(data.get("data"), dict):
            return malformed(self.name, ioc_value, ioc_type, http_status=resp.status_code)
        attrs = data["data"].get("attributes") or {}
        if not isinstance(attrs, dict):
            attrs = {}
        stats = attrs.get("last_analysis_stats") or {}
        if not isinstance(stats, dict):
            stats = {}

        def _count(key: str) -> int:
            value = stats.get(key, 0)
            return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0

        malicious = _count("malicious")
        suspicious = _count("suspicious")
        harmless = _count("harmless")
        undetected = _count("undetected")
        total = malicious + suspicious + harmless + undetected

        ratio = malicious / total if total > 0 else 0.0
        if total == 0:
            # The object exists but has never been scanned by any engine.
            verdict = "unrated"
        elif ratio >= 0.1:
            verdict = "malicious"
        elif malicious > 0 or suspicious > 0:
            verdict = "suspicious"
        elif harmless > 0:
            verdict = "clean"
        else:
            # Every engine answered "undetected": no detection, but no engine
            # asserted the object is harmless either.
            verdict = "undetected"

        score = ratio
        confidence = "high" if malicious >= 5 else "medium" if malicious > 0 else "low"
        raw_data = {
            "detection_ratio": f"{malicious}/{total}",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        }

        threat_classification = attrs.get("popular_threat_classification")
        if not isinstance(threat_classification, dict):
            threat_classification = {}
        threat_label = threat_classification.get("suggested_threat_label", "")
        family = ""
        if threat_label:
            parts = threat_label.split(".")
            family = parts[-1] if len(parts) > 1 else threat_label

        tags = [str(tag) for tag in (attrs.get("tags") or []) if isinstance(tag, str) and tag.strip()][:_MAX_TAGS]
        categories_data = attrs.get("categories")
        if not isinstance(categories_data, dict):
            categories_data = {}
        categories = list(dict.fromkeys(str(value) for value in categories_data.values() if value))

        mitre = []
        sandbox_verdicts = attrs.get("sandbox_verdicts")
        if not isinstance(sandbox_verdicts, dict):
            sandbox_verdicts = {}
        for v in sandbox_verdicts.values():
            if isinstance(v, dict):
                for m in v.get("mitre_attack_ids", []):
                    if m not in mitre:
                        mitre.append(m)

        last_analysis = attrs.get("last_analysis_results", {}) or {}
        samples = []
        for eng, res in last_analysis.items():
            if isinstance(res, dict) and res.get("result"):
                samples.append(f"{eng}: {res['result']}")
        samples = samples[:20]

        related = []
        if ioc_type in ("ipv4", "domain", "url"):
            resolutions = attrs.get("resolutions", []) or []
            for res in resolutions[:10]:
                if isinstance(res, dict) and res.get("host_name"):
                    related.append((res["host_name"], "resolves_to"))

        file_details = {}
        if attrs.get("type_description"):
            file_details["type_description"] = attrs.get("type_description")
        names = attrs.get("names") if isinstance(attrs.get("names"), list) else []
        if names:
            file_details["names"] = [str(name)[:200] for name in names[:5]]
        for key in ("meaningful_name", "size", "type_tag"):
            if attrs.get(key) not in (None, ""):
                file_details[key] = attrs.get(key)
        sig_info = attrs.get("signature_info")
        if isinstance(sig_info, dict) and sig_info:
            file_details["signature_info"] = {
                k: str(v)[:200] for k, v in sig_info.items()
                if k in {"product", "description", "copyright", "signers", "verified", "original name"} and v
            }
        if file_details:
            raw_data["file"] = file_details
        for key in ("as_owner", "asn", "country", "network", "registrar", "reputation"):
            if attrs.get(key) not in (None, ""):
                raw_data[key] = attrs.get(key)
        if threat_label:
            raw_data["suggested_threat_label"] = threat_label

        first_sub = attrs.get("first_submission_date")
        first_seen = None
        if first_sub:
            try:
                ts = int(first_sub)
                if ts > 1e10:
                    ts = ts / 1000
                first_seen = datetime.fromtimestamp(ts, tz=timezone.utc)
            except (TypeError, ValueError, OSError, OverflowError):
                first_seen = None

        last_sub = attrs.get("last_submission_date")
        last_seen = None
        if last_sub:
            try:
                ts = int(last_sub)
                if ts > 1e10:
                    ts = ts / 1000
                last_seen = datetime.fromtimestamp(ts, tz=timezone.utc)
            except (TypeError, ValueError, OSError, OverflowError):
                last_seen = None

        total_votes = attrs.get("total_votes")
        if isinstance(total_votes, dict) and total_votes:
            # Community votes are opinion, not engine detections; keep them
            # as structured context rather than as tags.
            raw_data["community_votes"] = {
                "malicious": total_votes.get("malicious", 0),
                "harmless": total_votes.get("harmless", 0),
            }

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            confidence=confidence,
            raw_score=round(score, 4),
            tags=tags,
            categories=categories,
            malware_family=family or None,
            mitre_attck=mitre,
            related_iocs=related,
            source_link=f"https://www.virustotal.com/gui/{self._url_type(ioc_type)}/{ioc_value}",
            reports_count=None,
            detection_count=malicious,
            total_engines=total,
            first_seen=first_seen,
            last_seen=last_seen,
            samples=samples,
            raw_data=raw_data,
            http_status=resp.status_code,
        )

    def _endpoint(self, value: str, ioc_type: str) -> str:
        base = "https://www.virustotal.com/api/v3"
        mapping = {
            "md5": f"{base}/files/{value}",
            "sha1": f"{base}/files/{value}",
            "sha256": f"{base}/files/{value}",
            "ipv4": f"{base}/ip_addresses/{value}",
            "ipv6": f"{base}/ip_addresses/{value}",
            "domain": f"{base}/domains/{value}",
            # VirusTotal URL objects use URL-safe base64 of the URL itself,
            # without padding, rather than a hash of the URL.
            "url": f"{base}/urls/{base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')}",
        }
        return mapping.get(ioc_type, "")

    def _url_type(self, ioc_type: str) -> str:
        return {
            "md5": "file",
            "sha1": "file",
            "sha256": "file",
            "ipv4": "ip-address",
            "ipv6": "ip-address",
        }.get(ioc_type, ioc_type)
