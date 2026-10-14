from app.backend.adapters._http import MalformedResponse, http_failure, malformed, read_json
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key, retry_after_seconds
from app.backend.config import settings


def _severity_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"

def _as_vulnerability(result):
    """Failures for CVE lookups stay in the vulnerability domain, where a
    verdict is never used (the execution state carries the failure)."""
    result.assessment_domain = "vulnerability"
    result.verdict = "unknown"
    return result


class NvdAdapter(SourceAdapter):
    """NVD CVE record lookup against the official NIST NVD JSON 2.0 API.

    ``GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}`` is
    publicly readable (no key) at 5 requests/30s; with ``NVD_API_KEY`` (sent as
    the ``apiKey`` header) the limit is 50 requests/30s. Records carry typed
    vulnerability data (CVSS, CWE, references) and never a reputation verdict.
    NVD complements cve.org as a second key-free CVE source.
    """

    name = "NVD"
    supported_types = ["cve"]
    public_without_key = True
    produces_reputation = False
    produces_vulnerability_intelligence = True
    produces_metadata = True
    produces_relationships = True
    provenance_family = "cve_records"
    # Without a key: 5 requests per rolling 30 s (= 10/min).
    rate_limit = RateLimitConfig(requests_per_minute=10)
    # With a key: 50 requests per rolling 30 s.
    KEYED_REQUESTS_PER_MINUTE = 100

    def __init__(self):
        self.api_key = settings.nvd_api_key
        if is_valid_api_key(self.api_key):
            self.rate_limit = self.rate_limit.model_copy(
                update={"requests_per_minute": self.KEYED_REQUESTS_PER_MINUTE}
            )

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        cve_id = ioc_value.strip().upper()
        client = self._get_client()
        key_sent = is_valid_api_key(self.api_key)
        resp = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers={"apiKey": self.api_key} if key_sent else None,
            timeout=15,
        )

        if resp.status_code in (429, 503):
            return NormalizedResult(
                ioc=cve_id, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="rate_limited", assessment_domain="vulnerability", tags=["rate_limited"], http_status=resp.status_code,
                retry_after_seconds=retry_after_seconds(resp),
            )
        failed = http_failure(self.name, cve_id, ioc_type, resp, key_sent=key_sent)
        if failed is not None:
            _as_vulnerability(failed)
            return failed

        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            failed = malformed(self.name, cve_id, ioc_type, exc.reason, resp.status_code)
            _as_vulnerability(failed)
            return failed
        if not isinstance(data, dict):
            failed = malformed(self.name, cve_id, ioc_type, http_status=resp.status_code)
            _as_vulnerability(failed)
            return failed
        vulnerabilities = data.get("vulnerabilities") or []
        if not vulnerabilities:
            return NormalizedResult(
                ioc=cve_id, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="record_not_found", assessment_domain="vulnerability", raw_score=0.0, status="not_found",
            )

        record = vulnerabilities[0].get("cve") or {}
        vuln_status = str(record.get("vulnStatus") or "")
        descriptions = record.get("descriptions") or []
        description = next(
            (d.get("value", "") for d in descriptions if (d.get("lang") or "").lower().startswith("en") and d.get("value")),
            next((d.get("value", "") for d in descriptions if d.get("value")), ""),
        )

        metrics = record.get("metrics") or {}
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries and isinstance(entries[0], dict) and isinstance(entries[0].get("cvssData"), dict):
                cvss = entries[0]["cvssData"]
                break

        base_score = None
        severity = ""
        if isinstance(cvss, dict):
            try:
                base_score = float(cvss.get("baseScore"))
            except (TypeError, ValueError):
                base_score = None
            severity = str(cvss.get("baseSeverity") or "")

        cwe_values = []
        for weakness in (record.get("weaknesses") or []):
            for desc in (weakness.get("description") or []):
                value = desc.get("value", "")
                if value:
                    cwe_values.append(value)
        cwes = list(dict.fromkeys(w.split(":")[-1].strip() if ":" in w else w for w in cwe_values if w))

        references = [
            ref.get("url", "") for ref in (record.get("references") or []) if ref.get("url")
        ]

        # Tags are labels only; CVSS, CWE and reference values are typed
        # fields on the result and in raw_data.
        tags = []
        if description:
            tags.append("record_found")
        if vuln_status.upper() == "REJECTED":
            tags.append("rejected")

        verdict = "unknown"
        raw_score = None
        confidence = "high" if base_score is not None else "low"

        return NormalizedResult(
            ioc=cve_id,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            assessment_domain="vulnerability",
            provider_verdict="record_found",
            normalized_verdict="unknown",
            raw_score=raw_score,
            confidence=confidence,
            tags=tags,
            categories=cwes,
            related_iocs=[(ref, "reference") for ref in references[:10]],
            first_seen=record.get("published"),
            last_seen=record.get("lastModified"),
            source_link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            reports_count=None,
            vulnerability_status=vuln_status.lower() or None,
            severity=(severity or (_severity_label(base_score) if base_score is not None else "informational")).lower(),
            cvss_score=base_score,
            cvss_vector=(cvss or {}).get("vectorString") or (cvss or {}).get("vector") if isinstance(cvss, dict) else None,
            cwe=cwes,
            affected_products=[],
            published_at=record.get("published"),
            modified_at=record.get("lastModified"),
            exploit_status="unknown",
            references=references,
            source_record_id=cve_id,
            source_independence_group="cve_record",
            raw_data={
                "cve_id": cve_id,
                "description": description[:500],
                "cvss": cvss,
                "cvss_score": base_score,
                "severity": (severity or (_severity_label(base_score) if base_score is not None else "")).lower() or None,
                "cwes": cwe_values,
                "reference_count": len(references),
                "cve_tags": record.get("cveTags") or [],
                "references": references[:20],
                "published": record.get("published"),
                "lastModified": record.get("lastModified"),
            },
        )
