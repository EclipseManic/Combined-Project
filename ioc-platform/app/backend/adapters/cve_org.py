from app.backend.adapters._http import MalformedResponse, http_failure, malformed, read_json
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter

def _as_vulnerability(result):
    """Failures for CVE lookups stay in the vulnerability domain, where a
    verdict is never used (the execution state carries the failure)."""
    result.assessment_domain = "vulnerability"
    result.verdict = "unknown"
    return result


class CveOrgAdapter(SourceAdapter):
    """Canonical CVE record lookup against cve.org's public CVE Services API.

    ``GET https://cveawg.mitre.org/api/cve/{id}`` is publicly readable (no
    key). Verdicts are derived conservatively from CVSS severity; the record
    existence plus full raw JSON is surfaced as evidence. CISA KEV / EPSS
    signals remain the domain of the dedicated CVE Intelligence stage.
    """

    name = "cve.org"
    supported_types = ["cve"]
    public_without_key = True
    produces_reputation = False
    produces_vulnerability_intelligence = True
    produces_metadata = True
    produces_relationships = True
    provenance_family = "cve_records"
    rate_limit = RateLimitConfig(requests_per_minute=30)

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        cve_id = ioc_value.strip().upper()
        client = self._get_client()
        resp = await client.get(
            f"https://cveawg.mitre.org/api/cve/{cve_id}",
            headers={"accept": "application/json"},
            timeout=10,
        )

        failed = http_failure(self.name, cve_id, ioc_type, resp, key_sent=False, not_found_summary="cve.org has no record of this CVE")
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
        meta = data.get("cveMetadata") or {}
        cna = (data.get("containers") or {}).get("cna") or {}

        state = str(meta.get("state") or "").upper()
        assigner = meta.get("assignerShortName") or meta.get("assignerOrgName") or ""

        descriptions = cna.get("descriptions") or []
        description = next(
            (d.get("value", "") for d in descriptions if (d.get("lang") or "").lower().startswith("en") and d.get("value")),
            next((d.get("value", "") for d in descriptions if d.get("value")), ""),
        )

        metrics = cna.get("metrics") or []
        cvss = None
        for metric in metrics:
            for key in ("cvssV3_1", "cvssV3_0", "cvssV2"):
                if isinstance(metric, dict) and isinstance(metric.get(key), dict):
                    cvss = metric[key]
                    break
            if cvss is not None:
                break

        base_score = None
        severity = ""
        if isinstance(cvss, dict):
            try:
                base_score = float(cvss.get("baseScore"))
            except (TypeError, ValueError):
                base_score = None
            severity = str(cvss.get("baseSeverity") or "")

        problem_types = cna.get("problemTypes") or []
        cwe_values = []
        for pt in problem_types:
            for desc in (pt.get("descriptions") or []):
                value = desc.get("value", "")
                if value:
                    cwe_values.append(value)
        cwes = list(dict.fromkeys(w.split(":")[-1].strip() if ":" in w else w for w in cwe_values if w))

        references = [
            ref.get("url", "") for ref in (cna.get("references") or []) if ref.get("url")
        ]

        affected = []
        for aff in (cna.get("affected") or []):
            product = aff.get("product", "")
            vendor = aff.get("vendor", "")
            label = f"{vendor} {product}".strip() if vendor else product
            if label:
                affected.append(label)

        # Labels only: CVSS, CWE, assigner and reference values are typed
        # fields on the result and in raw_data.
        tags = []
        if description:
            tags.append("record_found")
        if state == "REJECTED":
            tags.append("rejected")

        # CVSS and CVE lifecycle state are vulnerability semantics.  They must
        # not be emitted as malicious/suspicious reputation verdicts.
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
            first_seen=None,
            last_seen=None,
            source_link=f"https://cveawg.mitre.org/api/cve/{cve_id}",
            reports_count=None,
            vulnerability_status=state.lower() or None,
            severity=(severity or (_severity_label(base_score) if base_score is not None else "informational")).lower(),
            cvss_score=base_score,
            cvss_vector=(cvss or {}).get("vectorString") if isinstance(cvss, dict) else None,
            published_at=meta.get("datePublished"),
            modified_at=meta.get("dateUpdated"),
            cwe=cwes,
            affected_products=affected,
            exploit_status="unknown",
            references=references,
            source_record_id=cve_id,
            source_independence_group="cve_record",
            raw_data={
                "cve_id": cve_id,
                "state": state,
                "description": description[:500],
                "assigner": assigner,
                "cvss": cvss,
                "cvss_score": base_score,
                "severity": (severity or (_severity_label(base_score) if base_score is not None else "")).lower() or None,
                "cwes": cwe_values,
                "references": references[:20],
                "reference_count": len(references),
                "affected": affected[:50],
            },
        )


def _severity_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"
