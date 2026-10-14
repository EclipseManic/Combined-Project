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

logger = get_logger("hybrid_analysis")

_ARTIFACT_TYPES = ("mutex", "named_pipe", "registry_key", "service_name", "ssdeep")
_HASH_FIELDS = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}


class HybridAnalysisAdapter(SourceAdapter):
    name = "Hybrid Analysis"
    supported_types = ["md5", "sha1", "sha256", "mutex", "named_pipe", "registry_key", "service_name", "ssdeep"]
    # Free (restricted) API keys: 200 requests/minute, 2,000/hour; keep well under.
    rate_limit = RateLimitConfig(requests_per_minute=100, requests_per_day=3000)

    def __init__(self):
        self.api_key = settings.hybridanalysis_api_key

    def _headers(self, json_body: bool = False) -> dict:
        headers = {
            "api-key": self.api_key,
            "user-agent": "IOC-Lookup-Platform/1.0",
            "Accept": "application/json",
        }
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return not_configured(self.name, ioc_value, ioc_type)

        client = self._get_client()
        try:
            if ioc_type in _ARTIFACT_TYPES:
                return await self._lookup_artifact(client, ioc_value, ioc_type)
            return await self._lookup_hash(client, ioc_value, ioc_type)
        except httpx.HTTPError as exc:
            logger.warning("Hybrid Analysis request failed for %s: %s", ioc_value, describe_exception(exc))
            return exception_result(self.name, ioc_value, ioc_type, exc)

    async def _lookup_artifact(self, client, ioc_value: str, ioc_type: str) -> NormalizedResult:
        """Host-artifact and ssdeep lookups use the documented search/terms endpoint."""
        resp = await client.post(
            "https://hybrid-analysis.com/api/v2/search/terms",
            json={"terms": [ioc_value]},
            headers=self._headers(json_body=True),
            timeout=15,
        )
        failed = http_failure(self.name, ioc_value, ioc_type, resp, not_found_summary="No sandbox report references this artifact")
        if failed is not None:
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        # Response is {"result": [...]} or a bare list.
        items = data.get("result", data) if isinstance(data, dict) else data
        if not isinstance(items, list) or not [i for i in items if isinstance(i, dict)]:
            return failure(
                self.name, ioc_value, ioc_type, "not_found", ["term_not_found"],
                "No sandbox report references this artifact", http_status=resp.status_code,
            )
        term_result = next(i for i in items if isinstance(i, dict))
        # The term search returns a summary; fetch the full sample for its verdict.
        sha = term_result.get("sha256", "")
        if sha:
            full = await client.get(
                "https://hybrid-analysis.com/api/v2/search/hash",
                params={"hash": sha},
                headers=self._headers(),
                timeout=15,
            )
            if full.status_code == 200:
                try:
                    reports = read_json(full)
                except MalformedResponse:
                    reports = None
                if isinstance(reports, list) and reports and isinstance(reports[0], dict):
                    return await self._parse_report(reports[0], ioc_value, ioc_type, client, match_type="artifact_search")
        return await self._parse_report(term_result, ioc_value, ioc_type, client, match_type="artifact_search")

    async def _lookup_hash(self, client, ioc_value: str, ioc_type: str) -> NormalizedResult:
        resp = await client.get(
            "https://hybrid-analysis.com/api/v2/search/hash",
            params={"hash": ioc_value},
            headers=self._headers(),
            timeout=30,
        )
        failed = http_failure(self.name, ioc_value, ioc_type, resp, not_found_summary="No sandbox report for this hash")
        if failed is not None:
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        reports = [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
        if not reports:
            return failure(
                self.name, ioc_value, ioc_type, "not_found", [],
                "No sandbox report for this hash", http_status=resp.status_code,
            )
        # Only a report whose own hash is the queried hash may carry a verdict.
        # Reports that expose no hash fields at all are trusted (the query was
        # by hash), matching how the endpoint is documented to behave.
        field = _HASH_FIELDS.get(ioc_type)
        target = ioc_value.strip().lower()
        matching = [
            report for report in reports
            if not report.get(field) or str(report.get(field)).strip().lower() == target
        ]
        if not matching:
            return failure(
                self.name, ioc_value, ioc_type, "not_found", ["hash_mismatch"],
                "Hybrid Analysis returned reports for a different sample; none match this hash",
                http_status=resp.status_code,
            )
        return await self._parse_report(matching[0], ioc_value, ioc_type, client, match_type="exact")

    async def _parse_report(self, report: dict, ioc_value: str, ioc_type: str, client, match_type: str = "exact") -> NormalizedResult:
        raw_score_value = report.get("threat_score")
        threat_score = raw_score_value if isinstance(raw_score_value, (int, float)) and not isinstance(raw_score_value, bool) else None
        ha_verdict = str(report.get("verdict") or "unknown").strip().lower()

        if ha_verdict == "malicious" or (threat_score is not None and threat_score >= 70):
            verdict = "malicious"
            confidence = "high"
            raw_score = min((threat_score if threat_score is not None else 100) / 100.0, 1.0)
        elif ha_verdict == "suspicious" or (threat_score is not None and threat_score >= 30):
            verdict = "suspicious"
            confidence = "medium"
            raw_score = (threat_score if threat_score is not None else 50) / 100.0
        elif ha_verdict in ("clean", "whitelisted"):
            verdict = "clean"
            confidence = "medium"
            raw_score = 0.0
        elif threat_score == 0 or ha_verdict in ("no specific threat", "no verdict"):
            # The sandbox found nothing, which is not an assertion of safety.
            verdict = "undetected"
            confidence = "low"
            raw_score = 0.0
        else:
            verdict = "unknown"
            confidence = "low"
            raw_score = None

        tags = [str(tag) for tag in (report.get("classification_tags") or []) if isinstance(tag, str) and tag.strip()][:10]

        vx_family = report.get("vx_family") or ""
        submit_name = report.get("submit_name") or ""
        # ``submit_name`` is the uploaded file's name, not a malware family.
        malware_family = vx_family or None

        mitre = []
        if verdict in ("malicious", "suspicious"):
            sha256 = report.get("sha256", "") or ioc_value
            try:
                mitre_resp = await client.get(
                    f"https://hybrid-analysis.com/api/v2/report/{sha256}/mitre",
                    headers=self._headers(),
                    timeout=15,
                )
                if mitre_resp.status_code == 200:
                    mitre_data = mitre_resp.json()
                    if isinstance(mitre_data, list):
                        for entry in mitre_data:
                            if isinstance(entry, dict):
                                aid = entry.get("id", entry.get("attack_id", ""))
                                if aid:
                                    mitre.append(aid)
            except Exception as exc:
                logger.debug("Hybrid Analysis MITRE extraction failed: %s", describe_exception(exc))
        if not mitre:
            mitre = report.get("mitre_attack_ids", []) or []

        dropped = []
        for ef in report.get("extracted_files", []) or []:
            if isinstance(ef, dict):
                dropped.append(ef.get("name", ef.get("file_path", str(ef))))

        registry_keys = report.get("registry_keys", [])
        if isinstance(registry_keys, list):
            registry_keys = [str(rk) for rk in registry_keys]
        else:
            registry_keys = []

        network_iocs = []
        for d in report.get("domains", []) or []:
            if isinstance(d, str):
                network_iocs.append((d, "domain"))
        for h in report.get("hosts", []) or []:
            if isinstance(h, str) and not any(n[0] == h for n in network_iocs):
                network_iocs.append((h, "ip"))

        process_tree = ""
        process_list = report.get("process_list", [])
        if process_list:
            parts = []
            for proc in process_list:
                if isinstance(proc, dict):
                    parts.append(proc.get("name", str(proc)))
                elif isinstance(proc, str):
                    parts.append(proc)
            process_tree = " -> ".join(parts)

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            confidence=confidence,
            raw_score=raw_score,
            tags=tags,
            categories=[c for c in (submit_name, report.get("environment_description", ""), ha_verdict) if c],
            malware_family=malware_family,
            mitre_attck=mitre,
            first_seen=self._parse_dt(report.get("analysis_start_time")),
            source_link=f"https://hybrid-analysis.com/sample/{report.get('sha256') or ioc_value}",
            reports_count=1,
            dropped_files=dropped,
            registry_keys=registry_keys,
            network_iocs=network_iocs,
            process_tree=process_tree or None,
            ssdeep=report.get("ssdeep") or None,
            tlsh=report.get("tlsh") or None,
            raw_data={**report, "match_type": match_type},
        )

    def _parse_dt(self, val: str) -> datetime | None:
        if not val:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
        return None
