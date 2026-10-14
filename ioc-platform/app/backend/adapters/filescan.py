from app.backend.adapters._http import MalformedResponse, http_failure, malformed, not_configured, read_json
from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
)
from app.backend.config import settings


class FileScanAdapter(SourceAdapter):
    """FileScan.io malware sandbox report search by file hash."""

    name = "FileScan.io"
    supported_types = ["md5", "sha1", "sha256"]
    rate_limit = RateLimitConfig(requests_per_minute=20, requests_per_day=1000)
    produces_reputation = True
    produces_metadata = True

    def __init__(self):
        self.api_key = settings.filescan_api_key

    @staticmethod
    def _records(data):
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if not isinstance(data, dict):
            return []
        for key in ("reports", "results", "data", "items"):
            items = data.get(key)
            if isinstance(items, dict):
                items = [items]
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return [data] if any(key in data for key in ("verdict", "classification", "sha256", "hash")) else []

    @staticmethod
    def _record_hashes(record: dict) -> set[str]:
        """Every hash the report itself declares (top level and ``file``)."""
        hashes: set[str] = set()
        containers = [record]
        for key in ("file", "target", "sample"):
            if isinstance(record.get(key), dict):
                containers.append(record[key])
        for container in containers:
            for key in ("md5", "sha1", "sha256", "hash"):
                value = container.get(key)
                if isinstance(value, str) and value.strip():
                    hashes.add(value.strip().lower())
        return hashes

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return not_configured(self.name, ioc_value, ioc_type)
        response = await self._get_client().get(
            "https://www.filescan.io/api/reports/search",
            params={"query": ioc_value},
            headers={"X-Api-Key": self.api_key, "accept": "application/json"},
            timeout=15,
        )
        failed = http_failure(self.name, ioc_value, ioc_type, response, not_found_summary="No FileScan report for this hash")
        if failed is not None:
            return failed
        try:
            data = read_json(response)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, response.status_code)
        raw_data = data if isinstance(data, dict) else {"response": data}
        records = self._records(data)
        # A search hit may be a different sample that merely mentions the
        # query; only a report that declares this hash may carry a verdict.
        # Reports that declare no hash are trusted (searched by hash).
        target = ioc_value.strip().lower()
        records = [
            record for record in records
            if not self._record_hashes(record) or target in self._record_hashes(record)
        ]
        if not records:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", status="not_found", tags=["not_found"], raw_data=raw_data,
                source_link=f"https://www.filescan.io/scan?sha256={ioc_value}",
            )
        record = records[0]
        native = str(record.get("verdict") or record.get("classification") or record.get("status") or "unknown").lower()
        if native in {"malicious", "malware", "bad"} or record.get("malicious") is True:
            verdict, score, confidence = "malicious", 0.85, "high"
        elif native in {"suspicious", "harmful", "risky"}:
            verdict, score, confidence = "suspicious", 0.5, "medium"
        elif native in {"clean", "benign", "harmless"}:
            verdict, score, confidence = "clean", 0.0, "medium"
        else:
            verdict, score, confidence = "unknown", None, "low"
        tags = []
        for key in ("tags", "labels", "families"):
            values = record.get(key, [])
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                for item in values:
                    if not item:
                        continue
                    if isinstance(item, dict):
                        tag_obj = item.get("tag") if isinstance(item.get("tag"), dict) else item
                        name = tag_obj.get("name") or item.get("name")
                        if name:
                            tags.append(str(name).strip())
                    else:
                        tags.append(str(item).strip())
        family = record.get("malware_family") or record.get("family") or record.get("threat_name")
        behavior = record.get("behavior") or record.get("behaviour") or record.get("sandbox_summary")
        if behavior:
            tags.append("sandbox_behavior_available")
        clean_tags = list(dict.fromkeys(tags))
        provider_summary = f"FileScan verdict: {verdict.title()}" if verdict != "unknown" else "No conclusive threat detected"
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=score, confidence=confidence,
            tags=clean_tags, malware_family=str(family) if family else None,
            categories=[str(item) for item in record.get("categories", [])] if isinstance(record.get("categories"), list) else [],
            raw_data={**raw_data, "match_type": "exact"} if isinstance(raw_data, dict) else {"match_type": "exact"},
            source_link=f"https://www.filescan.io/scan?sha256={ioc_value}",
            provider_summary=provider_summary,
        )
