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

logger = get_logger("triage")


class TriageAdapter(SourceAdapter):
    name = "Tria.ge"
    supported_types = ["md5", "sha1", "sha256", "mutex", "named_pipe", "registry_key", "service_name", "ssdeep"]
    rate_limit = RateLimitConfig(requests_per_minute=10)

    def __init__(self):
        self.api_key = settings.triage_api_key

    async def _search_by_term(self, client, ioc_value: str, ioc_type: str):
        """Search Tria.ge by host-artifact term (v0 search API).

        Returns a sample id, ``None`` when nothing references the term, or a
        ready-made failure ``NormalizedResult``.
        """
        resp = await client.get(
            "https://api.tria.ge/v0/search",
            params={"query": ioc_value},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=15,
        )
        failed = http_failure(self.name, ioc_value, ioc_type, resp, not_found_summary="No sandbox sample references this artifact")
        if failed is not None:
            if failed.execution_state == "not_found":
                return None
            return failed
        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        items = data.get("data", []) if isinstance(data, dict) else data
        if not isinstance(items, list) or not items or not isinstance(items[0], dict):
            return None
        first = items[0]
        sample = first.get("sample") if isinstance(first.get("sample"), dict) else {}
        return first.get("id") or sample.get("id") or None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return not_configured(self.name, ioc_value, ioc_type)
        try:
            return await self._lookup(ioc_value, ioc_type)
        except httpx.HTTPError as exc:
            logger.warning("Tria.ge request failed for %s: %s", ioc_value, describe_exception(exc))
            return exception_result(self.name, ioc_value, ioc_type, exc)

    async def _lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        client = self._get_client()
        sample_id = None
        if ioc_type in ("mutex", "named_pipe", "registry_key", "service_name", "ssdeep"):
            sample_id = await self._search_by_term(client, ioc_value, ioc_type)
            if isinstance(sample_id, NormalizedResult):
                return sample_id
            if not sample_id:
                return failure(
                    self.name, ioc_value, ioc_type, "not_found", ["term_not_found"],
                    "No sandbox sample references this artifact",
                )
            # Fetch that sample
            resp = await client.get(
                f"https://api.tria.ge/v2/sample/{sample_id}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=30,
            )
        else:
            resp = await client.get(
                f"https://api.tria.ge/v2/sample/{ioc_value}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=30,
            )

        failed = http_failure(self.name, ioc_value, ioc_type, resp, not_found_summary="No sandbox sample for this indicator")
        if failed is not None:
            return failed

        try:
            data = read_json(resp)
        except MalformedResponse as exc:
            return malformed(self.name, ioc_value, ioc_type, exc.reason, resp.status_code)
        if not isinstance(data, dict):
            return malformed(self.name, ioc_value, ioc_type, http_status=resp.status_code)
        status = data.get("status", "")

        raw_tags = data.get("tags", [])
        tags = list(raw_tags) if isinstance(raw_tags, list) else []
        signatures = data.get("signatures", [])
        if isinstance(signatures, list):
            tags.extend(f"sig:{s}" for s in signatures if isinstance(s, str))

        mitre = data.get("mitre_attck", [])
        if isinstance(mitre, list):
            mitre = [str(m) for m in mitre]
        else:
            mitre = []

        if status == "complete":
            try:
                overview_id = sample_id if sample_id else ioc_value
                overview_resp = await client.get(
                    f"https://api.tria.ge/v2/sample/{overview_id}/overview.json",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=15,
                )
                if overview_resp.status_code == 200:
                    overview = overview_resp.json()
                    if isinstance(overview, dict):
                        for sig in overview.get("signatures", []):
                            if isinstance(sig, str) and sig not in tags:
                                tags.append(f"sig:{sig}")
                        for mitre_id in overview.get("mitre_attck", []):
                            if isinstance(mitre_id, str) and mitre_id not in mitre:
                                mitre.append(mitre_id)
            except Exception as exc:
                logger.debug("Triage overview enrichment failed: %s", describe_exception(exc))

        if status != "complete":
            # The sample exists but has no finished analysis, so there is no
            # verdict yet (not the same as "no sample").
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", raw_score=None, tags=[f"status_{status}"],
                status="not_found", provider_summary=f"Sandbox analysis not finished (status: {status or 'unknown'})",
            )

        sample_verdict = data.get("verdict", "unknown")
        score = data.get("score", 0)

        if sample_verdict == "malicious":
            verdict = "malicious"
            confidence = "high"
            raw_score = min(score / 10.0 if score else 1.0, 1.0)
        elif sample_verdict == "suspicious":
            verdict = "suspicious"
            confidence = "medium"
            raw_score = 0.5
        elif sample_verdict == "clean":
            verdict = "clean"
            confidence = "medium"
            raw_score = 0.0
        else:
            verdict = "unknown"
            confidence = "low"
            raw_score = 0.0

        target = data.get("target", {}) or {}
        file_info = target.get("file", {}) or {}
        file_name = file_info.get("name", "")

        dropped = []
        extracted = data.get("extracted", {}) or {}
        for f in extracted.get("files", []):
            if isinstance(f, dict):
                dropped.append(f.get("name", f.get("path", str(f))))
            elif isinstance(f, str):
                dropped.append(f)

        registry_keys = []
        for rkey in extracted.get("registry", []):
            if isinstance(rkey, dict):
                registry_keys.append(rkey.get("path", rkey.get("key", str(rkey))))
            elif isinstance(rkey, str):
                registry_keys.append(rkey)

        network_iocs = []
        network = data.get("network", {}) or {}
        for dns_entry in network.get("dns", []):
            if isinstance(dns_entry, dict):
                dom = dns_entry.get("domain", "")
                ip = dns_entry.get("ip", "")
                if dom:
                    network_iocs.append((dom, "domain"))
                if ip:
                    network_iocs.append((ip, "ip"))
        for tcp_entry in network.get("tcp", []):
            if isinstance(tcp_entry, dict):
                tip = tcp_entry.get("ip", "")
                if tip and not any(n[0] == tip for n in network_iocs):
                    network_iocs.append((tip, "ip"))

        process_tree = data.get("process", "")

        tlsh = extracted.get("tlsh", "") or file_info.get("tlsh", "")
        ssdeep = file_info.get("ssdeep", "")

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            confidence=confidence,
            raw_score=raw_score,
            tags=tags,
            categories=[file_name, sample_verdict] if file_name else [sample_verdict],
            malware_family=next((s for s in signatures if isinstance(s, str)), None),
            mitre_attck=mitre,
            first_seen=self._parse_dt(data.get("submitted")),
            last_seen=self._parse_dt(data.get("completed")),
            source_link=f"https://tria.ge/s/{sample_id if sample_id else ioc_value}",
            reports_count=1,
            dropped_files=dropped,
            registry_keys=registry_keys,
            network_iocs=network_iocs,
            process_tree=process_tree or None,
            ssdeep=ssdeep or None,
            tlsh=tlsh or None,
            raw_data=data,
        )

    def _parse_dt(self, val: str) -> datetime | None:
        if not val:
            return None
        try:
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(val[:19], fmt)
                    return dt
                except ValueError:
                    continue
            return None
        except Exception:
            return None
