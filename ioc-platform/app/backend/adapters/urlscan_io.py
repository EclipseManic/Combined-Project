import asyncio
import json
import time
from datetime import datetime

from app.backend.adapters._http import MalformedResponse, describe_exception, http_failure, malformed, read_json
from app.backend.adapters._matching import host_of, indicator_equals
from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, is_valid_api_key
from app.backend.config import settings
from app.backend.logger import get_logger

logger = get_logger("adapter.urlscan_io")

_MAX_RELATED = 20


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _overall_verdict(entry: dict) -> dict:
    for container in (entry.get("verdicts"), (entry.get("result") if isinstance(entry.get("result"), dict) else {}).get("verdicts")):
        if isinstance(container, dict) and isinstance(container.get("overall"), dict):
            return container["overall"]
    return {}


def _scan_is_about(entry: dict, ioc_value: str, ioc_type: str) -> bool:
    """True when the scan was *of* the queried indicator.

    urlscan.io search matches the final page, so a scan of an unrelated
    (possibly malicious) URL that redirected to the queried page is returned
    too.  Only the submitted target may carry a verdict for the IOC.
    """
    task = entry.get("task") if isinstance(entry.get("task"), dict) else {}
    page = entry.get("page") if isinstance(entry.get("page"), dict) else {}
    task_url = str(task.get("url") or "")
    if ioc_type == "url":
        if task_url:
            return indicator_equals(task_url, ioc_value, "url")
        return indicator_equals(str(page.get("url") or ""), ioc_value, "url")
    if ioc_type == "domain":
        task_host = str(task.get("domain") or "") or host_of(task_url)
        page_host = str(page.get("domain") or "")
        if task_host and not indicator_equals(task_host, ioc_value, "domain"):
            return False
        return indicator_equals(page_host or task_host, ioc_value, "domain")
    return False


class UrlScanIOAdapter(SourceAdapter):
    name = "urlscan.io"
    supported_types = ["domain", "url"]
    public_without_key = True
    produces_reputation = True
    produces_infrastructure_context = True
    produces_relationships = True
    # Free API: search 120/min and 1,000/hour; public scans 60/min, 500/hour.
    rate_limit = RateLimitConfig(requests_per_minute=30, requests_per_day=1000, max_retries=1, timeout_seconds=10.0)
    SCAN_POLL_ATTEMPTS = 7
    SCAN_POLL_DELAY = 2.0

    def __init__(self):
        self.api_key = settings.urlscanio_api_key

    async def _submit_scan(self, ioc_value: str) -> str | None:
        client = self._get_client()
        try:
            resp = await client.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": self.api_key, "Content-Type": "application/json"},
                json={"url": ioc_value, "public": "on"},
                timeout=15,
            )
            if resp.status_code in (200, 201):
                return resp.json().get("uuid")
            logger.info("urlscan.io scan submission for %s returned HTTP %s", ioc_value, resp.status_code)
        except Exception as exc:
            logger.warning("urlscan.io scan submission failed for %s: %s", ioc_value, describe_exception(exc))
        return None

    async def _poll_scan(self, scan_uuid: str, timeout: float = 15.0) -> dict | None:
        client = self._get_client()
        deadline = time.time() + timeout
        for _ in range(self.SCAN_POLL_ATTEMPTS):
            if time.time() > deadline:
                break
            try:
                resp = await client.get(
                    f"https://urlscan.io/api/v1/result/{scan_uuid}/",
                    timeout=10,
                )
                if resp.status_code == 200:
                    return resp.json()
            except Exception as exc:
                logger.debug("urlscan.io scan poll attempt failed: %s", describe_exception(exc))
            if time.time() < deadline:
                await asyncio.sleep(self.SCAN_POLL_DELAY)
        return None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        client = self._get_client()
        key_sent = is_valid_api_key(self.api_key)
        headers = {"API-Key": self.api_key} if key_sent else {}
        query_value = json.dumps(ioc_value, ensure_ascii=False)
        resp = await client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"page.{ioc_type}:{query_value}", "size": 10},
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

        results = data.get("results", [])
        if not isinstance(results, list):
            results = []
        results = [entry for entry in results if isinstance(entry, dict)]
        exact = [entry for entry in results if _scan_is_about(entry, ioc_value, ioc_type)]
        other = [entry for entry in results if entry not in exact]

        malicious_scans = 0
        max_score = 0
        brands: list[str] = []
        tags: set[str] = set()
        categories: set[str] = set()
        first = last = None
        for entry in exact:
            overall = _overall_verdict(entry)
            if overall.get("malicious"):
                malicious_scans += 1
            score = overall.get("score")
            if isinstance(score, (int, float)) and score > max_score:
                max_score = score
            for brand in overall.get("brands", []) or []:
                name = brand.get("name") if isinstance(brand, dict) else brand
                if isinstance(name, str) and name and name not in brands:
                    brands.append(name)
            for tag in overall.get("tags", []) or []:
                if isinstance(tag, str) and tag:
                    tags.add(tag)
            for category in overall.get("categories", []) or entry.get("categories", []) or []:
                if isinstance(category, str) and category:
                    categories.add(category)
            task = entry.get("task") if isinstance(entry.get("task"), dict) else {}
            submitted = _parse_dt(task.get("time"))
            if submitted:
                first = submitted if first is None or submitted < first else first
                last = submitted if last is None or submitted > last else last

        # Page/infrastructure context from the most recent exact scan (or,
        # failing that, the most recent returned scan).
        reference = (exact or results or [{}])[0]
        page = reference.get("page") if isinstance(reference.get("page"), dict) else {}
        task = reference.get("task") if isinstance(reference.get("task"), dict) else {}
        result_scan_uuid = str(task.get("uuid") or reference.get("_id") or "")
        screenshot_url = reference.get("screenshot", "") or ""
        report_url = task.get("reportURL") or (f"https://urlscan.io/result/{result_scan_uuid}/" if result_scan_uuid else "")

        related: list[tuple[str, str]] = []
        for entry in results:
            entry_page = entry.get("page") if isinstance(entry.get("page"), dict) else {}
            ip = entry_page.get("ip")
            if ip and (str(ip), "hosted_on") not in related:
                related.append((str(ip), "hosted_on"))
        for entry in other:
            entry_task = entry.get("task") if isinstance(entry.get("task"), dict) else {}
            if entry_task.get("url"):
                related.append((str(entry_task["url"]), "scan_redirected_to_target"))
        related = related[:_MAX_RELATED]

        scans_summary = []
        for entry in results[:10]:
            entry_task = entry.get("task") if isinstance(entry.get("task"), dict) else {}
            entry_page = entry.get("page") if isinstance(entry.get("page"), dict) else {}
            overall = _overall_verdict(entry)
            scans_summary.append({
                "uuid": entry_task.get("uuid") or entry.get("_id"),
                "time": entry_task.get("time"),
                "task_url": str(entry_task.get("url") or "")[:300],
                "page_url": str(entry_page.get("url") or "")[:300],
                "page_domain": entry_page.get("domain"),
                "page_ip": entry_page.get("ip"),
                "exact_target": entry in exact,
                "malicious": overall.get("malicious"),
                "score": overall.get("score"),
            })

        scan_uuid = None
        scan_completed = False
        active_malicious = False
        if not results and key_sent and settings.enable_public_url_submission:
            scan_uuid = await self._submit_scan(ioc_value)
        if scan_uuid:
            tags.add("active_scan_submitted")
            active = await self._poll_scan(scan_uuid)
            if active:
                scan_completed = True
                tags.add("active_scan_completed")
                verdicts = active.get("verdicts", {})
                overall = verdicts.get("overall", {}) if isinstance(verdicts, dict) else {}
                if isinstance(overall, dict) and overall.get("malicious"):
                    active_malicious = True
                    score = overall.get("score")
                    if isinstance(score, (int, float)):
                        max_score = max(max_score, score)
                active_page = active.get("page") if isinstance(active.get("page"), dict) else {}
                if active_page:
                    page = active_page
                if not screenshot_url:
                    screenshot_url = active.get("screenshot") or ""
                report_url = f"https://urlscan.io/result/{scan_uuid}/"
                result_scan_uuid = result_scan_uuid or scan_uuid

        raw_data = {
            "total_results": data.get("total"),
            "returned_scans": len(results),
            "exact_scans": len(exact),
            "malicious_exact_scans": malicious_scans,
            "scans": scans_summary,
            "page": {
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "asn": page.get("asn"),
                "asnname": page.get("asnname"),
                "country": page.get("country"),
                "server": page.get("server"),
            },
            "web_preview": {
                "screenshot_url": screenshot_url,
                "page_title": page.get("title", "") or "",
                "server": page.get("server", "") or "",
                "language": page.get("language", "") or "",
                "domain_age_days": page.get("domainAgeDays") if isinstance(page.get("domainAgeDays"), int) else None,
                "tls_issuer": page.get("tlsIssuer", "") or "",
                "tls_valid_days": page.get("tlsValidDays") if isinstance(page.get("tlsValidDays"), int) else None,
                "asn_name": page.get("asnname", "") or "",
                "detected_brands": brands,
                "detected_technologies": [],
                "mime_type": page.get("mimeType", "") or "",
                "scan_uuid": result_scan_uuid,
            },
        }

        if not exact and not scan_completed:
            summary = "No scan of this exact indicator"
            if results:
                summary += f"; {len(results)} scan(s) of other targets that reached it kept as context"
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", provider_verdict="not_found",
                execution_state="not_found", status="not_found",
                related_iocs=related, provider_summary=summary,
                source_link=report_url or None, raw_data=raw_data,
            )

        if malicious_scans or active_malicious:
            verdict = "malicious"
            confidence = "high" if malicious_scans >= 3 else "medium"
        else:
            # urlscan.io only flags scans it classifies as malicious; an
            # unflagged scan is "no detection", not an assertion of safety.
            verdict = "undetected"
            confidence = "low"
        scanned = len(exact) + (1 if scan_completed else 0)
        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            confidence=confidence,
            raw_score=round(min(max_score / 100.0, 1.0), 4) if max_score else (1.0 if verdict == "malicious" else 0.0),
            tags=sorted(tags)[:10],
            categories=sorted(categories),
            first_seen=first,
            last_seen=last,
            related_iocs=related,
            source_link=report_url or None,
            reports_count=scanned,
            provider_summary=(
                f"{malicious_scans + (1 if active_malicious else 0)} of {scanned} scan(s) of this indicator flagged malicious"
            ),
            raw_data=raw_data,
        )
