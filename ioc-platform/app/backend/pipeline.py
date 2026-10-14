import asyncio
import ipaddress
import json
import random
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from app.backend.cache import TASK_TTL, CacheLayer, cache_key, cache_ttl
from app.backend.config import settings
from app.backend.http_client import get_client
from app.backend.rate_limiter import RateLimiter
from app.backend.adapters.cve_org import CveOrgAdapter
from app.backend.adapters.hashlookup import HashlookupAdapter
from app.backend.adapters.abstract_api import (
    AbstractAPIAdapter,
    AbstractAPIIPAdapter,
    AbstractAPIPhoneAdapter,
)
from app.backend.adapters.ipquality import (
    IPQualityEmailAdapter,
    IPQualityIPAdapter,
    IPQualityPhoneAdapter,
)
from app.backend.adapters.hunter_io import HunterIOAdapter
from app.backend.adapters.team_cymru import TeamCymruAdapter
from app.backend.adapters.nvd import NvdAdapter
from app.backend.adapters.abuse_ipdb import AbuseIPDBAdapter
from app.backend.adapters.alienvault_otx import AlienVaultOTXAdapter
from app.backend.adapters.base import (
    CompositeScore,
    EnrichmentData,
    InfostealerIntel,
    IOCAssessment,
    LookupResponse,
    NormalizedResult,
    ProviderHealth,
    WebPreviewInfo,
)
from app.backend.adapters.censys import CensysAdapter
from app.backend.adapters.grey_noise import GreyNoiseAdapter
from app.backend.adapters.hybrid_analysis import HybridAnalysisAdapter
from app.backend.adapters.ipinfo import IPinfoAdapter
from app.backend.adapters.malware_bazaar import MalwareBazaarAdapter
from app.backend.adapters.openphish import OpenPhishAdapter
from app.backend.adapters.stop_forum_spam import StopForumSpamAdapter
from app.backend.adapters.shodan import ShodanAdapter
from app.backend.adapters.threatfox import ThreatFoxAdapter
from app.backend.adapters.tor_exit import TorExitAdapter
from app.backend.adapters.triage import TriageAdapter
from app.backend.adapters.urlhaus import URLHausAdapter
from app.backend.adapters.urlscan_io import UrlScanIOAdapter
from app.backend.adapters.virus_total import VirusTotalAdapter
from app.backend.adapters.etherscan import EtherscanAdapter
from app.backend.adapters.chainabuse import ChainAbuseAdapter
from app.backend.adapters.filescan import FileScanAdapter
from app.backend.adapters.blockchain_info import BlockchainInfoAdapter
from app.backend.adapters.hudson_rock import HudsonRockAdapter
from app.backend.adapters.hibp import HIBPAdapter
from app.backend.classifier import SUPPORTED_IOC_TYPES, is_password_digest, normalize_ioc, password_digest
from app.backend.domain_router import route_assessment_domain
from app.backend.evidence import normalize_provider_result
from app.backend.provider_capabilities import build_provider_plan
from app.backend.enrichment import enrich, normalize_cve_enrichment
from app.backend.executive_summary import generate_executive_summary
from app.backend.logger import describe_exception, get_logger
from app.backend.scorer import aggregate_evidence, compute_composite

logger = get_logger("pipeline")

_ADAPTERS_CACHE: list | None = None


def _init_adapters():
    global _ADAPTERS_CACHE
    if _ADAPTERS_CACHE is not None:
        return _ADAPTERS_CACHE
    client = get_client()
    adapters = [
        MalwareBazaarAdapter(),
        ThreatFoxAdapter(),
        VirusTotalAdapter(),
        AbuseIPDBAdapter(),
        UrlScanIOAdapter(),
        TriageAdapter(),
        HybridAnalysisAdapter(),
        GreyNoiseAdapter(),
        AlienVaultOTXAdapter(),
        ShodanAdapter(),
        OpenPhishAdapter(),
        URLHausAdapter(),
        TorExitAdapter(),
        CensysAdapter(),
        IPinfoAdapter(),
        StopForumSpamAdapter(),
        AbstractAPIAdapter(),
        AbstractAPIIPAdapter(),
        AbstractAPIPhoneAdapter(),
        IPQualityPhoneAdapter(),
        IPQualityIPAdapter(),
        IPQualityEmailAdapter(),
        HunterIOAdapter(),
        TeamCymruAdapter(),
        CveOrgAdapter(),
        NvdAdapter(),
        HashlookupAdapter(),
        EtherscanAdapter(),
        ChainAbuseAdapter(),
        FileScanAdapter(),
        BlockchainInfoAdapter(),
        HudsonRockAdapter(),
        HIBPAdapter(),
    ]
    for a in adapters:
        a.set_client(client)
    _ADAPTERS_CACHE = adapters
    return adapters


ADAPTERS = _init_adapters()

PIPELINE_TIMEOUT = 60.0
ADAPTER_TIMEOUT = 20.0
# Time a provider call needs after waiting for a rate-limit slot.  A lookup
# only waits for a slot when at least this much of the IOC deadline (or the
# provider budget, if smaller) remains afterwards.
MIN_PROVIDER_CALL_WINDOW = 5.0


@dataclass
class StageInfo:
    name: str
    status: str = "pending"  # pending | running | done | error | skipped
    message: str = ""
    progress: float = 0.0


@dataclass
class AnalysisTask:
    task_id: str
    status: str = "pending"  # pending | classifying | querying | enriching | scoring | done | error
    progress: float = 0.0
    stages: list[StageInfo] = field(default_factory=list)
    ioc_value: str = ""
    ioc_type: str = ""
    password_prehashed: bool = False
    normalized: str = ""
    assessment_domain: str = "ioc_reputation"
    provider_plan: list[dict] = field(default_factory=list)
    results: list[NormalizedResult] = field(default_factory=list)
    composite: Optional[object] = None
    final_assessment: Optional[IOCAssessment] = None
    provider_health: list[ProviderHealth] = field(default_factory=list)
    enrichment: Optional[EnrichmentData] = None
    relationships: list[dict] = field(default_factory=list)
    executive_summary: str = ""
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self):
        def _dump(obj):
            if obj is None:
                return None
            if hasattr(obj, "model_dump"):
                return obj.model_dump(mode="json")
            return obj

        return {
            "task_id": self.task_id,
            "status": self.status,
            "progress": self.progress,
            "stages": [{"name": s.name, "status": s.status, "message": s.message, "progress": s.progress} for s in self.stages],
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "password_prehashed": self.password_prehashed,
            "normalized": self.normalized,
            "assessment_domain": self.assessment_domain,
            "provider_plan": self.provider_plan,
            "results": [_dump(r) for r in self.results],
            "composite": _dump(self.composite),
            "final_assessment": _dump(self.final_assessment),
            "provider_health": [_dump(h) for h in self.provider_health],
            "enrichment": _dump(self.enrichment),
            "relationships": self.relationships,
            "executive_summary": self.executive_summary,
            "error": self.error,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AnalysisTask":
        stages = [
            StageInfo(name=s["name"], status=s.get("status", "pending"), message=s.get("message", ""), progress=s.get("progress", 0.0))
            for s in data.get("stages", [])
        ]
        results = [NormalizedResult.model_validate(r) for r in data.get("results", [])]
        composite = CompositeScore.model_validate(data["composite"]) if data.get("composite") else None
        final_assessment = IOCAssessment.model_validate(data["final_assessment"]) if data.get("final_assessment") else None
        provider_health = [ProviderHealth.model_validate(h) for h in data.get("provider_health", [])]
        enrichment = EnrichmentData.model_validate(data["enrichment"]) if data.get("enrichment") else None
        return cls(
            task_id=data["task_id"],
            status=data.get("status", "pending"),
            progress=data.get("progress", 0.0),
            stages=stages,
            ioc_value=data.get("ioc_value", ""),
            ioc_type=data.get("ioc_type", ""),
            password_prehashed=data.get("password_prehashed", False),
            normalized=data.get("normalized", ""),
            assessment_domain=data.get("assessment_domain", "ioc_reputation"),
            provider_plan=data.get("provider_plan", []),
            results=results,
            composite=composite,
            final_assessment=final_assessment,
            provider_health=provider_health,
            enrichment=enrichment,
            relationships=data.get("relationships", []),
            executive_summary=data.get("executive_summary", ""),
            error=data.get("error"),
            created_at=data.get("created_at", time.time()),
        )


def task_response_payload(task: AnalysisTask) -> dict:
    return LookupResponse(
        input=task.ioc_value,
        task_id=task.task_id,
        normalized=task.normalized or task.ioc_value,
        ioc_type=task.ioc_type or "unknown",
        password_prehashed=task.password_prehashed or (
            task.ioc_type == "password" and bool(re.fullmatch(r"[a-f0-9]{40}", task.normalized or "", re.IGNORECASE))
        ),
        composite=task.composite or CompositeScore(),
        final_assessment=task.final_assessment,
        provider_health=task.provider_health,
        enrichment=task.enrichment or EnrichmentData(),
        results=task.results,
        relationships=task.relationships,
        executive_summary=task.executive_summary,
    ).model_dump(mode="json")


_tasks: dict[str, AnalysisTask] = {}
_task_queues: dict[str, asyncio.Queue] = {}
_running_tasks: dict[str, asyncio.Task] = {}
_dict_lock = threading.Lock()
# provider cache key -> [lock, users]; entries are dropped when unused so the
# map does not grow with every IOC ever looked up.
_cache_locks: dict[str, list] = {}


@asynccontextmanager
async def _cache_key_lock(key: str):
    entry = _cache_locks.get(key)
    if entry is None:
        entry = [asyncio.Lock(), 0]
        _cache_locks[key] = entry
    entry[1] += 1
    try:
        async with entry[0]:
            yield
    finally:
        entry[1] -= 1
        if entry[1] <= 0 and _cache_locks.get(key) is entry:
            _cache_locks.pop(key, None)

cache: CacheLayer | None = None
rate_limiter: RateLimiter | None = None


def set_cache(cache_instance: CacheLayer | None):
    global cache
    cache = cache_instance


def get_cache() -> CacheLayer | None:
    return cache


def set_rate_limiter(limiter: RateLimiter | None):
    global rate_limiter
    rate_limiter = limiter


def get_rate_limiter() -> RateLimiter | None:
    return rate_limiter


# Enrichment cache TTLs by ioc_type (seconds).  Enrichment hits public
# infrastructure / OSINT endpoints (blockchain.info, RIPEstat, attack.mitre.org,
# hashlookup.circl.lu, ...) that are NOT wrapped by the per-provider rate
# limiter or circuit breaker the way reputation adapters are.  blockchain.info
# in particular issues a 24-hour ban (HTTP 429, retry-after: 86400) after only a
# few keyless calls; because enrich() was previously always called live, that
# ban zeroed out BTC context on every later lookup.  Caching the structured
# result — and, on a live failure, serving the last good snapshot even when
# expired — keeps context data visible instead of blanking it.
_ENRICHMENT_TTL_BY_TYPE = {
    "btc": 3600,
    "eth": 3600,
    "asn": 21600,
    "mitre_attack": 86400,
    "mutex": 86400,
    "named_pipe": 86400,
    "registry_key": 86400,
    "service_name": 86400,
    "cve": 21600,
    "md5": 3600,
    "sha1": 3600,
    "sha256": 3600,
    "ssdeep": 3600,
}
_ENRICHMENT_TTL_DEFAULT = 1800

# Bump when a type's enrichment payload shape changes, so the stale-snapshot
# fallback below can never serve a pre-change payload. eth v2: Etherscan
# address page (labels, holdings, multichain portfolio).
_ENRICHMENT_SCHEMA_VERSION = {"eth": 2}


def _enrichment_has_payload(enr: "EnrichmentData | None") -> bool:
    """True when enrichment carries usable data (structured payload or a typed
    section), False when it is only skipped/error/not-found completeness flags.

    An empty result is never cached (so a transient rate-limit / error does not
    poison the cache) and never overwrites a prior good snapshot.  ``extra`` may
    hold an empty container (e.g. ``{"hash_results": []}`` for a clean hash), which
    is a valid *not-found* answer worth caching, so a present ``extra`` key with
    any value counts as payload."""
    if enr is None:
        return False
    if getattr(enr, "extra", None):
        return True
    for attr in (
        "geoip", "whois", "dns", "ssl", "reverse_dns", "subdomains", "cve",
        "breach", "favicon", "email_security", "passive_dns", "host_intel",
        "web_preview", "infostealer", "hosting_ip_intel",
    ):
        if getattr(enr, attr, None):
            return True
    if (
        getattr(enr, "open_ports", None)
        or getattr(enr, "abuse_reports", None)
        or getattr(enr, "malware_urls", None)
        or getattr(enr, "associated_hashes", None)
        or getattr(enr, "relationships", None)
    ):
        return True
    return False


async def _run_enrichment_cached(
    normalized: str,
    ioc_type: str,
    timeout: float,
    bypass_cache: bool,
) -> tuple["EnrichmentData", str | None]:
    """Run type-specific enrichment through the cache with a stale-snapshot
    fallback.  Returns ``(enrichment, error_message)`` where ``error_message`` is
    non-None only when the live call failed AND no cached snapshot could be
    served — the caller emits that as the Enrichment stage error event."""
    version = _ENRICHMENT_SCHEMA_VERSION.get(ioc_type)
    enrich_key = f"enrich:{ioc_type}:{f'v{version}:' if version else ''}{normalized.lower().strip()}"
    ttl = _ENRICHMENT_TTL_BY_TYPE.get(ioc_type, _ENRICHMENT_TTL_DEFAULT)

    # 1. Fresh cache hit — skip the network entirely (a live re-scan bypasses).
    if cache is not None and not bypass_cache:
        try:
            cached = await cache.get(enrich_key)
            if cached is not None:
                return EnrichmentData.model_validate(cached), None
        except Exception as exc:
            logger.debug("Enrichment cache read failed for %s: %s", enrich_key, exc)

    # 2. Live enrichment (bounded by the remaining pipeline deadline).
    error_message: str | None = None
    enrichment = EnrichmentData()
    try:
        enrichment = await asyncio.wait_for(enrich(normalized, ioc_type), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("Enrichment timed out for %s (%s)", normalized, ioc_type)
        error_message = "Enrichment timed out"
    except Exception as ex:
        logger.warning("Enrichment failed for %s (%s): %s", normalized, ioc_type, ex)
        error_message = f"Enrichment failed: {ex}"

    if cache is None:
        return enrichment, error_message

    # 3. Cache a good answer; on an empty/failed answer, serve the last good
    #    snapshot (even if expired) so a rate-limit ban does not blank the UI.
    if _enrichment_has_payload(enrichment):
        try:
            await cache.set(enrich_key, enrichment.model_dump(mode="json"), ttl)
        except Exception as exc:
            logger.debug("Enrichment cache write failed for %s: %s", enrich_key, exc)
        return enrichment, error_message

    try:
        entry = await cache.get_entry(enrich_key)  # audit-preserving: returns expired too
    except Exception:
        entry = None
    if entry is not None:
        value, stale = entry
        try:
            salvaged = EnrichmentData.model_validate(value)
            salvaged.analysis_notes.append(
                "Live enrichment was unavailable (provider rate-limited or errored); "
                "showing the most recent cached snapshot"
                + (" (expired)." if stale else ".")
            )
            return salvaged, None
        except Exception as exc:
            logger.debug("Enrichment stale-snapshot restore failed for %s: %s", enrich_key, exc)

    return enrichment, error_message


async def _update_stage(task: AnalysisTask, stage_name: str, status: str, message: str = "", progress: float = 0.0):
    for s in task.stages:
        if s.name == stage_name:
            s.status = status
            if message:
                s.message = message
            if progress:
                s.progress = progress
            break


def _rebuild_stages_from_plan(task: AnalysisTask, plan: list, ioc_type: str) -> None:
    """Replace the provider stage rows with exactly the applicable providers.

    Runtime stage updates key off ``adapter.name`` (see run_adapter:
    ``stage_name = adapter.name``), and the plan's ``provider`` field is that same
    adapter name, so a stage built here lines up with its live updates by
    construction. Only *applicable* providers get a row — non-applicable ones no
    longer appear as noise. ``Classify & Normalize`` keeps whatever state it has
    already reached; ``Enrichment``/``Scoring & Relations`` bookend the list, with
    ``CVE Intelligence`` inserted only for CVE indicators.
    """
    classify = next((s for s in task.stages if s.name == "Classify & Normalize"), None)
    provider_names: list[str] = []
    seen: set[str] = set()
    for item in plan:
        provider = getattr(item, "provider", None)
        applicable = getattr(item, "applicable", False)
        if applicable and provider and provider not in seen:
            seen.add(provider)
            provider_names.append(provider)
    provider_names.sort(key=str.lower)

    rebuilt: list[StageInfo] = [classify or StageInfo("Classify & Normalize")]
    rebuilt.extend(StageInfo(name) for name in provider_names)
    if ioc_type == "cve":
        rebuilt.append(StageInfo("CVE Intelligence"))
    rebuilt.append(StageInfo("Enrichment"))
    rebuilt.append(StageInfo("Scoring & Relations"))
    task.stages = rebuilt


def _merge_provider_intel_into_enrichment(task: AnalysisTask) -> None:
    """Fold structured intelligence from adapter ``raw_data`` into enrichment.

    Several adapters carry richer structured payloads than the generic
    reputation shape (urlscan web previews, Hudson Rock infostealer stats,
    AbuseIPDB reports, OTX malware URLs/hashes). This copies the first such
    payload of each kind into ``task.enrichment`` so the UI enrichment tab can
    render it. It only reads ``task.results`` and mutates ``task.enrichment``;
    each merge is guarded so one malformed payload never aborts the rest.
    """
    if task.enrichment is None:
        return
    for r in task.results:
        # 1. urlscan.io -> WebPreviewInfo
        if r.source == "urlscan.io" and isinstance(r.raw_data, dict):
            wp_raw = r.raw_data.get("web_preview")
            if wp_raw and isinstance(wp_raw, dict) and not task.enrichment.web_preview:
                try:
                    scan_uuid = wp_raw.get("scan_uuid")
                    proxied_url = f"/api/screenshot?scan_id={scan_uuid}" if scan_uuid else None
                    task.enrichment.web_preview = WebPreviewInfo(
                        screenshot_url=proxied_url,
                        page_title=wp_raw.get("page_title"),
                        server=wp_raw.get("server"),
                        language=wp_raw.get("language"),
                        domain_age_days=wp_raw.get("domain_age_days"),
                        tls_issuer=wp_raw.get("tls_issuer"),
                        tls_valid_days=wp_raw.get("tls_valid_days"),
                        asn_name=wp_raw.get("asn_name"),
                        detected_brands=wp_raw.get("detected_brands", []) or [],
                        detected_technologies=wp_raw.get("detected_technologies", []) or [],
                        mime_type=wp_raw.get("mime_type"),
                        scan_uuid=scan_uuid,
                    )
                except Exception as exc:
                    logger.debug("Failed to construct WebPreviewInfo: %s", exc)

        # 2. Hudson Rock -> InfostealerIntel
        if r.source == "Hudson Rock" and isinstance(r.raw_data, dict):
            if not task.enrichment.infostealer:
                try:
                    families_raw = r.raw_data.get("stealer_families", {})
                    families_dict = families_raw if isinstance(families_raw, dict) else {}
                    dates_list = r.raw_data.get("dates_compromised", [])
                    date_range = f"{dates_list[0]} to {dates_list[-1]}" if dates_list else None
                    task.enrichment.infostealer = InfostealerIntel(
                        total_employee_compromises=r.raw_data.get("total_infections", 0) or 0,
                        total_client_compromises=r.raw_data.get("total_user_services", 0) or 0,
                        top_corporate_services=r.raw_data.get("top_corporate_services", []) or [],
                        top_external_services=r.raw_data.get("top_external_services", []) or [],
                        stealer_families=families_dict,
                        password_strength_weak_pct=r.raw_data.get("password_strength_weak_pct"),
                        password_strength_strong_pct=r.raw_data.get("password_strength_strong_pct"),
                        total_compromised_urls=r.raw_data.get("total_compromised_urls"),
                        date_range=date_range,
                    )
                except Exception as exc:
                    logger.debug("Failed to construct InfostealerIntel: %s", exc)

        # 3. AbuseIPDB -> abuse_reports
        if r.source == "AbuseIPDB" and isinstance(r.raw_data, dict):
            reports = r.raw_data.get("reports", []) or []
            if reports and not task.enrichment.abuse_reports:
                task.enrichment.abuse_reports = reports[:20]

        # 4. AlienVault OTX -> malware_urls & associated_hashes
        if r.source == "AlienVault OTX" and isinstance(r.raw_data, dict):
            mal_urls = r.raw_data.get("malware_urls", []) or []
            if mal_urls and not task.enrichment.malware_urls:
                task.enrichment.malware_urls = mal_urls[:25]
            assoc_hashes = r.raw_data.get("associated_hashes", []) or []
            if assoc_hashes and not task.enrichment.associated_hashes:
                task.enrichment.associated_hashes = assoc_hashes[:15]


def _result_metadata(result: NormalizedResult, *, started: float, retry_count: int = 0, request_made: bool = True) -> NormalizedResult:
    """Attach execution/cache-independent audit metadata to a provider result."""
    if result.observed_at is None:
        result.observed_at = datetime.now(timezone.utc)
    result.source_timestamp = result.source_timestamp or result.last_seen or result.first_seen
    result.latency_ms = round(max(0.0, (time.monotonic() - started) * 1000.0), 2)
    result.retry_count = max(int(result.retry_count or 0), retry_count)
    result.request_made = request_made
    return result


def _failure_result(ioc: str, ioc_type: str, source: str, state: str, tag: str, *, retry_count: int = 0, retry_after: float | None = None, request_made: bool = False, started: float | None = None) -> NormalizedResult:
    result = NormalizedResult(
        ioc=ioc,
        ioc_type=ioc_type,
        source=source,
        verdict="unknown",
        execution_state=state,
        tags=[tag],
        retry_count=retry_count,
        retry_after_seconds=retry_after,
        request_made=request_made,
    )
    if started is not None:
        result.latency_ms = round(max(0.0, (time.monotonic() - started) * 1000.0), 2)
    return result


def _retryable_result(result: NormalizedResult) -> bool:
    """True for transient provider failures worth another attempt.

    Timeouts are deliberately not retried: the attempt already used the
    provider's whole time budget, and a second attempt would hold the lookup
    for another full budget.  An upstream rate limit (the provider answered
    429) is retried through the shared scheduler, which first honors the
    provider's Retry-After and gives up when that does not fit the deadline.
    """
    state = result.execution_state
    if state == "rate_limited":
        return bool(result.request_made)
    if state != "error":
        return False
    tags = {str(tag).lower() for tag in (result.tags or [])}
    if any(tag in {"request_error", "connection_error"} or tag.startswith("http_5") for tag in tags):
        return True
    return bool(result.http_status and 500 <= int(result.http_status) < 600)


_OUTAGE_TAGS = {"request_error", "connection_error", "feed_unavailable", "timeout"}


def _is_provider_outage(result: NormalizedResult) -> bool:
    """Whether a result should count toward the provider's circuit breaker.

    Only provider-side failures of a request we actually sent count:
    transport errors, 5xx responses and provider timeouts.  Our own throttling
    (rate-limit waits, concurrency queueing, deadline aborts), upstream 429s
    (handled by the shared scheduler's back-off), missing/invalid keys and
    adapter parsing bugs must not open the circuit, because an open circuit
    turns every other lookup's result for that provider into "circuit_open".
    """
    if not result.request_made:
        return False
    state = result.execution_state
    if state == "timeout":
        return True
    if state != "error":
        return False
    tags = {str(tag).lower() for tag in (result.tags or [])}
    if tags & _OUTAGE_TAGS or any(tag.startswith("http_5") for tag in tags):
        return True
    return bool(result.http_status and int(result.http_status) >= 500)


def _provider_budget(adapter) -> float:
    """Wall-clock budget for one whole provider lookup call.

    ``PROVIDER_TIMEOUT_SECONDS`` (default 20s).  ``RateLimitConfig.timeout_seconds``
    is the adapter's per-HTTP-request timeout, enforced by the adapter's own
    client call; several adapters make more than one request per lookup, so it
    is not used as the budget for the whole call (a 10s cap made multi-request
    adapters such as OTX and Hudson Rock time out even when every request
    succeeded).  The caller additionally bounds the budget by the remaining
    IOC deadline.
    """
    configured = getattr(settings, "provider_timeout_seconds", ADAPTER_TIMEOUT)
    try:
        return max(0.1, float(configured or ADAPTER_TIMEOUT))
    except (TypeError, ValueError):
        return ADAPTER_TIMEOUT


def _retry_delay(result: NormalizedResult, retry_number: int, adapter) -> float:
    retry_after = result.retry_after_seconds
    if retry_after is not None and retry_after >= 0:
        return min(float(retry_after), float(getattr(adapter.rate_limit, "max_backoff_seconds", 8.0)))
    base = float(getattr(adapter.rate_limit, "backoff_factor", 0.5))
    ceiling = float(getattr(adapter.rate_limit, "max_backoff_seconds", 8.0))
    return min(ceiling, base * (2 ** max(0, retry_number - 1))) * random.uniform(0.8, 1.2)


def _finalize_assessment(task: AnalysisTask, assessment: IOCAssessment) -> IOCAssessment:
    """Attach the complete plan while keeping synthetic N/A rows out of evidence."""
    task_plan = list(task.provider_plan or [])
    # The capability declaration is already available from /api/sources. A
    # batch assessment only needs the decision that was made for this IOC;
    # embedding the full rate/retry policy once per provider and IOC inflated
    # exports without adding evidence.
    assessment.provider_plan = [
        {
            key: item.get(key)
            for key in ("provider", "ioc_type", "assessment_domain", "applicable", "operation", "reason")
            if key in item
        }
        for item in task_plan
    ]
    assessment.provider_breakdown = [
        observation for observation in assessment.provider_breakdown
        if observation.execution_state != "not_applicable"
    ]
    if assessment.evidence_counts:
        assessment.evidence_counts["provider_status"] = len([
            observation for observation in assessment.provider_breakdown
            if observation.execution_state not in {"success", "not_found"}
        ])
    assessment.evidence_summary["providers_aggregated"] = len(assessment.provider_breakdown)
    # Applicability lives in the provider plan; task.results no longer carries
    # one synthetic not_applicable row per unsupported provider.
    assessment.evidence_summary["not_applicable_providers"] = len([
        item for item in task_plan if not item.get("applicable", True)
    ])
    assessment.provider_summary = [
        item for item in assessment.provider_summary
        if item.get("execution_state") != "not_applicable"
    ]
    assessment.provenance = [
        item for item in assessment.provenance
        if item.get("source") in {observation.source for observation in assessment.provider_breakdown}
    ]
    return assessment


def _is_cacheable_result(result: NormalizedResult) -> bool:
    """Only real intelligence (success / not_found) is cached.

    A rate limit, timeout, error or health failure is never cached: it is not
    IOC intelligence and would poison later lookups.
    """
    return not (
        result.execution_state not in {"success", "not_found"}
        or bool(getattr(result, "error", None))
        or any(t in (result.tags or []) for t in ("error", "rate_limited", "timeout", "circuit_breaker", "failed", "service_unavailable"))
    )


async def _call_provider(task: AnalysisTask, adapter, ioc_value: str, ioc_type: str, deadline: float) -> NormalizedResult:
    """Run one provider lookup under the shared scheduler and the IOC deadline.

    1. Reserve a request slot from the process-wide provider scheduler (per
       minute / per day quota, minimum interval, provider Retry-After).  The
       lookup waits for the slot when the wait still leaves time for the call
       before the IOC deadline; otherwise it reports ``rate_limited`` with the
       required wait as ``retry_after_seconds``.
    2. Take one of the provider's concurrency slots (held only for the call).
    3. Call the adapter, bounded by the provider budget and the deadline.
    4. Retry transient failures (transport errors, 5xx, upstream 429) within
       ``max_retries`` and the deadline.  Timeouts are not retried.

    Always returns a result; only cancellation propagates.
    """
    stage_name = adapter.name
    started = time.monotonic()
    rate = adapter.rate_limit
    budget = _provider_budget(adapter)
    call_window = min(budget, MIN_PROVIDER_CALL_WINDOW)
    max_retries = max(0, int(getattr(rate, "max_retries", 2)))
    attempts = 0
    queue_wait = 0.0
    final_result: NormalizedResult | None = None
    limiter = rate_limiter

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0.05:
            break
        max_wait = max(0.0, remaining - call_window)

        # 1. Shared rate-limit slot.
        if limiter is not None and hasattr(limiter, "reserve_provider"):
            reservation = limiter.reserve_provider(
                adapter.name,
                getattr(rate, "requests_per_minute", 30),
                getattr(rate, "requests_per_day", 0),
                minimum_interval=float(getattr(rate, "minimum_interval_seconds", 0.0) or 0.0),
                max_wait=max_wait,
            )
            if reservation.granted and reservation.wait_seconds >= 1.0:
                message = f"Waiting {reservation.wait_seconds:.0f}s for a {adapter.name} rate-limit slot"
                await _update_stage(task, stage_name, "running", message)
                await _emit_stage_event(task, stage_name, "running", message)
            reservation = await limiter.wait_for_reservation(adapter.name, reservation, max_wait=max_wait)
            queue_wait += reservation.wait_seconds
            if not reservation.granted:
                if final_result is not None and final_result.request_made:
                    # Keep the provider's own answer (e.g. its 429) as the
                    # observation; the retry simply did not fit the deadline.
                    break
                final_result = _failure_result(
                    ioc_value, ioc_type, adapter.name, "rate_limited", reservation.reason or "rate_limited",
                    retry_count=attempts, retry_after=reservation.retry_after_seconds,
                    request_made=False, started=started,
                )
                final_result.provider_summary = (
                    f"Not queried: the next {adapter.name} request slot is "
                    f"{reservation.retry_after_seconds or 0:.0f}s away, beyond this lookup's deadline"
                )
                logger.info(
                    "Provider %s throttled for %s: next slot in %.1fs exceeds remaining %.1fs (%s)",
                    adapter.name, ioc_type, reservation.retry_after_seconds or 0.0, max_wait,
                    reservation.reason or "rate_limited",
                )
                break

        # 2. Concurrency slot + 3. provider call.
        if limiter is not None and hasattr(limiter, "provider_slot"):
            slot_cm = limiter.provider_slot(
                adapter.name,
                getattr(rate, "concurrency_limit", 2),
                timeout=max(0.1, deadline - time.monotonic() - call_window),
            )
        else:
            slot_cm = nullcontext()
        slot_acquired = False
        queue_started = time.monotonic()
        provider_timeout = budget
        call_started = queue_started
        try:
            async with slot_cm:
                slot_acquired = True
                queue_wait += time.monotonic() - queue_started
                await _update_stage(task, stage_name, "running", f"Querying {adapter.name}")
                provider_timeout = max(0.1, min(budget, deadline - time.monotonic()))
                call_started = time.monotonic()
                result = await asyncio.wait_for(
                    adapter.lookup(ioc_value, ioc_type),
                    timeout=provider_timeout,
                )
            if isinstance(result, Exception):
                raise result
            if not isinstance(result, NormalizedResult):
                result = NormalizedResult.model_validate(result)
            result = normalize_provider_result(result, task.assessment_domain)
            result.network_latency_ms = round((time.monotonic() - call_started) * 1000.0, 2)
            result = _result_metadata(result, started=started, retry_count=attempts)
        except asyncio.TimeoutError:
            if not slot_acquired:
                final_result = _failure_result(
                    ioc_value, ioc_type, adapter.name, "unavailable", "queue_wait_timeout",
                    retry_count=attempts, request_made=False, started=started,
                )
                final_result.provider_summary = "Not queried: no free concurrency slot before the deadline"
            else:
                final_result = _failure_result(
                    ioc_value, ioc_type, adapter.name, "timeout", "timeout",
                    retry_count=attempts, request_made=True, started=started,
                )
                final_result.provider_summary = f"No response within {provider_timeout:.0f}s"
                logger.warning(
                    "Provider %s timed out after %.1fs for %s (attempt %s)",
                    adapter.name, provider_timeout, ioc_type, attempts + 1,
                )
            break
        except httpx.TimeoutException as exc:
            final_result = _failure_result(
                ioc_value, ioc_type, adapter.name, "timeout", "timeout",
                retry_count=attempts, request_made=True, started=started,
            )
            final_result.provider_summary = f"Request timed out ({type(exc).__name__})"
            logger.warning(
                "Provider %s request timed out for %s (attempt %s): %s",
                adapter.name, ioc_type, attempts + 1, describe_exception(exc),
            )
            break
        except (httpx.RequestError, ConnectionError, OSError) as exc:
            logger.warning(
                "Provider %s request failed for %s (attempt %s): %s",
                adapter.name, ioc_type, attempts + 1, describe_exception(exc),
            )
            result = _failure_result(
                ioc_value, ioc_type, adapter.name, "error", "request_error",
                retry_count=attempts, request_made=True, started=started,
            )
            result.provider_summary = f"Request failed ({type(exc).__name__})"
        except Exception as exc:
            logger.warning(
                "Provider %s raised %s for %s",
                adapter.name, describe_exception(exc), ioc_type, exc_info=True,
            )
            final_result = _failure_result(
                ioc_value, ioc_type, adapter.name, "error", "adapter_exception",
                retry_count=attempts, request_made=True, started=started,
            )
            final_result.tags.append(f"exception_type:{exc.__class__.__name__}")
            final_result.provider_summary = f"Adapter error ({type(exc).__name__})"
            break

        final_result = result
        if result.execution_state == "rate_limited" and result.request_made:
            # The provider itself refused: share its back-off with every other
            # lookup so they wait instead of burning more requests into 429s.
            penalty = result.retry_after_seconds
            if penalty is None:
                per_minute = max(1, int(getattr(rate, "requests_per_minute", 30) or 30))
                penalty = max(1.0, _rate_window_seconds() / per_minute)
            if limiter is not None and hasattr(limiter, "penalize_provider"):
                limiter.penalize_provider(adapter.name, penalty)
        if not _retryable_result(result) or attempts >= max_retries:
            break
        if result.execution_state != "rate_limited":
            delay = _retry_delay(result, attempts + 1, adapter)
            if time.monotonic() + delay + call_window >= deadline:
                break
            attempts += 1
            logger.info(
                "Retrying provider %s for %s in %.1fs (attempt %s/%s)",
                adapter.name, ioc_type, delay, attempts, max_retries,
            )
            await asyncio.sleep(delay)
        else:
            attempts += 1
        # For an upstream 429 the next reservation waits for the provider's
        # back-off, or reports that it does not fit the deadline.

    if final_result is None:
        final_result = _failure_result(
            ioc_value, ioc_type, adapter.name,
            "aborted_due_to_ioc_deadline", "aborted_due_to_ioc_deadline",
            retry_count=attempts, request_made=False, started=started,
        )
    final_result.retry_count = max(int(final_result.retry_count or 0), attempts)
    final_result.queue_wait_ms = round(queue_wait * 1000.0, 2)
    final_result.assessment_domain = task.assessment_domain
    return normalize_provider_result(final_result, task.assessment_domain)


def _rate_window_seconds() -> float:
    from app.backend import rate_limiter as rate_limiter_module

    return float(getattr(rate_limiter_module, "PROVIDER_WINDOW_SECONDS", 60.0))


def _mark_cached(result: NormalizedResult, ck: str, *, stale: bool) -> NormalizedResult:
    """Describe a cached provider answer as served by *this* lookup."""
    if "cached" not in result.tags:
        result.tags = list(result.tags or []) + ["cached"]
    result.cached = True
    status = "stale" if stale else "cached"
    freshness = "historical" if stale else "cached"
    result.cache_status = status
    if not stale:
        # These fields describe this lookup, not the original request that
        # populated the cache.
        result.request_made = False
        result.latency_ms = 0.0
        result.network_latency_ms = 0.0
        result.queue_wait_ms = 0.0
    result.retrieved_at = datetime.now(timezone.utc)
    cache_reference = result.cache_created_at or result.observed_at
    if cache_reference is not None:
        if cache_reference.tzinfo is None:
            cache_reference = cache_reference.replace(tzinfo=timezone.utc)
        result.cache_age = max(0.0, (result.retrieved_at - cache_reference).total_seconds())
    result.freshness_class = freshness
    result.stale = stale
    result.cache_metadata.cached = True
    result.cache_metadata.cache_key = ck
    result.cache_metadata.cache_age = result.cache_age
    result.cache_metadata.retrieved_at = result.retrieved_at
    result.cache_metadata.freshness_class = freshness
    result.cache_metadata.stale = stale
    result.cache_metadata.status = status
    return result


def _stamp_cache_metadata(result: NormalizedResult, ck: str, ttl: int) -> None:
    cache_now = datetime.now(timezone.utc)
    result.cache_key = ck
    result.cache_created_at = cache_now
    result.retrieved_at = cache_now
    result.expires_at = cache_now + timedelta(seconds=ttl)
    result.source_timestamp = result.source_timestamp or result.last_seen or result.first_seen
    result.cache_status = "fresh"
    result.freshness_class = "fresh"
    result.stale = False
    result.cache_metadata.cached = False
    result.cache_metadata.cache_key = ck
    result.cache_metadata.cache_created_at = cache_now
    result.cache_metadata.retrieved_at = cache_now
    result.cache_metadata.observed_at = result.observed_at
    result.cache_metadata.expires_at = result.expires_at
    result.cache_metadata.source_timestamp = result.source_timestamp


def _private_ip_assessment(task: AnalysisTask, normalized: str, ioc_type: str) -> None:
    """Score a private/reserved address without any external lookup."""
    private_result = NormalizedResult(
        ioc=normalized, ioc_type=ioc_type, source="reserved_ip",
        verdict="unknown", execution_state="unavailable",
        request_made=False, tags=["private_ip", "no_external_lookup"],
    )
    task.results = [private_result]
    task.enrichment = EnrichmentData(
        completeness={"external_reputation": "skipped"},
        analysis_notes=["Private, reserved, or unspecified address; no external reputation lookup was performed."],
    )
    task.final_assessment = aggregate_evidence(
        normalized, ioc_type, task.results, task.enrichment, provider_plan=task.provider_plan
    )
    task.final_assessment = _finalize_assessment(task, task.final_assessment)
    task.provider_health = task.final_assessment.provider_health
    task.final_assessment.reason = "This is a private, reserved, or unspecified address; external reputation was not queried."
    task.composite = compute_composite(
        task.results,
        ioc=normalized,
        ioc_type=ioc_type,
        enrichment=task.enrichment,
        assessment=task.final_assessment,
    )
    for stage in task.stages:
        if stage.status in {"pending", "running"}:
            stage.status = "skipped"
            stage.message = stage.message or "Not needed for a private address"
            stage.progress = 1.0


def _is_private_address(normalized: str, ioc_type: str) -> bool:
    if ioc_type not in ("ipv4", "ipv6"):
        return False
    try:
        addr = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return not addr.is_global or addr.is_reserved or addr.is_unspecified


def _build_relationships(task: AnalysisTask, normalized: str, enrichment: EnrichmentData | None) -> list[dict]:
    relationships = []
    relationship_keys: set[str] = set()
    for r in task.results:
        for rel_ioc, rel_type in r.related_iocs:
            rel_ioc_clean = str(rel_ioc).strip()
            if not rel_ioc_clean or rel_ioc_clean.lower() in {"other", "unknown", "none", "n/a", "null"}:
                continue
            fingerprint = f"{normalized}|{rel_ioc_clean.lower()}|{rel_type.lower()}"
            if fingerprint in relationship_keys:
                continue
            relationship_keys.add(fingerprint)
            relationships.append({
                "source_ioc": normalized,
                "target_ioc": rel_ioc_clean,
                "relationship": rel_type,
                "via_source": r.source,
                "confidence": "medium",
                "evidence_type": "reference" if rel_type == "reference" else "observed_relationship",
                "observed_at": (r.observed_at or r.source_timestamp).isoformat() if (r.observed_at or r.source_timestamp) else None,
                "provenance": r.provenance_family or r.source,
                "relationship_fingerprint": fingerprint,
                "evidence_hash": r.evidence_hash,
            })

    enrichment_rels = enrichment.relationships if enrichment and enrichment.relationships else []
    for relationship in enrichment_rels:
        fingerprint = relationship.get("relationship_fingerprint") or f"{relationship.get('source_ioc', normalized)}|{relationship.get('target_ioc', '')}|{relationship.get('relationship', '')}".lower()
        if fingerprint not in relationship_keys:
            relationship_keys.add(fingerprint)
            relationship["relationship_fingerprint"] = fingerprint
            relationships.append(relationship)
    return relationships


async def _persist_completed_task(task: AnalysisTask) -> None:
    """Write a completed lookup to SQLite before it is reported as done.

    Persisting first means history (/api/recent, /api/lookup/stored) and the
    UI's follow-up /api/save always see exactly the result the live task
    returned, instead of racing it.
    """
    try:
        from app.backend.database import persist_lookup, persisted_verdict_fields

        # DV-1: persist the authoritative final_assessment verdict/score, not
        # the reputation-only composite.
        score, verdict, confidence = persisted_verdict_fields(task)
        await persist_lookup(
            value=task.normalized,
            ioc_type=task.ioc_type or "unknown",
            task_id=task.task_id,
            composite_score=score,
            composite_verdict=verdict,
            composite_confidence=confidence,
            full_response=json.dumps(task_response_payload(task), default=str),
            source_count=len(task.results),
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("Failed to persist task %s to SQLite: %s", task.task_id, describe_exception(exc))


async def _publish_terminal_state(task: AnalysisTask, status: str) -> None:
    """Make a finished task visible (memory, task cache, SSE) exactly once."""
    tid = task.task_id
    # In-memory state first (no await), so pollers see the terminal state
    # even if the cache write below is interrupted.
    task.status = status
    task.progress = 100.0
    for stage in task.stages:
        if stage.status == "running":
            stage.status = "skipped" if status != "done" else "done"
            stage.progress = 1.0
    with _dict_lock:
        _tasks[tid] = task
    if cache is not None:
        try:
            await cache.save_task(tid, task.to_dict(), TASK_TTL)
            if status == "done" and task.ioc_type:
                await cache.set(
                    cache_key("save", task.ioc_type, task.normalized),
                    {"task_id": tid},
                    TASK_TTL,
                )
        except Exception as exc:
            logger.warning("Failed to cache task %s: %s", tid, describe_exception(exc))
    if status in {"error", "cancelled"} and task.error:
        await _emit_error_event(task, "Pipeline", task.error)
    await _emit_done_event(task)


async def run_analysis(
    ioc_value: str,
    task_id: Optional[str] = None,
    fp_override: bool = False,
    ioc_type_override: str | None = None,
    ioc_deadline: float | None = None,
    bypass_cache: bool = False,
    password_prehashed: bool = False,
) -> AnalysisTask:
    tid = task_id or uuid.uuid4().hex[:12]
    configured_deadline = ioc_deadline if ioc_deadline is not None else getattr(settings, "ioc_deadline_seconds", PIPELINE_TIMEOUT)
    deadline = time.monotonic() + max(0.1, float(configured_deadline))
    # Stages start minimal; the provider stages are derived dynamically from
    # the provider plan once the IOC is classified (_rebuild_stages_from_plan).
    stages = [
        StageInfo("Classify & Normalize"),
        StageInfo("Enrichment"),
        StageInfo("Scoring & Relations"),
    ]

    normalized_info = normalize_ioc(ioc_value, expected_type=ioc_type_override)
    normalized = normalized_info.value
    ioc_type = ioc_type_override or normalized_info.ioc_type
    if ioc_type == "password" and password_prehashed and not is_password_digest(normalized):
        password_prehashed = False
    if ioc_type == "password" and normalized:
        safe_ioc_value = password_digest(normalized, already_digest=password_prehashed)
    elif normalized_info.valid:
        safe_ioc_value = normalized
    else:
        safe_ioc_value = ""

    task = AnalysisTask(
        task_id=tid,
        ioc_value=safe_ioc_value,
        stages=stages,
        status="pending",
        password_prehashed=password_prehashed,
    )
    previous = get_task(tid)
    if previous is not None:
        # Keep the submission time of a task registered while it was queued.
        task.created_at = previous.created_at

    with _dict_lock:
        _tasks[tid] = task
    if cache is not None:
        try:
            await cache.save_task(tid, task.to_dict(), TASK_TTL)
        except Exception as exc:
            logger.debug("Initial task cache write failed for %s: %s", tid, describe_exception(exc))

    _register_running(tid)
    final_status = "error"
    runners: list[asyncio.Task] = []
    cancelled: asyncio.CancelledError | None = None
    try:
        task.status = "classifying"
        task.progress = 2.0
        await _update_stage(task, "Classify & Normalize", "running", "Normalizing IOC value")
        await _emit_stage_event(task, "Classify & Normalize", "running", "Normalizing IOC value")

        if not normalized:
            raise ValueError("Empty IOC after normalization")
        if ioc_type not in SUPPORTED_IOC_TYPES:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
        if ioc_type_override and ioc_type not in normalized_info.candidate_types:
            raise ValueError(f"IOC value does not validate as {ioc_type}")
        if ioc_type == "password":
            normalized = password_digest(normalized, already_digest=password_prehashed)
        task.ioc_type = ioc_type
        task.normalized = normalized
        task.assessment_domain = route_assessment_domain(ioc_type, normalized).domain
        # Build the provider plan once and reuse it for the serialized plan,
        # the dynamic stage list, and the execution filter below.
        plan = build_provider_plan(ADAPTERS, ioc_type, normalized)
        task.provider_plan = [item.as_dict() for item in plan]
        _rebuild_stages_from_plan(task, plan, ioc_type)

        await _update_stage(task, "Classify & Normalize", "done", f"Classified as {ioc_type}", 1.0)
        await _emit_stage_event(task, "Classify & Normalize", "done", f"Classified as {ioc_type}", 1.0)

        if _is_private_address(normalized, ioc_type):
            task.status = "scoring"
            _private_ip_assessment(task, normalized, ioc_type)
            final_status = "done"
        else:
            await _run_lookup(task, plan, normalized, ioc_type, deadline, bypass_cache, fp_override, runners)
            final_status = "done"

    except asyncio.CancelledError as exc:
        cancelled = exc
        final_status = "cancelled"
        task.error = "Analysis cancelled"
        logger.info("Analysis %s cancelled", tid)
    except Exception as e:
        final_status = "error"
        # Input validation errors are shown to the analyst as-is; anything
        # else carries its exception type so an empty message is never shown.
        task.error = str(e) if isinstance(e, ValueError) and str(e) else describe_exception(e, limit=200)
        logger.warning(
            "Analysis %s failed for %s: %s", tid, task.ioc_type or ioc_type, task.error,
            exc_info=not isinstance(e, ValueError),
        )
    finally:
        # Never leave provider or enrichment work running behind a finished,
        # failed, or cancelled task.
        leftovers = [r for r in runners if not r.done()]
        for runner in leftovers:
            runner.cancel()
        if leftovers:
            await asyncio.gather(*leftovers, return_exceptions=True)

    try:
        if final_status == "done" and task.normalized:
            task.progress = max(task.progress, 95.0)
            try:
                await _persist_completed_task(task)
            except asyncio.CancelledError as exc:
                # The analysis itself is complete; publish it before honoring
                # the cancellation so the task never stays non-terminal.
                cancelled = cancelled or exc
        await _publish_terminal_state(task, final_status)
        if final_status == "done" and task.normalized:
            try:
                from app.backend.webhooks import queue_lookup_dispatch

                assessment = task.final_assessment
                verdict = (
                    assessment.final_verdict
                    if assessment is not None
                    else getattr(task.composite, "verdict", "unknown")
                )
                score = getattr(task.composite, "score", 0.0) if task.composite else 0.0
                await queue_lookup_dispatch(tid, task.normalized, verdict, score)
            except Exception as exc:
                logger.debug("Webhook completion dispatch skipped for task %s: %s", tid, describe_exception(exc))
    finally:
        _unregister_running(tid)

    if cancelled is not None:
        raise cancelled
    return task


async def _run_lookup(
    task: AnalysisTask,
    plan: list,
    normalized: str,
    ioc_type: str,
    deadline: float,
    bypass_cache: bool,
    fp_override: bool,
    runners: list[asyncio.Task],
) -> None:
    """Provider fan-out + enrichment + scoring for one classified IOC."""
    from app.backend.adapters.base import is_valid_api_key

    applicable_names = {item.provider for item in plan if item.applicable}
    matching = [a for a in ADAPTERS if a.name in applicable_names]

    # Keep explicit unavailable records for relevant providers.  A source that
    # is disabled, unconfigured, or quota-blocked must be visible in the audit
    # trail instead of silently disappearing from coverage.  Providers that do
    # not apply to this IOC type are recorded only in task.provider_plan.
    unavailable_results: list[NormalizedResult] = []
    key_filtered = []
    for a in matching:
        if not settings.is_source_enabled(a.name):
            unavailable_results.append(_failure_result(
                normalized, ioc_type, a.name, "unavailable", "disabled_by_policy",
                request_made=False,
            ))
            await _update_stage(task, a.name, "skipped", "Disabled by source policy", 1.0)
            continue
        key = getattr(a, 'api_key', None)
        if (
            key is not None
            and not is_valid_api_key(key)
            and not getattr(a, "public_without_key", False)
        ):
            unavailable_results.append(_failure_result(
                normalized, ioc_type, a.name, "unavailable", "no_api_key_configured",
                request_made=False,
            ))
            await _update_stage(task, a.name, "skipped", "No API key", 1.0)
        else:
            key_filtered.append(a)
    matching = key_filtered

    for s in task.stages:
        if s.name in ("Classify & Normalize", "Enrichment", "Scoring & Relations", "CVE Intelligence"):
            continue
        if not any(a.name == s.name for a in matching) and s.status == "pending":
            s.status = "skipped"
            s.progress = 1.0

    task.status = "querying"
    result_map: dict[str, NormalizedResult] = {r.source: r for r in unavailable_results}

    # Enrichment does not depend on provider results, so it runs alongside the
    # provider fan-out instead of after it; both are bounded by the deadline.
    enrichment_runner = asyncio.create_task(
        _run_enrichment_cached(normalized, ioc_type, max(1.0, deadline - time.monotonic()), bypass_cache)
    )
    runners.append(enrichment_runner)
    await _update_stage(task, "Enrichment", "running", f"Running type-specific enrichment for {ioc_type}")
    await _emit_stage_event(task, "Enrichment", "running", f"Running type-specific enrichment for {ioc_type}")

    async def finish_provider(adapter, result: NormalizedResult, *, cached: bool = False) -> None:
        result_map[adapter.name] = result
        if cached:
            await _update_stage(task, adapter.name, "done", f"{adapter.name} (cached)", 1.0)
            await _emit_stage_event(task, adapter.name, "done", f"{adapter.name} (cached)", 1.0)
            await _emit_result_event(task, result)
        else:
            stage_status = "done" if result.execution_state in {"success", "not_found"} else "error"
            stage_message = (
                f"{adapter.name} done"
                if stage_status == "done"
                else result.execution_state.replace("_", " ").capitalize()
            )
            if result.execution_state == "unavailable" and "circuit_open" in (result.tags or []):
                stage_status = "skipped"
                stage_message = "Provider unavailable (circuit open)"
            await _update_stage(task, adapter.name, stage_status, stage_message, 1.0)
            await _emit_stage_event(task, adapter.name, stage_status, stage_message, 1.0)
            await _emit_result_event(task, result)
            if stage_status == "error":
                await _emit_error_event(task, adapter.name, stage_message)
        completed = sum(1 for s in task.stages if s.status in ("done", "error", "skipped"))
        total_stages = len(task.stages)
        task.progress = 5.0 + (completed / total_stages) * 55.0 if total_stages > 0 else 60.0

    async def run_live(adapter, ck: str) -> NormalizedResult:
        await _update_stage(task, adapter.name, "running", f"Querying {adapter.name}")
        started = time.monotonic()
        if not adapter._check_circuit():
            result = _failure_result(
                normalized, ioc_type, adapter.name, "unavailable", "circuit_open",
                request_made=False, started=started,
            )
            result.provider_summary = "Skipped: the provider failed repeatedly and is paused briefly"
            result.assessment_domain = task.assessment_domain
            return normalize_provider_result(result, task.assessment_domain)

        result = await _call_provider(task, adapter, normalized, ioc_type, deadline)
        if _is_provider_outage(result):
            adapter._record_failure()
        elif result.execution_state in {"success", "not_found"}:
            adapter._record_success()
        logger.info(
            "Provider lookup source=%s state=%s latency_ms=%s queue_wait_ms=%s retries=%s http_status=%s",
            adapter.name, result.execution_state, result.latency_ms, result.queue_wait_ms,
            result.retry_count, result.http_status,
        )
        if cache is not None and _is_cacheable_result(result):
            ttl = int(getattr(adapter.rate_limit, "cache_ttl_seconds", None) or cache_ttl(adapter.name, ioc_type))
            _stamp_cache_metadata(result, ck, ttl)
            try:
                await cache.set(ck, result.model_dump(mode="json"), ttl)
            except Exception as exc:
                logger.debug("Provider cache write failed for %s: %s", ck, describe_exception(exc))
        return result

    async def run_adapter(adapter) -> None:
        ck = cache_key(adapter.name, ioc_type, normalized)
        if cache is None or bypass_cache:
            await finish_provider(adapter, await run_live(adapter, ck))
            return
        # One live request per provider+IOC at a time: a concurrent lookup of
        # the same IOC waits here and then reuses the fresh cache entry.
        async with _cache_key_lock(ck):
            cached = None
            cached_stale = False
            try:
                cache_entry = await cache.get_entry(ck) if hasattr(cache, "get_entry") else None
                if cache_entry is not None:
                    cached, cached_stale = cache_entry
                else:
                    cached = await cache.get(ck)
            except Exception as exc:
                logger.debug("Provider cache read failed for %s: %s", ck, describe_exception(exc))
                cached = None
            cached_result = None
            if cached is not None:
                try:
                    cached_result = NormalizedResult(**cached)
                except Exception:
                    cached_result = None
                # Older cache entries may predate explicit execution states.
                # Never reuse an error, rate-limit, or health failure.
                if cached_result is None or not _is_cacheable_result(cached_result):
                    await cache.delete(ck)
                    cached_result = None
            if cached_result is not None and not cached_stale:
                await finish_provider(adapter, _mark_cached(cached_result, ck, stale=False), cached=True)
                return
            live = await run_live(adapter, ck)
            if cached_result is not None and live.execution_state in {"error", "timeout", "rate_limited", "unavailable"}:
                # The live request failed: show the expired answer, clearly
                # labeled as historical, instead of nothing.
                await finish_provider(adapter, _mark_cached(cached_result, ck, stale=True))
                return
            await finish_provider(adapter, live)

    provider_runners = [asyncio.create_task(run_adapter(adapter)) for adapter in matching]
    runners.extend(provider_runners)
    pipeline_timed_out = False
    # A provider timeout is isolated inside _call_provider.  Only runners still
    # pending at the IOC deadline are aborted; completed observations are kept.
    if provider_runners:
        done, pending = await asyncio.wait(provider_runners, timeout=max(0.1, deadline - time.monotonic()))
        for runner in done:
            if runner.cancelled():
                continue
            exc = runner.exception()
            if exc is not None:
                logger.error("Provider orchestration failed: %s", describe_exception(exc), exc_info=exc)
        if pending:
            pipeline_timed_out = True
            for runner in pending:
                runner.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        for adapter in matching:
            if adapter.name in result_map:
                continue
            if pipeline_timed_out:
                result = _failure_result(
                    normalized, ioc_type, adapter.name,
                    "aborted_due_to_ioc_deadline", "aborted_due_to_ioc_deadline",
                    request_made=False,
                )
                result.provider_summary = "Aborted: the IOC deadline was reached before this provider finished"
                await _update_stage(task, adapter.name, "skipped", "Aborted due to IOC deadline", 1.0)
            else:
                result = _failure_result(
                    normalized, ioc_type, adapter.name, "error", "orchestration_error",
                    request_made=False,
                )
                await _update_stage(task, adapter.name, "error", "Internal error", 1.0)
            result.assessment_domain = task.assessment_domain
            result_map[adapter.name] = normalize_provider_result(result, task.assessment_domain)

    task.results = [result_map[a.name] for a in matching if a.name in result_map]
    task.results.extend(unavailable_results)

    task.status = "enriching"
    task.progress = max(task.progress, 65.0)
    try:
        enrichment, enrichment_error = await enrichment_runner
    except Exception as exc:
        logger.warning("Enrichment failed for %s: %s", ioc_type, describe_exception(exc), exc_info=True)
        enrichment, enrichment_error = EnrichmentData(), f"Enrichment failed: {describe_exception(exc, limit=120)}"
    if enrichment is None:
        enrichment = EnrichmentData()
    if enrichment_error:
        await _emit_error_event(task, "Enrichment", enrichment_error)
    task.enrichment = enrichment
    if not matching:
        enrichment.analysis_notes.append(
            f"No reputation adapter currently supports {ioc_type}; public structural or contextual enrichment was still collected."
        )
    elif not task.results:
        enrichment.analysis_notes.append(
            "Supporting sources were selected, but none returned a usable result."
        )
    if pipeline_timed_out:
        enrichment.completeness["pipeline"] = "partial"
        enrichment.analysis_notes.append(
            "IOC deadline reached: the assessment uses the provider results that completed before the deadline; "
            "unfinished providers are recorded as aborted."
        )

    # --- Propagate Structured Intelligence from Adapter Results ---
    _merge_provider_intel_into_enrichment(task)

    enrichment_stage_status = "error" if enrichment_error else "done"
    enrichment_stage_message = enrichment_error or "Enrichment complete"
    await _update_stage(task, "Enrichment", enrichment_stage_status, enrichment_stage_message, 1.0)
    await _emit_stage_event(task, "Enrichment", enrichment_stage_status, enrichment_stage_message, 1.0)

    if ioc_type == "cve" and enrichment and enrichment.cve:
        await _update_stage(task, "CVE Intelligence", "running", "Normalizing CVE enrichment data")
        try:
            cve_result = normalize_cve_enrichment(enrichment.cve, normalized)
            task.results.append(cve_result)
            await _update_stage(task, "CVE Intelligence", "done", "CVE analysis complete", 1.0)
        except Exception as exc:
            logger.warning("CVE normalization failed for %s: %s", normalized, describe_exception(exc))
            await _update_stage(task, "CVE Intelligence", "error", describe_exception(exc, limit=80), 1.0)
    else:
        await _update_stage(task, "CVE Intelligence", "skipped", "Not a CVE IOC", 1.0)

    task.status = "scoring"
    task.progress = max(task.progress, 85.0)
    await _update_stage(task, "Scoring & Relations", "running", "Computing composite score")

    if fp_override:
        task.results.insert(
            0,
            NormalizedResult(
                ioc=normalized, ioc_type=task.ioc_type or "unknown",
                source="User Feedback",
                verdict="clean", raw_score=0.0, confidence="high",
                tags=["user_marked_fp"],
            ),
        )

    final_assessment = aggregate_evidence(
        normalized,
        task.ioc_type or "unknown",
        task.results,
        enrichment,
        provider_plan=task.provider_plan,
    )
    final_assessment = _finalize_assessment(task, final_assessment)
    if fp_override:
        final_assessment.final_verdict = "benign"
        final_assessment.confidence = "high"
        final_assessment.normalized_score = 0.0
        final_assessment.reason = "The IOC was explicitly marked false positive by an analyst."
        final_assessment.analyst_review_recommended = False
        final_assessment.needs_review = False
        final_assessment.classification = "benign"
        final_assessment.risk_score = 0.0
        final_assessment.review_reasons = []
    if pipeline_timed_out:
        note = "IOC deadline reached before every provider finished; unfinished providers were aborted."
        if note not in final_assessment.review_reasons:
            final_assessment.review_reasons.append(note)
    composite = compute_composite(
        task.results,
        ioc=normalized,
        ioc_type=task.ioc_type or "unknown",
        enrichment=enrichment,
        assessment=final_assessment,
    )
    logger.info(
        "IOC assessment type=%s verdict=%s score=%s evidence_strength=%s coverage=%s needs_review=%s",
        task.ioc_type, final_assessment.final_verdict, final_assessment.normalized_score,
        final_assessment.evidence_strength, final_assessment.coverage,
        final_assessment.needs_review,
    )
    for observation in final_assessment.provider_breakdown:
        logger.debug(
            "Evidence contribution source=%s state=%s provider_verdict=%s normalized_verdict=%s contribution=%s weight=%s signal=%s",
            observation.source, observation.execution_state, observation.provider_verdict,
            observation.normalized_verdict, observation.contribution,
            observation.weight, observation.normalized_signal,
        )

    relationships = _build_relationships(task, normalized, enrichment)

    task.composite = composite
    task.final_assessment = final_assessment
    task.final_assessment.relationships = relationships
    task.provider_health = final_assessment.provider_health
    task.relationships = relationships
    await _update_stage(task, "Scoring & Relations", "done", "Analysis complete", 1.0)

    task.executive_summary = generate_executive_summary(
        LookupResponse(
            input=task.ioc_value,
            normalized=task.normalized,
            ioc_type=task.ioc_type or "unknown",
            composite=composite,
            final_assessment=final_assessment,
            provider_health=task.provider_health,
            enrichment=task.enrichment or EnrichmentData(),
            results=task.results,
            relationships=relationships,
        )
    )
    if pipeline_timed_out:
        task.error = "Pipeline timeout exceeded; partial result"
        logger.warning("IOC deadline reached for task %s (%s); partial result", task.task_id, ioc_type)
        await _emit_error_event(task, "Pipeline", "Pipeline timeout exceeded")


def get_task(task_id: str) -> Optional[AnalysisTask]:
    with _dict_lock:
        task = _tasks.get(task_id)
    if task is not None:
        return task
    return None


async def get_task_redis(task_id: str) -> Optional[AnalysisTask]:
    with _dict_lock:
        task = _tasks.get(task_id)
    if task is not None:
        return task
    if cache is not None:
        try:
            data = await cache.get_task(task_id)
            if data is not None:
                with _dict_lock:
                    _tasks[task_id] = AnalysisTask.from_dict(data)
                    return _tasks[task_id]
        except Exception as exc:
            logger.debug("get_task_redis(%s) cache read failed: %s", task_id, exc)
    return None


TERMINAL_TASK_STATES = frozenset({"done", "error", "cancelled"})


def register_pending_task(
    task_id: str,
    ioc_value: str,
    ioc_type: str,
    *,
    password_prehashed: bool = False,
) -> AnalysisTask:
    """Make a submitted lookup visible before it gets a lookup slot.

    ``POST /api/lookup`` queues analyses behind MAX_CONCURRENT_LOOKUPS.  Without
    this record a queued task was unknown until ``run_analysis`` started, so
    polling it returned 404 "Task not found" and the UI gave up on a lookup
    that was merely waiting.  ``ioc_value`` must already be safe to store
    (passwords are digested by the caller).
    """
    task = AnalysisTask(
        task_id=task_id,
        status="pending",
        ioc_value=ioc_value,
        normalized=ioc_value,
        ioc_type=ioc_type,
        password_prehashed=password_prehashed,
        stages=[
            StageInfo("Classify & Normalize", message="Queued: waiting for a free lookup slot"),
            StageInfo("Enrichment"),
            StageInfo("Scoring & Relations"),
        ],
    )
    with _dict_lock:
        _tasks[task_id] = task
    return task


def register_running_task(task_id: str, runner: asyncio.Task) -> None:
    """Let ``cancel_analysis`` reach a lookup that is still queued."""
    with _dict_lock:
        _running_tasks[task_id] = runner


def release_running_task(task_id: str, runner: asyncio.Task) -> None:
    with _dict_lock:
        if _running_tasks.get(task_id) is runner:
            _running_tasks.pop(task_id, None)


async def mark_task_cancelled(task_id: str, reason: str = "Analysis cancelled") -> None:
    """Terminal state for a lookup cancelled before run_analysis started."""
    task = get_task(task_id)
    if task is not None and task.status not in TERMINAL_TASK_STATES:
        task.error = reason
        await _publish_terminal_state(task, "cancelled")
    _unregister_running(task_id)


async def cleanup_old_tasks(max_age: float = 3600):
    now = time.time()
    with _dict_lock:
        to_remove = [
            tid for tid, t in _tasks.items()
            if now - t.created_at > max_age and t.status in TERMINAL_TASK_STATES
        ]
        for tid in to_remove:
            _tasks.pop(tid, None)
            _task_queues.pop(tid, None)


# --- SSE streaming ---

SSE_QUEUE_MAXSIZE = 500


def get_task_queue(task_id: str) -> asyncio.Queue:
    with _dict_lock:
        if task_id not in _task_queues:
            _task_queues[task_id] = asyncio.Queue(maxsize=SSE_QUEUE_MAXSIZE)
        return _task_queues[task_id]


def cleanup_task_queue(task_id: str):
    with _dict_lock:
        _task_queues.pop(task_id, None)


async def _emit_event(task_id: str, event: str, data: dict):
    with _dict_lock:
        queue = _task_queues.get(task_id)
    if queue is None:
        return
    try:
        queue.put_nowait((event, data))
    except asyncio.QueueFull:
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            queue.put_nowait((event, data))
        except asyncio.QueueFull:
            pass


async def _emit_stage_event(task: AnalysisTask, stage_name: str, status: str, message: str = "", progress: float = 0.0):
    await _emit_event(task.task_id, "stage", {
        "name": stage_name, "status": status, "message": message, "progress": progress,
    })


async def _emit_result_event(task: AnalysisTask, result: NormalizedResult):
    await _emit_event(task.task_id, "result", {
        "source": result.source, "verdict": result.verdict, "score": result.raw_score,
    })


async def _emit_error_event(task: AnalysisTask, stage_name: str, message: str):
    await _emit_event(task.task_id, "task_error", {
        "stage": stage_name, "message": message,
    })


async def _emit_done_event(task: AnalysisTask):
    await _emit_event(task.task_id, "done", {
        "status": task.status, "progress": task.progress, "error": task.error,
    })


def _register_running(task_id: str):
    current = asyncio.current_task()
    if current is not None:
        with _dict_lock:
            _running_tasks[task_id] = current


def _unregister_running(task_id: str):
    with _dict_lock:
        _running_tasks.pop(task_id, None)


def cancel_analysis(task_id: str) -> bool:
    """Cancel only the running analysis for this task (used on client disconnect)."""
    with _dict_lock:
        running = _running_tasks.get(task_id)
    if running is None:
        return False
    running.cancel()
    return True
