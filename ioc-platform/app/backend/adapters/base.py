from abc import ABC, abstractmethod
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Optional

import httpx
import json


from pydantic import BaseModel, Field, model_validator


class RateLimitConfig(BaseModel):
    requests_per_minute: int = 30
    requests_per_day: int = 1000
    timeout_seconds: float = 10.0
    connect_timeout: float = 5.0
    # Provider-specific controls used by the orchestration layer.  Adapters
    # remain responsible for parsing their API, while the pipeline owns
    # concurrency, throttling, and bounded retries.
    concurrency_limit: int = 2
    max_retries: int = 2
    backoff_factor: float = 0.5
    max_backoff_seconds: float = 8.0
    minimum_interval_seconds: float = 0.0
    cache_ttl_seconds: int | None = None


EXECUTION_STATES = {
    "success", "not_found", "rate_limited", "timeout", "error",
    "invalid_request", "unavailable", "not_applicable",
    "aborted_due_to_ioc_deadline", "batch_deadline_exceeded",
}

NORMALIZED_VERDICTS = {
    "malicious", "suspicious", "clean", "benign", "harmless",
    "undetected", "not_found", "unknown", "unrated", "whitelisted",
    "error",
}


def normalize_provider_verdict(value: object) -> str:
    """Map provider vocabulary to a stable semantic vocabulary.

    ``provider_verdict`` is never discarded.  This mapping intentionally
    keeps ``undetected``, ``not_found``, ``unknown`` and ``unrated`` distinct;
    they describe different kinds of absence of evidence.
    """
    raw = str(value or "unknown").strip().lower().replace("-", "_")
    aliases = {
        "bad": "malicious",
        "malware": "malicious",
        "phishing": "malicious",
        "harmful": "malicious",
        "suspicious": "suspicious",
        "safe": "clean",
        "legitimate": "clean",
        "harmless": "harmless",
        "whitelist": "whitelisted",
        "notfound": "not_found",
        "no_result": "not_found",
        "no_data": "unknown",
        "unrated": "unrated",
    }
    return aliases.get(raw, raw if raw in NORMALIZED_VERDICTS else "unknown")


def infer_execution_state(status: object, verdict: object, tags: object, provider_verdict: object = None) -> str:
    """Derive an explicit execution state from legacy adapter fields."""
    tag_values = {str(tag).strip().lower() for tag in (tags or [])}
    provider_state = str(provider_verdict or "").strip().lower().replace("-", "_")
    if "rate_limited" in tag_values or any("rate_limit" in tag for tag in tag_values):
        return "rate_limited"
    if "timeout" in tag_values or "timed_out" in tag_values:
        return "timeout"
    if any(tag in tag_values for tag in {"invalid_request", "unsupported_type", "invalid_hash_format", "invalid_hash_length"}):
        return "invalid_request"
    if str(status or "").lower() == "unavailable":
        return "unavailable"
    if any(
        tag in tag_values
        for tag in {
            "no_api_key_configured", "feed_unavailable", "lite_api_unavailable",
            "daily_quota_exhausted", "weekly_quota_exhausted", "monthly_quota_exhausted", "out_of_credits",
            "circuit_open", "provider_unavailable",
        }
    ):
        return "unavailable"
    if any(tag in tag_values for tag in {
        "request_error", "unexpected_response", "malformed_response", "unauthorized",
        "invalid_api_key", "auth_error", "quota_exhausted",
    }) or any(tag.startswith("http_4") or tag.startswith("http_5") for tag in tag_values):
        return "error"
    if provider_state in {"rate_limited", "quota_exhausted", "too_many_requests"}:
        return "rate_limited"
    if provider_state in {"record_not_found", "hash_not_found", "no_result", "not_found"}:
        return "not_found"
    if provider_state in {"provider_error", "malformed_response", "unexpected_response", "request_error", "adapter_exception"}:
        return "error"
    if str(status or "").lower() == "not_found":
        return "not_found"
    if str(status or "").lower() == "error" or str(verdict or "").lower() == "error":
        return "error"
    return "success"


def retry_after_seconds(response) -> Optional[float]:
    """Parse the RFC Retry-After header without trusting malformed values."""
    try:
        value = (getattr(response, "headers", {}) or {}).get("Retry-After")
        if value is None:
            return None
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            retry_at = parsedate_to_datetime(str(value))
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=datetime.now().astimezone().tzinfo)
            return max(0.0, (retry_at - datetime.now(retry_at.tzinfo)).total_seconds())
    except (TypeError, ValueError, OverflowError, IndexError):
        return None


RAW_DATA_MAX_BYTES = 10 * 1024
# Small top-level values (counts, flags, verdict strings, short lists) are the
# typed fields scoring reads. They are kept as real JSON when a payload is
# truncated, so one large nested blob (e.g. a full VirusTotal ``api_response``)
# cannot erase ``malicious``/``isWhitelisted``/``match_type`` alongside it.
_PRESERVED_FIELD_MAX_BYTES = 512
_PRESERVED_FIELDS_BUDGET_BYTES = 4 * 1024


def _encoded_size(value: object) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return RAW_DATA_MAX_BYTES + 1


def truncate_raw_data(value: object, limit: int = RAW_DATA_MAX_BYTES) -> dict:
    """Keep provider payloads useful without allowing one response to grow a task.

    The original JSON is retained up to 10 KiB. Larger payloads are represented
    as a clearly-marked JSON string fragment so the response remains safe to
    serialize and inspect in the analyst UI. Small top-level fields are kept as
    structured values next to the fragment so typed evidence survives.
    """
    if not isinstance(value, dict):
        return {}
    if value.get("_truncated") is True and "_json_fragment" in value:
        return value
    try:
        encoded = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        encoded = json.dumps({"serialization_error": str(value)}, ensure_ascii=False)
    size = len(encoded.encode("utf-8"))
    if size <= limit:
        return value
    preserved: dict = {}
    budget = min(_PRESERVED_FIELDS_BUDGET_BYTES, max(0, limit // 2))
    for key, item in value.items():
        if not isinstance(key, str) or key.startswith("_truncat") or key == "_json_fragment":
            continue
        item_size = _encoded_size(item) + len(key) + 4
        if item_size > _PRESERVED_FIELD_MAX_BYTES or item_size > budget:
            continue
        preserved[key] = item
        budget -= item_size
    preserved_size = _encoded_size(preserved)
    fragment_bytes = max(256, limit - 180 - preserved_size)
    fragment = encoded.encode("utf-8")[:fragment_bytes].decode("utf-8", errors="ignore")
    return {
        **preserved,
        "_truncated": True,
        "_original_size_bytes": size,
        "_truncation_limit_bytes": limit,
        "_json_fragment": fragment,
    }


def provider_summary_for(
    source: str,
    verdict: str,
    execution_state: str,
    raw_data: dict | None = None,
    *,
    detection_count: int | None = None,
    total_engines: int | None = None,
    reports_count: int | None = None,
    malware_family: str | None = None,
    tags: list[str] | None = None,
) -> str:
    """Create a compact provider finding for the primary analyst card."""
    if execution_state not in {"success", "not_found"}:
        return {
            "unavailable": "Provider unavailable",
            "rate_limited": "Provider rate limited",
            "timeout": "Provider timed out",
            "error": "Provider returned an error",
            "invalid_request": "Request was rejected by provider",
        }.get(execution_state, execution_state.replace("_", " ").capitalize())
    if execution_state == "not_found":
        return "No matching record"
    raw = raw_data if isinstance(raw_data, dict) else {}
    if detection_count is not None and total_engines:
        return f"{detection_count}/{total_engines} engines flagged"
    ratio = raw.get("detection_ratio")
    if ratio:
        return f"{ratio} engines flagged"
    if reports_count is not None and reports_count > 0:
        return f"{reports_count} report{'' if reports_count == 1 else 's'} returned"
    for key in ("match_count", "breach_count", "pulse_count", "report_count"):
        if isinstance(raw.get(key), (int, float)):
            count = int(raw[key])
            return f"{count} matching record{'' if count == 1 else 's'}"
    if malware_family:
        return f"Family: {malware_family}"
    if raw.get("abuse_confidence_score") is not None:
        return f"Abuse score: {raw['abuse_confidence_score']}/100"
    if raw.get("balance") is not None or raw.get("balance_btc") is not None:
        return f"Balance: {raw.get('balance_btc', raw.get('balance'))}"
    if verdict in {"malicious", "suspicious", "clean", "benign"}:
        return f"Provider verdict: {verdict.capitalize()}"
    tag_list = [str(tag) for tag in (tags or []) if not str(tag).startswith("cached")]
    return tag_list[0].replace("_", " ").capitalize() if tag_list else "Context returned"


class CacheMetadata(BaseModel):
    cache_key: Optional[str] = None
    cached: bool = False
    cache_age: Optional[float] = None
    cache_created_at: Optional[datetime] = None
    retrieved_at: Optional[datetime] = None
    observed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    source_timestamp: Optional[datetime] = None
    status: str = "fresh"  # fresh | cached | expired | bypassed | unavailable
    freshness_class: str = "fresh"
    stale: bool = False


class ProviderHealth(BaseModel):
    """Per-provider health for one lookup or an aggregated batch."""
    source: str
    request_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    rate_limit_count: int = 0
    timeout_count: int = 0
    error_count: int = 0
    unavailable_count: int = 0
    not_found_count: int = 0
    invalid_request_count: int = 0
    retry_count: int = 0
    cache_hit_count: int = 0
    cache_miss_count: int = 0
    total_latency_ms: float = 0.0
    average_latency_ms: float = 0.0
    queue_wait_ms: float = 0.0
    average_queue_wait_ms: float = 0.0
    total_latency: float = 0.0
    average_latency: float = 0.0
    queue_wait: float = 0.0
    last_execution_state: str = "unknown"


class NormalizedResult(BaseModel):
    ioc: str
    ioc_type: str
    source: str
    # ``verdict`` is retained for API compatibility and is the platform's
    # legacy normalized field.  New consumers should use
    # ``normalized_verdict`` and inspect ``provider_verdict`` separately.
    verdict: str = "unknown"
    status: str = "found"  # legacy: found | not_found | error
    execution_state: str = "success"
    assessment_domain: str = "ioc_reputation"
    domain_classification: Optional[str] = None
    provider_verdict: Optional[str] = None
    normalized_verdict: str = "unknown"
    raw_score: Optional[float] = None
    confidence: str = "low"
    tags: list[str] = []
    categories: list[str] = []
    malware_family: Optional[str] = None
    mitre_attck: list[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    related_iocs: list[tuple[str, str]] = []
    source_link: Optional[str] = None
    reports_count: Optional[int] = None
    # Provider-native detection telemetry, when the source exposes it.  These
    # fields are kept separate from raw_score because provider score scales
    # are not comparable across sources.
    detection_count: Optional[int] = None
    total_engines: Optional[int] = None
    cached: bool = False
    cache_age: Optional[float] = None
    cache_key: Optional[str] = None
    cache_created_at: Optional[datetime] = None
    retrieved_at: Optional[datetime] = None
    observed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    source_timestamp: Optional[datetime] = None
    cache_status: str = "fresh"
    freshness_class: str = "fresh"
    stale: bool = False
    cache_metadata: CacheMetadata = Field(default_factory=CacheMetadata)
    latency_ms: Optional[float] = None
    queue_wait_ms: Optional[float] = None
    network_latency_ms: Optional[float] = None
    retry_count: int = 0
    http_status: Optional[int] = None
    retry_after_seconds: Optional[float] = None
    request_made: bool = True
    reports: list[dict] = []
    raw_data: dict = {}
    provider_summary: str = ""
    samples: list[str] = []
    dropped_files: list[str] = []
    registry_keys: list[str] = []
    network_iocs: list[tuple[str, str]] = []
    process_tree: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    vulnerability_status: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    cwe: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    exploit_status: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    evidence_items: list[dict] = Field(default_factory=list)
    provenance_family: Optional[str] = None
    source_record_id: Optional[str] = None
    record_fingerprint: Optional[str] = None
    source_independence_group: Optional[str] = None
    evidence_hash: Optional[str] = None
    duplicate_of: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _coerce_none_lists(cls, data):
        if isinstance(data, dict):
            data = dict(data)
            data["raw_data"] = truncate_raw_data(data.get("raw_data", {}))
            provider_verdict = data.get("provider_verdict")
            if provider_verdict is None:
                provider_verdict = data.get("verdict", "unknown")
                data["provider_verdict"] = str(provider_verdict)
            normalized_verdict = data.get("normalized_verdict")
            if normalized_verdict is None or normalized_verdict == "unknown":
                normalized_from_provider = normalize_provider_verdict(provider_verdict)
                # Adapter authors often retain a provider-native value such as
                # ``15/91`` in provider_verdict while explicitly setting the
                # platform semantic verdict. Do not erase that semantic field
                # merely because the native vocabulary is unknown.
                data["normalized_verdict"] = (
                    normalized_from_provider
                    if normalized_from_provider != "unknown"
                    else normalize_provider_verdict(data.get("verdict", "unknown"))
                )
            if data.get("execution_state") in (None, "", "success"):
                data["execution_state"] = infer_execution_state(
                    data.get("status", "found"),
                    data.get("verdict", provider_verdict),
                    data.get("tags", []),
                    provider_verdict,
                )
            # Provider payloads are not a stable schema. Keep optional
            # enrichment metadata from turning one malformed upstream field
            # into a failed IOC analysis.
            for field_name in ("tags", "categories", "mitre_attck", "samples", "dropped_files", "registry_keys", "cwe", "affected_products", "references", "evidence_items"):
                values = data.get(field_name)
                if values is None:
                    data[field_name] = []
                elif isinstance(values, (list, tuple, set)):
                    data[field_name] = list(dict.fromkeys(value.strip() for value in values if isinstance(value, str) and value.strip()))
                elif isinstance(values, str) and values.strip():
                    data[field_name] = [values.strip()]
                else:
                    data[field_name] = []

            for field_name in ("related_iocs", "network_iocs"):
                values = data.get(field_name)
                if not isinstance(values, (list, tuple, set)):
                    data[field_name] = []
                    continue
                data[field_name] = [
                    (str(value[0]).strip(), str(value[1]).strip())
                    for value in values
                    if isinstance(value, (list, tuple)) and len(value) >= 2 and value[0] is not None and value[1] is not None
                    and str(value[0]).strip() and str(value[1]).strip()
                ]

            for field_name in ("reports",):
                if not isinstance(data.get(field_name), list):
                    data[field_name] = []
        return data

    @model_validator(mode="after")
    def _normalize_lists(self):
        self.provider_verdict = self.provider_verdict or self.verdict or "unknown"
        self.normalized_verdict = normalize_provider_verdict(
            self.normalized_verdict or self.provider_verdict
        )
        if self.assessment_domain != "vulnerability" and self.verdict == "unknown" and self.normalized_verdict not in {"unknown", "not_found", "undetected", "unrated"}:
            self.verdict = self.normalized_verdict
        if self.execution_state not in EXECUTION_STATES:
            self.execution_state = infer_execution_state(self.status, self.verdict, self.tags, self.provider_verdict)
        self.raw_data = truncate_raw_data(self.raw_data)
        if not self.provider_summary:
            self.provider_summary = provider_summary_for(
                self.source,
                self.normalized_verdict or self.verdict,
                self.execution_state,
                self.raw_data,
                detection_count=self.detection_count,
                total_engines=self.total_engines,
                reports_count=self.reports_count,
                malware_family=self.malware_family,
                tags=self.tags,
            )
        if self.execution_state == "not_found":
            self.status = "not_found"
        elif self.execution_state == "not_applicable":
            self.status = "not_applicable"
        elif self.execution_state == "unavailable":
            self.status = "unavailable"
        elif self.execution_state in {"aborted_due_to_ioc_deadline", "batch_deadline_exceeded"}:
            self.status = self.execution_state
        elif self.execution_state != "success":
            self.status = "error"
        if self.cache_metadata:
            # Keep the flat fields and nested metadata interoperable for old
            # clients and for serialized task/cache records.
            if self.cached and not self.cache_metadata.cached:
                self.cache_metadata.cached = True
            self.cache_metadata.cache_age = self.cache_age if self.cache_age is not None else self.cache_metadata.cache_age
            self.cache_metadata.cache_key = self.cache_key or self.cache_metadata.cache_key
            self.cache_metadata.cache_created_at = self.cache_created_at or self.cache_metadata.cache_created_at
            self.cache_metadata.retrieved_at = self.retrieved_at or self.cache_metadata.retrieved_at
            self.cache_metadata.observed_at = self.observed_at or self.cache_metadata.observed_at
            self.cache_metadata.expires_at = self.expires_at or self.cache_metadata.expires_at
            self.cache_metadata.source_timestamp = self.source_timestamp or self.cache_metadata.source_timestamp
            self.cache_metadata.freshness_class = self.freshness_class or self.cache_metadata.freshness_class
            self.cache_metadata.stale = self.stale or self.cache_metadata.stale
            if self.cache_status != "fresh":
                self.cache_metadata.status = self.cache_status
            else:
                self.cache_status = self.cache_metadata.status
            self.cached = self.cached or self.cache_metadata.cached
            self.cache_age = self.cache_age if self.cache_age is not None else self.cache_metadata.cache_age
            self.cache_key = self.cache_key or self.cache_metadata.cache_key
            self.cache_created_at = self.cache_created_at or self.cache_metadata.cache_created_at
            self.retrieved_at = self.retrieved_at or self.cache_metadata.retrieved_at
            self.observed_at = self.observed_at or self.cache_metadata.observed_at
            self.expires_at = self.expires_at or self.cache_metadata.expires_at
            self.source_timestamp = self.source_timestamp or self.cache_metadata.source_timestamp
            self.freshness_class = self.cache_metadata.freshness_class or self.freshness_class
            self.stale = self.stale or self.cache_metadata.stale
        if self.execution_state not in {"success", "not_found"}:
            return self
        if self.verdict == "error":
            self.status = "error"
        # A successful provider response with no classification is still an
        # answered lookup. Only an explicit not-found status/provider state
        # may become ``not_found``; absence of fields is not proof that the
        # provider searched and found nothing.
        return self


class GeoIPInfo(BaseModel):
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    is_anycast: bool = False


class WhoisInfo(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    nameservers: list[str] = []
    status_codes: list[str] = []
    registrant_country: Optional[str] = None
    dnssec: Optional[str] = None
    domain_age_days: Optional[int] = None
    is_newly_registered: bool = False
    abuse_email: Optional[str] = None
    org: Optional[str] = None
    privacy_protected: bool = False
    fallback_tier_used: Optional[int] = None


class DNSInfo(BaseModel):
    a: list[str] = []
    aaaa: list[str] = []
    mx: list[str] = []
    ns: list[str] = []
    txt: list[str] = []
    cname: list[str] = []


class SSLInfo(BaseModel):
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    fingerprint: Optional[str] = None
    subject_alt_names: list[str] = []
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False
    days_remaining: Optional[int] = None


class ReverseDNSInfo(BaseModel):
    hostnames: list[str] = []


class SubdomainInfo(BaseModel):
    subdomains: list[str] = []


class PassiveDNSInfo(BaseModel):
    records: list[dict] = []


class CVEInfo(BaseModel):
    is_in_kev: bool = False
    kev_date_added: str = ""
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    cvss_score: Optional[float] = None
    cvss_severity: str = ""
    cvss_vector: str = ""
    cvss_attack_vector: str = ""
    cvss_complexity: str = ""
    cvss_privileges_required: str = ""
    cvss_user_interaction: str = ""
    cwe: list[str] = []
    references: list[str] = []
    public_exploits_exist: bool = False
    exploit_sources: list[str] = []
    poc_available: bool = False
    affected_products: list[str] = []
    cvss_breakdown: dict[str, object] = Field(default_factory=dict)
    vulnerability_status: Optional[str] = None
    published_at: Optional[str] = None
    modified_at: Optional[str] = None
    exploit_status: str = "unknown"


class BreachInfo(BaseModel):
    breach_count: Optional[int] = 0
    breach_names: list[str] = []
    most_recent_breach: str = ""
    exposed_data_types: list[str] = Field(default_factory=list)
    source: str = ""


class FaviconInfo(BaseModel):
    favicon_hash: int = 0
    favicon_url: str = ""


class EmailSecurityInfo(BaseModel):
    spf: str = "missing"
    dkim: str = "missing"
    dmarc: str = "missing"


class HostIntelligence(BaseModel):
    """Structured host infrastructure data from Shodan InternetDB / Censys."""
    open_ports: list[int] = []
    port_services: dict[int, str] = {}  # {443: "HTTPS/nginx", 22: "SSH/OpenSSH"}
    unpatched_cves: list[str] = []  # CVE IDs detected by Shodan
    cpes: list[str] = []  # Software inventory (CPE strings)
    tags: list[str] = []  # Infrastructure tags: "vpn", "tor", "cloud"
    hostnames: list[str] = []  # PTR + forward hostnames
    source: str = ""  # "internetdb" | "shodan_api" | "censys" | "active_scan"


class WebPreviewInfo(BaseModel):
    """Structured web page preview data from urlscan.io."""
    screenshot_url: Optional[str] = None  # proxied URL via /api/screenshot
    page_title: Optional[str] = None
    server: Optional[str] = None
    language: Optional[str] = None
    domain_age_days: Optional[int] = None
    tls_issuer: Optional[str] = None
    tls_valid_days: Optional[int] = None
    asn_name: Optional[str] = None
    detected_brands: list[str] = []
    detected_technologies: list[str] = []
    mime_type: Optional[str] = None
    scan_uuid: Optional[str] = None


class InfostealerIntel(BaseModel):
    """Structured infostealer attack surface data from Hudson Rock Cavalier."""
    total_employee_compromises: int = 0
    total_client_compromises: int = 0
    top_corporate_services: list[str] = []  # e.g. ["okta.corp.com", "vpn.corp.com"]
    top_external_services: list[str] = []
    stealer_families: dict[str, int] = {}  # e.g. {"Lumma": 45, "RedLine": 12}
    password_strength_weak_pct: Optional[float] = None
    password_strength_strong_pct: Optional[float] = None
    total_compromised_urls: Optional[int] = None
    date_range: Optional[str] = None  # "2023-01 to 2025-06"


class EnrichmentData(BaseModel):
    geoip: Optional[GeoIPInfo] = None
    open_ports: list[int] = []  # kept for backward compat; prefer host_intel
    whois: Optional[WhoisInfo] = None
    dns: Optional[DNSInfo] = None
    ssl: Optional[SSLInfo] = None
    reverse_dns: Optional[ReverseDNSInfo] = None
    subdomains: Optional[SubdomainInfo] = None
    cve: Optional[CVEInfo] = None
    breach: Optional[BreachInfo] = None
    favicon: Optional[FaviconInfo] = None
    email_security: Optional[EmailSecurityInfo] = None
    passive_dns: Optional[PassiveDNSInfo] = None
    redirect_chain: list[dict] = []
    url_preview: dict = {}
    extra: dict = {}
    relationships: list[dict] = []
    completeness: dict[str, str] = {}
    analysis_notes: list[str] = []
    # Phase 1 structured intelligence fields
    host_intel: Optional[HostIntelligence] = None
    web_preview: Optional[WebPreviewInfo] = None
    infostealer: Optional[InfostealerIntel] = None
    abuse_reports: list[dict] = []  # Structured AbuseIPDB verbose reports
    hosting_ip_intel: dict = {}  # Domain→IP pivot results
    malware_urls: list[str] = []  # OTX /url_list + URLhaus URLs on host
    associated_hashes: list[str] = []  # OTX /malware hashes for IP/domain


class SourceWeight(BaseModel):
    name: str
    weight: float = 1.0
    verdict: str
    score: Optional[float] = None
    confidence: Optional[str] = None


class EvidenceObservation(BaseModel):
    """Comparable, explainable evidence derived from one provider result."""

    source: str
    status: str = "unknown"  # success | not_found | rate_limited | timeout | error | unavailable | invalid_request
    execution_state: str = "success"
    verdict: str = "unknown"
    provider_verdict: str = "unknown"
    normalized_verdict: str = "unknown"
    role: str = "threat"  # threat | supporting | context | health
    evidence_class: str = "contextual"  # direct | supporting | contextual | negative | conflicting
    weight: float = 0.0
    normalized_signal: float = 0.0
    contribution: str = "neutral"  # positive | negative | neutral | excluded
    confidence: str = "low"
    reason: str = ""
    detection_count: Optional[int] = None
    total_engines: Optional[int] = None
    reports_count: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    malware_family: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    cached: bool = False
    cache_age: Optional[float] = None
    observed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    source_timestamp: Optional[datetime] = None
    provenance: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
    assessment_domain: str = "ioc_reputation"
    evidence_hash: Optional[str] = None
    source_record_id: Optional[str] = None
    provenance_family: Optional[str] = None
    source_independence_group: Optional[str] = None
    duplicate_of: Optional[str] = None


class IOCAssessment(BaseModel):
    """The authoritative IOC-level assessment built from provider evidence."""

    ioc: str
    normalized_ioc: Optional[str] = None
    ioc_type: str
    assessment_domain: str = "ioc_reputation"
    classification: Optional[str] = None
    final_verdict: str = "unknown"
    risk_score: float = 0.0
    confidence_score: float = 0.0
    confidence: str = "low"
    normalized_score: float = 0.0
    evidence_strength: float = 0.0
    coverage: float = 0.0
    assessment_status: str = "complete"
    review_reasons: list[str] = Field(default_factory=list)
    freshness: str = "unavailable"
    evidence_counts: dict[str, int] = Field(default_factory=dict)
    needs_review: bool = False
    cache_status: str = "fresh"  # fresh | cached | mixed | unavailable
    evidence_summary: dict[str, object] = Field(default_factory=dict)
    provider_breakdown: list[EvidenceObservation] = Field(default_factory=list)
    # The plan is kept separate from executed evidence so unsupported
    # provider/IOC combinations remain explicit without flooding result
    # payloads with synthetic not-applicable observations.
    provider_plan: list[dict] = Field(default_factory=list)
    provider_health: list[ProviderHealth] = Field(default_factory=list)
    relationships: list[dict] = Field(default_factory=list)
    malicious_sources: list[str] = Field(default_factory=list)
    suspicious_sources: list[str] = Field(default_factory=list)
    clean_sources: list[str] = Field(default_factory=list)
    unknown_sources: list[str] = Field(default_factory=list)
    not_found_sources: list[str] = Field(default_factory=list)
    rate_limited_sources: list[str] = Field(default_factory=list)
    unavailable_sources: list[str] = Field(default_factory=list)
    error_sources: list[str] = Field(default_factory=list)
    strongest_evidence: list[EvidenceObservation] = Field(default_factory=list)
    supporting_evidence: list[EvidenceObservation] = Field(default_factory=list)
    conflicting_evidence: list[EvidenceObservation] = Field(default_factory=list)
    negative_evidence: list[EvidenceObservation] = Field(default_factory=list)
    context: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    mitre_attck: list[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    reason: str = "Insufficient reliable evidence to assess this IOC."
    analyst_review_recommended: bool = False
    techniques: list[dict] = Field(default_factory=list)
    vulnerabilities: list[dict] = Field(default_factory=list)
    timestamps: dict[str, object] = Field(default_factory=dict)
    provider_summary: list[dict] = Field(default_factory=list)
    provider_health_summary: list[dict] = Field(default_factory=list)
    provenance: list[dict] = Field(default_factory=list)
    assessment_engine_version: str = "2026.08.1"
    normalization_version: str = "2026.08.1"
    scoring_policy_version: str = "2026.08.1"
    provider_config_version: str = "1"
    analyzed_at: Optional[datetime] = None


class CompositeScore(BaseModel):
    score: float = 0.0
    verdict: str = "unknown"
    confidence: str = "low"
    sources_contributing: int = 0
    source_breakdown: list[SourceWeight] = []
    # Vote/agreement transparency (R): how many meaningful per-source votes
    # landed on each verdict, and the share of weight held by malicious claims.
    malicious_sources: int = 0
    suspicious_sources: int = 0
    clean_sources: int = 0
    agreement: float = 0.0


class LookupResponse(BaseModel):
    input: str
    task_id: Optional[str] = None
    normalized: str
    ioc_type: str
    password_prehashed: bool = False

    composite: CompositeScore

    final_assessment: Optional[IOCAssessment] = None
    provider_health: list[ProviderHealth] = Field(default_factory=list)
    enrichment: EnrichmentData = EnrichmentData()
    results: list[NormalizedResult] = []
    relationships: list[dict] = []
    executive_summary: str = ""


_PLACEHOLDER_KEYS = {"", "null", "none", "true", "false", "1", "0", "yes", "no", "y", "n", "t", "f", "placeholder", "your_api_key", "api_key", "test", "dummy", "key"}


def is_valid_api_key(key: str) -> bool:
    return key.strip().lower() not in _PLACEHOLDER_KEYS and len(key.strip()) >= 4


class SourceAdapter(ABC):
    name: str = ""
    supported_types: list[str] = []
    public_without_key: bool = False
    operations: tuple[str, ...] = ("lookup",)
    evidence_roles: tuple[str, ...] = ("threat",)
    provenance_family: str = "independent"
    reliability: float = 0.5
    direct_threat_evidence: bool | None = None
    produces_reputation: bool | None = None
    produces_vulnerability_intelligence: bool | None = None
    produces_infrastructure_context: bool | None = None
    produces_metadata: bool | None = None
    produces_relationships: bool | None = None
    rate_limit: RateLimitConfig = RateLimitConfig()
    _client: httpx.AsyncClient | None = None

    def set_client(self, client: httpx.AsyncClient):
        self._client = client

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        from app.backend.http_client import get_timeout
        t = get_timeout(self.name)
        return httpx.AsyncClient(timeout=t)

    def _check_circuit(self) -> bool:
        from app.backend.circuit_breaker import get_breaker
        return get_breaker(self.name).allow_request()

    def _record_success(self):
        from app.backend.circuit_breaker import get_breaker
        get_breaker(self.name).record_success()

    def _record_failure(self):
        from app.backend.circuit_breaker import get_breaker
        get_breaker(self.name).record_failure()

    @abstractmethod
    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        ...
