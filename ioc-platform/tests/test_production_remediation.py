"""Regression coverage for the production IOC semantics and orchestration contract."""

import asyncio
import base64
import time
from pathlib import Path

from app.backend.adapters.base import NormalizedResult, SourceAdapter
from app.backend.adapters.virus_total import VirusTotalAdapter
from app.backend.cache import LocalFileCache
from app.backend.classifier import classify_ioc, normalize_ioc
from app.backend.domain_router import route_assessment_domain
from app.backend.evidence import normalize_provider_result
from app.backend.provider_capabilities import build_provider_plan
from app.backend.rate_limiter import RateLimiter
from app.backend.scorer import aggregate_evidence


def test_canonical_normalization_and_domain_routing():
    assert normalize_ioc("Example.COM.").value == "example.com"
    assert normalize_ioc("https://EXAMPLE.com:443/a%2Fb/").value == "https://example.com/a%2Fb/"
    assert normalize_ioc("2001:0db8:0:0:0:0:0:1").value == "2001:db8::1"
    assert classify_ioc(r"C:\Windows\Temp\payload.exe") == "windows_path"
    assert classify_ioc("/var/tmp/payload") == "linux_path"
    assert classify_ioc("a" * 128) == "sha512"
    assert classify_ioc("T1" + "A" * 68) == "tlsh"
    assert route_assessment_domain("cve", "CVE-2024-1").domain == "vulnerability"
    assert route_assessment_domain("mitre_attack", "T1059.001").domain == "attack_technique"
    assert route_assessment_domain("md5", "44d88612fea8a8f36de82e1278abb02f").domain == "security_test_artifact"
    assert route_assessment_domain("user_agent", "Mozilla/5.0").domain == "artifact_metadata"


class _CapabilityAdapter(SourceAdapter):
    name = "ContextOnly"
    supported_types = ["ipv4"]
    produces_reputation = False
    produces_infrastructure_context = True

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name)


def test_provider_plan_is_explicit_about_not_applicable_sources():
    plan = build_provider_plan([_CapabilityAdapter()], "ipv4", "8.8.8.8")
    assert len(plan) == 1
    assert plan[0].applicable is True
    assert plan[0].assessment_domain == "ioc_reputation"


def test_nested_malwarebazaar_vendor_intel_becomes_auditable_evidence():
    result = NormalizedResult(
        ioc="6408276cdfd12a1d5d3ed7256bfba639",
        ioc_type="md5",
        source="MalwareBazaar",
        provider_verdict="record_found",
        normalized_verdict="unknown",
        raw_data={
            "record_id": "mb-6408276",
            "vendor_intel": {
                "ANY.RUN": {"verdict": "malicious", "malware_family": "RustyStealer"},
                "VirusTotal": {"malicious": 12, "suspicious": 1},
            },
        },
    )
    assessment = aggregate_evidence(result.ioc, result.ioc_type, [result])
    nested = assessment.provider_breakdown[0].metadata["evidence_items"]
    assert assessment.final_verdict == "malicious"
    assert assessment.malware_families == ["RustyStealer"]
    assert len(nested) == 2
    assert {item["source"] for item in nested} == {"ANY.RUN", "VirusTotal"}
    assert all(item["evidence_hash"] for item in nested)


def test_virustotal_url_lookup_uses_the_api_url_identifier():
    adapter = VirusTotalAdapter()
    value = "https://evil.example/path?id=1"
    expected = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    assert adapter._endpoint(value, "url").endswith(f"/urls/{expected}")


def test_http_client_errors_cannot_be_reclassified_as_not_found():
    result = NormalizedResult(
        ioc="https://evil.example/path",
        ioc_type="url",
        source="VirusTotal",
        status="not_found",
        execution_state="not_found",
        tags=["http_400"],
    )
    normalize_provider_result(result)
    assert result.http_status == 400
    assert result.execution_state == "invalid_request"
    assert result.status == "error"


def test_detection_ratio_is_backfilled_for_cached_or_legacy_records():
    result = NormalizedResult(
        ioc="8.8.8.8",
        ioc_type="ipv4",
        source="VirusTotal",
        raw_data={"detection_ratio": "16/91"},
    )
    normalize_provider_result(result)
    assert result.detection_count == 16
    assert result.total_engines == 91


def test_cve_provider_reputation_labels_are_quarantined_from_assessment():
    result = NormalizedResult(
        ioc="CVE-2024-21412",
        ioc_type="cve",
        source="legacy-cve-adapter",
        verdict="malicious",
        provider_verdict="malicious",
        severity="high",
        cvss_score=8.1,
        raw_data={"cve_id": "CVE-2024-21412"},
    )
    normalize_provider_result(result, "vulnerability")
    assert result.verdict == "unknown"
    assert result.provider_verdict == "vulnerability_record"
    assert result.normalized_verdict == "unknown"
    assert result.raw_data["provider_native_verdict"] == "malicious"


def test_security_test_artifact_has_neutral_risk_and_explicit_classification():
    ioc = "44d88612fea8a8f36de82e1278abb02f"
    assessment = aggregate_evidence(ioc, "md5", [
        NormalizedResult(ioc=ioc, ioc_type="md5", source="VirusTotal", verdict="malicious", raw_score=1.0),
    ])
    assert assessment.assessment_domain == "security_test_artifact"
    assert assessment.final_verdict == "malicious_test_artifact"
    assert assessment.classification == "known_security_test_artifact"
    assert assessment.normalized_score == 0.0
    assert assessment.provider_breakdown[0].evidence_class == "test_artifact"
    assert assessment.provider_breakdown[0].contribution == "neutral"


def test_context_assessment_is_partial_when_a_supported_provider_fails():
    results = [
        NormalizedResult(
            ioc="person@example.com",
            ioc_type="email",
            source="Hunter.io",
            execution_state="success",
            status="found",
            verdict="unknown",
            raw_data={"reputation": "none"},
        ),
        NormalizedResult(
            ioc="person@example.com",
            ioc_type="email",
            source="StopForumSpam",
            execution_state="unavailable",
            status="error",
            verdict="unknown",
        ),
    ]
    assessment = aggregate_evidence(results[0].ioc, results[0].ioc_type, results)
    assert assessment.assessment_domain == "identity_reputation"
    assert assessment.assessment_status == "partial"


def test_not_applicable_plan_rows_do_not_make_healthy_reputation_partial():
    results = [
        NormalizedResult(
            ioc="8.8.8.8",
            ioc_type="ipv4",
            source="VirusTotal",
            verdict="clean",
            cached=True,
            cache_status="cached",
        ),
        NormalizedResult(
            ioc="8.8.8.8",
            ioc_type="ipv4",
            source="Hunter.io",
            verdict="unknown",
            status="not_applicable",
            execution_state="not_applicable",
        ),
    ]
    assessment = aggregate_evidence(results[0].ioc, results[0].ioc_type, results)
    assert assessment.assessment_status == "complete"
    assert assessment.cache_status == "cached"


def test_successful_unknown_provider_response_stays_unknown_not_not_found():
    result = NormalizedResult(
        ioc="example.com",
        ioc_type="domain",
        source="Provider",
        verdict="unknown",
    )
    assert result.execution_state == "success"
    assert result.status == "found"


def test_known_ip_conflict_preserves_clean_source_and_supporting_sources():
    results = [
        NormalizedResult(ioc="47.236.149.142", ioc_type="ipv4", source="ThreatFox", verdict="malicious", confidence="high", source_record_id="tf-1"),
        NormalizedResult(ioc="47.236.149.142", ioc_type="ipv4", source="VirusTotal", verdict="suspicious", provider_verdict="15/91", detection_count=15, total_engines=91, source_record_id="vt-1"),
        NormalizedResult(ioc="47.236.149.142", ioc_type="ipv4", source="AlienVault OTX", verdict="suspicious", source_record_id="otx-1"),
        NormalizedResult(ioc="47.236.149.142", ioc_type="ipv4", source="AbuseIPDB", verdict="clean", reports_count=0, source_record_id="abuse-1"),
    ]
    assessment = aggregate_evidence(results[0].ioc, results[0].ioc_type, results)
    assert assessment.final_verdict in {"malicious", "suspicious"}
    assert "ThreatFox" in assessment.malicious_sources
    assert "VirusTotal" in assessment.suspicious_sources
    assert "AlienVault OTX" in assessment.suspicious_sources
    assert "AbuseIPDB" in assessment.clean_sources
    assert assessment.needs_review is True
    assert "AbuseIPDB" in assessment.reason


def test_cve_and_attack_identifiers_never_become_reputation_verdicts():
    cve = NormalizedResult(
        ioc="CVE-2021-44228",
        ioc_type="cve",
        source="NVD",
        provider_verdict="record_found",
        normalized_verdict="unknown",
        severity="critical",
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vulnerability_status="modified",
        source_record_id="CVE-2021-44228",
        raw_data={"description": "remote code execution"},
    )
    cve_assessment = aggregate_evidence(cve.ioc, cve.ioc_type, [cve])
    technique_assessment = aggregate_evidence("T1059.001", "mitre_attack", [])
    assert cve_assessment.assessment_domain == "vulnerability"
    assert cve_assessment.final_verdict == "critical"
    assert cve_assessment.final_verdict not in {"malicious", "suspicious"}
    assert technique_assessment.assessment_domain == "attack_technique"
    assert technique_assessment.final_verdict == "technique_metadata"


def test_context_and_security_test_artifact_are_explicit_domains():
    context = aggregate_evidence(r"C:\Users\Public\payload.exe", "windows_path", [])
    eicar = aggregate_evidence("44d88612fea8a8f36de82e1278abb02f", "md5", [])
    assert context.assessment_domain == "artifact_metadata"
    assert context.final_verdict == "context_only"
    assert eicar.assessment_domain == "security_test_artifact"
    assert eicar.final_verdict == "malicious_test_artifact"


def test_expired_local_cache_is_retrievable_as_stale(tmp_path: Path):
    cache = LocalFileCache(str(tmp_path))
    cache.set("provider:md5:abc", {"value": "historical"}, ttl=-1)
    entry = cache.get_entry("provider:md5:abc")
    assert entry is not None
    value, stale = entry
    assert value == {"value": "historical"}
    assert stale is True
    assert cache.get("provider:md5:abc") is None


def test_provider_slots_are_per_provider_and_respect_concurrency():
    async def exercise():
        limiter = RateLimiter()
        active = {"slow": 0, "fast": 0}
        maximum = {"slow": 0, "fast": 0}

        async def work(source: str):
            async with limiter.provider_slot(source, 2, timeout=1):
                active[source] += 1
                maximum[source] = max(maximum[source], active[source])
                await asyncio.sleep(0.01)
                active[source] -= 1

        started = time.monotonic()
        await asyncio.gather(*(work("slow") for _ in range(8)), *(work("fast") for _ in range(8)))
        elapsed = time.monotonic() - started
        assert maximum == {"slow": 2, "fast": 2}
        assert elapsed < 0.25
        await limiter.close()

    asyncio.run(exercise())


def test_provider_quota_reservation_does_not_leak_tokens_when_denied():
    async def exercise():
        limiter = RateLimiter()
        now = time.time()
        limiter._local_counters["Provider:day"] = [now]
        denied = await limiter.acquire_provider("Provider", 1, 1)
        assert denied.allowed is False
        assert denied.reason == "daily_quota_exhausted"
        assert "Provider" not in limiter._local_counters

        del limiter._local_counters["Provider:day"]
        allowed = await limiter.acquire_provider("Provider", 1, 1)
        assert allowed.allowed is True
        await limiter.close()

    asyncio.run(exercise())


def test_credential_breached_verdict():
    results = [
        NormalizedResult(
            ioc="compromised@example.com",
            ioc_type="email",
            source="Hudson Rock",
            execution_state="success",
            status="found",
            verdict="malicious",
            tags=["infostealer_compromised", "infections:3"],
            reports_count=3,
        ),
    ]
    assessment = aggregate_evidence(results[0].ioc, results[0].ioc_type, results)
    assert assessment.assessment_domain == "identity_reputation"
    assert assessment.final_verdict == "breached"
    assert assessment.classification == "breached"
    assert assessment.normalized_score > 0
    assert assessment.needs_review is True


def test_credential_not_breached_verdict():
    results = [
        NormalizedResult(
            ioc="clean@example.com",
            ioc_type="email",
            source="Hudson Rock",
            execution_state="success",
            status="not_found",
            verdict="clean",
            tags=[],
            reports_count=0,
        ),
    ]
    assessment = aggregate_evidence(results[0].ioc, results[0].ioc_type, results)
    assert assessment.assessment_domain == "identity_reputation"
    assert assessment.final_verdict == "not_breached"
    assert assessment.classification == "not_breached"
    assert assessment.normalized_score == 0.0


def test_public_dns_resolver_dampening():
    results = [
        NormalizedResult(
            ioc="1.1.1.1",
            ioc_type="ipv4",
            source="VirusTotal",
            execution_state="success",
            status="found",
            verdict="clean",
            detection_count=0,
            total_engines=90,
        ),
        NormalizedResult(
            ioc="1.1.1.1",
            ioc_type="ipv4",
            source="AbuseIPDB",
            execution_state="success",
            status="found",
            verdict="clean",
            reports_count=0,
        ),
        NormalizedResult(
            ioc="1.1.1.1",
            ioc_type="ipv4",
            source="Hudson Rock",
            execution_state="success",
            status="found",
            verdict="suspicious",
            tags=["infostealer_compromised", "infections:2"],
            reports_count=2,
        ),
    ]
    assessment = aggregate_evidence("1.1.1.1", "ipv4", results)
    assert assessment.final_verdict in {"benign", "clean"}
    assert assessment.normalized_score == 0.0


def test_threatfox_boundary_matching():
    from app.backend.adapters.threatfox import _matches_target_ioc
    # Substring in URL query parameter or path should NOT match
    assert _matches_target_ioc("https://phish.net/?site=cloudflare.com", "cloudflare.com", "domain") is False
    assert _matches_target_ioc("https://malicious.ru/login/cloudflare.com/index.html", "cloudflare.com", "domain") is False
    # Subdomain, exact domain, or domain with port SHOULD match
    assert _matches_target_ioc("https://sub.cloudflare.com/login", "cloudflare.com", "domain") is True
    assert _matches_target_ioc("cloudflare.com:443", "cloudflare.com", "domain") is True
    assert _matches_target_ioc("cloudflare.com", "cloudflare.com", "domain") is True
