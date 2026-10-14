import sys

sys.path.insert(0, ".")

from app.backend.adapters.base import EnrichmentData, GeoIPInfo, NormalizedResult
from app.backend.evidence import normalize_provider_result
from app.backend.scorer import aggregate_evidence


def result(source, verdict, ioc="8.8.8.8", ioc_type="ipv4", **kwargs):
    return NormalizedResult(
        ioc=ioc,
        ioc_type=ioc_type,
        source=source,
        verdict=verdict,
        **kwargs,
    )


def test_not_found_unknown_and_health_failures_are_not_reputation_evidence():
    assessment = aggregate_evidence("example.com", "domain", [
        result("ThreatFox", "unknown", ioc="example.com", status="not_found"),
        result("VirusTotal", "unknown", ioc="example.com", tags=["rate_limited"]),
        result("URLhaus", "error", ioc="example.com", tags=["timeout"]),
    ])
    assert assessment.final_verdict == "unknown"
    assert assessment.malicious_sources == []
    assert set(assessment.error_sources) == {"VirusTotal", "URLhaus"}
    assert assessment.unknown_sources == ["ThreatFox"]


def test_not_found_alone_is_not_complete_coverage_or_clean():
    assessment = aggregate_evidence("325cdd043d594116ac783d779ebeab207883966ab4c41c7004cd41f59976700f", "sha256", [
        result("VirusTotal", "unknown", ioc="325cdd04", ioc_type="sha256", status="not_found"),
        result("MalwareBazaar", "unknown", ioc="325cdd04", ioc_type="sha256", status="not_found"),
        result("ThreatFox", "unknown", ioc="325cdd04", ioc_type="sha256", status="not_found"),
    ])
    assert assessment.final_verdict == "unknown"
    assert assessment.evidence_strength == 0.0
    assert assessment.assessment_status == "partial"
    assert assessment.needs_review is True
    assert any("not-found" in reason for reason in assessment.review_reasons)


def test_email_is_not_clean_when_breach_source_is_unavailable():
    assessment = aggregate_evidence("billing-update@apple-security-check.com", "email", [
        result("AbstractAPI", "unknown", ioc="billing-update@apple-security-check.com", ioc_type="email", tags=["no_api_key_configured"]),
        result("Hunter.io", "suspicious", ioc="billing-update@apple-security-check.com", ioc_type="email", confidence="medium"),
        result("Hudson Rock", "unknown", ioc="billing-update@apple-security-check.com", ioc_type="email", status="not_found"),
        result("StopForumSpam", "unknown", ioc="billing-update@apple-security-check.com", ioc_type="email", status="not_found"),
    ])
    assert assessment.final_verdict != "not_breached"
    assert assessment.needs_review is True
    assert assessment.review_reasons


def test_email_is_not_breached_when_every_source_answers():
    # "not_breached" is a claim about breach/infostealer data, so at least one
    # exposure source (Hudson Rock here) must have answered.
    assessment = aggregate_evidence("user@example.com", "email", [
        result("AbstractAPI", "unknown", ioc="user@example.com", ioc_type="email", status="not_found"),
        result("Hunter.io", "unknown", ioc="user@example.com", ioc_type="email", status="not_found"),
        result("Hudson Rock", "unknown", ioc="user@example.com", ioc_type="email", status="not_found"),
    ])
    assert assessment.final_verdict == "not_breached"
    assert assessment.needs_review is False


def test_email_without_any_exposure_source_is_not_claimed_not_breached():
    assessment = aggregate_evidence("user@example.com", "email", [
        result("AbstractAPI", "unknown", ioc="user@example.com", ioc_type="email", status="not_found"),
        result("Hunter.io", "unknown", ioc="user@example.com", ioc_type="email", status="not_found"),
    ])
    assert assessment.final_verdict == "unknown"
    assert "exposure" in assessment.reason


def test_infrastructure_context_does_not_raise_score_by_itself():
    assessment = aggregate_evidence("185.199.108.153", "ipv4", [
        result("Shodan", "unknown", tags=["ports:80,443", "org:Fastly"]),
        result("Censys", "unknown", tags=["active_ip", "asn:54113"]),
        result("IPinfo", "unknown", tags=["asn_name:Fastly"]),
    ], EnrichmentData(geoip=GeoIPInfo(org="Fastly"), open_ports=[80, 443]))
    assert assessment.final_verdict == "unknown"
    assert assessment.normalized_score == 0.0
    assert assessment.context
    assert all(item.role == "context" for item in assessment.provider_breakdown)


def test_abuse_ipdb_is_supporting_and_single_report_is_not_malicious():
    assessment = aggregate_evidence("8.8.8.8", "ipv4", [
        result("AbuseIPDB", "malicious", confidence="high", reports_count=3),
    ])
    assert assessment.final_verdict == "suspicious"
    assert assessment.analyst_review_recommended is True
    assert assessment.provider_breakdown[0].role == "supporting"
    assert "supporting evidence" in assessment.provider_breakdown[0].reason


def test_virustotal_engine_count_and_ratio_are_standardized():
    assessment = aggregate_evidence("x", "sha256", [
        result("VirusTotal", "malicious", ioc="x", ioc_type="sha256", confidence="high",
               raw_score=0.99, raw_data={"malicious": 1, "suspicious": 0, "harmless": 20, "undetected": 79}),
    ])
    observation = assessment.provider_breakdown[0]
    assert observation.detection_count == 1
    assert observation.total_engines == 100
    assert assessment.final_verdict == "suspicious"


def test_eicar_is_explicit_test_artifact_not_live_malware():
    ioc = "44d88612fea8a8f36de82e1278abb02f"
    assessment = aggregate_evidence(ioc, "md5", [
        result("VirusTotal", "malicious", ioc=ioc, ioc_type="md5", confidence="high", malware_family="EICAR"),
        result("Hashlookup", "clean", ioc=ioc, ioc_type="md5", confidence="high", tags=["FileName:eicar.com"]),
    ])
    assert assessment.final_verdict == "malicious_test_artifact"
    assert assessment.confidence == "high"
    assert "EICAR" in assessment.reason


def test_duplicate_provider_results_are_counted_once():
    assessment = aggregate_evidence("evil.example", "domain", [
        result("ThreatFox", "malicious", ioc="evil.example", ioc_type="domain", confidence="high"),
        result("ThreatFox", "malicious", ioc="evil.example", ioc_type="domain", confidence="high"),
    ])
    assert assessment.evidence_summary["providers_received"] == 2
    assert assessment.evidence_summary["providers_aggregated"] == 1
    assert assessment.evidence_summary["duplicate_provider_results_ignored"] == 1
    assert assessment.malicious_sources == ["ThreatFox"]


# --- FM-A regression: free-text keywords must not fabricate malicious verdicts ---

# A live md5 hash routes to the ``ioc_reputation`` domain, so nested-evidence
# promotion runs. (The all-zeros EICAR hash routes to security_test_artifact.)
_LIVE_MD5 = "6408276cdfd12a1d5d3ed7256bfba639"


def test_benign_free_text_no_malware_detected_is_not_promoted():
    """A benign payload mentioning the keyword must stay unknown, not malicious."""
    res = NormalizedResult(
        ioc=_LIVE_MD5,
        ioc_type="md5",
        source="MalwareBazaar",
        provider_verdict="record_found",
        normalized_verdict="unknown",
        raw_data={
            "vendor_intel": {
                # Prose containing the keyword, plus a zero count and a
                # negation-laden verdict: none of these are a real detection.
                "ScanEngine": {"description": "no malware detected", "malicious": 0, "verdict": "clean"},
                "Sandbox": {"notes": "trojan removal completed; sample is benign"},
            },
        },
    )
    normalize_provider_result(res, "ioc_reputation")
    assert res.normalized_verdict == "unknown"
    assert res.verdict != "malicious"
    # The evidence is still preserved for the analyst, just not as a detection.
    classes = {item["evidence_class"] for item in res.evidence_items}
    assert "direct_positive" not in classes


def test_zero_detection_count_and_key_name_alone_do_not_promote():
    """The key ``malicious`` with value 0 must not read as a detection."""
    assessment = aggregate_evidence(_LIVE_MD5, "md5", [
        result("MalwareBazaar", "unknown", ioc=_LIVE_MD5, ioc_type="md5",
               provider_verdict="record_found",
               raw_data={"vendor_intel": {"VirusTotal": {"malicious": 0, "suspicious": 0, "harmless": 70}}}),
    ])
    assert assessment.final_verdict != "malicious"
    assert assessment.malicious_sources == []


def test_structured_positive_detection_count_is_promoted():
    """A real positive detection count still promotes to malicious/high."""
    res = NormalizedResult(
        ioc=_LIVE_MD5,
        ioc_type="md5",
        source="MalwareBazaar",
        provider_verdict="record_found",
        normalized_verdict="unknown",
        raw_data={"vendor_intel": {"VirusTotal": {"malicious": 12, "suspicious": 1, "harmless": 20}}},
    )
    normalize_provider_result(res, "ioc_reputation")
    assert res.normalized_verdict == "malicious"
    assert res.verdict == "malicious"
    assert res.confidence == "high"


def test_structured_vendor_verdict_field_is_promoted():
    """A structured verdict field whose value is malicious still promotes."""
    assessment = aggregate_evidence(_LIVE_MD5, "md5", [
        result("MalwareBazaar", "unknown", ioc=_LIVE_MD5, ioc_type="md5",
               provider_verdict="record_found",
               raw_data={"vendor_intel": {"ANY.RUN": {"verdict": "malicious", "malware_family": "RustyStealer"}}}),
    ])
    assert assessment.final_verdict == "malicious"
    assert "MalwareBazaar" in assessment.malicious_sources


def test_vendor_prefixed_tag_with_zero_detection_is_not_promoted():
    """A vendor_ tag encoding a clean/zero result must not promote."""
    res = NormalizedResult(
        ioc=_LIVE_MD5,
        ioc_type="md5",
        source="MalwareBazaar",
        provider_verdict="record_found",
        normalized_verdict="unknown",
        tags=["vendor_CrowdStrike: {\"malicious\": 0, \"verdict\": \"clean\"}"],
    )
    normalize_provider_result(res, "ioc_reputation")
    assert res.normalized_verdict != "malicious"
