"""Regression fixtures for assessment semantics, built from real provider
payload shapes captured by a live probe run (google.com, 8.8.8.8, a Tor exit,
CVE-2021-44228, test@example.com and the EICAR hash)."""

import json
import sys

sys.path.insert(0, ".")

from app.backend.adapters.base import (
    BreachInfo,
    CVEInfo,
    EnrichmentData,
    LookupResponse,
    NormalizedResult,
    WhoisInfo,
    truncate_raw_data,
)
from app.backend.executive_summary import generate_executive_summary
from app.backend.misp_export import build_misp_event
from app.backend.scorer import aggregate_evidence, compute_composite
from app.backend.siem_export import export_splunk
from app.backend.stix_export import build_stix_bundle
from app.backend.thresholds import DISPLAY_CLEAN, DISPLAY_MALICIOUS


def nr(source, ioc, ioc_type, verdict="unknown", **kwargs):
    return NormalizedResult(ioc=ioc, ioc_type=ioc_type, source=source, verdict=verdict, **kwargs)


def by_source(assessment, source):
    return next(o for o in assessment.provider_breakdown if o.source == source)


def full_response(ioc, ioc_type, results, enrichment=None):
    enrichment = enrichment or EnrichmentData()
    assessment = aggregate_evidence(ioc, ioc_type, results, enrichment)
    composite = compute_composite(results, ioc=ioc, ioc_type=ioc_type, enrichment=enrichment, assessment=assessment)
    response = LookupResponse(
        input=ioc, normalized=ioc, ioc_type=ioc_type, composite=composite,
        final_assessment=assessment, enrichment=enrichment, results=results,
    )
    response.executive_summary = generate_executive_summary(response)
    return response


def assert_band(assessment):
    """The displayed score must sit in the band of the verdict it accompanies."""
    verdict, score = assessment.final_verdict, assessment.normalized_score
    if verdict == "malicious":
        assert score >= DISPLAY_MALICIOUS
    elif verdict == "suspicious":
        assert DISPLAY_CLEAN <= score < DISPLAY_MALICIOUS
    elif verdict in {"benign", "unknown"}:
        assert score == 0.0
    assert assessment.needs_review == bool(assessment.review_reasons) or assessment.needs_review


# --------------------------------------------------------------------------
# google.com: one ThreatFox search hit for URLs *under* the domain
# --------------------------------------------------------------------------

_SITES = [
    "https://sites.google.com/view/antibot172881",
    "https://sites.google.com/view/facturacion2026mx",
    "https://drive.google.com/uc?export=download&id=1HcFfTSeJ59rLIfby_DJTz0sLYvQV_a7T",
]


def _threatfox_google(raw=None):
    return nr(
        "ThreatFox", "google.com", "domain", "malicious", confidence="high", raw_score=1.0,
        reports_count=len(_SITES), related_iocs=[(url, "same_malware") for url in _SITES],
        tags=["ClickFix", "Google-Sites", "reported_by: HaloSword"],
        raw_data=raw if raw is not None else {
            "query_status": "ok",
            "data": [{"ioc": url, "ioc_type": "url", "threat_type": "payload_delivery", "confidence_level": 100} for url in _SITES],
        },
    )


def _urlscan_google():
    return nr(
        "urlscan.io", "google.com", "domain", "clean", reports_count=5,
        raw_data={"results": [{"page": {"apexDomain": "google.com", "umbrellaRank": 5, "domain": "www.google.com"}}]},
    )


def _google_enrichment():
    return EnrichmentData(whois=WhoisInfo(registrar="MarkMonitor Inc.", domain_age_days=10606))


def test_google_threatfox_related_urls_do_not_make_google_malicious():
    results = [
        _threatfox_google(),
        nr("VirusTotal", "google.com", "domain", tags=["rate_limited"]),
        _urlscan_google(),
        nr("URLhaus", "google.com", "domain", status="not_found"),
    ]
    response = full_response("google.com", "domain", results, _google_enrichment())
    assessment = response.final_assessment
    assert assessment.final_verdict not in {"malicious", "suspicious"}
    assert response.composite.verdict == assessment.final_verdict
    threatfox = by_source(assessment, "ThreatFox")
    assert threatfox.contribution != "positive"
    assert threatfox.evidence_class == "related_indicator"
    assert "ThreatFox" not in assessment.malicious_sources
    assert "sites.google.com" in assessment.reason
    assert "established infrastructure" in assessment.reason
    assert "significant threat" not in response.executive_summary
    assert_band(assessment)


def test_google_related_match_is_detected_from_a_truncated_payload():
    big = {
        "query_status": "ok",
        "data": [{"ioc": url, "reporter": "x" * 3000, "threat_type": "payload_delivery"} for url in _SITES * 3],
    }
    raw = truncate_raw_data(big)
    assert raw["_truncated"] is True
    result = _threatfox_google(raw=raw)
    result.related_iocs = [(url, "same_malware") for url in _SITES * 3]
    result.reports_count = len(_SITES) * 3
    assessment = aggregate_evidence("google.com", "domain", [result, _urlscan_google()], _google_enrichment())
    assert assessment.final_verdict != "malicious"
    assert by_source(assessment, "ThreatFox").metadata["match_type"] == "related"


def test_related_url_match_on_unestablished_domain_is_only_suspicious():
    result = nr(
        "ThreatFox", "evil-example.xyz", "domain", "malicious", confidence="high", reports_count=1,
        related_iocs=[("http://evil-example.xyz/payload.exe", "same_malware")],
        raw_data={"query_status": "ok", "data": [{"ioc": "http://evil-example.xyz/payload.exe"}]},
    )
    assessment = aggregate_evidence("evil-example.xyz", "domain", [result])
    assert assessment.final_verdict == "suspicious"
    assert by_source(assessment, "ThreatFox").evidence_class == "related_indicator"
    assert by_source(assessment, "ThreatFox").normalized_signal <= 0.40
    assert_band(assessment)


def _exact_threatfox(domain):
    return nr(
        "ThreatFox", domain, "domain", "malicious", confidence="high", reports_count=1,
        raw_data={"query_status": "ok", "data": [{"ioc": domain, "ioc_type": "domain"}]},
    )


def test_single_exact_high_reliability_record_can_still_be_malicious():
    assessment = aggregate_evidence("evil-example.xyz", "domain", [
        _exact_threatfox("evil-example.xyz"),
        nr("URLhaus", "evil-example.xyz", "domain", status="not_found"),
    ])
    assert by_source(assessment, "ThreatFox").metadata["match_type"] == "exact"
    assert assessment.final_verdict == "malicious"
    assert_band(assessment)


def test_single_record_with_conflicting_clean_reputation_is_not_malicious():
    assessment = aggregate_evidence("evil-example.xyz", "domain", [
        _exact_threatfox("evil-example.xyz"),
        nr("urlscan.io", "evil-example.xyz", "domain", "clean"),
    ])
    assert assessment.final_verdict == "suspicious"
    assert "explicit clean result" in assessment.reason
    assert "urlscan.io" in assessment.reason
    assert assessment.needs_review is True
    assert_band(assessment)


def test_single_record_on_established_domain_is_not_malicious():
    enrichment = EnrichmentData(whois=WhoisInfo(domain_age_days=20 * 365))
    assessment = aggregate_evidence("old-company.com", "domain", [_exact_threatfox("old-company.com")], enrichment)
    assert assessment.final_verdict == "suspicious"
    assert "established" in assessment.reason
    assert_band(assessment)


# --------------------------------------------------------------------------
# 8.8.8.8: explicit negatives plus exposure context and community votes
# --------------------------------------------------------------------------

def _google_dns_results():
    ip = "8.8.8.8"
    return [
        nr("ThreatFox", ip, "ipv4", status="not_found"),
        nr("VirusTotal", ip, "ipv4", "clean", detection_count=0, total_engines=91,
           tags=["suspicious-udp", "votes_malicious: 59", "votes_harmless: 294"]),
        nr("AbuseIPDB", ip, "ipv4", "clean", confidence="high", reports_count=357,
           tags=["ISP: Google LLC", "Usage: Content Delivery Network", "whitelisted"],
           raw_data={"isWhitelisted": True, "abuseConfidenceScore": 0, "totalReports": 357}),
        nr("GreyNoise", ip, "ipv4", tags=["rate_limited"]),
        nr("AlienVault OTX", ip, "ipv4", verdict="error", tags=["timeout"]),
        nr("Shodan", ip, "ipv4", tags=["ports:53,443", "hostname:dns.google"]),
        nr("Tor Exit", ip, "ipv4", status="not_found"),
        nr("Hudson Rock", ip, "ipv4", "malicious", confidence="medium", reports_count=1, raw_score=0.55,
           tags=["infostealer_compromised", "infections:1", "credentials_at_risk:1"],
           raw_data={"total_infections": 1, "total_corporate_services": 0, "total_user_services": 1}),
    ]


def test_google_dns_is_benign_from_explicit_negatives_and_says_why():
    response = full_response("8.8.8.8", "ipv4", _google_dns_results())
    assessment = response.final_assessment
    assert assessment.final_verdict == "benign"
    assert response.composite.verdict == "clean"
    assert set(assessment.clean_sources) == {"VirusTotal", "AbuseIPDB"}
    assert "whitelisted" in assessment.reason
    assert "abuse confidence 0/100" in assessment.reason
    assert "community votes 59 malicious / 294 harmless" in assessment.reason
    assert "GreyNoise (rate limited)" in assessment.reason
    hudson = by_source(assessment, "Hudson Rock")
    assert hudson.role == "context"
    assert hudson.evidence_class == "exposure_context"
    assert hudson.contribution == "neutral"
    assert "Hudson Rock" not in assessment.malicious_sources
    assert "not maliciousness" in assessment.reason
    assert_band(assessment)


def test_infostealer_exposure_alone_never_makes_an_ip_malicious_or_suspicious():
    assessment = aggregate_evidence("203.0.113.50", "ipv4", [
        nr("Hudson Rock", "203.0.113.50", "ipv4", "malicious", confidence="high", reports_count=40,
           tags=["infostealer_compromised", "infections:40"]),
    ])
    assert assessment.final_verdict == "unknown"
    assert assessment.normalized_score == 0.0
    assert assessment.malicious_sources == []


def test_malicious_leaning_community_votes_cancel_a_clean_engine_result():
    assessment = aggregate_evidence("198.51.100.7", "ipv4", [
        nr("VirusTotal", "198.51.100.7", "ipv4", "clean", detection_count=0, total_engines=90,
           raw_data={"total_votes": {"malicious": 30, "harmless": 2}}),
        nr("AbuseIPDB", "198.51.100.7", "ipv4", "clean", reports_count=0),
    ])
    virustotal = by_source(assessment, "VirusTotal")
    assert virustotal.contribution == "neutral"
    assert "community votes lean malicious" in virustotal.reason
    # Votes are weak: they block the clean claim, they do not create malice.
    assert assessment.final_verdict == "unknown"


# --------------------------------------------------------------------------
# Tor exit relay
# --------------------------------------------------------------------------

def _tor_results():
    ip = "185.220.101.1"
    return [
        nr("VirusTotal", ip, "ipv4", "malicious", confidence="high", detection_count=11, total_engines=91,
           tags=["tor", "votes_malicious: 10", "votes_harmless: 11"]),
        nr("AbuseIPDB", ip, "ipv4", "malicious", confidence="high", reports_count=835,
           tags=["tor_exit_node"], raw_data={"abuseConfidenceScore": 100, "isTor": True}),
        nr("Tor Exit", ip, "ipv4", "malicious", raw_score=0.8, tags=["tor_exit_node"]),
        nr("Hudson Rock", ip, "ipv4", "malicious", confidence="high", reports_count=5,
           tags=["infostealer_compromised", "infections:5"]),
        nr("GreyNoise", ip, "ipv4", tags=["rate_limited"]),
    ]


def test_tor_exit_with_abuse_evidence_is_malicious_with_anonymization_context():
    response = full_response("185.220.101.1", "ipv4", _tor_results())
    assessment = response.final_assessment
    assert assessment.final_verdict == "malicious"
    assert set(assessment.malicious_sources) == {"VirusTotal", "AbuseIPDB"}
    tor = by_source(assessment, "Tor Exit")
    assert tor.role == "context" and tor.evidence_class == "anonymization" and tor.contribution == "context_risk"
    assert by_source(assessment, "Hudson Rock").contribution == "neutral"
    assert "Supporting threat sources: VirusTotal (11/91 engines) and AbuseIPDB (abuse confidence 100/100, 835 reports)" in assessment.reason
    assert "Hudson Rock" not in assessment.reason.split("Context:")[0]
    assert "Tor exit" in assessment.reason
    assert assessment.needs_review is True
    assert_band(assessment)


def test_tor_exit_membership_alone_is_a_risk_not_proof():
    assessment = aggregate_evidence("185.220.101.2", "ipv4", [
        nr("Tor Exit", "185.220.101.2", "ipv4", "malicious", raw_score=0.8, tags=["tor_exit_node"]),
        nr("ThreatFox", "185.220.101.2", "ipv4", status="not_found"),
    ])
    assert assessment.final_verdict == "suspicious"
    assert assessment.malicious_sources == []
    assert "not proof of malicious activity" in assessment.reason
    assert_band(assessment)


# --------------------------------------------------------------------------
# Typed domains: vulnerability and credential exposure
# --------------------------------------------------------------------------

def test_log4shell_verdict_score_reason_and_summary_agree():
    cve = "CVE-2021-44228"
    results = [
        nr("cve.org", cve, "cve", provider_verdict="record_found", severity="informational", vulnerability_status="published"),
        nr("NVD", cve, "cve", provider_verdict="record_found", severity="critical", cvss_score=10.0, confidence="high"),
        nr("CVE", cve, "cve", provider_verdict="vulnerability_record", severity="critical", cvss_score=10.0,
           epss_score=0.99999, exploit_status="known_exploited", tags=["cisa_kev", "kev_added:2021-12-10"]),
    ]
    enrichment = EnrichmentData(cve=CVEInfo(is_in_kev=True, epss_score=0.99999, cvss_score=10.0, cvss_severity="CRITICAL"))
    response = full_response(cve, "cve", results, enrichment)
    assessment = response.final_assessment
    assert assessment.final_verdict == "critical"
    assert assessment.normalized_score == 100.0
    assert response.composite.verdict == "critical"
    assert response.composite.score == 100.0
    assert "CISA Known Exploited" in assessment.reason
    assert "CVSS 10" in assessment.reason
    assert assessment.evidence_summary["known_exploited"] is True
    assert "critical-severity" in response.executive_summary
    assert "incomplete or conflicting" not in response.executive_summary


def _email_results():
    email = "test@example.com"
    return [
        nr("StopForumSpam", email, "email", "malicious", confidence="high", raw_score=0.9,
           tags=["spam_report", "appears:1", "frequency:2"]),
        nr("AbstractAPI", email, "email", execution_state="unavailable", tags=["unauthorized", "invalid_api_key"]),
        nr("Hunter.io", email, "email", "suspicious", confidence="high",
           tags=["hunter:result:risky", "hunter:status:disposable", "hunter:disposable"],
           raw_data={"status": "disposable", "result": "risky", "disposable": True}),
        nr("Hudson Rock", email, "email", "malicious", confidence="high", reports_count=5,
           tags=["infostealer_compromised", "infections:5", "credentials_at_risk:23064"],
           raw_data={"total_infections": 5, "total_corporate_services": 620, "total_user_services": 22444}),
    ]


def test_email_exposure_is_separate_from_spam_reputation():
    enrichment = EnrichmentData(breach=BreachInfo(breach_count=50, breach_names=["Twitter", "Adobe"], source="multiple"))
    response = full_response("test@example.com", "email", _email_results(), enrichment)
    assessment = response.final_assessment
    assert assessment.final_verdict == "breached"
    assert response.composite.verdict == "breached"
    assert response.composite.score == assessment.normalized_score > 0
    summary = assessment.evidence_summary
    assert summary["exposure_sources"] == ["Hudson Rock", "breach_enrichment"]
    assert set(summary["abuse_reputation_sources"]) == {"StopForumSpam", "Hunter.io"}
    assert by_source(assessment, "Hudson Rock").evidence_class == "credential_exposure"
    assert "5 infostealer infections" in assessment.reason
    assert "50 breaches" in assessment.reason
    assert "2 spam reports" in assessment.reason
    assert "AbstractAPI (unavailable)" in assessment.reason
    assert "breach or infostealer data" in response.executive_summary


def test_email_spam_reputation_without_exposure_is_suspicious_not_breached():
    email = "spammer@example.net"
    assessment = aggregate_evidence(email, "email", [
        nr("StopForumSpam", email, "email", "malicious", tags=["spam_report", "frequency:12"]),
        nr("Hudson Rock", email, "email", status="not_found"),
    ], EnrichmentData(breach=BreachInfo(breach_count=0)))
    assert assessment.final_verdict == "suspicious"
    assert assessment.evidence_summary["breached"] is False
    assert "No credential exposure was found" in assessment.reason
    assert_band(assessment)


def test_eicar_composite_mirrors_test_artifact_assessment():
    ioc = "44d88612fea8a8f36de82e1278abb02f"
    response = full_response(ioc, "md5", [
        nr("FileScan.io", ioc, "md5", "malicious", confidence="high"),
        nr("VirusTotal", ioc, "md5", tags=["rate_limited"]),
    ])
    assert response.final_assessment.final_verdict == "malicious_test_artifact"
    assert response.composite.verdict == "malicious_test_artifact"
    assert response.composite.score == 0.0


# --------------------------------------------------------------------------
# Robustness: provider failures, missing not_applicable rows, plan input
# --------------------------------------------------------------------------

def test_all_reputation_providers_failing_is_unknown_and_needs_review():
    ip = "192.0.2.10"
    assessment = aggregate_evidence(ip, "ipv4", [
        nr("VirusTotal", ip, "ipv4", tags=["rate_limited"]),
        nr("AbuseIPDB", ip, "ipv4", tags=["rate_limited"]),
        nr("ThreatFox", ip, "ipv4", verdict="error", tags=["timeout"]),
        nr("AlienVault OTX", ip, "ipv4", verdict="error", tags=["timeout"]),
        nr("Shodan", ip, "ipv4", tags=["ports:22"]),
        nr("IPinfo", ip, "ipv4", tags=["country:US"]),
        nr("Team Cymru", ip, "ipv4", "clean", tags=["not_bogon"]),
    ])
    assert assessment.final_verdict == "unknown"
    assert assessment.confidence == "low"
    assert assessment.needs_review is True
    assert assessment.evidence_summary["reputation_coverage"] == 0.0
    assert "No reputation provider returned a usable answer" in assessment.reason
    assert any("No reputation provider answered" in reason for reason in assessment.review_reasons)


def test_benign_with_most_reputation_providers_failing_is_low_confidence():
    ip = "192.0.2.11"
    assessment = aggregate_evidence(ip, "ipv4", [
        nr("VirusTotal", ip, "ipv4", "clean", detection_count=0, total_engines=90),
        nr("AbuseIPDB", ip, "ipv4", "clean", reports_count=0),
        nr("ThreatFox", ip, "ipv4", tags=["rate_limited"]),
        nr("AlienVault OTX", ip, "ipv4", tags=["rate_limited"]),
        nr("GreyNoise", ip, "ipv4", tags=["rate_limited"]),
        nr("Tor Exit", ip, "ipv4", tags=["timeout"], verdict="error"),
        nr("URLhaus", ip, "ipv4", tags=["timeout"], verdict="error"),
    ])
    assert assessment.final_verdict == "benign"
    assert assessment.confidence == "low"
    assert assessment.needs_review is True


def test_scoring_does_not_depend_on_not_applicable_rows():
    base = _google_dns_results()
    with_na = base + [
        nr("Hunter.io", "8.8.8.8", "ipv4", status="not_applicable", execution_state="not_applicable"),
        nr("MalwareBazaar", "8.8.8.8", "ipv4", status="not_applicable", execution_state="not_applicable"),
    ]
    without = aggregate_evidence("8.8.8.8", "ipv4", _google_dns_results())
    with_rows = aggregate_evidence("8.8.8.8", "ipv4", with_na)
    for key in ("final_verdict", "normalized_score", "confidence", "coverage", "needs_review"):
        assert getattr(without, key) == getattr(with_rows, key)
    assert without.evidence_summary["expected_providers"] == with_rows.evidence_summary["expected_providers"]


def test_provider_plan_counts_applicable_providers_without_results():
    plan = [
        {"provider": "VirusTotal", "applicable": True},
        {"provider": "AbuseIPDB", "applicable": True},
        {"provider": "URLhaus", "applicable": True},
        {"provider": "Hunter.io", "applicable": False},
        {"provider": "HIBP Pwned Passwords", "applicable": False},
    ]
    ip = "192.0.2.12"
    assessment = aggregate_evidence(ip, "ipv4", [
        nr("VirusTotal", ip, "ipv4", "clean", detection_count=0, total_engines=90),
        nr("AbuseIPDB", ip, "ipv4", "clean", reports_count=0),
    ], provider_plan=plan)
    summary = assessment.evidence_summary
    assert summary["expected_providers"] == 3
    assert summary["evaluated_providers"] == 2
    assert summary["planned_providers_without_result"] == ["URLhaus"]
    assert summary["not_applicable_providers"] == 2
    assert assessment.assessment_status == "partial"


# --------------------------------------------------------------------------
# Raw payload truncation keeps typed fields
# --------------------------------------------------------------------------

def test_truncation_keeps_small_top_level_fields():
    payload = {
        "malicious": 11, "suspicious": 3, "harmless": 48, "undetected": 29,
        "detection_ratio": "11/91", "match_type": "exact",
        "api_response": {"blob": "x" * 30000},
    }
    raw = truncate_raw_data(payload)
    assert raw["_truncated"] is True
    assert raw["malicious"] == 11 and raw["match_type"] == "exact"
    assert "api_response" not in raw
    assert len(json.dumps(raw)) < 12 * 1024
    result = nr("VirusTotal", "x", "sha256", "malicious", raw_data=payload)
    assert result.raw_data["detection_ratio"] == "11/91"


# --------------------------------------------------------------------------
# Exports reflect the corrected assessment
# --------------------------------------------------------------------------

def _dump(response):
    return json.loads(response.model_dump_json())


def test_exports_skip_non_answers_and_do_not_export_context_as_malicious():
    response = _dump(full_response("185.220.101.1", "ipv4", _tor_results() + [
        nr("ThreatFox", "185.220.101.1", "ipv4", status="not_found"),
    ]))
    bundle = build_stix_bundle(response)
    per_source = {o["name"].split(" — ")[-1]: o for o in bundle["objects"] if o["type"] == "indicator" and " — " in o["name"]}
    assert "GreyNoise" not in per_source and "ThreatFox" not in per_source
    assert per_source["Hudson Rock"]["indicator_types"] == ["unknown"]
    assert per_source["Tor Exit"]["indicator_types"] == ["anonymization"]
    assert "malicious-activity" in per_source["VirusTotal"]["indicator_types"]
    sighting = next(o for o in bundle["objects"] if o["type"] == "sighting")
    assert sighting["count"] == 2

    splunk = export_splunk(response)
    assert "source=GreyNoise" not in splunk and "source=ThreatFox" not in splunk
    hudson_line = next(line for line in splunk.splitlines() if "source=Hudson Rock" in line)
    assert "severity=10" not in hudson_line


def test_misp_does_not_flag_benign_indicator_for_ids():
    response = _dump(full_response("8.8.8.8", "ipv4", _google_dns_results()))
    event = build_misp_event(response)["Event"]
    attributes = event["Attribute"]
    assert attributes[0]["to_ids"] is False
    comments = " ".join(attribute["comment"] for attribute in attributes[1:])
    assert "GreyNoise" not in comments and "Tor Exit" not in comments and "ThreatFox" not in comments
    assert all(attribute["to_ids"] is False for attribute in attributes[1:])
    bundle = build_stix_bundle(response)
    assert not [o for o in bundle["objects"] if o["type"] == "sighting"]


def test_structured_adapter_payloads_are_read_without_tags():
    """Typed raw_data (compact adapter records) is preferred over tag strings."""
    threatfox = nr(
        "ThreatFox", "evil-example.xyz", "domain", "malicious", confidence="high", reports_count=1,
        raw_data={"query_status": "ok", "match_count": 1, "records": [{"ioc": "evil-example.xyz", "ioc_type": "domain"}],
                  "related_records": [{"ioc": "https://evil-example.xyz/a", "ioc_type": "url"}]},
    )
    abuse = nr(
        "AbuseIPDB", "8.8.4.4", "ipv4", "whitelisted", reports_count=12,
        raw_data={"abuse_confidence_score": 0, "is_whitelisted": True, "is_tor": False},
    )
    virustotal = nr(
        "VirusTotal", "8.8.4.4", "ipv4", "clean", detection_count=0, total_engines=90,
        raw_data={"community_votes": {"malicious": 4, "harmless": 40}},
    )
    domain_assessment = aggregate_evidence("evil-example.xyz", "domain", [threatfox])
    assert by_source(domain_assessment, "ThreatFox").metadata["match_type"] == "exact"
    ip_assessment = aggregate_evidence("8.8.4.4", "ipv4", [abuse, virustotal])
    assert ip_assessment.final_verdict == "benign"
    assert "abuse confidence 0/100" in ip_assessment.reason and "whitelisted" in ip_assessment.reason
    assert "community votes 4 malicious / 40 harmless" in ip_assessment.reason
