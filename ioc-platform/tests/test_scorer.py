import sys
sys.path.insert(0, ".")

from datetime import datetime

from app.backend.adapters.base import NormalizedResult
from app.backend.scorer import compute_composite


def _result(source, verdict, raw_score=None, confidence="low"):
    return NormalizedResult(
        ioc="8.8.8.8", ioc_type="ipv4", source=source,
        verdict=verdict, raw_score=raw_score, confidence=confidence,
    )


def test_all_malicious():
    results = [
        _result("VirusTotal", "malicious", 0.95, "high"),
        _result("AbuseIPDB", "malicious", 0.85, "high"),
        _result("ThreatFox", "malicious", 1.0, "high"),
    ]
    c = compute_composite(results)
    assert c.verdict == "malicious"
    assert c.score >= 70
    assert c.confidence == "high"


def test_mixed_verdicts():
    results = [
        _result("VirusTotal", "malicious", 0.9, "high"),
        _result("AbuseIPDB", "suspicious", 0.4, "medium"),
        _result("ThreatFox", "clean", 0.0, "low"),
    ]
    c = compute_composite(results)
    assert c.verdict in ("malicious", "suspicious")


def test_all_clean():
    results = [
        _result("VirusTotal", "clean", 0.0, "low"),
        _result("AbuseIPDB", "clean", 0.0, "low"),
    ]
    c = compute_composite(results)
    assert c.verdict == "clean"
    assert c.score < 15


def test_single_source():
    results = [_result("VirusTotal", "malicious", 0.95, "high")]
    c = compute_composite(results)
    assert c.verdict == "malicious"
    assert c.sources_contributing == 1


def test_empty_results():
    c = compute_composite([])
    assert c.verdict == "unknown"
    assert c.score == 0.0


def test_error_results_skipped():
    results = [
        _result("VirusTotal", "error", None),
        _result("AbuseIPDB", "error", None),
    ]
    c = compute_composite(results)
    assert c.verdict == "unknown"
    assert c.score == 0.0


def test_one_error_one_malicious():
    results = [
        _result("VirusTotal", "error", None),
        _result("AbuseIPDB", "malicious", 0.9, "high"),
    ]
    c = compute_composite(results)
    assert c.verdict == "malicious"
    assert c.score >= 50


def test_source_breakdown():
    results = [
        _result("VirusTotal", "malicious", 1.0, "high"),
        _result("ThreatFox", "clean", 0.0, "low"),
    ]
    c = compute_composite(results)
    assert len(c.source_breakdown) == 2


def test_confidence_high():
    results = [
        _result("VirusTotal", "malicious", 1.0, "high"),
        _result("AbuseIPDB", "malicious", 0.9, "high"),
        _result("ThreatFox", "malicious", 1.0, "high"),
    ]
    c = compute_composite(results)
    assert c.confidence == "high"


def test_score_range():
    results = [
        _result("VirusTotal", "malicious", 0.5, "medium"),
        _result("AbuseIPDB", "suspicious", 0.3, "medium"),
    ]
    c = compute_composite(results)
    assert 0 <= c.score <= 100


def test_unknown_verdict():
    results = [_result("VirusTotal", "unknown", None)]
    c = compute_composite(results)
    assert c.verdict == "unknown"


def test_not_found_not_clean():
    results = [
        _result("VirusTotal", "unknown", 0.0, "low"),
        _result("AbuseIPDB", "unknown", 0.0, "low"),
    ]
    for r in results:
        r.status = "not_found"
    c = compute_composite(results)
    assert c.verdict == "unknown"
    assert c.score == 0.0


def test_not_found_excluded_from_clean_denominator():
    results = [
        _result("VirusTotal", "unknown", 0.0, "low"),
        _result("AbuseIPDB", "clean", 0.0, "low"),
    ]
    results[0].status = "not_found"
    c = compute_composite(results)
    assert c.verdict == "clean"
    assert c.sources_contributing == 1


def test_override_requires_min_weight():
    results = [
        _result("GreyNoise", "malicious", 1.0, "low"),
        _result("OpenPhish", "malicious", 0.8, "medium"),
    ]
    for r in results:
        r.status = "found"
    c = compute_composite(results)
    assert c.verdict == "malicious"


def test_source_breakdown_has_confidence():
    results = [
        _result("VirusTotal", "malicious", 1.0, "high"),
        _result("ThreatFox", "clean", 0.0, "low"),
    ]
    c = compute_composite(results)
    assert c.source_breakdown[0].confidence == "high"
    assert c.source_breakdown[1].confidence == "low"


def _family_result(source, verdict, family, raw_score=None, last_seen=None):
    return NormalizedResult(
        ioc="8.8.8.8", ioc_type="ipv4", source=source,
        verdict=verdict, raw_score=raw_score, confidence="high",
        malware_family=family, last_seen=last_seen,
    )


def test_time_decay_lowers_weight_for_old_ioc():
    old = datetime(2020, 1, 1)
    recent = _result("VirusTotal", "malicious", 0.95, "high")
    recent.last_seen = datetime.now()
    stale = _result("AbuseIPDB", "malicious", 0.95, "high")
    stale.last_seen = old
    c = compute_composite([recent, stale])
    assert c.verdict == "malicious"
    stale_weight = next(w.weight for w in c.source_breakdown if w.name == "AbuseIPDB")
    recent_weight = next(w.weight for w in c.source_breakdown if w.name == "VirusTotal")
    assert stale_weight < recent_weight
    assert stale_weight < 0.5


def test_time_decay_floors_at_minimum():
    from datetime import timedelta
    r = _result("VirusTotal", "malicious", 0.95, "high")
    r.last_seen = datetime.now() - timedelta(days=10000)
    c = compute_composite([r])
    assert c.verdict == "malicious"
    assert c.source_breakdown[0].weight >= 0.2


def test_time_decay_no_dates_is_full_weight():
    r = _result("VirusTotal", "malicious", 0.95, "high")
    c = compute_composite([r])
    assert c.source_breakdown[0].weight == 1.0


def test_dedupe_by_family_keeps_highest_weight_source():
    fresh = _family_result("VirusTotal", "malicious", "Emotet", 0.95)
    fresh.last_seen = datetime.now()
    stale = _family_result("AbuseIPDB", "malicious", "emotet", 0.95)
    stale.last_seen = datetime(2019, 1, 1)
    c = compute_composite([fresh, stale])
    names = [w.name for w in c.source_breakdown]
    assert "AbuseIPDB" not in names
    assert "VirusTotal" in names


def test_dedupe_by_family_distinct_families_both_counted():
    a = _family_result("VirusTotal", "malicious", "Emotet", 0.9)
    b = _family_result("ThreatFox", "malicious", "Qakbot", 0.8)
    c = compute_composite([a, b])
    assert len(c.source_breakdown) == 2


def test_cve_override_cisa_kev_forces_malicious_high():
    cve = NormalizedResult(
        ioc="CVE-2021-44228", ioc_type="cve", source="CVE",
        verdict="unknown", raw_score=0.0, confidence="low",
        tags=["cisa_kev"],
    )
    clean = _result("VirusTotal", "clean", 0.0, "low")
    c = compute_composite([clean, cve])
    assert c.verdict == "malicious"
    assert c.confidence == "high"


def test_cve_override_high_verdict():
    cve = NormalizedResult(
        ioc="CVE-2021-44228", ioc_type="cve", source="CVE",
        verdict="malicious", raw_score=1.0, confidence="high",
    )
    clean = _result("VirusTotal", "clean", 0.0, "low")
    c = compute_composite([clean, cve])
    assert c.verdict == "malicious"
    assert c.confidence == "high"


def test_cve_override_suspicious():
    cve = NormalizedResult(
        ioc="CVE-2021-1234", ioc_type="cve", source="CVE",
        verdict="suspicious", raw_score=0.5, confidence="medium",
    )
    clean = _result("VirusTotal", "clean", 0.0, "low")
    c = compute_composite([clean, cve])
    assert c.verdict == "suspicious"


def test_no_cve_override_without_kev_or_verdict():
    cve = NormalizedResult(
        ioc="CVE-2021-1234", ioc_type="cve", source="CVE",
        verdict="unknown", raw_score=0.0, confidence="low",
    )
    clean = _result("VirusTotal", "clean", 0.0, "low")
    c = compute_composite([clean, cve])
    assert c.verdict == "clean"


def test_score_in_medium_band_is_malicious_medium():
    results = [_result("VirusTotal", "malicious", 0.5, "medium")]
    c = compute_composite(results)
    assert c.verdict == "malicious"
    assert c.confidence == "medium"
    assert 40 <= c.score < 70


def test_score_at_high_threshold_is_malicious_high():
    results = [_result("VirusTotal", "malicious", 0.7, "high")]
    c = compute_composite(results)
    assert c.verdict == "malicious"
    assert c.confidence == "high"


def test_score_in_suspicious_band():
    results = [_result("VirusTotal", "suspicious", 0.25, "medium")]
    c = compute_composite(results)
    assert c.verdict == "suspicious"
    assert 15 <= c.score < 40


def test_score_at_suspicious_threshold():
    results = [_result("VirusTotal", "suspicious", 0.15, "medium")]
    c = compute_composite(results)
    assert c.verdict == "suspicious"
    assert c.score == 15.0


def test_score_below_suspicious_is_clean():
    results = [_result("VirusTotal", "clean", 0.05, "low")]
    c = compute_composite(results)
    assert c.verdict == "clean"


def test_clean_two_sources_is_high_confidence():
    results = [
        _result("VirusTotal", "clean", 0.0, "low"),
        _result("AbuseIPDB", "clean", 0.0, "low"),
    ]
    for r in results:
        r.status = "found"
    c = compute_composite(results)
    assert c.verdict == "clean"
    assert c.confidence == "high"


def test_clean_single_source_is_medium_confidence():
    results = [_result("VirusTotal", "clean", 0.0, "low")]
    results[0].status = "found"
    c = compute_composite(results)
    assert c.verdict == "clean"
    assert c.confidence == "medium"


def test_medium_count_override_single_malicious():
    results = [_result("AbuseIPDB", "malicious", 0.3, "medium")]
    results[0].status = "found"
    c = compute_composite(results)
    assert c.verdict == "suspicious"
    assert c.confidence == "medium"


def test_high_count_override_two_high_weight_malicious():
    results = [
        _result("VirusTotal", "malicious", 0.35, "medium"),
        _result("ThreatFox", "malicious", 0.35, "medium"),
    ]
    for r in results:
        r.status = "found"
    c = compute_composite(results)
    assert c.verdict == "suspicious"


def test_weak_single_source_detection_does_not_force_malicious():
    result = _result("VirusTotal", "malicious", 0.02, "medium")
    result.status = "found"
    composite = compute_composite([result])
    assert composite.verdict == "suspicious"
    assert composite.score == 2.0
    assert composite.confidence == "low"


def test_malicious_without_raw_score_is_not_found_unknown():
    r = _result("VirusTotal", "malicious", None, "high")
    c = compute_composite([r])
    assert c.verdict == "unknown"


# --------------------------------------------------------------------------
# Provider-aware aggregation regressions (aggregate_evidence)
# --------------------------------------------------------------------------

from app.backend.scorer import aggregate_evidence


def _obs(source, verdict, ioc, ioc_type, confidence="high", **kwargs):
    return NormalizedResult(
        ioc=ioc, ioc_type=ioc_type, source=source,
        verdict=verdict, confidence=confidence, **kwargs,
    )


def test_context_domain_escalates_on_explicit_malicious_provider_verdict():
    # BUG-FIX (FC-A): a provider flagging an artifact/ASN as malicious must not
    # be silently dropped in the infrastructure/identity/artifact_metadata
    # domains. A single strong positive escalates beyond context_only.
    assessment = aggregate_evidence("AS64500", "asn", [
        _obs("VirusTotal", "malicious", "AS64500", "asn", raw_score=0.99,
             raw_data={"malicious": 40, "suspicious": 0, "harmless": 5, "undetected": 55}),
    ])
    assert assessment.assessment_domain == "infrastructure"
    assert assessment.final_verdict in {"malicious", "suspicious"}
    assert assessment.final_verdict != "context_only"
    assert assessment.normalized_score > 0.0
    assert "VirusTotal" in (assessment.malicious_sources + assessment.suspicious_sources)


def test_artifact_metadata_escalates_to_suspicious_on_single_positive():
    assessment = aggregate_evidence(r"C:\Users\Public\payload.exe", "windows_path", [
        _obs("ThreatFox", "suspicious", r"C:\Users\Public\payload.exe", "windows_path"),
    ])
    assert assessment.assessment_domain == "artifact_metadata"
    assert assessment.final_verdict == "suspicious"
    assert assessment.needs_review is True


def test_context_domain_stays_context_only_without_positive_signal():
    # No positive provider evidence -> the verdict must remain context_only,
    # exactly as before the fix (no fabricated escalation, no benign).
    assessment = aggregate_evidence("AS64500", "asn", [
        _obs("Shodan", "unknown", "AS64500", "asn", tags=["org:Example"]),
        _obs("IPinfo", "clean", "AS64500", "asn"),
    ])
    assert assessment.final_verdict == "context_only"
    assert assessment.normalized_score == 0.0


def test_btc_with_only_balance_context_is_not_benign():
    # BUG-FIX (crypto context): blockchain.info/Etherscan are context-only
    # sources. A funded wallet reported by them alone must not score benign or
    # malicious -- it stays unknown/context_only (no clean ladder off context).
    wallet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assessment = aggregate_evidence(wallet, "btc", [
        _obs("Blockchain.info", "unknown", wallet, "btc", confidence="low",
             tags=["final_balance_btc:12.5", "n_tx:340"]),
    ])
    assert assessment.final_verdict not in {"benign", "malicious"}
    assert assessment.final_verdict in {"unknown", "context_only"}
    assert assessment.normalized_score == 0.0


def test_btc_context_plus_chainabuse_report_is_not_benign():
    # ChainAbuse reports ARE abuse evidence; context balance must never dilute
    # them into benign. With a real abuse report the wallet is not benign.
    wallet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assessment = aggregate_evidence(wallet, "btc", [
        _obs("Blockchain.info", "unknown", wallet, "btc", confidence="low",
             tags=["final_balance_btc:12.5"]),
        _obs("ChainAbuse", "malicious", wallet, "btc", raw_score=1.0, reports_count=8),
    ])
    assert assessment.final_verdict != "benign"
