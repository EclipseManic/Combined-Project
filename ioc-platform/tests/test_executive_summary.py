import sys

sys.path.insert(0, ".")

from app.backend.adapters.base import (
    BreachInfo,
    CompositeScore,
    CVEInfo,
    EnrichmentData,
    LookupResponse,
    SourceWeight,
)
from app.backend.executive_summary import _join_names, generate_executive_summary


def _response(score=0.0, verdict="clean", confidence="high", breakdown=None, cve=None, breach=None):
    return LookupResponse(
        input="8.8.8.8",
        normalized="8.8.8.8",
        ioc_type="ipv4",
        composite=CompositeScore(
            score=score,
            verdict=verdict,
            confidence=confidence,
            source_breakdown=breakdown or [],
        ),
        enrichment=EnrichmentData(cve=cve, breach=breach),
    )


def test_summary_significant_threat():
    r = _response(score=90.0, verdict="malicious", confidence="high")
    s = generate_executive_summary(r)
    assert "significant threat" in s


def test_summary_caution():
    r = _response(score=50.0, verdict="malicious", confidence="medium")
    s = generate_executive_summary(r)
    assert "further investigation" in s


def test_summary_no_threat():
    r = _response(score=5.0, verdict="clean", confidence="high")
    s = generate_executive_summary(r)
    assert "No threat indicators" in s


def test_summary_malicious_sources():
    breakdown = [
        SourceWeight(name="VirusTotal", verdict="malicious", score=0.9),
        SourceWeight(name="ThreatFox", verdict="malicious", score=0.8),
    ]
    r = _response(score=90.0, verdict="malicious", confidence="high", breakdown=breakdown)
    s = generate_executive_summary(r)
    assert "flagged as malicious by VirusTotal and ThreatFox" in s


def test_summary_suspicious_sources():
    breakdown = [SourceWeight(name="AlienVault", verdict="suspicious")]
    r = _response(score=50.0, verdict="suspicious", confidence="medium", breakdown=breakdown)
    s = generate_executive_summary(r)
    assert "marked suspicious by AlienVault" in s


def test_summary_clean_sources():
    breakdown = [SourceWeight(name="AbuseIPDB", verdict="clean")]
    r = _response(score=5.0, verdict="clean", confidence="high", breakdown=breakdown)
    s = generate_executive_summary(r)
    assert "reported clean by AbuseIPDB" in s


def test_summary_kev_cve():
    r = _response(
        score=90.0,
        verdict="malicious",
        cve=CVEInfo(is_in_kev=True),
    )
    s = generate_executive_summary(r)
    assert "Known Exploited Vulnerabilities" in s


def test_summary_epss_cve():
    r = _response(
        score=90.0,
        verdict="malicious",
        cve=CVEInfo(is_in_kev=False, epss_score=0.9),
    )
    s = generate_executive_summary(r)
    assert "high EPSS exploit probability" in s


def test_summary_breach_count():
    r = _response(score=90.0, verdict="malicious", breach=BreachInfo(breach_count=2))
    s = generate_executive_summary(r)
    assert "2 known data breaches" in s


def test_summary_truncates_sentences():
    breakdown = [SourceWeight(name="VirusTotal", verdict="malicious", score=0.9)]
    r = _response(
        score=90.0,
        verdict="malicious",
        confidence="high",
        breakdown=breakdown,
        cve=CVEInfo(is_in_kev=True),
        breach=BreachInfo(breach_count=1),
    )
    s = generate_executive_summary(r)
    assert s.count(". ") <= 4


def test_join_names():
    assert _join_names(["A"]) == "A"
    assert _join_names(["A", "B"]) == "A and B"
    assert _join_names(["A", "B", "C"]) == "A, B, and C"
    assert _join_names(["A", "B", "C", "D"]) == "A, B, C, and D"
