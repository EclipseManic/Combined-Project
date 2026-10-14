import sys

sys.path.insert(0, ".")

from app.backend.main import _build_html_report


def _make_response(score=85.0, verdict="malicious", raw_score=0.9):
    return {
        "input": "8.8.8.8",
        "normalized": "8.8.8.8",
        "ioc_type": "ipv4",
        "composite": {"score": score, "verdict": verdict, "confidence": "high",
                       "sources_contributing": 2, "source_breakdown": []},
        "enrichment": {
            "geoip": {"country": "US", "country_code": "US", "city": "Mountain View",
                       "asn": "AS15169", "asn_name": "GOOGLE", "isp": "Google LLC", "org": ""},
            "whois": None, "dns": None, "ssl": None, "reverse_dns": None, "relationships": [],
        },
        "results": [
            {"source": "VirusTotal", "ioc_type": "ipv4", "verdict": verdict,
             "raw_score": raw_score, "confidence": "high", "tags": ["malicious"],
             "categories": [], "mitre_attck": ["T1071"], "source_link": "https://virustotal.com/"},
        ],
        "relationships": [],
    }


def test_html_composite_score_not_double_multiplied():
    html = _build_html_report(_make_response(score=85.0, raw_score=0.9))
    assert "85/100" in html
    assert "8500/100" not in html


def test_html_raw_score_scaled_once():
    html = _build_html_report(_make_response(score=85.0, raw_score=0.9))
    assert "90/100" in html


def test_html_score_none_shows_dash():
    html = _build_html_report(_make_response(score=None, raw_score=None))
    assert "—/100" not in html
    assert "—" in html


def test_html_contains_ioc_and_verdict():
    html = _build_html_report(_make_response())
    assert "8.8.8.8" in html
    assert "malicious" in html
