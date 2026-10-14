import sys

sys.path.insert(0, ".")

import pytest

from app.backend.siem_export import export_ecs, export_leef, export_siem, export_splunk


def _make_response(verdict="malicious", score=85.0, results=None):
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
        "results": results or [
            {"source": "VirusTotal", "ioc_type": "ipv4", "verdict": "malicious",
             "raw_score": 0.9, "confidence": "high", "tags": ["malicious"], "categories": [],
             "mitre_attck": ["T1071"], "source_link": "https://virustotal.com/"},
        ],
        "relationships": [],
    }


def test_export_splunk_basic():
    text = export_splunk(_make_response())
    assert "ioc_value=8.8.8.8" in text
    assert "index=ioc_platform" in text
    assert "composite_verdict=malicious" in text


def test_export_splunk_escapes_special_chars():
    resp = _make_response(results=[
        {"source": 'VT="x"\n', "ioc_type": "ipv4", "verdict": "clean",
         "raw_score": 0.0, "confidence": "low", "tags": [], "mitre_attck": []},
    ])
    text = export_splunk(resp)
    assert '\\=' in text
    assert '\n' not in text.split("source=", 1)[1].split(" ", 1)[0]


def test_export_ecs_is_valid_json_lines():
    resp = _make_response()
    text = export_ecs(resp)
    lines = [l for l in text.split("\n") if l.strip()]
    assert lines
    for line in lines:
        import json
        event = json.loads(line)
        assert event["@timestamp"]
        assert event["threat"]["indicator"]["type"] == "ipv4"
        assert event["source"]["address"] == "8.8.8.8"


def test_export_ecs_validation_rejects_malformed():
    from app.backend.siem_export import _validate_ecs_events

    with pytest.raises(ValueError):
        _validate_ecs_events([{"@timestamp": "x"}])
    with pytest.raises(ValueError):
        _validate_ecs_events([{"threat": {"indicator": {}}}])
    _validate_ecs_events([{"@timestamp": "t", "event": {}, "threat": {}}])


def test_export_leef_basic():
    text = export_leef(_make_response())
    assert text.startswith("LEEF:2.0|IOC Lookup Platform|ioc-lookup-platform|0.2.0|IOC Lookup|")
    assert "cat=IOC Lookup" in text


def test_export_siem_unsupported_format():
    with pytest.raises(ValueError):
        export_siem(_make_response(), "cef")


def test_export_siem_dispatches():
    resp = _make_response()
    assert export_siem(resp, "splunk") == export_splunk(resp)
    assert export_siem(resp, "ecs") == export_ecs(resp)
    assert export_siem(resp, "leef") == export_leef(resp)
