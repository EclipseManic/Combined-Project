import sys
sys.path.insert(0, ".")

from app.backend.stix_export import build_stix_bundle, results_to_csv


def _make_response(verdict="malicious", score=85.0, results=None, rels=None):
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
        "relationships": rels or [],
    }


def test_stix_is_bundle():
    resp = _make_response()
    bundle = build_stix_bundle(resp)
    assert bundle["type"] == "bundle"
    assert "id" in bundle
    assert "objects" in bundle


def test_stix_has_indicator():
    resp = _make_response()
    bundle = build_stix_bundle(resp)
    types = {o["type"] for o in bundle["objects"]}
    assert "indicator" in types


def test_stix_indicator_verdict():
    resp = _make_response(verdict="malicious")
    bundle = build_stix_bundle(resp)
    indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
    assert "malicious-activity" in indicator["indicator_types"]


def test_stix_indicator_clean():
    resp = _make_response(verdict="clean", score=0)
    bundle = build_stix_bundle(resp)
    indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
    assert "benign" in indicator["indicator_types"]


def test_stix_has_sighting():
    resp = _make_response()
    bundle = build_stix_bundle(resp)
    types = {o["type"] for o in bundle["objects"]}
    assert "sighting" in types


def test_stix_has_relationships():
    resp = _make_response(rels=[{"source_ioc": "8.8.8.8", "target_ioc": "evil.com",
                                  "relationship": "resolves_to", "via_source": "reverse_dns"}])
    bundle = build_stix_bundle(resp)
    rel_types = {o["type"] for o in bundle["objects"]}
    assert "relationship" in rel_types


def test_stix_has_location():
    resp = _make_response()
    bundle = build_stix_bundle(resp)
    types = {o["type"] for o in bundle["objects"]}
    assert "location" in types


def test_stix_pattern_ipv4():
    bundle = build_stix_bundle(_make_response())
    indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
    assert "ipv4-addr" in indicator["pattern"]


def test_stix_pattern_file():
    resp = _make_response()
    resp["ioc_type"] = "md5"
    resp["normalized"] = "d41d8cd98f00b204e9800998ecf8427e"
    bundle = build_stix_bundle(resp)
    indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
    assert "file:hashes" in indicator["pattern"]


def test_csv_export():
    results = [
        {"source": "VT", "ioc_type": "ipv4", "verdict": "malicious",
         "raw_score": 0.9, "confidence": "high", "malware_family": "",
         "reports_count": 5, "tags": ["mal"], "categories": [], "mitre_attck": [],
         "source_link": "https://vt.com"},
    ]
    csv = results_to_csv(results)
    assert "Source" in csv
    assert "VT" in csv
    assert "malicious" in csv


def test_csv_empty():
    csv = results_to_csv([])
    assert csv.strip() != ""
    assert "Source" in csv


def test_stix_uses_actual_first_last_seen():
    resp = _make_response(results=[
        {"source": "VT", "ioc_type": "ipv4", "verdict": "malicious",
         "confidence": "high", "first_seen": "2024-01-01T00:00:00.000Z",
         "last_seen": "2024-06-01T00:00:00.000Z"},
        {"source": "OTX", "ioc_type": "ipv4", "verdict": "suspicious",
         "confidence": "medium", "first_seen": "2024-03-15T00:00:00.000Z",
         "last_seen": "2024-04-01T00:00:00.000Z"},
    ])
    bundle = build_stix_bundle(resp)
    obs = [o for o in bundle["objects"] if o["type"] == "observed-data"]
    assert obs[0]["first_observed"] == "2024-01-01T00:00:00.000Z"
    assert obs[0]["last_observed"] == "2024-06-01T00:00:00.000Z"
    assert obs[1]["first_observed"] == "2024-01-01T00:00:00.000Z"
    assert obs[1]["last_observed"] == "2024-06-01T00:00:00.000Z"
    assert obs[2]["first_observed"] == "2024-03-15T00:00:00.000Z"
    assert obs[2]["last_observed"] == "2024-04-01T00:00:00.000Z"


def test_stix_per_result_uses_own_first_last_seen():
    resp = _make_response(results=[
        {"source": "VT", "ioc_type": "ipv4", "verdict": "clean",
         "confidence": "high", "first_seen": "2025-05-05T00:00:00.000Z",
         "last_seen": "2025-05-05T00:00:00.000Z"},
    ])
    bundle = build_stix_bundle(resp)
    obs = [o for o in bundle["objects"] if o["type"] == "observed-data"]
    assert obs[1]["first_observed"] == "2025-05-05T00:00:00.000Z"


def test_stix_indicator_types_precedence():
    resp = _make_response(results=[
        {"source": "VT", "ioc_type": "ipv4", "verdict": "malicious",
         "confidence": "high"},
        {"source": "OTX", "ioc_type": "ipv4", "verdict": "suspicious",
         "confidence": "low"},
    ])
    bundle = build_stix_bundle(resp)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    per_source = {o["name"].split(" — ")[-1]: o for o in indicators if " — " in o["name"]}
    assert "malicious-activity" in per_source["VT"]["indicator_types"]
    assert "malicious-activity" not in per_source["OTX"]["indicator_types"]
