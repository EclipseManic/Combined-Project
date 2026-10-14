import sys

sys.path.insert(0, ".")

from app.backend.misp_export import build_misp_event


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
            "whois": {"registrar": "GoDaddy", "org": "ACME", "creation_date": "2020-01-01"},
            "dns": None, "ssl": None, "reverse_dns": None, "relationships": [],
        },
        "results": results or [
            {"source": "VirusTotal", "ioc_type": "ipv4", "verdict": "malicious",
             "raw_score": 0.9, "confidence": "high", "tags": ["malicious"], "categories": [],
             "mitre_attck": ["T1071"], "source_link": "https://virustotal.com/"},
        ],
        "relationships": rels or [],
    }


def test_misp_event_structure():
    event = build_misp_event(_make_response())
    assert "Event" in event
    assert event["Event"]["info"] == "IOC Lookup Platform lookup: 8.8.8.8 (ipv4)"
    assert event["Event"]["Tag"][0]["name"] == "tlp:red"


def test_misp_event_bare_uuid_id():
    event = build_misp_event(_make_response())
    eid = event["Event"]["id"]
    assert "Event--" not in eid
    assert "prefix--" not in eid
    assert event["Event"]["uuid"] == eid
    assert len(eid) == 32


def test_misp_has_attributes():
    event = build_misp_event(_make_response())
    attrs = event["Event"]["Attribute"]
    assert len(attrs) == 2
    assert attrs[0]["type"] == "ip-dst"
    assert attrs[0]["value"] == "8.8.8.8"


def test_misp_first_last_seen_aggregated():
    resp = _make_response(results=[
        {"source": "VT", "ioc_type": "ipv4", "verdict": "malicious",
         "confidence": "high", "first_seen": "2024-01-01T00:00:00Z",
         "last_seen": "2024-06-01T00:00:00Z"},
        {"source": "OTX", "ioc_type": "ipv4", "verdict": "suspicious",
         "confidence": "medium", "first_seen": "2024-03-15T00:00:00Z",
         "last_seen": "2024-04-01T00:00:00Z"},
    ])
    event = build_misp_event(resp)
    attrs = event["Event"]["Attribute"]
    assert attrs[0]["first_seen"] == "2024-01-01T00:00:00Z"
    assert attrs[0]["last_seen"] == "2024-06-01T00:00:00Z"
    assert attrs[1]["first_seen"] == "2024-01-01T00:00:00Z"
    assert attrs[1]["last_seen"] == "2024-06-01T00:00:00Z"
    assert attrs[2]["first_seen"] == "2024-03-15T00:00:00Z"
    assert attrs[2]["last_seen"] == "2024-04-01T00:00:00Z"


def test_misp_geoip_object():
    event = build_misp_event(_make_response())
    objs = event["Event"]["Object"]
    geo = [o for o in objs if o["name"] == "geo-ip"]
    assert geo
    vals = {a["object_relation"]: a["value"] for a in geo[0]["attributes"]}
    assert vals["country"] == "US"
    assert vals["asn"] == "AS15169"


def test_misp_whois_object():
    event = build_misp_event(_make_response())
    objs = event["Event"]["Object"]
    whois = [o for o in objs if o["name"] == "whois"]
    assert whois
    vals = {a["object_relation"]: a["value"] for a in whois[0]["attributes"]}
    assert vals["registrar"] == "GoDaddy"
    assert vals["org"] == "ACME"


def test_misp_threat_level_clean():
    event = build_misp_event(_make_response(verdict="clean", score=0))
    assert event["Event"]["threat_level_id"] == 4


def test_misp_hash_category():
    resp = _make_response()
    resp["ioc_type"] = "sha256"
    resp["normalized"] = "d41d8cd98f00b204e9800998ecf8427e"
    event = build_misp_event(resp)
    attrs = event["Event"]["Attribute"]
    assert attrs[0]["type"] == "sha256"
    assert attrs[1]["category"] == "Payload delivery"
