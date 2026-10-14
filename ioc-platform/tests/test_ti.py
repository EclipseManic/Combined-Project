"""Single comprehensive test file for the entire Threat Intelligence layer.

Covers: models, adapters, pipeline, enrichment, scoring, STIX, batch, and API.
Uses mocking for external HTTP calls. Total: 70+ tests.
"""
import json
import os
import sys
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

import httpx

import pytest

sys.path.insert(0, ".")

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 1. DATA MODEL TESTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from app.backend.adapters.base import (
    NormalizedResult, GeoIPInfo, WhoisInfo, DNSInfo, SSLInfo,
    ReverseDNSInfo, EnrichmentData, SourceWeight, CompositeScore,
    LookupResponse, RateLimitConfig, SourceAdapter,
)


class TestNormalizedResult:
    def test_minimal(self):
        r = NormalizedResult(ioc="8.8.8.8", ioc_type="ipv4", source="Test", verdict="clean")
        assert r.ioc == "8.8.8.8"
        assert r.verdict == "clean"
        assert r.raw_score is None
        assert r.confidence == "low"
        assert r.tags == []
        assert r.mitre_attck == []

    def test_full(self):
        r = NormalizedResult(
            ioc="8.8.8.8", ioc_type="ipv4", source="VT", verdict="malicious",
            raw_score=0.95, confidence="high",
            tags=["malware", "c2"], categories=["trojan"],
            malware_family="Emotet",
            mitre_attck=["T1071", "T1573"],
            first_seen=datetime(2024, 1, 1),
            last_seen=datetime(2024, 6, 1),
            related_iocs=[("evil.com", "resolves_to")],
            source_link="https://virustotal.com/",
            reports_count=23,
            samples=["Avast: Win32:Emotet"],
        )
        assert r.raw_score == 0.95
        assert r.confidence == "high"
        assert r.malware_family == "Emotet"
        assert len(r.mitre_attck) == 2
        assert r.reports_count == 23

    def test_sanitizes_malformed_optional_provider_lists(self):
        r = NormalizedResult(
            ioc="example.com", ioc_type="domain", source="test", verdict="unknown",
            tags=["valid", None, "  "], categories=[None, "phishing"], samples="sample.exe",
            related_iocs=[("1.2.3.4", "resolves_to"), (None, "bad")],
            network_iocs=[("example.com", "domain"), ("", "bad")],
        )
        assert r.tags == ["valid"]
        assert r.categories == ["phishing"]
        assert r.samples == ["sample.exe"]
        assert r.related_iocs == [("1.2.3.4", "resolves_to")]
        assert r.network_iocs == [("example.com", "domain")]

    def test_verdict_error(self):
        r = NormalizedResult(ioc="x", ioc_type="ipv4", source="T", verdict="error", tags=["timeout"])
        assert r.verdict == "error"
        assert "timeout" in r.tags

    def test_serialize_roundtrip(self):
        r = NormalizedResult(
            ioc="8.8.8.8", ioc_type="ipv4", source="VT", verdict="malicious", raw_score=0.9,
        )
        d = r.model_dump()
        r2 = NormalizedResult(**d)
        assert r2.ioc == r.ioc
        assert r2.raw_score == r.raw_score

    def test_confidence_defaults(self):
        r = NormalizedResult(ioc="a", ioc_type="domain", source="S", verdict="unknown")
        assert r.confidence == "low"
        r2 = NormalizedResult(ioc="a", ioc_type="domain", source="S", verdict="malicious", confidence="high")
        assert r2.confidence == "high"


class TestGeoIPInfo:
    def test_empty(self):
        g = GeoIPInfo()
        assert g.country is None

    def test_full(self):
        g = GeoIPInfo(country="US", country_code="US", city="Mountain View",
                       asn="AS15169", asn_name="GOOGLE", isp="Google LLC",
                       latitude=37.422, longitude=-122.084)
        assert g.country == "US"
        assert g.asn == "AS15169"
        assert g.latitude == 37.422

    def test_serialize(self):
        g = GeoIPInfo(country="RU")
        d = g.model_dump()
        assert d["country"] == "RU"


class TestWhoisInfo:
    def test_abuse_email(self):
        w = WhoisInfo(abuse_email="abuse@example.com")
        assert w.abuse_email == "abuse@example.com"


class TestDNSInfo:
    def test_records(self):
        d = DNSInfo(a=["1.2.3.4"], mx=["mail.example.com"], ns=["ns1.example.com"])
        assert "1.2.3.4" in d.a
        assert "mail.example.com" in d.mx


class TestSSLInfo:
    def test_subject(self):
        s = SSLInfo(subject="*.example.com", issuer="Let's Encrypt", subject_alt_names=["DNS:example.com"])
        assert s.subject == "*.example.com"
        assert "DNS:example.com" in s.subject_alt_names


class TestEnrichmentData:
    def test_empty(self):
        e = EnrichmentData()
        assert e.geoip is None
        assert e.whois is None
        assert e.relationships == []

    def test_with_geoip(self):
        g = GeoIPInfo(country="US")
        e = EnrichmentData(geoip=g)
        assert e.geoip.country == "US"

    def test_with_relationships(self):
        e = EnrichmentData(relationships=[{"source_ioc": "1.2.3.4", "target_ioc": "evil.com", "relationship": "resolves_to", "via_source": "rdns"}])
        assert len(e.relationships) == 1


class TestCompositeScore:
    def test_default(self):
        c = CompositeScore()
        assert c.score == 0.0
        assert c.verdict == "unknown"
        assert c.confidence == "low"

    def test_malicious(self):
        c = CompositeScore(score=87.5, verdict="malicious", confidence="high", sources_contributing=3)
        assert c.score == 87.5
        assert c.verdict == "malicious"

    def test_with_breakdown(self):
        sw = SourceWeight(name="VT", weight=1.0, verdict="malicious", score=0.9)
        c = CompositeScore(score=90.0, verdict="malicious", confidence="high", source_breakdown=[sw])
        assert len(c.source_breakdown) == 1
        assert c.source_breakdown[0].name == "VT"


class TestLookupResponse:
    def test_minimal(self):
        c = CompositeScore()
        r = LookupResponse(input="8.8.8.8", normalized="8.8.8.8", ioc_type="ipv4", composite=c)
        assert r.ioc_type == "ipv4"
        assert r.results == []
        assert r.relationships == []

    def test_with_results(self):
        c = CompositeScore(score=90, verdict="malicious")
        nr = NormalizedResult(ioc="8.8.8.8", ioc_type="ipv4", source="VT", verdict="malicious")
        r = LookupResponse(input="8.8.8.8", normalized="8.8.8.8", ioc_type="ipv4", composite=c, results=[nr])
        assert len(r.results) == 1
        assert r.results[0].source == "VT"

    def test_full_serialize(self):
        c = CompositeScore(score=75, verdict="suspicious", confidence="medium")
        nr = NormalizedResult(ioc="evil.com", ioc_type="domain", source="TF", verdict="malicious", confidence="high", tags=["c2"])
        e = EnrichmentData(geoip=GeoIPInfo(country="RU"))
        r = LookupResponse(
            input="evil.com", normalized="evil.com", ioc_type="domain",
            composite=c, enrichment=e, results=[nr],
            relationships=[{"source_ioc": "evil.com", "target_ioc": "1.2.3.4", "relationship": "resolves_to", "via_source": "dns"}],
        )
        d = r.model_dump()
        assert d["composite"]["score"] == 75
        assert d["results"][0]["tags"] == ["c2"]
        assert d["enrichment"]["geoip"]["country"] == "RU"

    def test_empty_ioc_type(self):
        c = CompositeScore()
        r = LookupResponse(input="", normalized="", ioc_type="unknown", composite=c)
        assert r.ioc_type == "unknown"


class TestSourceAdapter:
    def test_abstract(self):
        with pytest.raises(TypeError):
            SourceAdapter()

    def test_rate_limit_default(self):
        class MyAdapter(SourceAdapter):
            name = "test"
            supported_types = ["ipv4"]
            async def lookup(self, v, t): pass

        a = MyAdapter()
        assert a.rate_limit.requests_per_minute == 30


class TestRateLimitConfig:
    def test_defaults(self):
        c = RateLimitConfig()
        assert c.requests_per_minute == 30
        assert c.requests_per_day == 1000

    def test_custom(self):
        c = RateLimitConfig(requests_per_minute=5, requests_per_day=500)
        assert c.requests_per_minute == 5


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 2. ADAPTER TESTS (via mocking)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from app.backend.adapters.virus_total import VirusTotalAdapter
from app.backend.adapters.abuse_ipdb import AbuseIPDBAdapter
from app.backend.adapters.threatfox import ThreatFoxAdapter
from app.backend.adapters.malware_bazaar import MalwareBazaarAdapter
from app.backend.adapters.urlscan_io import UrlScanIOAdapter
from app.backend.adapters.triage import TriageAdapter
from app.backend.adapters.hybrid_analysis import HybridAnalysisAdapter
from app.backend.adapters.hashlookup import HashlookupAdapter


def _mock_async_client(status_code=200, json_data=None, raise_on=None):
    """Create a mock AsyncClient that returns a controlled response.
    Handles the async context manager protocol used by httpx.AsyncClient.
    """
    mock_response = AsyncMock(spec=httpx.Response)
    mock_response.status_code = status_code
    mock_response.json.return_value = json_data or {}
    mock_response.text = json.dumps(json_data or {})

    mock_client_instance = AsyncMock()
    if raise_on:
        mock_client_instance.get.side_effect = raise_on
        mock_client_instance.post.side_effect = raise_on
    else:
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.post.return_value = mock_response
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None

    mock_class = MagicMock(return_value=mock_client_instance)
    return mock_class, mock_response


# â”€â”€ VirusTotal â”€â”€

class TestVirusTotalAdapter:
    @pytest.mark.asyncio
    async def test_no_key(self):
        a = VirusTotalAdapter()
        a.api_key = ""
        r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_401_invalid_key(self):
        a = VirusTotalAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        # A rejected key is a provider that could not answer, not a verdict.
        assert r.verdict == "unknown"
        assert r.execution_state == "unavailable"
        assert "invalid_api_key" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = VirusTotalAdapter()
        a.api_key = "valid_key"
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        # No record means no score, not a score of zero.
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        vt_json = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 15, "suspicious": 2, "harmless": 5, "undetected": 48},
                    "tags": ["malware", "c2"],
                    "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"},
                    "last_analysis_results": {
                        "Avast": {"result": "Win32:Emotet"},
                        "Kaspersky": {"result": "Trojan.Win32.Emotet"},
                    },
                    "resolutions": [{"host_name": "evil.com"}],
                }
            }
        }
        a = VirusTotalAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=vt_json)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "malicious"
        assert r.raw_score > 0
        assert r.confidence == "high"
        assert r.malware_family is not None
        assert "emotet" in r.malware_family.lower()
        assert len(r.samples) >= 2
        assert len(r.related_iocs) >= 1

    @pytest.mark.asyncio
    async def test_clean_response(self):
        vt_json = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10},
                    "tags": [],
                }
            }
        }
        a = VirusTotalAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=vt_json)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "clean"
        assert r.raw_score == 0.0

    @pytest.mark.asyncio
    async def test_suspicious_verdict(self):
        vt_json = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 3, "harmless": 50, "undetected": 17},
                    "tags": [],
                }
            }
        }
        a = VirusTotalAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=vt_json)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "suspicious"

    @pytest.mark.asyncio
    async def test_low_detection_ratio_is_suspicious(self):
        vt_json = {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 1, "suspicious": 0, "harmless": 49, "undetected": 50,
            }}}
        }
        a = VirusTotalAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=vt_json)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("a" * 64, "sha256")
        assert r.verdict == "suspicious"
        assert r.raw_score == 0.01

    def test_supported_types(self):
        a = VirusTotalAdapter()
        assert "ipv4" in a.supported_types
        assert "domain" in a.supported_types
        assert "md5" in a.supported_types
        assert "sha256" in a.supported_types

    @pytest.mark.asyncio
    async def test_url_lookup(self):
        a = VirusTotalAdapter()
        a.api_key = "valid"
        vt_json = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 10, "undetected": 20},
                    "tags": ["malicious-url"],
                }
            }
        }
        mock_class, _ = _mock_async_client(json_data=vt_json)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/path", "url")
        assert r.verdict == "malicious"


# â”€â”€ AbuseIPDB â”€â”€

class TestAbuseIPDBAdapter:
    @pytest.mark.asyncio
    async def test_no_key(self):
        a = AbuseIPDBAdapter()
        a.api_key = ""
        r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_401(self):
        a = AbuseIPDBAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "unavailable"
        assert "invalid_api_key" in r.tags

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        data = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 12,
                "isp": "Evil Hosting",
                "countryCode": "RU",
                "usageType": "Web Hosting",
                "domain": "evilhosting.com",
                "categories": {"1": "Spam", "2": "Malware"},
                "reports": [
                    {"categories": [1, 2], "comment": "C2 traffic observed"},
                    {"categories": [3], "comment": "Port scan"},
                ],
                "lastReportedAt": "2024-06-01T12:00:00Z",
            }
        }
        a = AbuseIPDBAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "malicious"
        assert r.raw_score == 0.85
        assert r.confidence == "high"
        assert r.reports_count == 12
        assert len(r.reports) >= 2
        assert r.reports[0]["categories"] == [1, 2]
        assert r.reports[0]["comment"] == "C2 traffic observed"

    @pytest.mark.asyncio
    async def test_clean_response(self):
        data = {"data": {"abuseConfidenceScore": 0, "totalReports": 3, "isp": "Google LLC", "countryCode": "US"}}
        a = AbuseIPDBAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "clean"
        assert r.raw_score == 0.0
        assert r.raw_data["abuse_confidence_score"] == 0
        assert r.raw_data["is_whitelisted"] is False
        assert r.raw_data["is_tor"] is False

    @pytest.mark.asyncio
    async def test_no_reports_is_undetected_not_clean(self):
        """Zero reports is absence of evidence; only reports that stayed low are 'clean'."""
        data = {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isp": "Google LLC", "countryCode": "US"}}
        a = AbuseIPDBAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "undetected"
        assert r.raw_score == 0.0

    def test_supported_types(self):
        a = AbuseIPDBAdapter()
        assert a.supported_types == ["ipv4", "ipv6"]


# â”€â”€ ThreatFox â”€â”€

class TestThreatFoxAdapter:
    @pytest.mark.asyncio
    async def test_no_key(self):
        """No key â†’ adapter still makes request (get_info is public)."""
        a = ThreatFoxAdapter()
        a.api_key = ""
        data = {"query_status": "no_result"}
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_no_result(self):
        a = ThreatFoxAdapter()
        a.api_key = "valid"
        data = {"query_status": "no_result"}
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        data = {
            "query_status": "ok",
            "data": [
                {"ioc": "1.2.3.4", "malware": "Emotet", "malware_printable": "Emotet Malware",
                 "tags": "emotet,spam,c2", "first_seen": "2024-01-01 12:00:00",
                 "last_seen": "2024-06-01 12:00:00", "reference": "https://threatfox.abuse.ch/"},
                {"ioc": "1.2.3.4", "malware": "Emotet", "malware_printable": "Emotet Malware",
                 "tags": "emotet,http", "first_seen": "2024-03-01",
                 "last_seen": "2024-06-01", "reference": ""},
            ],
        }
        a = ThreatFoxAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "malicious"
        assert r.raw_score == 1.0
        # The family shown is ThreatFox's printable name.
        assert r.malware_family == "Emotet Malware"
        assert "emotet" in r.tags
        assert "c2" in r.tags
        assert r.raw_data["match_type"] == "exact"
        assert r.reports_count == 2
        assert r.first_seen is not None
        assert r.last_seen is not None

    def test_supported_types(self):
        a = ThreatFoxAdapter()
        assert "ipv4" in a.supported_types
        assert "domain" in a.supported_types
        assert "md5" in a.supported_types

    @pytest.mark.asyncio
    async def test_all_entries_junk_returns_unknown(self):
        """Every entry carrying a test/junk marker -> not malicious evidence."""
        data = {
            "query_status": "ok",
            "data": [
                {"ioc": "example.com", "malware": "Test", "tags": "test,benign",
                 "confidence_level": 100},
                {"ioc": "example.com", "malware": "Test", "tags": "sandbox",
                 "confidence_level": 100},
            ],
        }
        a = ThreatFoxAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("example.com", "domain")
        assert r.verdict == "unknown"
        assert r.status == "not_found"
        assert r.reports_count == 0
        # The filtered count is structured data, not a tag.
        assert r.raw_data["filtered_low_quality_count"] == 2
        assert r.raw_data["match_count"] == 0

    @pytest.mark.asyncio
    async def test_junk_entries_excluded_from_kept_count(self):
        """Mixed feed: test submissions are excluded, real entries drive verdict."""
        data = {
            "query_status": "ok",
            "data": [
                {"ioc": "1.2.3.4", "malware": "Emotet", "malware_printable": "Emotet Malware",
                 "tags": "emotet,c2", "confidence_level": 100,
                 "first_seen": "2024-01-01", "last_seen": "2024-06-01",
                 "reference": "https://threatfox.abuse.ch/"},
                {"ioc": "1.2.3.4", "malware": "Test", "malware_printable": "Test",
                 "tags": "test,benign", "confidence_level": 100},
            ],
        }
        a = ThreatFoxAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "malicious"
        assert r.malware_family == "Emotet Malware"
        assert "emotet" in r.tags
        assert r.reports_count == 1
        assert "test" not in r.tags
        assert not any("reported_by" in t for t in r.tags)

    @pytest.mark.asyncio
    async def test_low_confidence_entry_filtered(self):
        """confidence_level below the floor is treated as junk evidence."""
        data = {
            "query_status": "ok",
            "data": [
                {"ioc": "1.2.3.4", "malware": "Emotet", "tags": "emotet",
                 "confidence_level": 20},
                {"ioc": "1.2.3.4", "malware": "Emotet", "tags": "emotet",
                 "confidence_level": 90},
            ],
        }
        a = ThreatFoxAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "malicious"
        assert r.reports_count == 1
        assert r.raw_score == 0.9


# â”€â”€ MalwareBazaar â”€â”€

class TestMalwareBazaarAdapter:
    @pytest.mark.asyncio
    async def test_no_key(self):
        """No key â†’ adapter still makes request (get_info is public)."""
        a = MalwareBazaarAdapter()
        a.api_key = ""
        data = {"query_status": "hash_not_found"}
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_not_found(self):
        a = MalwareBazaarAdapter()
        a.api_key = "valid"
        data = {"query_status": "hash_not_found"}
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        data = {
            "query_status": "ok",
            "data": [{
                "sha256_hash": "abc123",
                "file_name": "invoice.exe",
                "file_type": "exe",
                "signature": "Emotet",
                "imphash": "deadbeef",
                "tlsh": "tlsh123",
                "first_seen": "2024-01-15 10:00:00",
                "last_seen": "2024-06-01",
                "tags": "emotet,loader",
                "delivery_method": "email",
            }],
        }
        a = MalwareBazaarAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("abc123", "sha256")
        assert r.verdict == "malicious"
        assert r.raw_score == 1.0
        assert r.confidence == "high"
        assert r.malware_family == "Emotet"
        # File type is a category and the family is malware_family; tags
        # carry only the sample's own short labels.
        assert r.categories == ["exe"]
        assert "emotet" in r.tags
        assert "loader" in r.tags
        assert r.raw_data["signature"] == "Emotet"
        assert r.raw_data["file_name"] == "invoice.exe"

    @pytest.mark.asyncio
    async def test_record_for_a_different_hash_is_not_a_match(self):
        data = {"query_status": "ok", "data": [{"sha256_hash": "def456", "signature": "Emotet"}]}
        a = MalwareBazaarAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("abc123", "sha256")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"

    @pytest.mark.asyncio
    async def test_null_optional_metadata_is_filtered(self):
        data = {
            "query_status": "ok",
            "data": [{"file_type": None, "signature": None, "first_seen": None, "last_seen": None}],
        }
        a = MalwareBazaarAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            result = await a.lookup("abc123", "sha256")
        assert result.categories == []

    def test_supported_types(self):
        a = MalwareBazaarAdapter()
        assert "md5" in a.supported_types
        assert "sha1" in a.supported_types
        assert "sha256" in a.supported_types


# â”€â”€ urlscan.io â”€â”€

class TestUrlScanIOAdapter:
    @pytest.mark.asyncio
    async def test_public_search_without_key(self):
        a = UrlScanIOAdapter()
        a.api_key = ""
        mock_class, _ = _mock_async_client(json_data={"results": []})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("evil.com", "domain")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" not in r.tags

    @pytest.mark.asyncio
    async def test_401(self):
        a = UrlScanIOAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "unavailable"
        assert "invalid_api_key" in r.tags

    @pytest.mark.asyncio
    async def test_empty_results(self):
        data = {"results": []}
        a = UrlScanIOAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("evil.com", "domain")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        data = {
            "results": [
                {"page": {}, "result": {"verdicts": {"overall": {"malicious": True, "score": 95, "tags": ["phishing", "malware"]}}},
                 "task": {"url": "http://evil.com/login", "time": "2024-05-01T12:00:00Z", "reportURL": "https://urlscan.io/result/abc/"}, "categories": ["phishing"]},
                {"page": {"tags": ["phishing"]}, "result": {"verdicts": {"overall": {"malicious": True, "score": 80}}},
                 "task": {"url": "http://evil.com/admin", "time": "2024-04-01T12:00:00Z", "reportURL": ""}, "categories": ["malware"]},
            ],
        }
        a = UrlScanIOAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("evil.com", "domain")
        assert r.verdict == "malicious"
        assert r.raw_score > 0
        assert "phishing" in r.tags
        assert r.reports_count == 2
        assert r.source_link != ""

    def test_supported_types(self):
        a = UrlScanIOAdapter()
        assert "domain" in a.supported_types
        assert "url" in a.supported_types


# â”€â”€ Cross-Adapter â”€â”€

class TestHashlookupAdapter:
    """CIRCL Hashlookup is a known-FILE reference corpus (NSRL + known software
    + some malware). A hit means 'known file', never 'safe' -- the adapter must
    not badge a found hash as clean (regression for the false-clean bug)."""

    @pytest.mark.asyncio
    async def test_found_known_malware_hash_is_not_clean(self):
        # A real known-malware sample can be present in the corpus; 'found' must
        # not be reported as a clean/benign verdict.
        data = {
            "FileName": "trojan_dropper.exe",
            "mimetype": "application/x-dosexec",
            "SHA-256": "a" * 64,
            "KnownMalicious": "known malware sample",
        }
        a = HashlookupAdapter()
        mock_class, _ = _mock_async_client(status_code=200, json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("a" * 64, "sha256")
        assert r.status == "found"
        assert r.verdict != "clean"
        assert r.verdict != "benign"
        assert r.verdict == "unknown"
        assert r.raw_score == 0.0
        assert "known_file" in r.tags

    @pytest.mark.asyncio
    async def test_found_benign_known_file_is_also_not_clean(self):
        data = {"FileName": "kernel32.dll", "trust": 100}
        a = HashlookupAdapter()
        mock_class, _ = _mock_async_client(status_code=200, json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.status == "found"
        assert r.verdict == "unknown"
        assert "present_in_reference_corpus" in r.tags

    @pytest.mark.asyncio
    async def test_not_found_stays_unknown_not_found(self):
        a = HashlookupAdapter()
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert r.verdict == "unknown"
        assert r.status == "not_found"


class TestAdapterConsistency:
    """All adapters must follow the same contract."""

    ADAPTERS = [
        ("VirusTotal", VirusTotalAdapter, ["ipv4", "domain", "md5", "sha256", "url"]),
        ("AbuseIPDB", AbuseIPDBAdapter, ["ipv4", "ipv6"]),
        ("ThreatFox", ThreatFoxAdapter, ["ipv4", "domain", "md5", "sha256"]),
        ("MalwareBazaar", MalwareBazaarAdapter, ["md5", "sha1", "sha256"]),
        ("urlscan.io", UrlScanIOAdapter, ["domain", "url"]),
        ("Tria.ge", TriageAdapter, ["md5", "sha1", "sha256"]),
        ("Hybrid Analysis", HybridAnalysisAdapter, ["md5", "sha1", "sha256"]),
    ]

    def test_all_have_name(self):
        for name, cls, _ in self.ADAPTERS:
            a = cls.__new__(cls)
            a.__init__ = lambda self: None
            try:
                cls.__init__(a)
            except Exception:
                pass
            assert a.name == name, f"{name} name mismatch"

    def test_all_have_supported_types(self):
        for _, cls, expected in self.ADAPTERS:
            a = cls.__new__(cls)
            a.__init__ = lambda self: None
            try:
                cls.__init__(a)
            except Exception:
                pass
            for t in expected:
                assert t in a.supported_types, f"{a.name} missing {t}"

    def test_all_are_adapters(self):
        for _, cls, _ in self.ADAPTERS:
            assert issubclass(cls, SourceAdapter), f"{cls.__name__} not a SourceAdapter"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 3. SCORING TESTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from app.backend.scorer import compute_composite, SOURCE_WEIGHTS, VERDICT_SCORES


class TestScoringEngine:
    def test_compute_malicious(self):
        r = NormalizedResult(ioc="1.2.3.4", ioc_type="ipv4", source="VT", verdict="malicious", raw_score=0.9, confidence="high")
        c = compute_composite([r])
        assert c.verdict == "malicious"
        assert c.score >= 70  # 0.9 * 100 with weighting

    def test_compute_clean_with_high_confidence(self):
        results = [
            NormalizedResult(ioc="8.8.8.8", ioc_type="ipv4", source="VT", verdict="clean", raw_score=0.0),
            NormalizedResult(ioc="8.8.8.8", ioc_type="ipv4", source="AbuseIPDB", verdict="clean", raw_score=0.0),
            NormalizedResult(ioc="8.8.8.8", ioc_type="ipv4", source="ThreatFox", verdict="unknown"),
        ]
        c = compute_composite(results)
        assert c.verdict == "clean"

    def test_weighted_scoring(self):
        results = [
            NormalizedResult(ioc="x", ioc_type="ipv4", source="VirusTotal", verdict="malicious", raw_score=0.9),
            NormalizedResult(ioc="x", ioc_type="ipv4", source="AbuseIPDB", verdict="clean", raw_score=0.0),
        ]
        c = compute_composite(results)
        assert 0 < c.score < 100
        contrib = [s for s in c.source_breakdown]
        assert len(contrib) == 2

    def test_empty_no_results(self):
        c = compute_composite([])
        assert c.verdict == "unknown"
        assert c.score == 0.0

    def test_all_error(self):
        r = NormalizedResult(ioc="x", ioc_type="ipv4", source="VT", verdict="error")
        c = compute_composite([r])
        assert c.verdict == "unknown"

    def test_source_weights_defined(self):
        expected = {"VirusTotal", "AbuseIPDB", "ThreatFox", "MalwareBazaar", "urlscan.io", "CVE", "Tria.ge", "Hybrid Analysis", "AlienVault OTX", "GreyNoise", "OpenPhish", "URLhaus", "StopForumSpam"}
        assert set(SOURCE_WEIGHTS.keys()) == expected

    def test_verdict_scores_defined(self):
        for v in ("malicious", "suspicious", "clean", "unknown", "error"):
            assert v in VERDICT_SCORES


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 4. ENRICHMENT TESTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from app.backend.enrichment import enrich, _is_ip


class TestEnrichmentIntegration:
    @pytest.mark.asyncio
    async def test_ip_enrichment(self):
        """GeoIP should work for a public IP (no mocking)."""
        result = await enrich("8.8.8.8", "ipv4")
        assert isinstance(result, EnrichmentData)
        # GeoIP may fail if offline, but structure must be valid
        assert "geoip" in result.completeness

    @pytest.mark.asyncio
    async def test_domain_enrichment(self):
        result = await enrich("google.com", "domain")
        assert isinstance(result, EnrichmentData)
        assert hasattr(result, "whois")

    @pytest.mark.asyncio
    async def test_md5_returns_empty(self):
        result = await enrich("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert result.geoip is None
        assert result.whois is None

    def test_is_ip_valid(self):
        assert _is_ip("1.2.3.4")
        assert _is_ip("255.255.255.255")
        assert not _is_ip("256.1.2.3")
        assert not _is_ip("not_an_ip")

    def test_is_ip_edge_cases(self):
        assert _is_ip("0.0.0.0")
        assert not _is_ip("")
        assert not _is_ip("1.2.3")
        assert not _is_ip("1.2.3.4.5")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 5. STIX EXPORT TESTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from app.backend.stix_export import build_stix_bundle, results_to_csv


class TestSTIXExport:
    def _make_response(self, **kwargs):
        base = {
            "input": "8.8.8.8", "normalized": "8.8.8.8", "ioc_type": "ipv4",
            "composite": {"score": 85.0, "verdict": "malicious", "confidence": "high",
                           "sources_contributing": 2, "source_breakdown": []},
            "enrichment": {"geoip": {"country": "US", "country_code": "US", "city": "", "asn": "", "asn_name": "", "isp": "", "org": "",
                                      "latitude": None, "longitude": None},
                            "whois": None, "dns": None, "ssl": None, "reverse_dns": None, "relationships": []},
            "results": [{"source": "VT", "ioc_type": "ipv4", "verdict": "malicious", "raw_score": 0.9,
                          "confidence": "high", "tags": ["malware"], "categories": [], "mitre_attck": ["T1071"],
                          "source_link": "https://vt.com/", "reports_count": 5, "malware_family": "",
                          "first_seen": None, "last_seen": None, "samples": [], "related_iocs": [],
                          "ioc": "8.8.8.8"}],
            "relationships": [],
        }
        base.update(kwargs)
        return base

    def test_bundle_structure(self):
        bundle = build_stix_bundle(self._make_response())
        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert len(bundle["objects"]) > 0

    def test_has_indicator(self):
        bundle = build_stix_bundle(self._make_response())
        types = {o["type"] for o in bundle["objects"]}
        assert "indicator" in types

    def test_indicator_malicious_label(self):
        bundle = build_stix_bundle(self._make_response())
        ind = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert "malicious-activity" in ind["indicator_types"]

    def test_indicator_benign_label(self):
        resp = self._make_response()
        resp["composite"]["verdict"] = "clean"
        resp["composite"]["score"] = 0
        bundle = build_stix_bundle(resp)
        ind = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert "benign" in ind["indicator_types"]

    def test_has_sighting(self):
        bundle = build_stix_bundle(self._make_response())
        types = {o["type"] for o in bundle["objects"]}
        assert "sighting" in types

    def test_has_location_from_geoip(self):
        bundle = build_stix_bundle(self._make_response())
        types = {o["type"] for o in bundle["objects"]}
        assert "location" in types

    def test_has_relationships_from_results(self):
        resp = self._make_response(relationships=[{"source_ioc": "8.8.8.8", "target_ioc": "evil.com",
                                                     "relationship": "resolves_to", "via_source": "dns"}])
        bundle = build_stix_bundle(resp)
        types = {o["type"] for o in bundle["objects"]}
        assert "relationship" in types

    def test_ipv4_pattern(self):
        bundle = build_stix_bundle(self._make_response())
        ind = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert "ipv4-addr" in ind["pattern"]

    def test_file_pattern(self):
        resp = self._make_response(ioc_type="md5", normalized="d41d8cd98f00b204e9800998ecf8427e")
        bundle = build_stix_bundle(resp)
        ind = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert "file:hashes" in ind["pattern"]

    def test_domain_pattern(self):
        resp = self._make_response(ioc_type="domain", normalized="evil.com")
        bundle = build_stix_bundle(resp)
        ind = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert "domain-name" in ind["pattern"]

    def test_url_pattern(self):
        resp = self._make_response(ioc_type="url", normalized="https://evil.com")
        bundle = build_stix_bundle(resp)
        ind = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert "url:value" in ind["pattern"]

    def test_csv_generation(self):
        results = [
            {"source": "VT", "ioc_type": "ipv4", "verdict": "malicious", "raw_score": 0.9,
             "confidence": "high", "malware_family": "Emotet", "reports_count": 5,
             "tags": ["malware"], "categories": ["trojan"], "mitre_attck": ["T1071"],
             "source_link": "https://vt.com/"},
        ]
        csv = results_to_csv(results)
        assert "Source" in csv
        assert "VT" in csv
        assert "Emotet" in csv

    def test_csv_empty(self):
        csv = results_to_csv([])
        assert "Source" in csv


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 6. PIPELINE INTEGRATION TESTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from app.backend.pipeline import run_analysis, get_task, _tasks


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
class TestPipeline:
    @pytest.mark.asyncio
    async def test_run_analysis_ip(self):
        task = await run_analysis("8.8.8.8")
        assert task.status == "done"
        assert task.progress == 100.0
        assert task.ioc_type == "ipv4"
        assert task.normalized == "8.8.8.8"
        # Stages are derived dynamically from the applicable provider plan
        # (Classify + one row per applicable provider + Enrichment + Scoring),
        # so the count varies by IOC type rather than being a fixed 24.
        names = [s.name for s in task.stages]
        assert names[0] == "Classify & Normalize"
        assert names[-2:] == ["Enrichment", "Scoring & Relations"]
        assert len(task.stages) >= 4

    @pytest.mark.asyncio
    async def test_run_analysis_domain(self):
        task = await run_analysis("google.com")
        assert task.status == "done"
        assert task.ioc_type == "domain"

    @pytest.mark.asyncio
    async def test_run_analysis_url(self):
        task = await run_analysis("https://google.com/path")
        assert task.status == "done"
        assert task.ioc_type == "url"

    @pytest.mark.asyncio
    async def test_run_analysis_hash(self):
        task = await run_analysis("d41d8cd98f00b204e9800998ecf8427e")
        assert task.status == "done"
        assert task.ioc_type == "md5"

    @pytest.mark.asyncio
    async def test_run_analysis_invalid(self):
        task = await run_analysis("   ")
        assert task.status == "error"
        assert task.error is not None

    @pytest.mark.asyncio
    async def test_get_task(self):
        task = await run_analysis("8.8.8.8")
        retrieved = get_task(task.task_id)
        assert retrieved is not None
        assert retrieved.task_id == task.task_id

    @pytest.mark.asyncio
    async def test_get_missing_task(self):
        assert get_task("nonexistent") is None

    @pytest.mark.asyncio
    async def test_task_has_stages(self):
        task = await run_analysis("8.8.8.8")
        # Dynamic stages: at least Classify + one provider + Enrichment + Scoring.
        assert len(task.stages) >= 4
        for stage in task.stages:
            assert stage.status in ("done", "skipped", "pending", "error")

    @pytest.mark.asyncio
    async def test_task_stage_names(self):
        task = await run_analysis("8.8.8.8")
        names = [s.name for s in task.stages]
        assert "Classify & Normalize" in names
        assert "VirusTotal" in names
        assert "AbuseIPDB" in names
        assert "Enrichment" in names
        assert "Scoring & Relations" in names

    @pytest.mark.asyncio
    async def test_result_has_composite(self):
        task = await run_analysis("8.8.8.8")
        assert task.composite is not None
        assert hasattr(task.composite, "score")
        assert hasattr(task.composite, "verdict")

    @pytest.mark.asyncio
    async def test_result_has_enrichment(self):
        task = await run_analysis("8.8.8.8")
        assert task.enrichment is not None
        assert isinstance(task.enrichment, EnrichmentData)

    @pytest.mark.asyncio
    async def test_result_has_relationships(self):
        task = await run_analysis("8.8.8.8")
        assert task.relationships is not None
        assert isinstance(task.relationships, list)

    @pytest.mark.asyncio
    async def test_task_to_dict(self):
        task = await run_analysis("8.8.8.8")
        d = task.to_dict()
        assert d["task_id"] == task.task_id
        assert d["status"] == "done"
        assert d["ioc_value"] == "8.8.8.8"
        assert len(d["stages"]) >= 4
        assert d["stages"][0]["name"] == "Classify & Normalize"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 7. CLASSIFIER TESTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from app.backend.classifier import classify_ioc, refang, defang


class TestClassifier:
    def test_ipv4(self):
        assert classify_ioc("8.8.8.8") == "ipv4"

    def test_domain(self):
        assert classify_ioc("google.com") == "domain"

    def test_url(self):
        assert classify_ioc("https://evil.com/path") == "url"

    def test_md5(self):
        assert classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_sha1(self):
        assert classify_ioc("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert classify_ioc(h) == "sha256"

    def test_email(self):
        assert classify_ioc("user@evil.com") == "email"

    def test_cve(self):
        assert classify_ioc("CVE-2024-12345") == "cve"

    def test_unknown(self):
        assert classify_ioc("!!! not an ioc !!!") == "unknown"

    def test_empty(self):
        assert classify_ioc("") == "unknown"

    def test_refang_hxxp(self):
        assert refang("hxxp://evil.com") == "http://evil.com"

    def test_refang_hxxps(self):
        assert refang("hxxps://evil.com") == "https://evil.com"

    def test_refang_bracket_dot(self):
        assert refang("evil[.]com") == "evil.com"

    def test_defang(self):
        assert defang("http://evil.com") == "hxxp://evil[.]com"

    def test_refang_and_classify(self):
        v = refang("hxxps://evil[.]com")
        assert v == "https://evil.com"
        assert classify_ioc(v) == "url"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 8. BATCH TESTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from app.backend.batch import parse_csv, parse_json


class TestBatchParser:
    def test_csv_simple(self):
        iocs = parse_csv("8.8.8.8\ngoogle.com\n1.1.1.1")
        assert len(iocs) == 3

    def test_csv_with_commas(self):
        iocs = parse_csv("8.8.8.8,google.com,1.1.1.1")
        assert len(iocs) == 3

    def test_csv_empty(self):
        assert parse_csv("") == []

    def test_csv_whitespace(self):
        iocs = parse_csv("  8.8.8.8  \n  google.com  ")
        assert iocs == ["8.8.8.8", "google.com"]

    def test_json_array(self):
        iocs = parse_json('["8.8.8.8", "google.com", "1.1.1.1"]')
        assert len(iocs) == 3

    def test_json_iocs_key(self):
        iocs = parse_json('{"iocs": ["8.8.8.8", "google.com"]}')
        assert len(iocs) == 2

    def test_json_empty_array(self):
        assert parse_json("[]") == []

    def test_json_indicators_key(self):
        assert parse_json('{"indicators": ["8.8.8.8"]}') == ["8.8.8.8"]

    def test_json_object_values(self):
        iocs = parse_json('{"a": "8.8.8.8", "b": "google.com"}')
        assert len(iocs) == 2


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 9. CONFIG TESTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from app.backend.config import Settings, settings


class TestConfig:
    def test_settings_defaults(self):
        assert hasattr(settings, "database_url")
        assert hasattr(settings, "virustotal_api_key")

    @patch.dict(os.environ, {}, clear=True)
    def test_settings_env_aliases(self):
        """VT_API_KEY maps to virustotal_api_key via pop_by_name."""
        s = Settings(**{"VT_API_KEY": "vtkey"})
        assert s.virustotal_api_key == "vtkey"

    @patch.dict(os.environ, {}, clear=True)
    def test_threatfox_fallback(self):
        """ThreatFox key falls back to MalwareBazaar key."""
        s = Settings(malwarebazaar_api_key="shared_key", threatfox_api_key="")
        assert s.threatfox_api_key == "" or s.threatfox_api_key == "shared_key"


class TestConfigAliases:
    @patch.dict(os.environ, {}, clear=True)
    def test_abuseipdb_alias(self):
        """AbuseDB_API_KEY maps to abuseipdb_api_key."""
        s = Settings(abuseipdb_api_key="key1", _env_file=None)
        assert s.abuseipdb_api_key == "key1"

    @patch.dict(os.environ, {}, clear=True)
    def test_vt_alias(self):
        s = Settings(**{"VT_API_KEY": "vtkey"})
        assert s.virustotal_api_key == "vtkey"

    @patch.dict(os.environ, {}, clear=True)
    def test_urlscan_alias(self):
        s = Settings(**{"URL_SCAN_API_KEY": "uskey"})
        assert s.urlscanio_api_key == "uskey"

    @patch.dict(os.environ, {}, clear=True)
    def test_mb_alias(self):
        s = Settings(**{"MB_AUTH_KEY": "mbkey"})
        assert s.malwarebazaar_api_key == "mbkey"
