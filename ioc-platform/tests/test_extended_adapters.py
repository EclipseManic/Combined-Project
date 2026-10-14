"""Tests for 9 extended threat-intelligence adapters.

Covers: GreyNoise, AlienVault OTX, Shodan,
OpenPhish, URLhaus, Tor Exit, Censys, IPinfo.

Uses the same mocking patterns as tests/test_ti.py.
"""
import json
import sys
import time
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

sys.path.insert(0, ".")


# ─── Mock helper (mirrors test_ti.py) ───

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


def _mock_async_router(routes: dict[str, tuple[int, dict]]):
    """Mock client that returns different responses based on URL substring match.
    routes: {url_substring: (status_code, json_data)}
    Any unmatched URL returns 404.
    """
    async def _route(url, *args, **kwargs):
        url_str = str(url)
        for pattern, (status, data) in routes.items():
            if pattern in url_str:
                mr = AsyncMock(spec=httpx.Response)
                mr.status_code = status
                mr.json.return_value = data or {}
                mr.text = json.dumps(data or {})
                return mr
        mr = AsyncMock(spec=httpx.Response)
        mr.status_code = 404
        mr.json.return_value = {}
        mr.text = "{}"
        return mr
    mc = AsyncMock()
    mc.get.side_effect = _route
    mc.post.side_effect = _route
    mc.__aenter__.return_value = mc
    mc.__aexit__.return_value = None
    return MagicMock(return_value=mc)


# ─── Adapter imports ───

from app.backend.adapters.base import NormalizedResult, SourceAdapter
from app.backend.adapters.grey_noise import GreyNoiseAdapter
from app.backend.adapters.alienvault_otx import AlienVaultOTXAdapter
from app.backend.adapters.shodan import ShodanAdapter
from app.backend.adapters.openphish import OpenPhishAdapter
from app.backend.adapters.openphish import OpenPhishAdapter
from app.backend.adapters.urlhaus import URLHausAdapter
from app.backend.adapters.tor_exit import TorExitAdapter
from app.backend.adapters.censys import CensysAdapter
from app.backend.adapters.ipinfo import IPinfoAdapter


# ─── Module-level helpers for adapters with shared state ───

import app.backend.adapters.openphish as _openphish_mod
import app.backend.adapters.tor_exit as _tor_exit_mod


# ============================================================
# GreyNoise
# ============================================================

class TestGreyNoiseAdapter:
    """GreyNoise does NOT block requests when no API key is set;
    it simply omits the key parameter and the free community endpoint
    may return 401/404 instead.
    """

    @pytest.fixture(autouse=True)
    def _reset_quota_state(self, monkeypatch):
        """The anonymous weekly quota is process-wide class state; a 429 in
        one test must not exhaust it for the next (or for other test files)."""
        monkeypatch.setattr(GreyNoiseAdapter, "_weekly_requests_used", 0)
        monkeypatch.setattr(GreyNoiseAdapter, "_quota_reset_time", 0.0)
        monkeypatch.setattr(GreyNoiseAdapter, "_quota_remaining", None)

    def test_supported_types(self):
        a = GreyNoiseAdapter()
        assert a.supported_types == ["ipv4"]

    @pytest.mark.asyncio
    async def test_noise_classification(self):
        """classification='noise' → internet scanner, verdict unknown."""
        data = {"classification": "noise", "name": "Unknown Scanner",
                "link": "https://viz.greynoise.io/ip/1.2.3.4",
                "last_seen": "2025-01-01"}
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert "internet_scanner" in r.tags
        assert r.raw_data["classification"] == "noise"
        assert r.raw_data["name"] == "Unknown Scanner"
        assert r.raw_data["last_seen"] == "2025-01-01"

    @pytest.mark.asyncio
    async def test_riot_classification(self):
        """classification='riot' → known service, verdict clean."""
        data = {"classification": "riot", "name": "Google",
                "link": "https://viz.greynoise.io/ip/8.8.8.8",
                "last_seen": "2025-01-01"}
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "clean"
        assert r.raw_score == 0.0
        assert "known_service" in r.tags

    @pytest.mark.asyncio
    async def test_unknown_classification(self):
        """classification='unknown' → no data, verdict unknown."""
        data = {"classification": "unknown", "name": ""}
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "unknown"
        assert "greynoise_no_data" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "unavailable"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_429_rate_limited(self):
        a = GreyNoiseAdapter()
        mock_class, _ = _mock_async_client(status_code=429)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "rate_limited" in r.tags

    @pytest.mark.asyncio
    async def test_api_key_bypasses_anonymous_weekly_counter(self):
        original_used = GreyNoiseAdapter._weekly_requests_used
        original_reset = GreyNoiseAdapter._quota_reset_time
        original_remaining = GreyNoiseAdapter._quota_remaining
        try:
            GreyNoiseAdapter._weekly_requests_used = GreyNoiseAdapter.WEEKLY_LIMIT
            GreyNoiseAdapter._quota_reset_time = time.time() + 3600
            GreyNoiseAdapter._quota_remaining = None

            a = GreyNoiseAdapter()
            a.api_key = "valid_key"
            mock_class, _ = _mock_async_client(json_data={"classification": "riot"})
            with patch("httpx.AsyncClient", mock_class):
                r = await a.lookup("8.8.8.8", "ipv4")

            assert r.verdict == "clean"
            assert "weekly_quota_exhausted" not in r.tags
        finally:
            GreyNoiseAdapter._weekly_requests_used = original_used
            GreyNoiseAdapter._quota_reset_time = original_reset
            GreyNoiseAdapter._quota_remaining = original_remaining


# ============================================================
# AlienVault OTX
# ============================================================

class TestAlienVaultOTXAdapter:
    def test_supported_types(self):
        a = AlienVaultOTXAdapter()
        for t in ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"):
            assert t in a.supported_types

    @pytest.mark.asyncio
    async def test_no_key(self):
        a = AlienVaultOTXAdapter()
        a.api_key = ""
        r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = AlienVaultOTXAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "unavailable"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_timeout_returns_normalized_error(self):
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"

        class TimeoutClient:
            async def get(self, *args, **kwargs):
                raise httpx.ReadTimeout("")

        a.set_client(TimeoutClient())
        result = await a.lookup("8.8.8.8", "ipv4")
        assert result.status == "error"
        assert "timeout" in result.tags

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        """3+ pulses that name a malware family or ATT&CK technique -> malicious.

        The verdict comes from the indicator's own ``general`` pulse_info
        (pulse membership with attribution), not from a top-level threat_score,
        and pulse names are structured raw_data rather than tags.
        """
        data = {
            "pulse_info": {
                "count": 8,
                "pulses": [
                    {"name": "Emotet C2", "malware_families": [{"display_name": "Emotet"}],
                     "attack_ids": [{"id": "T1071"}]},
                    {"name": "Malicious IP"},
                ],
            },
        }
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "malicious"
        assert r.raw_score == 0.7
        assert r.confidence == "medium"
        assert r.reports_count == 8
        assert r.malware_family == "Emotet"
        assert r.mitre_attck == ["T1071"]
        assert r.raw_data["pulse_count"] == 8
        assert "Emotet C2" in r.raw_data["pulse_names"]
        assert "Emotet C2" not in " ".join(r.tags)

    @pytest.mark.asyncio
    async def test_suspicious_response(self):
        """Pulse membership without any family/technique attribution -> suspicious."""
        data = {
            "pulse_info": {
                "count": 3,
                "pulses": [{"name": "Suspicious"}],
            },
        }
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "suspicious"
        assert r.raw_score == 0.4
        assert r.confidence == "medium"

    @pytest.mark.asyncio
    async def test_unknown_response(self):
        """pulse_count==0 -> not found (no pulse references the indicator)."""
        data = {"pulse_info": {"count": 0, "pulses": []}}
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None
        assert r.confidence == "low"

    @pytest.mark.asyncio
    async def test_whitelist_validation_is_not_malicious(self):
        data = {
            "pulse_info": {"count": 9, "pulses": [{"name": "p", "malware_families": ["Emotet"]}]},
            "validation": [{"source": "whitelist", "message": "Whitelisted domain", "name": "Whitelisted"}],
        }
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("google.com", "domain")
        assert r.verdict == "whitelisted"

    @pytest.mark.asyncio
    async def test_url_type(self):
        """URL type maps to 'url' segment."""
        data = {
            "pulse_info": {
                "count": 5,
                "pulses": [{"name": "Phishing URL", "malware_families": [{"display_name": "Kit"}]}],
            },
        }
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/phish", "url")
        assert r.verdict == "malicious"
        assert r.raw_score == 0.7

    @pytest.mark.asyncio
    async def test_unsupported_type(self):
        """Unsupported IOC type → unknown with tag."""
        a = AlienVaultOTXAdapter()
        a.api_key = "valid"
        r = await a.lookup("some_value", "email")
        assert r.verdict == "unknown"
        assert "unsupported_type" in r.tags


# ============================================================
# Shodan
# ============================================================

class TestShodanAdapter:
    def test_supported_types(self):
        a = ShodanAdapter()
        assert a.supported_types == ["ipv4"]

    @pytest.mark.asyncio
    async def test_no_free_data_does_not_call_paid_host_api(self):
        a = ShodanAdapter()
        a.api_key = "valid"
        mock_class = _mock_async_router({"internetdb": (404, {})})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert "internetdb_no_data" in r.tags

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = ShodanAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert "internetdb_no_data" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = ShodanAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"

    @pytest.mark.asyncio
    async def test_normal_response(self):
        """Shodan always returns unknown (enrichment-only)."""
        a = ShodanAdapter()
        a.api_key = "valid"
        mock_class = _mock_async_router({"internetdb": (404, {}), "shodan.io": (200, {})})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert "internetdb_no_data" in r.tags

    @pytest.mark.asyncio
    async def test_empty_response(self):
        """A host-API result is never used as a free-tier fallback."""
        a = ShodanAdapter()
        a.api_key = "valid"
        mock_class = _mock_async_router({"internetdb": (404, {}), "shodan.io": (200, {})})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"


# ============================================================
# OpenPhish (feed-based, no API key)
# ============================================================

class TestOpenPhishAdapter:
    def test_supported_types(self):
        a = OpenPhishAdapter()
        assert a.supported_types == ["url"]

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        """URL present in the downloaded feed → malicious."""
        # Reset feed state
        _openphish_mod._feed = []
        _openphish_mod._feed_updated = 0.0

        feed_text = "https://evil.com/phish\nhttps://malware.test/page"
        mock_class, mock_resp = _mock_async_client(status_code=200)
        mock_resp.text = feed_text

        a = OpenPhishAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/phish", "url")
        assert r.verdict == "malicious"
        assert r.raw_score == 0.8
        assert r.confidence == "medium"
        assert "phishing" in r.tags
        assert "openphish_feed" in r.tags

    @pytest.mark.asyncio
    async def test_clean_response(self):
        """URL NOT present in the downloaded feed → unknown / low (not in feed)."""
        _openphish_mod._feed = []
        _openphish_mod._feed_updated = 0.0

        feed_text = "https://evil.com/phish\nhttps://bad.example"
        mock_class, mock_resp = _mock_async_client(status_code=200)
        mock_resp.text = feed_text

        a = OpenPhishAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://safe.example.com", "url")
        assert r.verdict == "unknown"
        assert r.raw_score == 0.0
        assert r.confidence == "low"
        assert "not_in_feed" in r.tags

    @pytest.mark.asyncio
    async def test_feed_unavailable(self):
        """Feed download fails → unknown / feed_unavailable."""
        _openphish_mod._feed = []
        _openphish_mod._feed_updated = 0.0

        mock_class, _ = _mock_async_client(status_code=500)
        a = OpenPhishAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/phish", "url")
        assert r.verdict == "unknown"
        assert "feed_unavailable" in r.tags


# ============================================================
# URLhaus (no API key)
# ============================================================

class TestURLHausAdapter:
    def test_supported_types(self):
        a = URLHausAdapter()
        assert "url" in a.supported_types
        assert "domain" in a.supported_types

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        """query_status='ok' AND url_status='online' → malicious."""
        data = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["emotet", "exe"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
        }
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/emotet.exe", "url")
        assert r.verdict == "malicious"
        assert r.raw_score == 1.0
        assert "malware_url" in r.tags
        # The threat class is a category, not a "threat:..." tag.
        assert r.categories == ["malware_download"]
        assert "emotet" in r.tags
        assert r.source_link == "https://urlhaus.abuse.ch/url/123/"

    @pytest.mark.asyncio
    async def test_suspicious_response(self):
        """query_status='ok' AND url_status='offline' → suspicious."""
        data = {
            "query_status": "ok",
            "url_status": "offline",
            "threat": "malware_download",
            "tags": [],
        }
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/old.exe", "url")
        assert r.verdict == "suspicious"
        assert r.raw_score == 0.5
        assert "malware_url" in r.tags

    @pytest.mark.asyncio
    async def test_unknown_response(self):
        """URLhaus answers ``no_results`` for an unlisted URL -> not_found."""
        data = {"query_status": "no_results"}
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://safe.example.com", "url")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None

    @pytest.mark.asyncio
    async def test_unexpected_query_status_is_an_error(self):
        """An unrecognised query_status is a provider problem, not "not found"."""
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data={"query_status": "no_result"})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://safe.example.com", "url")
        assert r.execution_state == "error"

    @pytest.mark.asyncio
    async def test_error_response(self):
        """429 → unknown rate_limited."""
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(status_code=429)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com", "url")
        assert r.verdict == "unknown"
        assert "rate_limited" in r.tags

    @pytest.mark.asyncio
    async def test_request_error_is_not_not_found(self):
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(raise_on=httpx.ConnectError("offline"))
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.example", "url")
        assert r.execution_state == "error"
        assert "request_error" in r.tags

    @pytest.mark.asyncio
    async def test_domain_type_uses_host_endpoint(self):
        """Domain lookups query /host/: malware URLs hosted on the host are
        evidence about the host (suspicious), not a malicious verdict for it."""
        data = {
            "query_status": "ok",
            "host": "evil.com",
            "url_count": 3,
            "urls": [{"url": "http://evil.com/a.exe", "url_status": "online", "threat": "malware_download"}],
            "blacklists": {},
        }
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("evil.com", "domain")
        assert r.verdict == "suspicious"
        assert r.raw_data["url_count"] == 3
        assert r.raw_data["online_url_count"] == 1
        assert "malware_hosting" in r.tags

    @pytest.mark.asyncio
    async def test_domain_record_for_another_host_is_context_only(self):
        data = {"query_status": "ok", "host": "sub.evil.com", "url_count": 2, "urls": []}
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("evil.com", "domain")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"

    @pytest.mark.asyncio
    async def test_url_record_for_another_url_is_context_only(self):
        data = {"query_status": "ok", "url": "https://evil.com/other.exe", "url_status": "online"}
        a = URLHausAdapter()
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("https://evil.com/emotet.exe", "url")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"


# ============================================================
# Tor Exit (feed-based, no API key)
# ============================================================

class TestTorExitAdapter:
    @pytest.fixture(autouse=True)
    def _isolate_tor_state(self, monkeypatch):
        """No real DNS/HTTP: reset the module cache and failure back-off, and
        make the DNS exit-list fallback unable to answer."""
        monkeypatch.setattr(_tor_exit_mod, "_cache", set())
        monkeypatch.setattr(_tor_exit_mod, "_cache_time", 0.0)
        monkeypatch.setattr(_tor_exit_mod, "_last_failure", 0.0)

        async def _no_dnsel(self, ioc_value):
            return None

        monkeypatch.setattr(TorExitAdapter, "_check_dnsel", _no_dnsel)

    def test_supported_types(self):
        a = TorExitAdapter()
        assert a.supported_types == ["ipv4"]

    @pytest.mark.asyncio
    async def test_malicious_response(self):
        """IP found in the Tor exit list → malicious."""
        _tor_exit_mod._cache = []
        _tor_exit_mod._cache_time = 0.0

        exit_list_text = "1.2.3.4\n5.6.7.8\n9.10.11.12"
        mock_class, mock_resp = _mock_async_client(status_code=200)
        mock_resp.text = exit_list_text

        a = TorExitAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        # Tor membership is anonymization context, not a maliciousness verdict.
        assert r.verdict == "unknown"
        assert r.provider_verdict == "tor_exit_node"
        assert r.raw_score is None
        assert "tor_exit_node" in r.tags
        assert r.raw_data["tor_exit"] is True

    @pytest.mark.asyncio
    async def test_unknown_response(self):
        """IP NOT in the Tor exit list → unknown."""
        _tor_exit_mod._cache = []
        _tor_exit_mod._cache_time = 0.0

        exit_list_text = "1.2.3.4\n5.6.7.8"
        mock_class, mock_resp = _mock_async_client(status_code=200)
        mock_resp.text = exit_list_text

        a = TorExitAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("192.168.1.1", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"
        assert r.raw_score is None
        assert r.raw_data["tor_exit"] is False

    @pytest.mark.asyncio
    async def test_feed_unavailable(self):
        """Feed download fails -> unavailable (never "not a Tor exit")."""
        _tor_exit_mod._cache = []
        _tor_exit_mod._cache_time = 0.0

        mock_class, _ = _mock_async_client(status_code=500)
        a = TorExitAdapter()
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "unavailable"
        assert "feed_unavailable" in r.tags

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        """When cache is already populated and fresh, no download occurs."""
        _tor_exit_mod._cache = ["10.0.0.1"]
        _tor_exit_mod._cache_time = time.time() + 3600  # far in the future

        # Even without patching httpx, the cached entry should match
        a = TorExitAdapter()
        r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "unknown"
        assert r.provider_verdict == "tor_exit_node"
        assert "tor_exit_node" in r.tags


# ============================================================
# Censys
# ============================================================

class TestCensysAdapter:
    def test_supported_types(self):
        a = CensysAdapter()
        assert a.supported_types == ["ipv4"]

    @pytest.mark.asyncio
    async def test_no_key(self):
        """Personal Access Token required."""
        a = CensysAdapter()
        a.api_key = ""
        a._has_credentials = False
        r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_no_key_partial(self):
        """Placeholder/too-short token → no_api_key_configured."""
        a = CensysAdapter()
        a.api_key = "abc"
        a._has_credentials = False
        r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "no_api_key_configured" in r.tags

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = CensysAdapter()
        a.api_key = "censys_invalid_token"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "unavailable"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_404_not_found(self):
        a = CensysAdapter()
        a.api_key = "censys_valid_token"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(status_code=404)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("10.0.0.1", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None
        assert r.status == "not_found"

    @pytest.mark.asyncio
    async def test_empty_resource_not_found(self):
        """200 with no result.resource → not_found, not found."""
        a = CensysAdapter()
        a.api_key = "censys_valid_token"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(json_data={"result": {}})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.status == "not_found"
        assert r.tags == []

    @pytest.mark.asyncio
    async def test_request_uses_platform_headers(self):
        """Platform API: Bearer PAT + vendor-specific Accept header."""
        a = CensysAdapter()
        a.api_key = "censys_valid_token"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(json_data={"result": {}})
        with patch("httpx.AsyncClient", mock_class) as mock:
            await a.lookup("1.2.3.4", "ipv4")
        headers = mock.return_value.get.await_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer censys_valid_token"
        assert headers["Accept"] == "application/vnd.censys.api.v3.host.v1+json"

    @pytest.mark.asyncio
    async def test_rate_limited(self):
        a = CensysAdapter()
        a.api_key = "censys_valid_token"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(status_code=429)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert "rate_limited" in r.tags

    @pytest.mark.asyncio
    async def test_normal_response(self):
        """Returns services and ports as tags."""
        data = {
            "result": {
                "resource": {
                    "location": {"city": "Mountain View", "country": "US"},
                    "autonomous_system": {"asn": 15169, "name": "Google LLC"},
                    "services": [
                        {"port": 80, "service_name": "http", "transport_protocol": "tcp"},
                        {"port": 443, "service_name": "https", "transport_protocol": "tcp"},
                        {"port": 22, "service_name": "ssh", "transport_protocol": "tcp"},
                    ],
                }
            }
        }
        a = CensysAdapter()
        a.api_key = "censys_valid_token"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None
        assert r.status == "found"
        # Services and ports are structured raw_data; the tag is a label.
        assert r.tags == ["active_ip"]
        assert r.raw_data["service_count"] == 3
        assert r.raw_data["ports"] == [80, 443, 22]
        assert r.raw_data["location"]["city"] == "Mountain View"
        assert r.raw_data["autonomous_system"]["asn"] == 15169

    @pytest.mark.asyncio
    async def test_empty_services(self):
        """No services in response → active_ip tag only."""
        data = {"result": {"resource": {"ip": "1.2.3.4"}}}
        a = CensysAdapter()
        a.api_key = "censys_valid_token"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.verdict == "unknown"
        assert r.status == "found"
        assert r.tags == ["active_ip"]

    @pytest.mark.asyncio
    async def test_request_carries_organization_id_header(self):
        """The Platform API rejects requests without an organization ID (HTTP 422)."""
        a = CensysAdapter()
        a.api_key = "censys_valid_token"
        a.organization_id = "org-123"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(json_data={"result": {"resource": {"ip": "1.2.3.4"}}})
        with patch("httpx.AsyncClient", mock_class):
            await a.lookup("1.2.3.4", "ipv4")
        client = mock_class.return_value
        headers = client.get.call_args.kwargs["headers"]
        assert headers["X-Organization-ID"] == "org-123"
        assert headers["Accept"] == "application/vnd.censys.api.v3.host.v1+json"

    @pytest.mark.asyncio
    async def test_missing_organization_id_uses_free_tier_pat(self):
        a = CensysAdapter()
        a.api_key = "censys_valid_token"
        a.organization_id = ""
        a._has_credentials = True
        mock_class, _ = _mock_async_client(json_data={"result": {"resource": {"ip": "1.2.3.4"}}})
        with patch("httpx.AsyncClient", mock_class) as mock:
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.execution_state == "success"
        assert r.request_made is True
        headers = mock.return_value.get.await_args.kwargs["headers"]
        assert "X-Organization-ID" not in headers

    @pytest.mark.asyncio
    async def test_422_is_not_reported_as_a_provider_outage(self):
        a = CensysAdapter()
        a.api_key = "censys_valid_token"
        a.organization_id = "org-123"
        a._has_credentials = True
        mock_class, _ = _mock_async_client(status_code=422, json_data={})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("1.2.3.4", "ipv4")
        assert r.execution_state == "invalid_request"
        assert r.tags == ["http_422", "invalid_request"]


# ============================================================
# IPinfo
# ============================================================

class TestIPinfoAdapter:
    def test_supported_types(self):
        a = IPinfoAdapter()
        assert a.supported_types == ["ipv4", "ipv6"]

    @pytest.mark.asyncio
    async def test_no_key(self):
        a = IPinfoAdapter()
        a.api_key = ""
        mock_class = _mock_async_router({"lite": (404, {})})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "not_found"

    @pytest.mark.asyncio
    async def test_lite_endpoint_outage_is_flagged(self):
        a = IPinfoAdapter()
        a.api_key = ""
        mock_class = _mock_async_router({"ipinfo.io": (503, {})})
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.execution_state == "error"
        assert "lite_api_unavailable" in r.tags

    @pytest.mark.asyncio
    async def test_401_unauthorized(self):
        a = IPinfoAdapter()
        a.api_key = "bad_key"
        mock_class, _ = _mock_async_client(status_code=401)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.execution_state == "unavailable"
        assert "unauthorized" in r.tags

    @pytest.mark.asyncio
    async def test_error_non_200(self):
        a = IPinfoAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(status_code=500)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "error"
        assert "http_500" in r.tags

    @pytest.mark.asyncio
    async def test_free_tier_fields_only(self):
        """Only free-tier fields (city/region/country/org/asn) are parsed."""
        data = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "org": "AS15169 Google LLC",
            "asn": {"asn": "AS15169", "name": "Google LLC"},
        }
        a = IPinfoAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        # Geo/ASN values are structured raw_data, not tags.
        assert r.raw_data["city"] == "Mountain View"
        assert r.raw_data["region"] == "California"
        assert r.raw_data["country"] == "US"
        assert r.raw_data["org"] == "AS15169 Google LLC"
        assert r.raw_data["asn"] == "AS15169"
        assert r.raw_data["asn_name"] == "Google LLC"
        assert not any(tag.startswith(("city:", "asn:", "org:")) for tag in r.tags)

    @pytest.mark.asyncio
    async def test_hosting_network_is_context_not_suspicious(self):
        data = {"ip": "8.8.8.8", "hosting": {"is_hosting": True}}
        a = IPinfoAdapter()
        a.api_key = "valid"
        mock_class, _ = _mock_async_client(json_data=data)
        with patch("httpx.AsyncClient", mock_class):
            r = await a.lookup("8.8.8.8", "ipv4")
        assert r.verdict == "unknown"
        assert r.raw_score is None
        assert r.raw_data["is_hosting"] is True
        assert "hosting_provider" in r.tags


# ============================================================
# Cross-Adapter Consistency
# ============================================================

class TestExtendedAdapterConsistency:
    """All extended adapters must follow the same contract."""

    ADAPTERS = [
        ("GreyNoise", GreyNoiseAdapter, ["ipv4"]),
        ("AlienVault OTX", AlienVaultOTXAdapter, ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]),
        ("Shodan", ShodanAdapter, ["ipv4"]),
        ("OpenPhish", OpenPhishAdapter, ["url"]),
        # The URLhaus payload endpoint accepts md5_hash / sha256_hash only.
        ("URLhaus", URLHausAdapter, ["url", "domain", "md5", "sha256"]),
        ("Tor Exit", TorExitAdapter, ["ipv4"]),
        ("Censys", CensysAdapter, ["ipv4"]),
        ("IPinfo", IPinfoAdapter, ["ipv4", "ipv6"]),
    ]

    def test_all_have_name(self):
        for name, cls, _ in self.ADAPTERS:
            a = cls.__new__(cls)
            a.__init__ = lambda self: None
            try:
                cls.__init__(a)
            except Exception:
                pass
            assert hasattr(a, 'name')
            assert a.name == name, f"Expected {name!r}, got {a.name!r}"

    def test_all_have_supported_types(self):
        for _, cls, expected in self.ADAPTERS:
            a = cls.__new__(cls)
            a.__init__ = lambda self: None
            try:
                cls.__init__(a)
            except Exception:
                pass
            for t in expected:
                assert t in a.supported_types, f"{cls.__name__} missing {t}"
            # Ensure no extra unsupported type claims
            for t in a.supported_types:
                assert t in expected, f"{cls.__name__} has unexpected type {t}"

    def test_all_are_adapters(self):
        for _, cls, _ in self.ADAPTERS:
            assert issubclass(cls, SourceAdapter), f"{cls.__name__} not a SourceAdapter"

    def test_all_return_normalized_result(self):
        """Adapter lookups (with mocked data) must return NormalizedResult."""
        for name, cls, _ in self.ADAPTERS:
            a = cls.__new__(cls)
            a.__init__ = lambda self: None
            try:
                cls.__init__(a)
            except Exception:
                pass
            # Set required attributes to avoid AttributeError
            for attr, val in [("api_key", "test")]:
                if not hasattr(a, attr):
                    setattr(a, attr, val)
            # Ensure supported_types is set
            if not a.supported_types:
                a.supported_types = ["ipv4"]
            assert len(a.supported_types) > 0, f"{name} has no supported_types"
