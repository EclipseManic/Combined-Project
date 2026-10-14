"""End-to-end pipeline integration tests with mocked adapter HTTP.

WU-9.4: run the real run_analysis() pipeline with a small set of
real adapter instances whose HTTP clients are mocked, then verify
the full flow: classify -> query (3-4 sources) -> enrich -> score ->
composite verdict.
"""
import hashlib
import json
import sys
from unittest.mock import AsyncMock

import httpx
import pytest

sys.path.insert(0, ".")

from app.backend import pipeline as pipeline_mod
from app.backend.adapters.abuse_ipdb import AbuseIPDBAdapter
from app.backend.adapters.grey_noise import GreyNoiseAdapter
from app.backend.adapters.threatfox import ThreatFoxAdapter
from app.backend.adapters.virus_total import VirusTotalAdapter
from app.backend.adapters.base import EnrichmentData, NormalizedResult, RateLimitConfig
from app.backend.pipeline import run_analysis


def _mock_client(json_data=None, status_code=200):
    """Mock AsyncClient returning a fixed JSON payload for GET/POST."""
    mock_response = AsyncMock(spec=httpx.Response)
    mock_response.status_code = status_code
    mock_response.json.return_value = json_data or {}
    mock_response.text = json.dumps(json_data or {})

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.post.return_value = mock_response
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    return mock_client


def _mock_adapter(adapter_cls, json_data, key="valid_key", status_code=200):
    """Instantiate a real adapter, set a valid API key, inject a mocked client."""
    adapter = adapter_cls()
    adapter.api_key = key
    adapter.set_client(_mock_client(json_data, status_code=status_code))
    return adapter


@pytest.fixture
def mocked_adapters():
    vt = _mock_adapter(VirusTotalAdapter, {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 18, "suspicious": 1, "harmless": 4, "undetected": 47},
                "tags": ["malware", "c2"],
                "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"},
            }
        }
    })
    abuse = _mock_adapter(AbuseIPDBAdapter, {
        "data": {"abuseConfidenceScore": 82, "totalReports": 9, "isp": "Evil Hosting", "countryCode": "RU"}
    })
    tf = _mock_adapter(ThreatFoxAdapter, {
        "query_status": "ok",
        "data": [
            {"ioc": "8.8.8.8", "malware": "Emotet", "tags": "emotet,c2",
             "first_seen": "2024-01-01", "last_seen": "2024-06-01", "reference": "https://threatfox.abuse.ch/"}
        ],
    })
    gn = _mock_adapter(GreyNoiseAdapter, {
        "classification": "riot", "name": "Google", "link": "https://viz.greynoise.io/ip/8.8.8.8"
    })
    return [vt, abuse, tf, gn]


@pytest.fixture
def disable_cache_rate_limit(monkeypatch):
    monkeypatch.setattr(pipeline_mod, "cache", None)
    monkeypatch.setattr(pipeline_mod, "rate_limiter", None)


@pytest.mark.asyncio
async def test_pipeline_end_to_end_ipv4(mocked_adapters, disable_cache_rate_limit, monkeypatch):
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", mocked_adapters)

    task = await run_analysis("8.8.8.8")

    assert task.status == "done"
    assert task.progress == 100.0
    assert task.ioc_type == "ipv4"
    assert task.normalized == "8.8.8.8"

    by_source = {r.source: r for r in task.results}
    assert "VirusTotal" in by_source
    assert "AbuseIPDB" in by_source
    assert "ThreatFox" in by_source
    assert "GreyNoise" in by_source

    assert by_source["VirusTotal"].verdict == "malicious"
    assert by_source["AbuseIPDB"].verdict == "malicious"
    assert by_source["ThreatFox"].verdict == "malicious"
    assert by_source["GreyNoise"].verdict == "clean"

    assert task.composite is not None
    assert task.composite.verdict == "malicious"
    assert task.composite.score >= 40.0
    assert task.composite.sources_contributing == 3

    done_sources = {s.name for s in task.stages if s.status == "done"}
    assert {"VirusTotal", "AbuseIPDB", "ThreatFox", "GreyNoise"} <= done_sources

    assert task.enrichment is not None
    assert isinstance(task.relationships, list)


@pytest.mark.asyncio
async def test_pipeline_mixed_verdicts_dilute_score(mocked_adapters, disable_cache_rate_limit, monkeypatch):
    clean_vt = _mock_adapter(VirusTotalAdapter, {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10},
                "tags": [],
            }
        }
    })
    adapters = [clean_vt, mocked_adapters[3]]  # VT clean + GreyNoise riot
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", adapters)

    task = await run_analysis("8.8.8.8")

    assert task.status == "done"
    by_source = {r.source: r for r in task.results}
    assert by_source["VirusTotal"].verdict == "clean"
    assert task.composite.verdict in ("clean", "unknown")


@pytest.mark.asyncio
async def test_pipeline_adapter_failure_marks_error_result(mocked_adapters, disable_cache_rate_limit, monkeypatch):
    failing = _mock_adapter(VirusTotalAdapter, {}, status_code=500)
    adapters = [failing, mocked_adapters[3]]
    monkeypatch.setattr(pipeline_mod, "ADAPTERS", adapters)

    task = await run_analysis("8.8.8.8")

    assert task.status == "done"
    by_source = {r.source: r for r in task.results}
    assert by_source["VirusTotal"].verdict in ("error", "unknown")
    assert by_source["VirusTotal"].status == "error"


@pytest.mark.asyncio
async def test_pipeline_runs_public_adapter_without_api_key(disable_cache_rate_limit, monkeypatch):
    class PublicAdapter:
        name = "Public Source"
        supported_types = ["ipv4"]
        public_without_key = True
        api_key = ""
        rate_limit = RateLimitConfig(requests_per_minute=100)

        async def lookup(self, ioc_value, ioc_type):
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
                tags=["public_result"],
            )

        def _check_circuit(self):
            return True

        def _record_success(self):
            pass

        def _record_failure(self):
            pass

    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [PublicAdapter()])

    task = await run_analysis("8.8.8.8")

    assert task.status == "done"
    assert task.results[0].source == "Public Source"
    assert "public_result" in task.results[0].tags


@pytest.mark.asyncio
async def test_rate_limit_denial_is_reported_without_calling_the_provider(disable_cache_rate_limit, monkeypatch):
    """When the shared scheduler cannot fit a slot before the IOC deadline the
    provider is not called and the result is an explicit rate_limited record
    carrying the required wait (replaces the old fixed retry-budget loop)."""
    from contextlib import asynccontextmanager

    from app.backend.rate_limiter import SlotReservation

    calls = []

    class RateLimitedAdapter:
        name = "VirusTotal"
        supported_types = ["ipv4"]
        public_without_key = True
        api_key = ""
        rate_limit = RateLimitConfig(requests_per_minute=4, max_retries=2, minimum_interval_seconds=0.01, max_backoff_seconds=0.02)

        async def lookup(self, ioc_value, ioc_type):
            calls.append(ioc_value)
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name, verdict="unknown")

        def _check_circuit(self):
            return True

        def _record_success(self):
            pass

        def _record_failure(self):
            pass

    class AlwaysRateLimited:
        def provider_slot(self, *args, **kwargs):
            @asynccontextmanager
            async def _cm():
                yield None

            return _cm()

        def reserve_provider(self, *args, **kwargs):
            return SlotReservation(False, retry_after_seconds=120.0, reason="rate_limited")

        async def wait_for_reservation(self, source, reservation, *, max_wait):
            return reservation

    async def fake_enrich(value, ioc_type):
        return EnrichmentData()

    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [RateLimitedAdapter()])
    monkeypatch.setattr(pipeline_mod, "enrich", fake_enrich)
    monkeypatch.setattr(pipeline_mod, "rate_limiter", AlwaysRateLimited())

    task = await run_analysis("8.8.8.8")

    assert task.status == "done"
    assert calls == []
    assert len(task.results) == 1
    rate_limited = task.results[0]
    assert rate_limited.execution_state == "rate_limited"
    assert rate_limited.request_made is False
    assert rate_limited.retry_after_seconds == 120.0


@pytest.mark.asyncio
async def test_password_input_is_hashed_before_pipeline_boundaries(disable_cache_rate_limit, monkeypatch):
    observed = []

    class PasswordAdapter:
        name = "HIBP Pwned Passwords"
        supported_types = ["password"]
        public_without_key = True
        api_key = ""
        rate_limit = RateLimitConfig(requests_per_minute=100)

        async def lookup(self, ioc_value, ioc_type):
            observed.append(ioc_value)
            return NormalizedResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                source=self.name,
                verdict="unknown",
            )

        def _check_circuit(self):
            return True

        def _record_success(self):
            pass

        def _record_failure(self):
            pass

    async def fake_enrich(value, ioc_type):
        return EnrichmentData()

    monkeypatch.setattr(pipeline_mod, "ADAPTERS", [PasswordAdapter()])
    monkeypatch.setattr(pipeline_mod, "enrich", fake_enrich)

    task = await run_analysis("S3cret!", ioc_type_override="password")
    digest = hashlib.sha1(b"S3cret!").hexdigest()

    assert observed == [digest]
    assert task.ioc_value == digest
    assert task.normalized == digest
    assert "S3cret!" not in json.dumps(task.to_dict())
