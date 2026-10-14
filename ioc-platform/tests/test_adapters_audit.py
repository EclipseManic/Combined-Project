"""Adapter audit regressions: honest execution states, exact matching and typed data.

All HTTP is mocked with ``httpx.MockTransport``; nothing here touches a provider.
"""
import httpx
import pytest

from app.backend.adapters._http import describe_exception
from app.backend.adapters.abstract_api import AbstractAPIAdapter
from app.backend.adapters.abuse_ipdb import AbuseIPDBAdapter
from app.backend.adapters.censys import CensysAdapter
from app.backend.adapters.chainabuse import ChainAbuseAdapter
from app.backend.adapters.filescan import FileScanAdapter
from app.backend.adapters.grey_noise import GreyNoiseAdapter
from app.backend.adapters.hybrid_analysis import HybridAnalysisAdapter
from app.backend.adapters.hudson_rock import HudsonRockAdapter
from app.backend.adapters.malware_bazaar import MalwareBazaarAdapter
from app.backend.adapters.nvd import NvdAdapter
from app.backend.adapters.stop_forum_spam import StopForumSpamAdapter
from app.backend.adapters.threatfox import ThreatFoxAdapter
from app.backend.adapters.tor_exit import TorExitAdapter
from app.backend.adapters.virus_total import VirusTotalAdapter


def client_for(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def respond(status: int = 200, body=None, headers: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if body is None:
            return httpx.Response(status, headers=headers)
        if isinstance(body, (dict, list)):
            return httpx.Response(status, json=body, headers=headers)
        return httpx.Response(status, content=body, headers=headers)
    return handler


def keyed(adapter, key="valid-test-key-0123456789"):
    adapter.api_key = key
    return adapter


# (adapter factory, ioc, ioc_type) for providers whose failures go through _http
CASES = [
    (lambda: keyed(VirusTotalAdapter()), "8.8.8.8", "ipv4"),
    (lambda: keyed(AbuseIPDBAdapter()), "8.8.8.8", "ipv4"),
    (lambda: keyed(ThreatFoxAdapter()), "8.8.8.8", "ipv4"),
    (lambda: keyed(MalwareBazaarAdapter()), "a" * 64, "sha256"),
    (lambda: keyed(HybridAnalysisAdapter()), "a" * 32, "md5"),
    (lambda: keyed(FileScanAdapter()), "a" * 32, "md5"),
    (lambda: keyed(NvdAdapter()), "CVE-2024-0001", "cve"),
    (lambda: StopForumSpamAdapter(), "a@example.com", "email"),
    (lambda: GreyNoiseAdapter(), "8.8.8.8", "ipv4"),
]


@pytest.fixture(autouse=True)
def _fresh_shared_state(monkeypatch):
    monkeypatch.setattr(GreyNoiseAdapter, "_weekly_requests_used", 0)
    monkeypatch.setattr(GreyNoiseAdapter, "_quota_reset_time", 0.0)
    monkeypatch.setattr(GreyNoiseAdapter, "_quota_remaining", None)
    monkeypatch.setattr(AbuseIPDBAdapter, "_daily_requests_used", 0)
    monkeypatch.setattr(AbuseIPDBAdapter, "_quota_reset_time", 0.0)


@pytest.mark.parametrize("factory,ioc,ioc_type", CASES)
async def test_429_with_retry_after_is_rate_limited(factory, ioc, ioc_type):
    adapter = factory()
    adapter.set_client(client_for(respond(429, {"error": "slow down"}, {"Retry-After": "42"})))
    result = await adapter.lookup(ioc, ioc_type)
    assert result.execution_state == "rate_limited"
    assert result.retry_after_seconds == 42
    assert result.verdict not in {"clean", "malicious", "suspicious"}


@pytest.mark.parametrize("factory,ioc,ioc_type", CASES)
async def test_5xx_is_error_not_clean(factory, ioc, ioc_type):
    adapter = factory()
    adapter.set_client(client_for(respond(503, {"error": "down"})))
    result = await adapter.lookup(ioc, ioc_type)
    if isinstance(adapter, NvdAdapter):
        # NVD documents 503 as its throttling response.
        assert result.execution_state == "rate_limited"
    else:
        assert result.execution_state == "error"
        assert "http_503" in result.tags
    assert result.verdict not in {"clean", "malicious", "suspicious"}


@pytest.mark.parametrize("factory,ioc,ioc_type", CASES)
@pytest.mark.parametrize("body", [b"", b"<html>not json</html>"])
async def test_empty_or_malformed_body_is_error(factory, ioc, ioc_type, body):
    adapter = factory()
    adapter.set_client(client_for(respond(200, body)))
    result = await adapter.lookup(ioc, ioc_type)
    assert result.execution_state == "error"
    assert result.verdict not in {"clean", "malicious", "suspicious"}


@pytest.mark.parametrize("factory,ioc,ioc_type", CASES)
async def test_rejected_key_is_unavailable_with_summary(factory, ioc, ioc_type):
    adapter = factory()
    adapter.set_client(client_for(respond(401, {"error": "bad key"})))
    result = await adapter.lookup(ioc, ioc_type)
    if isinstance(adapter, (StopForumSpamAdapter,)):
        pytest.skip("keyless provider")
    assert result.execution_state == "unavailable"
    assert result.provider_summary


def test_describe_exception_never_empty_for_blank_httpx_errors():
    text = describe_exception(httpx.ConnectError(""))
    assert "ConnectError" in text and "ConnectError('')" in text


def test_virustotal_uses_the_public_api_limits():
    limits = VirusTotalAdapter.rate_limit
    assert limits.requests_per_minute == 4
    assert limits.requests_per_day == 500


async def test_threatfox_marks_exact_matches_and_ignores_related_urls():
    adapter = keyed(ThreatFoxAdapter())
    payload = {
        "query_status": "ok",
        "data": [
            {"ioc": "https://sites.google.com/view/antibot", "ioc_type": "url", "malware_printable": "Phish",
             "confidence_level": 100, "tags": ["phishing"]},
        ],
    }
    adapter.set_client(client_for(respond(200, payload)))
    related_only = await adapter.lookup("google.com", "domain")
    assert related_only.verdict == "unknown"
    assert related_only.execution_state == "not_found"
    assert related_only.raw_data["related_record_count"] == 1

    payload["data"].append({"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "malware_printable": "Cobalt Strike",
                            "confidence_level": 90})
    adapter.set_client(client_for(respond(200, payload)))
    exact = await adapter.lookup("1.2.3.4", "ipv4")
    assert exact.verdict == "malicious"
    assert exact.raw_data["match_type"] == "exact"


async def test_censys_pat_without_organization_id_is_allowed():
    adapter = CensysAdapter()
    adapter.api_key = "censys_valid_token_0123456789"
    adapter.organization_id = ""
    adapter._has_credentials = True
    adapter.set_client(client_for(respond(200, {"result": {"resource": {"ip": "1.2.3.4"}}})))
    result = await adapter.lookup("1.2.3.4", "ipv4")
    assert result.execution_state == "success"
    assert result.request_made is True


async def test_abstractapi_invalid_key_is_unavailable():
    adapter = keyed(AbstractAPIAdapter())
    adapter.set_client(client_for(respond(401, {"error": {"code": "invalid_api_key"}})))
    result = await adapter.lookup("a@example.com", "email")
    assert result.execution_state == "unavailable"
    assert "invalid_api_key" in result.tags


async def test_nvd_sends_the_configured_api_key_and_raises_the_rate_limit():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["key"] = request.headers.get("apiKey")
        return httpx.Response(200, json={"vulnerabilities": []})

    from app.backend.config import settings
    original = settings.nvd_api_key

    # The keyless adapter must be built with the key actually absent. conftest
    # sets IOC_ENV_FILE="" to disable .env loading, but Settings still falls back
    # to the process environment, so a real NVD_API_KEY exported on the host
    # (here it is a User-scope Windows variable) reached the adapter and raised
    # the rate limit to the keyed value.
    settings.nvd_api_key = ""
    try:
        keyless = NvdAdapter()
    finally:
        settings.nvd_api_key = original
    assert keyless.rate_limit.requests_per_minute == 10

    settings.nvd_api_key = "nvd-test-key-0123456789"
    try:
        adapter = NvdAdapter()
    finally:
        settings.nvd_api_key = original
    adapter.set_client(client_for(handler))
    await adapter.lookup("CVE-2024-0001", "cve")
    assert seen["key"] == "nvd-test-key-0123456789"
    assert adapter.rate_limit.requests_per_minute > keyless.rate_limit.requests_per_minute

    keyless.set_client(client_for(handler))
    await keyless.lookup("CVE-2024-0001", "cve")
    assert seen["key"] is None


async def test_hudson_rock_exposure_is_never_malicious_and_keeps_infection_count():
    body = {"stealers": [{"computer_name": "PC", "date_compromised": "2024-05-12T10:00:00Z"}] * 2,
            "total_corporate_services": 1, "total_user_services": 2}
    adapter = HudsonRockAdapter()
    adapter.set_client(client_for(respond(200, body)))
    for ioc, ioc_type in (("8.8.8.8", "ipv4"), ("example.com", "domain"), ("a@example.com", "email")):
        result = await adapter.lookup(ioc, ioc_type)
        assert result.verdict == "unknown"
        assert result.raw_data["total_infections"] == 2


async def test_tor_exit_membership_is_context_not_malicious(monkeypatch):
    from app.backend.adapters import tor_exit
    monkeypatch.setattr(tor_exit, "_cache", {"185.220.101.1"})
    monkeypatch.setattr(tor_exit, "_cache_time", 4_000_000_000.0)
    result = await TorExitAdapter().lookup("185.220.101.1", "ipv4")
    assert result.verdict == "unknown"
    assert result.provider_verdict == "tor_exit_node"
    assert result.raw_data["tor_exit"] is True


async def test_stop_forum_spam_confidence_is_a_percentage():
    weak = {"success": 1, "email": {"appears": 1, "frequency": 1, "confidence": 0.9}}
    strong = {"success": 1, "email": {"appears": 4, "frequency": 40, "confidence": 92.5}}
    adapter = StopForumSpamAdapter()
    adapter.set_client(client_for(respond(200, weak)))
    assert (await adapter.lookup("a@example.com", "email")).verdict == "suspicious"
    adapter.set_client(client_for(respond(200, strong)))
    result = await adapter.lookup("a@example.com", "email")
    assert result.verdict == "malicious"
    assert result.raw_data["frequency"] == 40


async def test_filescan_report_for_another_hash_is_ignored():
    adapter = keyed(FileScanAdapter())
    body = {"reports": [{"sha256": "f" * 64, "md5": "b" * 32, "verdict": "malicious"}]}
    adapter.set_client(client_for(respond(200, body)))
    result = await adapter.lookup("a" * 32, "md5")
    assert result.verdict == "unknown"
    assert result.execution_state == "not_found"


async def test_chainabuse_reports_use_short_tags_and_typed_counts():
    adapter = keyed(ChainAbuseAdapter())
    body = {"reports": [{"category": "PHISHING"}, {"category": "RANSOMWARE"}]}
    adapter.set_client(client_for(respond(200, body)))
    monkey = ChainAbuseAdapter
    monkey._monthly_requests_used = 0
    result = await adapter.lookup("bc1qexample", "btc")
    assert result.verdict == "malicious"
    assert result.tags == ["abuse_reports"]
    assert result.reports_count == 2
    assert result.categories == ["PHISHING", "RANSOMWARE"]
