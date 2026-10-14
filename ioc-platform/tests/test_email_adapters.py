"""Unit tests for AbstractAPI and Hunter.io email intelligence adapters.

All tests use mocked HTTP clients to ensure 0 external network requests
and 0 consumed API credits.
"""

from unittest.mock import AsyncMock, MagicMock
import pytest

from app.backend.adapters.abstract_api import (
    AbstractAPIAdapter,
    AbstractAPIIPAdapter,
    AbstractAPIPhoneAdapter,
)
from app.backend.adapters.hunter_io import HunterIOAdapter
from app.backend.provider_capabilities import build_provider_plan


def _make_mock_client(status_code: int = 200, payload: dict = None, headers: dict = None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload or {}
    response.headers = headers or {}
    client = AsyncMock()
    client.get.return_value = response
    return client


# ---------------------------------------------------------------------------
# AbstractAPI Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_abstractapi_deliverable_clean():
    client = _make_mock_client(200, {
        "email_address": "user@corporate.com",
        "email_deliverability": {
            "status": "deliverable",
            "is_format_valid": True,
            "is_smtp_valid": True,
            "is_mx_valid": True,
        },
        "email_quality": {
            "score": 0.95,
            "is_free_email": False,
            "is_disposable": False,
            "is_role": False,
            "is_catchall": False,
        },
        "email_risk": {"address_risk_status": "low", "domain_risk_status": "low"},
        "email_breaches": {"total_breaches": 0},
    })
    adapter = AbstractAPIAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("user@corporate.com", "email")
    assert result.verdict == "clean"
    assert result.raw_score == 0.0
    assert "deliverability:deliverable" in result.tags
    # The numeric quality score lives in raw_data, not a tag.
    assert result.raw_data["email_quality"]["score"] == 0.95
    assert "abstract:disposable_email" not in result.tags


@pytest.mark.asyncio
async def test_abstractapi_disposable_suspicious():
    client = _make_mock_client(200, {
        "email_address": "tempuser@10minutemail.com",
        "email_deliverability": {
            "status": "deliverable",
            "is_format_valid": True,
            "is_smtp_valid": True,
            "is_mx_valid": True,
        },
        "email_quality": {
            "score": 0.30,
            "is_free_email": True,
            "is_disposable": True,
            "is_role": False,
            "is_catchall": False,
        },
        "email_risk": {"address_risk_status": "low", "domain_risk_status": "low"},
        "email_breaches": {"total_breaches": 0},
    })
    adapter = AbstractAPIAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("tempuser@10minutemail.com", "email")
    assert result.verdict == "suspicious"
    assert result.raw_score == 0.70
    assert result.confidence == "high"
    assert "abstract:disposable_email" in result.tags


@pytest.mark.asyncio
async def test_abstractapi_undeliverable_or_invalid():
    client = _make_mock_client(200, {
        "email_address": "bademail@",
        "email_deliverability": {
            "status": "undeliverable",
            "is_format_valid": False,
            "is_smtp_valid": False,
            "is_mx_valid": False,
        },
        "email_quality": {"score": 0.0, "is_disposable": False},
        "email_risk": {"address_risk_status": "low", "domain_risk_status": "low"},
        "email_breaches": {"total_breaches": 0},
    })
    adapter = AbstractAPIAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("bademail@", "email")
    assert result.verdict == "suspicious"
    assert "abstract:invalid_format" in result.tags
    assert "abstract:no_mx_record" in result.tags


@pytest.mark.asyncio
async def test_abstractapi_rate_limited():
    client = _make_mock_client(429, {"error": "rate limited"}, headers={"Retry-After": "5"})
    adapter = AbstractAPIAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("test@example.com", "email")
    assert result.execution_state == "rate_limited"
    assert "rate_limited" in result.tags
    assert result.retry_after_seconds == 5.0


@pytest.mark.asyncio
async def test_abstractapi_missing_key():
    adapter = AbstractAPIAdapter()
    adapter.api_key = ""
    result = await adapter.lookup("test@example.com", "email")
    assert result.execution_state == "unavailable"
    assert "no_api_key_configured" in result.tags


# ---------------------------------------------------------------------------
# Hunter.io Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hunterio_deliverable_clean():
    client = _make_mock_client(200, {
        "data": {
            "status": "valid",
            "result": "deliverable",
            "score": 98,
            "email": "lead@company.com",
            "disposable": False,
            "gibberish": False,
            "webmail": False,
            "sources": [
                {"domain": "company.com", "uri": "https://company.com/team"},
                {"domain": "linkedin.com", "uri": "https://linkedin.com/in/lead"},
            ],
        }
    })
    adapter = HunterIOAdapter()
    adapter.api_key = "mock_hunter_key_456"
    adapter.set_client(client)

    result = await adapter.lookup("lead@company.com", "email")
    assert result.verdict == "clean"
    assert result.raw_score == 0.0
    assert "hunter:result:deliverable" in result.tags
    # Score and source count are structured values, not tags.
    assert result.raw_data["score"] == 98
    assert result.raw_data["sources_found"] == 2


@pytest.mark.asyncio
async def test_hunterio_gibberish_suspicious():
    client = _make_mock_client(200, {
        "data": {
            "status": "invalid",
            "result": "risky",
            "score": 15,
            "email": "xqzk19875938@spambot.xyz",
            "disposable": False,
            "gibberish": True,
            "webmail": False,
            "sources": [],
        }
    })
    adapter = HunterIOAdapter()
    adapter.api_key = "mock_hunter_key_456"
    adapter.set_client(client)

    result = await adapter.lookup("xqzk19875938@spambot.xyz", "email")
    assert result.verdict == "suspicious"
    assert result.raw_score == 0.60
    assert result.confidence == "high"
    assert "hunter:gibberish" in result.tags


@pytest.mark.asyncio
async def test_hunterio_disposable_suspicious():
    client = _make_mock_client(200, {
        "data": {
            "status": "valid",
            "result": "deliverable",
            "score": 40,
            "email": "burner@throwawaymail.com",
            "disposable": True,
            "gibberish": False,
            "webmail": True,
            "sources": [],
        }
    })
    adapter = HunterIOAdapter()
    adapter.api_key = "mock_hunter_key_456"
    adapter.set_client(client)

    result = await adapter.lookup("burner@throwawaymail.com", "email")
    assert result.verdict == "suspicious"
    assert result.raw_score == 0.65
    assert "hunter:disposable" in result.tags


@pytest.mark.asyncio
async def test_hunterio_rate_limited():
    client = _make_mock_client(429, {"errors": [{"id": "too_many_requests"}]})
    adapter = HunterIOAdapter()
    adapter.api_key = "mock_hunter_key_456"
    adapter.set_client(client)

    result = await adapter.lookup("test@example.com", "email")
    assert result.execution_state == "rate_limited"
    assert "rate_limited" in result.tags


@pytest.mark.asyncio
async def test_hunterio_missing_key():
    adapter = HunterIOAdapter()
    adapter.api_key = ""
    result = await adapter.lookup("test@example.com", "email")
    assert result.execution_state == "unavailable"
    assert "no_api_key_configured" in result.tags


# ---------------------------------------------------------------------------
# Provider Capabilities & Plan Verification
# ---------------------------------------------------------------------------

def test_email_provider_plan_includes_new_adapters():
    from app.backend.pipeline import _init_adapters
    adapters = _init_adapters()
    plan = build_provider_plan(adapters, "email")
    
    email_providers = [p.provider for p in plan if p.applicable]
    assert "AbstractAPI" in email_providers
    assert "Hunter.io" in email_providers

    # Make sure they do not apply to IP or IPv6 lookups
    ip_plan = build_provider_plan(adapters, "ipv4")
    ip_applicable = [p.provider for p in ip_plan if p.applicable]
    assert "AbstractAPI" not in ip_applicable
    assert "Hunter.io" not in ip_applicable


# ---------------------------------------------------------------------------
# AbstractAPI per-product keys
# ---------------------------------------------------------------------------

def test_each_abstractapi_product_binds_its_own_credential():
    """AbstractAPI rejects a key issued for another product, so no two
    adapters may share a credential or fall back to the legacy field."""
    from app.backend.config import settings

    email = AbstractAPIAdapter().api_key
    ip = AbstractAPIIPAdapter().api_key
    phone = AbstractAPIPhoneAdapter().api_key
    legacy = settings.abstractapi_api_key

    assert email == settings.abstractapi_email_api_key
    assert ip == settings.abstractapi_ip_api_key
    assert phone == settings.abstractapi_phone_api_key
    # None of them may silently adopt the undifferentiated legacy key.
    if legacy:
        assert legacy not in (email, ip, phone)
    # Configured products must not share a key with each other.
    configured = [k for k in (email, ip, phone) if k]
    assert len(set(configured)) == len(configured)


def test_abstractapi_products_target_distinct_endpoints():
    from app.backend.adapters import abstract_api as mod

    urls = {mod.EMAIL_REPUTATION_URL, mod.IP_INTELLIGENCE_URL, mod.PHONE_INTELLIGENCE_URL}
    assert len(urls) == 3
    assert AbstractAPIAdapter.name == "AbstractAPI"
    assert AbstractAPIIPAdapter.name == "AbstractAPI IP"
    assert AbstractAPIPhoneAdapter.name == "AbstractAPI Phone"
    assert AbstractAPIPhoneAdapter.supported_types == ["phone"]


@pytest.mark.asyncio
async def test_abstractapi_ip_tor_is_malicious():
    client = _make_mock_client(200, {
        "ip_address": "185.197.192.65",
        "security": {"is_vpn": True, "is_proxy": False, "is_tor": True,
                     "is_hosting": False, "is_relay": False, "is_mobile": False, "is_abuse": False},
        "asn": {"asn": 136787, "name": "PacketHub S.A."},
        "location": {"country_code": "US", "city": "Miami"},
    })
    adapter = AbstractAPIIPAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("185.197.192.65", "ipv4")
    assert result.verdict == "malicious"
    assert "abstractip:tor:true" in result.tags
    assert "asn:136787" in result.tags


@pytest.mark.asyncio
async def test_abstractapi_ip_without_risk_flags_is_unknown_not_clean():
    """A flag-free IP is absence of evidence, not proof of safety."""
    client = _make_mock_client(200, {
        "ip_address": "8.8.8.8",
        "security": {"is_vpn": False, "is_proxy": False, "is_tor": False,
                     "is_hosting": False, "is_relay": False, "is_mobile": False, "is_abuse": False},
        "asn": {"asn": 15169, "name": "Google LLC"},
        "location": {"country_code": "US"},
    })
    adapter = AbstractAPIIPAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("8.8.8.8", "ipv4")
    assert result.verdict == "unknown"
    assert result.raw_score == 0.0


@pytest.mark.asyncio
async def test_abstractapi_ip_rejects_email_type():
    adapter = AbstractAPIIPAdapter()
    adapter.api_key = "mock_key_test_123"
    result = await adapter.lookup("user@corporate.com", "email")
    assert "unsupported_type" in result.tags


@pytest.mark.asyncio
async def test_abstractapi_phone_abuse_is_malicious():
    client = _make_mock_client(200, {
        "phone_number": "+14152007986",
        "phone_carrier": {"name": "T-Mobile USA Inc.", "line_type": "mobile"},
        "phone_location": {"country_code": "US", "region": "California"},
        "phone_validation": {"is_valid": True, "line_status": "active", "is_voip": False},
        "phone_risk": {"risk_level": "low", "is_disposable": False, "is_abuse_detected": True},
        "phone_breaches": {"total_breaches": 0},
    })
    adapter = AbstractAPIPhoneAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("+14152007986", "phone")
    assert result.verdict == "malicious"
    assert "abstractphone:abuse" in result.tags
    assert "carrier:T-Mobile USA Inc." in result.tags


@pytest.mark.asyncio
async def test_abstractapi_phone_strips_plus_before_request():
    """The API takes bare digits for the phone parameter."""
    client = _make_mock_client(200, {"phone_number": "14152007986"})
    adapter = AbstractAPIPhoneAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    await adapter.lookup("+14152007986", "phone")
    sent = client.get.await_args.kwargs["params"]
    assert sent["phone"] == "14152007986"
    assert sent["api_key"] == "mock_key_test_123"


@pytest.mark.asyncio
async def test_abstractapi_phone_quota_exhausted_is_not_retried_this_session():
    """AbstractAPI answers 422 when the monthly free allowance is spent."""
    client = _make_mock_client(422, {"error": {"message": "quota reached"}})
    adapter = AbstractAPIPhoneAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("+14152007986", "phone")
    assert result.execution_state == "unavailable"
    assert "monthly_quota_exhausted" in result.tags
    assert result.retry_after_seconds == 86400.0


@pytest.mark.asyncio
async def test_abstractapi_phone_invalid_number_is_not_a_reputation_signal():
    client = _make_mock_client(200, {
        "phone_number": "+10000000000",
        "phone_validation": {"is_valid": False, "line_status": "not_active", "is_voip": False},
        "phone_risk": {"risk_level": "low", "is_disposable": False, "is_abuse_detected": False},
    })
    adapter = AbstractAPIPhoneAdapter()
    adapter.api_key = "mock_key_test_123"
    adapter.set_client(client)

    result = await adapter.lookup("+10000000000", "phone")
    assert result.verdict == "unknown"
    assert result.raw_score == 0.0
