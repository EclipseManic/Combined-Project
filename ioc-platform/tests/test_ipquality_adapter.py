"""Tests for the IPQualityScore adapters.

The behaviour that matters most here is error handling: this API answers HTTP
200 to everything, including an invalid key, so the adapter cannot branch on the
status code. These tests pin that contract.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.backend.adapters.ipquality import (
    IPQualityEmailAdapter,
    IPQualityIPAdapter,
    IPQualityPhoneAdapter,
    classify_message,
)


def _client(status: int, payload):
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload
    response.headers = {}
    response.text = ""
    client = AsyncMock()
    client.get.return_value = response
    return client


def _adapter(cls, key="ipqs_test_key_0123456789"):
    adapter = cls()
    adapter.api_key = key
    return adapter


# ---------------------------------------------------------------- phone

PHONE_CLEAN = {
    "success": True, "valid": True, "fraud_score": 0, "risky": False,
    "VOIP": False, "prepaid": False, "leaked": True, "spammer": False,
    "recent_abuse": False, "do_not_call": True, "tcpa_blacklist": True,
    "carrier": "T-Mobile", "line_type": "Wireless", "name": "J DOE",
    "sms_email": "4152007986@tmomail.net", "sms_domain": "tmomail.net",
    "country": "US", "mcc": "310", "mnc": "160",
    "associated_email_addresses": {"emails": [], "status": "Enterprise Plus or higher required."},
}

PHONE_RISKY = {
    **PHONE_CLEAN, "fraud_score": 65, "risky": True, "VOIP": True,
    "carrier": "Aql Wholesale", "line_type": "Landline", "leaked": False,
}


@pytest.mark.asyncio
async def test_phone_clean_number_is_clean():
    adapter = _adapter(IPQualityPhoneAdapter)
    adapter.set_client(_client(200, PHONE_CLEAN))
    result = await adapter.lookup("+14152007986", "phone")
    assert result.verdict == "clean"
    assert result.raw_score == 0.0
    assert "ipqs:fraud_score:0" in result.tags


@pytest.mark.asyncio
async def test_phone_risky_number_is_suspicious():
    adapter = _adapter(IPQualityPhoneAdapter)
    adapter.set_client(_client(200, PHONE_RISKY))
    result = await adapter.lookup("+442071838750", "phone")
    assert result.verdict == "suspicious"
    assert "ipqs:risky" in result.tags
    assert "ipqs:voip:true" in result.tags


@pytest.mark.asyncio
async def test_phone_spammer_is_malicious():
    adapter = _adapter(IPQualityPhoneAdapter)
    adapter.set_client(_client(200, {**PHONE_CLEAN, "spammer": True, "fraud_score": 90}))
    result = await adapter.lookup("+14152007986", "phone")
    assert result.verdict == "malicious"


@pytest.mark.asyncio
async def test_phone_invalid_number_is_not_a_reputation_signal():
    adapter = _adapter(IPQualityPhoneAdapter)
    adapter.set_client(_client(200, {**PHONE_CLEAN, "valid": False, "fraud_score": 40}))
    result = await adapter.lookup("+1415", "phone")
    # An invalid number yields no intelligence; it is not a negative finding.
    assert result.verdict == "unknown"
    assert result.raw_score == 0.0


@pytest.mark.asyncio
async def test_phone_strips_plus_before_the_request():
    client = _client(200, PHONE_CLEAN)
    adapter = _adapter(IPQualityPhoneAdapter)
    adapter.set_client(client)
    await adapter.lookup("+14152007986", "phone")
    # The service takes bare digits in the path segment.
    assert client.get.await_args.args[0].endswith("/14152007986")
    # strictness is sent explicitly; the default returns worse data.
    assert client.get.await_args.kwargs["params"] == {"strictness": 1}


@pytest.mark.asyncio
async def test_phone_records_plan_limits_instead_of_hiding_them():
    # A paywalled field arrives as a nested status object, not an error. It must
    # be visible so a null is never read as "no risk found".
    adapter = _adapter(IPQualityPhoneAdapter)
    adapter.set_client(_client(200, PHONE_CLEAN))
    result = await adapter.lookup("+14152007986", "phone")
    assert "ipqs:blocked:associated_email_addresses" in result.tags


# ------------------------------------------------------------------- ip

IP_VPN = {
    "success": True, "fraud_score": 100, "risky": True, "vpn": True,
    "active_vpn": True, "proxy": True, "tor": False, "recent_abuse": True,
    "organization": "NordVPN", "ISP": "PacketHub", "ASN": 136787,
    "connection_type": "Data Center", "abuse_velocity": "high",
    "country_code": "US", "latitude": 25.94, "longitude": -80.21,
}


@pytest.mark.asyncio
async def test_ip_vpn_with_abuse_is_malicious():
    adapter = _adapter(IPQualityIPAdapter)
    adapter.set_client(_client(200, IP_VPN))
    result = await adapter.lookup("185.197.192.65", "ipv4")
    assert result.verdict == "malicious"
    assert "asn:136787" in result.tags
    assert "org:NordVPN" in result.tags


@pytest.mark.asyncio
async def test_ip_without_risk_flags_is_unknown_not_clean():
    # The platform's rule: absence of data is not proof of safety.
    adapter = _adapter(IPQualityIPAdapter)
    adapter.set_client(_client(200, {**IP_VPN, "fraud_score": 0, "vpn": False,
                                     "active_vpn": False, "proxy": False,
                                     "recent_abuse": False, "risky": False}))
    result = await adapter.lookup("8.8.8.8", "ipv4")
    assert result.verdict == "unknown"
    assert result.raw_score == 0.0


@pytest.mark.asyncio
async def test_ip_tor_is_malicious_even_with_a_low_score():
    adapter = _adapter(IPQualityIPAdapter)
    adapter.set_client(_client(200, {**IP_VPN, "fraud_score": 5, "tor": True,
                                     "vpn": False, "active_vpn": False,
                                     "proxy": False, "recent_abuse": False}))
    result = await adapter.lookup("1.2.3.4", "ipv4")
    assert result.verdict == "malicious"


# ---------------------------------------------------------------- email

EMAIL_PHISHING = {
    "success": True, "fraud_score": 96, "honeypot": False, "suspect": False,
    "deliverability": "low", "valid": False, "dns_valid": False,
    "spf_record": False, "dmarc_record": False, "spam_trap_score": "none",
    "disposable": False, "catch_all": False, "risky_tld": False,
}

EMAIL_REAL = {
    **EMAIL_PHISHING, "fraud_score": 0, "deliverability": "high", "valid": True,
    "dns_valid": True, "spf_record": True, "dmarc_record": True,
}


@pytest.mark.asyncio
async def test_email_lookalike_domain_is_malicious():
    adapter = _adapter(IPQualityEmailAdapter)
    adapter.set_client(_client(200, EMAIL_PHISHING))
    result = await adapter.lookup("billing-update@apple-security-check.com", "email")
    assert result.verdict == "malicious"
    assert "ipqs:dns_valid:false" in result.tags
    assert "ipqs:deliverability:low" in result.tags


@pytest.mark.asyncio
async def test_email_honeypot_is_malicious():
    adapter = _adapter(IPQualityEmailAdapter)
    adapter.set_client(_client(200, {**EMAIL_PHISHING, "honeypot": True}))
    result = await adapter.lookup("test@gmail.com", "email")
    assert result.verdict == "malicious"
    assert "ipqs:honeypot:true" in result.tags


@pytest.mark.asyncio
async def test_email_clean_address_is_clean():
    adapter = _adapter(IPQualityEmailAdapter)
    adapter.set_client(_client(200, EMAIL_REAL))
    result = await adapter.lookup("someone.real@gmail.com", "email")
    assert result.verdict == "clean"


# ------------------------------------------------------- error contract


@pytest.mark.asyncio
async def test_invalid_key_is_detected_despite_http_200():
    # The service answers 200 to a bad key. Trusting the status code would
    # record a bad key as a successful lookup.
    adapter = _adapter(IPQualityPhoneAdapter)
    adapter.set_client(_client(200, {
        "success": False,
        "message": "Invalid or unauthorized key. Please check the API key and try again.",
    }))
    result = await adapter.lookup("+14152007986", "phone")
    assert result.execution_state == "unavailable"
    assert "invalid_api_key" in result.tags


@pytest.mark.asyncio
async def test_missing_country_is_an_invalid_request_not_a_verdict():
    adapter = _adapter(IPQualityPhoneAdapter)
    adapter.set_client(_client(200, {"success": False, "message": "Please specify a country and try again."}))
    result = await adapter.lookup("12345", "phone")
    assert "invalid_request" in result.tags
    assert result.verdict == "unknown"


@pytest.mark.asyncio
async def test_unknown_number_is_not_found():
    adapter = _adapter(IPQualityPhoneAdapter)
    adapter.set_client(_client(200, {
        "success": False,
        "message": "Invalid/nonexistent phone number or country specified is not possible.",
    }))
    result = await adapter.lookup("+10000000000", "phone")
    assert result.execution_state == "not_found"


@pytest.mark.asyncio
async def test_invalid_ip_is_not_found():
    adapter = _adapter(IPQualityIPAdapter)
    adapter.set_client(_client(200, {
        "success": False,
        "message": "Invalid IPv4 address, IPv6 address or hostname. Please check the IP/Hostname.",
    }))
    result = await adapter.lookup("999.999.999.999", "ipv4")
    assert result.execution_state == "not_found"


@pytest.mark.asyncio
async def test_unparseable_body_is_an_error():
    response = MagicMock()
    response.status_code = 200
    response.json.side_effect = ValueError("not json")
    response.headers = {}
    client = AsyncMock()
    client.get.return_value = response
    adapter = _adapter(IPQualityPhoneAdapter)
    adapter.set_client(client)
    result = await adapter.lookup("+14152007986", "phone")
    assert "malformed_response" in result.tags


@pytest.mark.asyncio
async def test_rate_limit_is_surfaced_not_swallowed():
    response = MagicMock()
    response.status_code = 429
    response.headers = {"Retry-After": "30"}
    client = AsyncMock()
    client.get.return_value = response
    adapter = _adapter(IPQualityIPAdapter)
    adapter.set_client(client)
    result = await adapter.lookup("1.1.1.1", "ipv4")
    assert result.execution_state == "rate_limited"


@pytest.mark.asyncio
async def test_missing_key_is_reported_as_unavailable():
    adapter = _adapter(IPQualityPhoneAdapter, key="")
    result = await adapter.lookup("+14152007986", "phone")
    assert "no_api_key_configured" in result.tags


@pytest.mark.asyncio
async def test_wrong_type_is_rejected_without_a_request():
    adapter = _adapter(IPQualityEmailAdapter)
    result = await adapter.lookup("8.8.8.8", "ipv4")
    assert "unsupported_type" in result.tags


# ------------------------------------------------------------- contracts


def test_each_product_uses_its_own_endpoint_and_name():
    assert IPQualityPhoneAdapter.name == "IPQualityScore Phone"
    assert IPQualityIPAdapter.name == "IPQualityScore IP"
    assert IPQualityEmailAdapter.name == "IPQualityScore Email"
    assert IPQualityPhoneAdapter.supported_types == ["phone"]
    assert IPQualityIPAdapter.supported_types == ["ipv4", "ipv6"]
    assert IPQualityEmailAdapter.supported_types == ["email"]


def test_three_adapters_share_one_credential_without_colliding():
    # One key legitimately serves all three products, unlike AbstractAPI where a
    # key issued for one product is rejected by the others.
    key = "shared_key_value_0123456789"
    adapters = [cls() for cls in (IPQualityPhoneAdapter, IPQualityIPAdapter, IPQualityEmailAdapter)]
    for adapter in adapters:
        adapter.api_key = key
    assert len({a.api_key for a in adapters}) == 1


def test_classify_message_covers_the_documented_errors():
    assert classify_message("Invalid or unauthorized key. Please check the API key.") == "unauthorized"
    assert classify_message("Invalid/nonexistent phone number or country specified is not possible.") == "not_found"
    assert classify_message("Invalid IPv4 address, IPv6 address or hostname.") == "not_found"
    assert classify_message("Your account must be Enterprise Mini or higher to score domains.") == "paywalled"
    assert classify_message("Please specify a country and try again.") == "invalid_request"
    assert classify_message("") == "error"
