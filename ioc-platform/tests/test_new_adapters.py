import hashlib
import pytest
from unittest.mock import AsyncMock, MagicMock

from app.backend.adapters.threatfox import _matches_target_ioc
from app.backend.adapters.hibp import HIBPAdapter
from app.backend.adapters.hudson_rock import HudsonRockAdapter
from app.backend.pipeline import ADAPTERS


def test_threatfox_requires_exact_match_for_non_domain_iocs():
    assert _matches_target_ioc("a" * 32, "b" * 32, "md5") is False
    assert _matches_target_ioc("https://example.com/path", "https://other.example/path", "url") is False
    assert _matches_target_ioc("a" * 32, "A" * 32, "md5") is True


@pytest.mark.asyncio
async def test_hibp_adapter_pwned_hash():
    adapter = HIBPAdapter()
    sha1 = hashlib.sha1(b"password").hexdigest()
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = f"{sha1[5:].upper()}:12345\nOTHERHASH:1\n"
    
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    adapter.set_client(mock_client)
    
    result = await adapter.lookup(sha1, "sha1")
    assert result.source == "HIBP Pwned Passwords"
    assert result.verdict == "malicious"
    assert result.confidence == "high"
    assert result.reports_count == 12345
    assert "compromised_credential" in result.tags
    assert "pwned_password" in result.tags


@pytest.mark.asyncio
async def test_hibp_adapter_clean_hash():
    adapter = HIBPAdapter()
    sha1 = "0" * 40
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ABCDE12345:1\n"
    
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    adapter.set_client(mock_client)
    
    result = await adapter.lookup(sha1, "sha1")
    assert result.source == "HIBP Pwned Passwords"
    # Absence from the breach corpus is "not observed", never "clean".
    assert result.verdict == "undetected"
    assert "not_in_pwned_passwords" in result.tags


@pytest.mark.asyncio
async def test_hibp_adapter_invalid_type():
    adapter = HIBPAdapter()
    result = await adapter.lookup("8.8.8.8", "ipv4")
    assert result.verdict == "unknown"
    assert "unsupported_type" in result.tags


@pytest.mark.asyncio
async def test_hudson_rock_keyless_public():
    adapter = HudsonRockAdapter()
    assert adapter.public_without_key is True
    result = await adapter.lookup("invalid", "unsupported_type")
    assert result.source == "Hudson Rock"
    assert result.verdict == "unknown"


@pytest.mark.asyncio
async def test_hudson_rock_with_compromise():
    adapter = HudsonRockAdapter()
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "stealers": [
            {
                "stealer_family": "RedLine",
                "computer_name": "DESKTOP-ABC",
                "operating_system": "Windows 10",
                "date_compromised": "2024-05-12T10:00:00Z",
            }
        ],
        "stealerFamilies": {"RedLine": 1},
        "total_corporate_services": 2,
        "total_user_services": 3,
    }
    
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    adapter.set_client(mock_client)
    
    result = await adapter.lookup("victim@example.com", "email")
    assert result.source == "Hudson Rock"
    # Infostealer exposure is context/credential exposure, never a
    # maliciousness verdict for the indicator.
    assert result.verdict == "unknown"
    assert result.provider_verdict == "credential_exposure"
    assert result.execution_state == "success"
    assert "infostealer_compromised" in result.tags
    assert result.raw_data["total_infections"] == 1
    assert result.raw_data["stealer_families"] == {"RedLine": 1}
    assert result.raw_data["credentials_at_risk"] == 5


@pytest.mark.asyncio
async def test_hudson_rock_clean():
    adapter = HudsonRockAdapter()
    
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    adapter.set_client(mock_client)
    
    result = await adapter.lookup("clean@example.com", "email")
    assert result.source == "Hudson Rock"
    # No record is "not found", not a clean verdict.
    assert result.verdict == "unknown"
    assert result.execution_state == "not_found"
    assert "infostealer_compromised" not in result.tags


def test_adapters_registered_in_pipeline():
    adapter_names = [a.name for a in ADAPTERS]
    assert "Hudson Rock" in adapter_names
    assert "HIBP Pwned Passwords" in adapter_names
