from unittest.mock import AsyncMock, MagicMock

import pytest

from app.backend.adapters.team_cymru import TeamCymruAdapter


def _make_client(status_code=200, payload=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload or {}
    client = AsyncMock()
    client.get.return_value = response
    return client


@pytest.mark.asyncio
async def test_team_cymru_bogon_ipv4_is_suspicious():
    payload = {
        "Status": 0,
        "Answer": [{"type": 16, "data": '"198.51.100.0/24"'}],
    }
    adapter = TeamCymruAdapter()
    adapter.set_client(_make_client(200, payload))
    result = await adapter.lookup("198.51.100.24", "ipv4")
    assert result.verdict == "suspicious"
    assert result.raw_score == 0.3
    assert "bogon_prefix:198.51.100.0/24" in result.tags


@pytest.mark.asyncio
async def test_team_cymru_bogon_ipv6_query_name():
    payload = {
        "Status": 0,
        "Answer": [{"type": 16, "data": '"2001:db8::/29"'}],
    }
    client = _make_client(200, payload)
    adapter = TeamCymruAdapter()
    adapter.set_client(client)
    result = await adapter.lookup("2001:DB8:FEEB:DEEF::242", "ipv6")
    assert result.verdict == "suspicious"
    request_params = client.get.call_args.kwargs.get("params", {})
    assert "name" in request_params
    assert request_params["name"].endswith(".v6.fullbogons.cymru.com")


@pytest.mark.asyncio
async def test_team_cymru_non_bogon_is_not_a_clean_verdict():
    # Being allocated address space says nothing about reputation.
    adapter = TeamCymruAdapter()
    adapter.set_client(_make_client(200, {"Status": 0, "Answer": []}))
    result = await adapter.lookup("8.8.8.8", "ipv4")
    assert result.verdict == "unknown"
    assert result.normalized_verdict == "unknown"
    assert result.execution_state == "success"
    assert "not_bogon" in result.tags
    assert result.raw_score is None


@pytest.mark.asyncio
async def test_team_cymru_doh_failure_is_error():
    adapter = TeamCymruAdapter()
    adapter.set_client(_make_client(200, {"Status": 2, "Answer": []}))
    result = await adapter.lookup("8.8.8.8", "ipv4")
    assert result.execution_state == "error"
    assert "doh_status:2" in result.tags


@pytest.mark.asyncio
async def test_team_cymru_http_error():
    adapter = TeamCymruAdapter()
    adapter.set_client(_make_client(500))
    result = await adapter.lookup("8.8.8.8", "ipv4")
    assert result.execution_state == "error"
    assert "http_500" in result.tags
    assert "http_500" in result.tags