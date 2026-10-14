from unittest.mock import AsyncMock

import pytest

from app.backend.adapters.stop_forum_spam import StopForumSpamAdapter


@pytest.mark.asyncio
async def test_stop_forum_spam_weak_sighting_is_suspicious():
    response = AsyncMock()
    response.status_code = 200
    response.json.return_value = {
        "success": 1,
        "email": {"appears": 1, "frequency": 1, "confidence": 0.02, "lastseen": "2026-01-11 18:19:56"},
    }
    client = AsyncMock()
    client.get.return_value = response
    adapter = StopForumSpamAdapter()
    adapter.set_client(client)
    result = await adapter.lookup("test@example.com", "email")
    assert result.verdict == "suspicious"
    assert result.raw_score == 0.2


@pytest.mark.asyncio
async def test_stop_forum_spam_not_listed_is_not_found():
    response = AsyncMock()
    response.status_code = 200
    response.json.return_value = {"success": 1, "email": {"appears": 0, "frequency": 0, "confidence": 0}}
    client = AsyncMock()
    client.get.return_value = response
    adapter = StopForumSpamAdapter()
    adapter.set_client(client)
    result = await adapter.lookup("nobody@example.com", "email")
    assert result.verdict == "unknown"
    assert result.status == "not_found"
