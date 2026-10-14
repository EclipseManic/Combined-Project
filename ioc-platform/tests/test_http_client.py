import sys

sys.path.insert(0, ".")

import ipaddress
import pytest

from app.backend.http_client import DEFAULT_TIMEOUT, close_client, get_client, get_timeout, resolve_public_url


@pytest.fixture(autouse=True)
def _reset_client():
    import app.backend.http_client as hc

    hc._SHARED_CLIENT = None
    hc._CLIENT_REFCOUNT = 0
    yield
    hc._SHARED_CLIENT = None
    hc._CLIENT_REFCOUNT = 0


def test_get_client_creates_shared():
    c1 = get_client()
    c2 = get_client()
    assert c1 is c2


def test_get_timeout_known_adapter():
    t = get_timeout("VirusTotal")
    assert t.connect == 5.0


def test_get_timeout_default_for_unknown():
    assert get_timeout("Unknown Adapter") == DEFAULT_TIMEOUT


def test_close_client():
    import app.backend.http_client as hc

    c = get_client()
    assert hc._SHARED_CLIENT is c

    import asyncio

    asyncio.run(close_client())
    assert hc._SHARED_CLIENT is None


def test_close_client_when_none():
    import asyncio

    asyncio.run(close_client())


@pytest.mark.asyncio
async def test_resolve_public_url_pins_ip_and_preserves_sni():
    async def resolver(host):
        assert host == "hooks.example.com"
        return [ipaddress.ip_address("8.8.8.8")]

    pinned_url, headers, extensions = await resolve_public_url(
        "https://hooks.example.com:8443/events",
        resolver=resolver,
    )

    assert pinned_url == "https://8.8.8.8:8443/events"
    assert headers == {"Host": "hooks.example.com:8443"}
    assert extensions == {"sni_hostname": "hooks.example.com"}


@pytest.mark.asyncio
async def test_resolve_public_url_rejects_mixed_dns_results():
    async def resolver(host):
        return [ipaddress.ip_address("8.8.8.8"), ipaddress.ip_address("127.0.0.1")]

    assert await resolve_public_url("https://hooks.example.com/events", resolver=resolver) is None
