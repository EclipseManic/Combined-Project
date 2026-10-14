import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit, urlunsplit

from httpx import AsyncClient, Limits, Timeout

_SHARED_CLIENT: AsyncClient | None = None
_CLIENT_REFCOUNT = 0

DEFAULT_TIMEOUT = Timeout(10.0, connect=5.0, read=15.0)
SIZE_LIMIT = 10 * 1024 * 1024  # 10 MB response limit

ADAPTER_TIMEOUTS: dict[str, Timeout] = {
    "VirusTotal": Timeout(10.0, connect=5.0, read=20.0),
    "AbuseIPDB": Timeout(5.0, connect=3.0, read=10.0),
    "GreyNoise": Timeout(5.0, connect=3.0, read=10.0),
    "Shodan": Timeout(10.0, connect=5.0, read=20.0),
    "AlienVault OTX": Timeout(10.0, connect=5.0, read=15.0),
    "URLhaus": Timeout(5.0, connect=3.0, read=10.0),
    "MalwareBazaar": Timeout(10.0, connect=5.0, read=15.0),
    "ThreatFox": Timeout(10.0, connect=5.0, read=15.0),
    "Tria.ge": Timeout(10.0, connect=5.0, read=20.0),
    "Hybrid Analysis": Timeout(10.0, connect=5.0, read=20.0),
    "Tor Exit": Timeout(5.0, connect=3.0, read=10.0),
    "Censys": Timeout(10.0, connect=5.0, read=15.0),
    "IPinfo": Timeout(5.0, connect=3.0, read=10.0),
    "urlscan.io": Timeout(10.0, connect=5.0, read=20.0),
    "AbstractAPI": Timeout(10.0, connect=5.0, read=15.0),
    "AbstractAPI IP": Timeout(10.0, connect=5.0, read=15.0),
    "AbstractAPI Phone": Timeout(10.0, connect=5.0, read=15.0),
    "IPQualityScore Phone": Timeout(10.0, connect=5.0, read=15.0),
    "IPQualityScore IP": Timeout(10.0, connect=5.0, read=15.0),
    "IPQualityScore Email": Timeout(10.0, connect=5.0, read=15.0),
    "Hunter.io": Timeout(10.0, connect=5.0, read=15.0),
    "Team Cymru": Timeout(5.0, connect=3.0, read=10.0),
    "cve.org": Timeout(5.0, connect=3.0, read=10.0),
}


async def resolve_public_url(
    url: str,
    resolver: Callable[[str], Awaitable[list[ipaddress.IPv4Address | ipaddress.IPv6Address]]] | None = None,
) -> tuple[str, dict[str, str], dict[str, str]] | None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if resolver is None:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.run_in_executor(
                None,
                socket.getaddrinfo,
                parsed.hostname,
                port or 443,
                0,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
        except OSError:
            return None
        addresses = []
        for info in infos:
            try:
                address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
            except ValueError:
                return None
            if address not in addresses:
                addresses.append(address)
    else:
        try:
            addresses = []
            for candidate in await resolver(parsed.hostname):
                address = ipaddress.ip_address(str(candidate).split("%", 1)[0])
                if address not in addresses:
                    addresses.append(address)
        except (OSError, ValueError):
            return None
    if not addresses or any(not address.is_global for address in addresses):
        return None
    address = addresses[0]
    address_text = f"[{address}]" if address.version == 6 else str(address)
    default_port = port in (None, 443)
    pinned_netloc = address_text if default_port else f"{address_text}:{port}"
    original_host = parsed.hostname
    host_text = f"[{original_host}]" if ":" in original_host else original_host
    host_header = host_text if default_port else f"{host_text}:{port}"
    pinned_url = urlunsplit((parsed.scheme, pinned_netloc, parsed.path or "/", parsed.query, ""))
    headers = {"Host": host_header}
    extensions = {"sni_hostname": original_host}
    return pinned_url, headers, extensions


def get_client() -> AsyncClient:
    global _SHARED_CLIENT
    # A closed client (previous app lifespan, tests) cannot send requests;
    # hand out a fresh one instead of failing every provider call.
    if _SHARED_CLIENT is None or _SHARED_CLIENT.is_closed:
        _SHARED_CLIENT = AsyncClient(
            limits=Limits(max_connections=200, max_keepalive_connections=50),
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        )
    return _SHARED_CLIENT


def get_timeout(adapter_name: str) -> Timeout:
    return ADAPTER_TIMEOUTS.get(adapter_name, DEFAULT_TIMEOUT)


async def close_client():
    global _SHARED_CLIENT
    if _SHARED_CLIENT:
        await _SHARED_CLIENT.aclose()
        _SHARED_CLIENT = None
