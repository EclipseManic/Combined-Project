"""Live API key test — calls each service endpoint to verify the key works."""
import asyncio
import os

import httpx
import pytest

from app.backend.adapters.base import is_valid_api_key
from app.backend.config import settings


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_LIVE_API_TESTS") != "1",
    reason="live provider checks require RUN_LIVE_API_TESTS=1",
)

REQUEST_TIMEOUT = 15.0


async def _test(service: str, fn):
    try:
        result = await asyncio.wait_for(fn(), timeout=REQUEST_TIMEOUT)
    except asyncio.TimeoutError:
        result = "TIMEOUT"
    except Exception as e:
        result = f"EXCEPTION: {e}"
    print(f"  {service:20s} -> {result}")


async def test_vt():
    k = settings.virustotal_api_key
    if not is_valid_api_key(k):
        return "SKIPPED (no key)"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.get(
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            headers={"x-apikey": k},
        )
        if r.status_code == 200:
            return "OK (clean IP)"
        if r.status_code == 401:
            return "401 UNAUTHORIZED"
        return f"HTTP {r.status_code}"


async def test_abuseipdb():
    k = settings.abuseipdb_api_key
    if not is_valid_api_key(k):
        return "SKIPPED (no key)"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": "8.8.8.8"},
            headers={"Key": k, "Accept": "application/json"},
        )
        if r.status_code == 200:
            return "OK (clean IP)"
        if r.status_code == 401:
            return "401 UNAUTHORIZED"
        return f"HTTP {r.status_code}"


async def test_urlscan():
    k = settings.urlscanio_api_key
    if not is_valid_api_key(k):
        return "SKIPPED (no key)"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.post(
            "https://urlscan.io/api/v1/scan/",
            json={"url": "https://example.com"},
            headers={"API-Key": k, "Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            uid = r.json().get("uuid", "")
            return f"OK (scan queued: {uid[:8]}...)" if uid else "OK"
        if r.status_code == 401:
            return "401 UNAUTHORIZED"
        if r.status_code == 429:
            return "429 RATE LIMITED"
        return f"HTTP {r.status_code}"


async def test_malwarebazaar():
    k = settings.malwarebazaar_api_key
    if not is_valid_api_key(k):
        return "SKIPPED (no key)"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": "d41d8cd98f00b204e9800998ecf8427e"},
            headers={"Auth-Key": k},
        )
        if r.status_code == 200:
            qs = r.json().get("query_status", "?")
            return f"OK ({qs})"
        if r.status_code == 401:
            return "401 UNAUTHORIZED"
        return f"HTTP {r.status_code}"


async def test_threatfox():
    k = settings.threatfox_api_key
    if not is_valid_api_key(k):
        return "SKIPPED (no key)"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": "8.8.8.8"},
            headers={"Auth-Key": k},
        )
        if r.status_code == 200:
            qs = r.json().get("query_status", "?")
            return f"OK ({qs})"
        if r.status_code == 401:
            return "401 UNAUTHORIZED"
        return f"HTTP {r.status_code}"


async def test_triage():
    k = settings.triage_api_key
    if not is_valid_api_key(k):
        return "SKIPPED (no key)"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.get(
            "https://tria.ge/api/v0/samples?page=1",
            headers={"Authorization": f"Bearer {k}"},
        )
        if r.status_code == 200:
            return "OK (samples list)"
        if r.status_code == 401:
            return "401 UNAUTHORIZED"
        if r.status_code == 403:
            return "403 FORBIDDEN"
        return f"HTTP {r.status_code}"


async def test_hybrid_analysis():
    k = settings.hybridanalysis_api_key
    if not is_valid_api_key(k):
        return "SKIPPED (no key)"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.get(
            "https://hybrid-analysis.com/api/v2/search/hash",
            params={"hash": "d41d8cd98f00b204e9800998ecf8427e"},
            headers={
                "api-key": k,
                "user-agent": "IOC-Lookup-Platform/1.0",
                "Accept": "application/json",
            },
        )
        if r.status_code == 200:
            return "OK (hash found)"
        if r.status_code == 401:
            return "401 UNAUTHORIZED"
        if r.status_code == 403:
            return "403 FORBIDDEN"
        return f"HTTP {r.status_code}"


async def test_nvd():
    k = settings.nvd_api_key
    if not is_valid_api_key(k):
        return "SKIPPED (no key)"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": "CVE-2023-23397"},
            headers={"X-Api-Key": k} if k else {},
        )
        if r.status_code == 200:
            return "OK (CVE found)"
        if r.status_code == 403:
            return "403 FORBIDDEN"
        return f"HTTP {r.status_code}"


async def main():
    print("=== API Key Live Test ===\n")
    tests = [
        ("VirusTotal", test_vt),
        ("AbuseIPDB", test_abuseipdb),
        ("urlscan.io", test_urlscan),
        ("MalwareBazaar", test_malwarebazaar),
        ("ThreatFox", test_threatfox),
        ("Tria.ge", test_triage),
        ("Hybrid Analysis", test_hybrid_analysis),
        ("NVD", test_nvd),
    ]
    for name, fn in tests:
        await _test(name, fn)
        await asyncio.sleep(0.5)


if __name__ == "__main__":
    asyncio.run(main())
