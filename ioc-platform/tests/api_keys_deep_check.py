"""Deep live analysis of every configured third-party API key.

Standalone script - run with:

    python tests/api_keys_deep_check.py

For each of the 16 provider keys it resolves the credential through its full
alias chain (.env first, then system env - same priority as the app),
performs ONE live request against the provider's real endpoint (rate-limit
friendly), and reports:

    - HTTP status code + response time
    - which response fields were actually returned
    - which fields the adapter in this project can extract from a good
      response (i.e. what data the key unlocks)
    - which OTHER providers in this project return the same category of data
      (overlap analysis) and whether it is redundant
    - a USABLE / PARTIAL / BROKEN / NO KEY verdict with the reason

Keys are never printed - only a masked prefix.
"""
import asyncio
import base64
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.backend.config import resolve_credential

REQUEST_TIMEOUT = 20.0
PROBE_IP = "8.8.8.8"
PROBE_URL = "https://example.com"
PROBE_HASH = "d41d8cd98f00b204e9800998ecf8427e"  # md5 of empty string
PROBE_CVE = "CVE-2023-23397"


def mask(key: str) -> str:
    if not key:
        return ""
    return f"{key[:6]}...{key[-4:]}" if len(key) > 12 else f"{key[:3]}..."


# ---------------------------------------------------------------------------
# Provider catalogue. expected_fields mirrors what the adapter extracts.
# ---------------------------------------------------------------------------

SERVICES = [
    {
        "name": "VirusTotal",
        "env_aliases": ["VT_API_KEY"],
        "probe_desc": "GET /api/v3/ip_addresses/8.8.8.8",
        "method": "GET",
        "url": f"https://www.virustotal.com/api/v3/ip_addresses/{PROBE_IP}",
        "headers_fn": lambda k: {"x-apikey": k, "accept": "application/json"},
        "expected_fields": [
            "last_analysis_stats (malicious/suspicious/harmless/undetected)",
            "tags, categories, threat label + malware family",
            "MITRE ATT&CK ids (via sandbox_verdicts)",
            "resolutions (related hostnames)",
            "first/last submission date, total_votes",
            "per-engine analysis results (samples)",
        ],
        "note": "Broadest coverage; needs a paid API key for rate limits.",
    },
    {
        "name": "AbuseIPDB",
        "env_aliases": ["ABUSEIPDB_API_KEY", "AbuseDB_API_KEY", "ABUSH_CH_AUTH_KEY"],
        "probe_desc": "GET /api/v2/check?ipAddress=8.8.8.8",
        "method": "GET",
        "url": "https://api.abuseipdb.com/api/v2/check",
        "params_fn": lambda: {"ipAddress": PROBE_IP, "maxAgeInDays": 365},
        "headers_fn": lambda k: {"Key": k, "Accept": "application/json"},
        "expected_fields": [
            "abuseConfidenceScore (0-100)",
            "totalReports, lastReportedAt",
            "isp, countryCode, usageType, domain",
            "hostnames, isTor, isWhitelisted, categories",
            "report details (categories, comment, date)",
        ],
        "note": "IP-only; free tier ~1000 req/day.",
    },
    {
        "name": "urlscan.io",
        "env_aliases": ["URL_SCAN_API_KEY"],
        "works_without_key": True,
        "probe_desc": f"POST /api/v1/scan/ (submit {PROBE_URL})",
        "method": "POST",
        "url": "https://urlscan.io/api/v1/scan/",
        "json_fn": lambda: {"url": PROBE_URL, "public": "on"},
        "headers_fn": lambda k: {"API-Key": k, "Content-Type": "application/json"},
        "expected_fields": [
            "uuid (scan id), result URL, screenshot URL",
            "overall score + verdict",
            "page info (title, domain, server)",
            "detected technologies / behaviour summary",
            "full scan report after polling",
        ],
        "note": "Submits a live scan; a real URL must be publicly reachable.",
    },
    {
        "name": "MalwareBazaar",
        "env_aliases": ["MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY"],
        "probe_desc": "POST /api/v1/ query=get_info (md5 of empty string)",
        "method": "POST",
        "url": "https://mb-api.abuse.ch/api/v1/",
        "data_fn": lambda: {"query": "get_info", "hash": PROBE_HASH},
        "headers_fn": lambda k: {"Auth-Key": k},
        "expected_fields": [
            "query_status (ok / hash_not_found / invalid)",
            "file size, delivery, signature status + signer",
            "vendor detection ratios (AV hits)",
            "YARA rule matches, tags, malware family",
            "download link for the sample",
        ],
        "note": "Hash/domain/URL intel; free tier generous.",
    },
    {
        "name": "ThreatFox",
        "env_aliases": ["THREATFOX_API_KEY", "MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY"],
        "probe_desc": "POST /api/v1/ query=search_ioc term=8.8.8.8",
        "method": "POST",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "json_fn": lambda: {"query": "search_ioc", "search_term": PROBE_IP},
        "headers_fn": lambda k: {"Auth-Key": k},
        "expected_fields": [
            "query_status (ok / no_result / invalid)",
            "malware family, threat type, confidence",
            "malpedia reference links, tags",
            "first/last seen of the IOC",
        ],
        "note": "Shares backend with MalwareBazaar - often redundant.",
    },
    {
        "name": "NVD",
        "env_aliases": ["NVD_API_KEY"],
        "probe_desc": "GET /rest/json/cves/2.0?cveId=CVE-2023-23397",
        "method": "GET",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "params_fn": lambda: {"cveId": PROBE_CVE},
        "headers_fn": lambda k: ({"X-Api-Key": k} if k else {}),
        "expected_fields": [
            "CVE description (EN), published/modified dates",
            "CVSS v3/v2 base metrics (score, vector)",
            "CWE weakness ids, references, vendor advisories",
        ],
        "note": "Only CVE data in the project; key optional (rate-limit boost).",
    },
    {
        "name": "Tria.ge",
        "env_aliases": ["TRIAGE_API_KEY", "TRIA_GE_API_KEY"],
        "probe_desc": "GET /api/v2/sample/d41d8cd9...",
        "method": "GET",
        "url": f"https://api.tria.ge/v2/sample/{PROBE_HASH}",
        "headers_fn": lambda k: {"Authorization": f"Bearer {k}"},
        "expected_fields": [
            "sample status, score, family",
            "tags + signatures (YARA-ish)",
            "MITRE ATT&CK ids",
            "overview.json (static analysis summary)",
        ],
        "note": "Hash-only (md5/sha1/sha256); free tier limits scans.",
    },
    {
        "name": "Hybrid Analysis",
        "env_aliases": ["HA_API_KEY"],
        "probe_desc": "GET /api/v2/search/hash?hash=d41d8cd9...",
        "method": "GET",
        "url": "https://hybrid-analysis.com/api/v2/search/hash",
        "params_fn": lambda: {"hash": PROBE_HASH},
        "headers_fn": lambda k: {
            "api-key": k,
            "user-agent": "IOC-Lookup-Platform/1.0",
            "Accept": "application/json",
        },
        "expected_fields": [
            "threat_score (0-100), verdict",
            "classification_tags, vx_family, submit_name",
            "MITRE ATT&CK report (separate endpoint)",
            "AV detection ratio",
        ],
        "note": "Hash-only; requires a real User-Agent header.",
    },
    {
        "name": "GreyNoise",
        "env_aliases": ["GREYNOISE_API_KEY"],
        "works_without_key": True,
        "probe_desc": "GET /v3/community/8.8.8.8",
        "method": "GET",
        "url": f"https://api.greynoise.io/v3/community/{PROBE_IP}",
        "headers_fn": lambda k: (
            {"key": k, "accept": "application/json"} if k else {"accept": "application/json"}
        ),
        "expected_fields": [
            "classification (noise / riot / malicious / unknown)",
            "name (scanner/service), link",
            "last_seen date",
        ],
        "note": "Works without a key (free community endpoint, 50/wk).",
    },
    {
        "name": "AlienVault OTX",
        "env_aliases": ["OTX_API_KEY", "ALIENVAULT_OTX_KEY"],
        "probe_desc": "GET /api/v1/indicators/IPv4/8.8.8.8/reputation",
        "method": "GET",
        "url": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{PROBE_IP}/reputation",
        "headers_fn": lambda k: {"X-OTX-API-KEY": k},
        "expected_fields": [
            "reputation pulses (count, names, threat type)",
            "general info section",
            "whois, geo, passive_dns sections",
            "analysis plugin results (AV detections)",
        ],
        "note": "Multi-section API (reputation/general/whois/geo/passive_dns/analysis).",
    },
    {
        "name": "Shodan",
        "env_aliases": ["SHODAN_API_KEY"],
        "works_without_key": True,
        "probe_desc": "GET /shodan/host/8.8.8.8",
        "method": "GET",
        "url": f"https://api.shodan.io/shodan/host/{PROBE_IP}",
        "headers_fn": lambda k: {"Authorization": k},
        "expected_fields": [
            "ports + per-port service details (product, version, cpe, banner)",
            "vulns (CVE ids), hostnames, org, isp, os",
            "free internetdb fallback (ports, vulns, cpes)",
        ],
        "note": "IP-only; free tier 100 credits/month.",
    },
    {
        "name": "Censys",
        "env_aliases": ["CENSYS_API_KEY"],
        "probe_desc": "GET /v3/global/asset/host/8.8.8.8",
        "method": "GET",
        "url": f"https://api.platform.censys.io/v3/global/asset/host/{PROBE_IP}",
        "headers_fn": lambda k: (
            {"Authorization": f"Bearer {k}"}
            if ":" not in k
            else {"Authorization": f"Basic {base64.b64encode(k.encode()).decode()}"}
        ),
        "expected_fields": [
            "location (city, country, timezone)",
            "autonomous_system (asn, name)",
            "services (port, product, version, protocols)",
            "ports list",
        ],
        "note": "Key format id:secret (Basic auth); free 100 credits/month.",
    },
    {
        "name": "IPinfo",
        "env_aliases": ["IPINFO_API_KEY", "IPINFO_ACCESS_TOKEN"],
        "works_without_key": True,
        "probe_desc": "GET /8.8.8.8/json (Bearer)",
        "method": "GET",
        "url": f"https://ipinfo.io/{PROBE_IP}/json",
        "headers_fn": lambda k: ({"Authorization": f"Bearer {k}"} if k else {}),
        "expected_fields": [
            "ip, city, region, country, loc, postal, timezone",
            "org (ASN + name), asn object",
            "hosting flags (is_hosting, is_bogon) with key",
        ],
        "note": "Works keyless for basics (lite), key adds hosting/bogon flags.",
    },
    {
        "name": "OpenPhish",
        "env_aliases": [],
        "works_without_key": True,
        "probe_desc": "GET feed.txt (GitHub raw)",
        "method": "GET",
        "url": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        "headers_fn": lambda k: {},
        "expected_fields": [
            "plain-text list of active phishing URLs",
            "fetched with ETag / Last-Modified caching (600s TTL)",
        ],
        "note": "Free keyless feed; URL-only source.",
    },
    {
        "name": "URLhaus",
        "env_aliases": ["URLHAUS_API_KEY", "MB_AUTH_KEY", "ABUSH_CH_AUTH_KEY"],
        "works_without_key": True,
        "probe_desc": "POST /v1/host/ (8.8.8.8)",
        "method": "POST",
        "url": "https://urlhaus-api.abuse.ch/v1/host/",
        "data_fn": lambda: {"host": PROBE_IP},
        "headers_fn": lambda k: (
            {"Content-Type": "application/x-www-form-urlencoded", "Auth-Key": k} if k else {"Content-Type": "application/x-www-form-urlencoded"}
        ),
        "expected_fields": [
            "query_status (ok / no_results / rate_limited)",
            "blacklists count, url_count",
            "malware samples (md5, signature, first_seen)",
        ],
        "note": "abuse.ch API now requires an Auth-Key; falls back to the shared MB_AUTH_KEY/ABUSH_CH_AUTH_KEY chain.",
    },
    {
        "name": "StopForumSpam",
        "env_aliases": [],
        "works_without_key": True,
        "probe_desc": "GET /api?email=...&json=",
        "method": "GET",
        "url": "https://api.stopforumspam.org/api",
        "params_fn": lambda: {"email": "test@example.com", "json": ""},
        "headers_fn": lambda k: {},
        "expected_fields": [
            "email reputation: appears, frequency, lastseen",
            "confidence score + app/blacklist hits",
        ],
        "note": "Free keyless API; email-only source.",
    },
    {
        "name": "Tor Exit",
        "env_aliases": [],
        "works_without_key": True,
        "probe_desc": "GET torbulkexitlist (feed)",
        "method": "GET",
        "url": "https://check.torproject.org/torbulkexitlist",
        "headers_fn": lambda k: {},
        "expected_fields": [
            "plain-text list of Tor exit node IPs",
            "DNSEL lookup (dnsel.torproject.org) per IP",
        ],
        "note": "Free keyless list + DNSEL; IP-only source.",
    },
    {
        "name": "HIBP Pwned Passwords",
        "env_aliases": [],
        "works_without_key": True,
        "probe_desc": "GET /range/5BAA6 (SHA-1 prefix for 'password')",
        "method": "GET",
        "url": "https://api.pwnedpasswords.com/range/5BAA6",
        "headers_fn": lambda k: {"Add-Padding": "true", "User-Agent": "IOC-Lookup-Platform/1.0"},
        "expected_fields": [
            "k-anonymity SHA-1 hash suffix matches",
            "breach occurrence count per hash",
        ],
        "note": "100% Free keyless k-anonymity API; hash/credential source.",
    },
    {
        "name": "Hudson Rock",
        "env_aliases": ["HUDSON_API_KEY", "HUDSON_ROCK_API_KEY", "HUDSONROCK_API_KEY"],
        "probe_desc": "POST /json/v3/search-by-login/emails",
        "method": "POST",
        "url": "https://api.hudsonrock.com/json/v3/search-by-login/emails",
        "json_fn": lambda: {"emails": ["test@example.com"]},
        "headers_fn": lambda k: {"api-key": k, "accept": "application/json", "content-type": "application/json"},
        "expected_fields": [
            "infostealer infection history",
            "compromised credentials count",
            "malware family (RedLine, Vidar, Lumma)",
        ],
        "note": "Free developer API key from docs.hudsonrock.com; email source.",
    },
]

# Static capability map for the redundancy report.
CAPABILITY_OWNERS = {
    "IP reputation verdicts": ["VirusTotal", "AbuseIPDB", "GreyNoise", "AlienVault OTX"],
    "Port/service enumeration": ["Shodan", "Censys"],
    "ISP/geo/ASN context": ["AbuseIPDB", "IPinfo", "Censys", "AlienVault OTX", "Shodan"],
    "Hash sandbox + MITRE": ["VirusTotal", "Hybrid Analysis", "Tria.ge"],
    "Hash context (family/AV)": ["VirusTotal", "MalwareBazaar", "ThreatFox"],
    "URL reputation / phishing": ["urlscan.io", "VirusTotal", "OpenPhish", "URLhaus"],
    "Email reputation": ["StopForumSpam"],
    "Tor exit node detection": ["Tor Exit"],
    "CVE data": ["NVD"],
}


async def probe(service: dict, key: str) -> dict:
    """Perform one live request mirroring the adapter, capture details."""
    started = time.monotonic()
    result = {"status_code": None, "took_ms": None, "error": None, "top_keys": [], "response_preview": {}}
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            kwargs: dict = {}
            if service.get("params_fn"):
                kwargs["params"] = service["params_fn"]()
            if service.get("json_fn"):
                kwargs["json"] = service["json_fn"]()
            if service.get("data_fn_keyed"):
                kwargs["data"] = service["data_fn_keyed"](key)
            elif service.get("data_fn"):
                kwargs["data"] = service["data_fn"]()
            if service.get("headers_fn"):
                kwargs["headers"] = service["headers_fn"](key)

            resp = await client.request(service["method"], service["url"], **kwargs)
            result["status_code"] = resp.status_code
            result["took_ms"] = int((time.monotonic() - started) * 1000)

            try:
                data = resp.json()
            except Exception:
                data = None

            if isinstance(data, dict):
                result["top_keys"] = sorted(data.keys())
                result["response_preview"] = {k: str(v)[:120] for k, v in data.items()}
            elif isinstance(data, list):
                result["top_keys"] = [f"list[{len(data)}]"]
                if data and isinstance(data[0], dict):
                    result["response_preview"] = {k: str(v)[:120] for k, v in data[0].items()}
            else:
                result["response_preview"] = {"body": resp.text[:200]}
    except asyncio.TimeoutError:
        result["error"] = "TIMEOUT"
    except Exception as exc:
        result["error"] = f"EXCEPTION: {type(exc).__name__}: {exc}"
    return result


def classify(service: dict, key: str, probe_result: dict) -> dict:
    """Turn probe output into a verdict with reasoning."""
    name = service["name"]
    if not key and not service.get("works_without_key"):
        return {"verdict": "NO KEY", "reason": f"{name}: no key configured (env/.env) - skipped."}

    code = probe_result["status_code"]
    err = probe_result["error"]

    if not key and service.get("works_without_key"):
        if err == "TIMEOUT":
            return {"verdict": "UNKNOWN", "reason": f"{name}: request timed out after {REQUEST_TIMEOUT}s (network/provider issue)."}
        if err:
            return {"verdict": "BROKEN", "reason": f"{name}: {err}"}
        if code in (200, 201):
            return {
                "verdict": "WORKS (keyless)",
                "reason": f"{name}: no key needed - HTTP {code}, public endpoint returned data.",
            }
        return {
            "verdict": "UNKNOWN",
            "reason": f"{name}: no key needed but probe returned HTTP {code} - endpoint reachable.",
        }

    code = probe_result["status_code"]
    err = probe_result["error"]

    if err == "TIMEOUT":
        return {"verdict": "UNKNOWN", "reason": f"{name}: request timed out after {REQUEST_TIMEOUT}s (network/provider issue)."}
    if err:
        return {"verdict": "BROKEN", "reason": f"{name}: {err}"}
    if code == 401:
        return {"verdict": "BROKEN", "reason": f"{name}: HTTP 401 UNAUTHORIZED - key is invalid or revoked."}
    if code == 403:
        return {"verdict": "BROKEN", "reason": f"{name}: HTTP 403 FORBIDDEN - key lacks permission/plan for this endpoint."}
    if code == 429:
        return {"verdict": "RATE LIMITED", "reason": f"{name}: HTTP 429 - key works but quota/rate limit reached right now."}
    if code in (404, 400):
        return {"verdict": "USABLE*", "reason": f"{name}: HTTP {code} - auth OK but the probe IOC has no record (expected for clean data)."}
    if code == 200:
        return {"verdict": "USABLE", "reason": f"{name}: HTTP 200 - key accepted, data returned ({len(probe_result['top_keys'])} top-level fields)."}
    return {"verdict": "UNKNOWN", "reason": f"{name}: HTTP {code} - not an auth failure, treat as usable-but-odd."}


def overlap_report(service: dict) -> list[str]:
    """Which other providers share this service's data category."""
    lines = []
    for cap, owners in CAPABILITY_OWNERS.items():
        if service["name"] in owners:
            others = [o for o in owners if o != service["name"]]
            if others:
                lines.append(f"  - {cap}: also from {', '.join(others)}")
    return lines


def mask_headers(service: dict, key: str) -> dict:
    h = {}
    try:
        h = service["headers_fn"](key) or {}
    except Exception:
        pass
    sensitive = {"key", "api-key", "x-apikey", "x-otx-api-key", "auth-key", "authorization"}
    masked = {}
    for k_, v in h.items():
        if k_.lower() in sensitive:
            masked[k_] = mask(v) if v else "(empty)"
        else:
            masked[k_] = v
    return masked


def resolve_chain(service: dict) -> tuple[str, str]:
    """Resolve a credential through its alias chain (.env first, then system
    env). Returns ``(key, source_var)`` - source_var is the exact env-var
    name that supplied the key, or "" when nothing is configured."""
    for name in service["env_aliases"]:
        value = resolve_credential(name)
        if value:
            return value, name
    return "", ""


async def run_all() -> None:
    print("=" * 100)
    print("DEEP API KEY ANALYSIS - one live request per provider")
    print("=" * 100)
    print("Resolver: .env first, then system env - 16 adapters (keyed + keyless)")
    print()

    summary = []
    for svc in SERVICES:
        key, source_var = resolve_chain(svc)
        print("-" * 100)
        print(
            f"  {svc['name']:22s}  ({', '.join(svc['env_aliases']) if svc['env_aliases'] else 'no key needed'})  key: {mask(key) or 'NOT SET'}"
        )
        if key:
            print(f"  supplied by env var: {source_var}")
        print(f"  probe: {svc['probe_desc']}")

        if not key and not svc.get("works_without_key"):
            cls = classify(svc, key, {})
            pr = {"status_code": None, "took_ms": None, "error": None, "top_keys": [], "response_preview": {}}
        else:
            pr = await probe(svc, key)
            cls = classify(svc, key, pr)
            await asyncio.sleep(0.5)

        print(f"  http: {pr['status_code']}   time: {pr['took_ms']}ms   error: {pr['error'] or '-'}")
        if pr["top_keys"]:
            print(f"  response fields: {', '.join(pr['top_keys'][:20])}")
        if pr["response_preview"]:
            preview = "; ".join(f"{k}={v}" for k, v in list(pr["response_preview"].items())[:8])
            print(f"  sample data:     {preview[:400]}")
        if key:
            print(f"  request headers: {mask_headers(svc, key)}")
        print(f"  VERDICT: {cls['verdict']}")
        print(f"  REASON:  {cls['reason']}")
        if key:
            print("  data the key unlocks (adapter fields):")
            for f in svc["expected_fields"]:
                print(f"    - {f}")
            ov = overlap_report(svc)
            if ov:
                print("  overlap with other providers in this project:")
                for line in ov:
                    print(line)
            else:
                print("  overlap: (unique category - no other provider returns this)")
        if svc.get("note"):
            print(f"  note: {svc['note']}")
        summary.append((svc["name"], cls["verdict"]))

    print()
    print("=" * 100)
    print("SUMMARY")
    print("=" * 100)
    for name, verdict in summary:
        print(f"  {name:22s} -> {verdict}")
    ok = [n for n, v in summary if v in ("USABLE", "USABLE*", "WORKS (keyless)", "KEYLESS OK")]
    broken = [n for n, v in summary if v == "BROKEN"]
    no_key = [n for n, v in summary if v == "NO KEY"]
    print()
    print(f"  USABLE: {len(ok)}   BROKEN: {len(broken)}   NO KEY: {len(no_key)}")
    if broken:
        print(f"  Broken keys: {', '.join(broken)}")
    if no_key:
        print(f"  Missing keys: {', '.join(no_key)}")


if __name__ == "__main__":
    asyncio.run(run_all())
