#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from app.backend.adapters.abuse_ipdb import AbuseIPDBAdapter
from app.backend.adapters.alienvault_otx import AlienVaultOTXAdapter
from app.backend.adapters.base import NormalizedResult
from app.backend.adapters.censys import CensysAdapter
from app.backend.adapters.grey_noise import GreyNoiseAdapter
from app.backend.adapters.hybrid_analysis import HybridAnalysisAdapter
from app.backend.adapters.ipinfo import IPinfoAdapter
from app.backend.adapters.malware_bazaar import MalwareBazaarAdapter
from app.backend.adapters.openphish import OpenPhishAdapter
from app.backend.adapters.shodan import ShodanAdapter
from app.backend.adapters.stop_forum_spam import StopForumSpamAdapter
from app.backend.adapters.threatfox import ThreatFoxAdapter
from app.backend.adapters.tor_exit import TorExitAdapter
from app.backend.adapters.triage import TriageAdapter
from app.backend.adapters.urlhaus import URLHausAdapter
from app.backend.adapters.urlscan_io import UrlScanIOAdapter
from app.backend.adapters.virus_total import VirusTotalAdapter
from app.backend.config import settings


@dataclass(frozen=True)
class ProbeCase:
    name: str
    adapter: Any
    ioc_type: str
    ioc_value: str
    note: str


def _count_useful_fields(result: NormalizedResult) -> int:
    fields = [
        result.verdict,
        result.confidence,
        result.status,
        result.malware_family,
        result.source_link,
        result.first_seen,
        result.last_seen,
        result.reports_count,
        result.process_tree,
        result.ssdeep,
        result.tlsh,
    ]
    score = sum(1 for value in fields if value not in (None, "", [], {}))
    score += len(result.tags)
    score += len(result.categories)
    score += len(result.related_iocs)
    score += len(result.samples)
    score += len(result.dropped_files)
    score += len(result.registry_keys)
    score += len(result.network_iocs)
    score += len(result.mitre_attck)
    score += len(result.raw_data)
    return score


def _classify(result: NormalizedResult) -> str:
    if "no_api_key_configured" in result.tags:
        return "missing_key"
    if "unauthorized" in result.tags or "invalid_api_key" in result.tags:
        return "auth_failed"
    if "rate_limited" in result.tags or "daily_quota_exhausted" in result.tags or "weekly_quota_exhausted" in result.tags:
        return "quota_limited"
    if result.status == "not_found":
        return "no_sample_hit"
    if result.verdict in {"malicious", "suspicious", "clean"}:
        return "useful"
    return "limited"


async def _run_probe(case: ProbeCase) -> dict[str, Any]:
    adapter = case.adapter
    try:
        result = await adapter.lookup(case.ioc_value, case.ioc_type)
        if not isinstance(result, NormalizedResult):
            return {
                "name": case.name,
                "note": case.note,
                "status": "unexpected_result",
            }
        payload = result.model_dump()
        return {
            "name": case.name,
            "note": case.note,
            "ioc_type": case.ioc_type,
            "ioc_value": case.ioc_value,
            "verdict": result.verdict,
            "confidence": result.confidence,
            "status": result.status,
            "classification": _classify(result),
            "data_score": _count_useful_fields(result),
            "tags": result.tags[:20],
            "categories": result.categories[:10],
            "related_iocs": result.related_iocs[:10],
            "reports_count": result.reports_count,
            "source_link": result.source_link,
            "payload": payload,
        }
    except Exception as exc:
        return {
            "name": case.name,
            "note": case.note,
            "status": "exception",
            "error": f"{exc.__class__.__name__}: {exc}",
        }


async def main() -> int:
    openphish = OpenPhishAdapter()
    await openphish._ensure_feed()
    openphish_probe = openphish._feed[0] if openphish._feed else "https://example.com/"

    cases = [
        ProbeCase("VirusTotal", VirusTotalAdapter(), "ipv4", "8.8.8.8", "free/public API, strong IP reputation"),
        ProbeCase("AbuseIPDB", AbuseIPDBAdapter(), "ipv4", "8.8.8.8", "free API, useful IP abuse score"),
        ProbeCase("urlscan.io", UrlScanIOAdapter(), "domain", "urlscan.io", "free/community search visibility"),
        ProbeCase("MalwareBazaar", MalwareBazaarAdapter(), "sha256", "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754", "free abuse.ch community hash intel"),
        ProbeCase("ThreatFox", ThreatFoxAdapter(), "ipv4", "94.103.84.81", "free abuse.ch community IOC intel"),
        ProbeCase("Tria.ge", TriageAdapter(), "sha256", "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754", "free sandbox hash lookup if sample exists"),
        ProbeCase("Hybrid Analysis", HybridAnalysisAdapter(), "sha256", "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754", "hash lookup only"),
        ProbeCase("GreyNoise", GreyNoiseAdapter(), "ipv4", "8.8.8.8", "community IP intelligence"),
        ProbeCase("AlienVault OTX", AlienVaultOTXAdapter(), "ipv4", "8.8.8.8", "free community pulses and indicator enrichment"),
        ProbeCase("Shodan", ShodanAdapter(), "ipv4", "8.8.8.8", "InternetDB first, paid host API fallback"),
        ProbeCase("Censys", CensysAdapter(), "ipv4", "8.8.8.8", "free tier host lookup if PAT is valid"),
        ProbeCase("IPinfo", IPinfoAdapter(), "ipv4", "8.8.8.8", "lite/public enrichment or bearer-token mode"),
        ProbeCase("OpenPhish", openphish, "url", openphish_probe, "public phishing feed membership check"),
        ProbeCase("URLHaus", URLHausAdapter(), "url", "http://example.com/", "public malware URL, host, payload, and tag lookup"),
        ProbeCase("StopForumSpam", StopForumSpamAdapter(), "email", "noreply@example.com", "public spam reputation check"),
        ProbeCase("Tor Exit", TorExitAdapter(), "ipv4", "8.8.8.8", "public Tor exit node check"),
    ]

    print(json.dumps({
        "run_mode": "live_probe",
        "env_present": {
            "VT_API_KEY": bool(settings.virustotal_api_key.strip()),
            "ABUSEIPDB_API_KEY": bool(settings.abuseipdb_api_key.strip()),
            "AbuseDB_API_KEY": bool(settings.abuseipdb_api_key.strip()),
            "URL_SCAN_API_KEY": bool(settings.urlscanio_api_key.strip()),
            "MB_AUTH_KEY": bool(settings.malwarebazaar_api_key.strip()),
            "THREATFOX_API_KEY": bool(settings.threatfox_api_key.strip()),
            "TRIAGE_API_KEY": bool(settings.triage_api_key.strip()),
            "TRIA_GE_API_KEY": bool(settings.triage_api_key.strip()),
            "HA_API_KEY": bool(settings.hybridanalysis_api_key.strip()),
            "GREYNOISE_API_KEY": bool(settings.greynoise_api_key.strip()),
            "OTX_API_KEY": bool(settings.alienvault_otx_api_key.strip()),
            "ALIENVAULT_OTX_KEY": bool(settings.alienvault_otx_api_key.strip()),
            "SHODAN_API_KEY": bool(settings.shodan_api_key.strip()),
            "CENSYS_API_KEY": bool(settings.censys_api_key.strip()),
            "IPINFO_API_KEY": bool(settings.ipinfo_api_key.strip()),
            "IPINFO_ACCESS_TOKEN": bool(settings.ipinfo_api_key.strip()),
            "API_KEYS": bool(settings.api_keys.strip()),
            "JWT_SECRET": bool(settings.jwt_secret.strip()),
        },
    }, indent=2))

    results = await asyncio.gather(*[_run_probe(case) for case in cases])
    print(json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))