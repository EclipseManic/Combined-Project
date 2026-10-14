import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from datetime import datetime

import httpx
import mmh3

from app.backend.http_client import get_client as _get_http_client, resolve_public_url
from app.backend.config import settings
from app.backend.logger import get_logger
from app.backend.adapters.base import (
    BreachInfo,
    CVEInfo,
    DNSInfo,
    EmailSecurityInfo,
    EnrichmentData,
    FaviconInfo,
    GeoIPInfo,
    HostIntelligence,
    NormalizedResult,
    ReverseDNSInfo,
    SSLInfo,
    SubdomainInfo,
    WhoisInfo,
)

logger = get_logger("enrichment")


async def enrich(value: str, ioc_type: str) -> EnrichmentData:
    dispatch = {
        "ipv4": enrich_ip,
        "ipv6": enrich_ip,
        "domain": enrich_domain,
        "url": enrich_url,
        "md5": enrich_hash,
        "sha1": enrich_hash,
        "sha256": enrich_hash,
        "email": enrich_email,
        "cve": enrich_cve,
        "ssdeep": enrich_ssdeep,
        "btc": enrich_btc,
        "eth": enrich_eth,
        "mitre_attack": enrich_mitre_attack,
        "asn": enrich_asn,
        "mutex": lambda value: enrich_host_artifact(value, "mutex"),
        "named_pipe": lambda value: enrich_host_artifact(value, "named_pipe"),
        "registry_key": lambda value: enrich_host_artifact(value, "registry_key"),
        "service_name": lambda value: enrich_host_artifact(value, "service_name"),
        "filename": enrich_filename,
        "windows_path": lambda value: enrich_filepath(value, "windows"),
        "linux_path": lambda value: enrich_filepath(value, "linux"),
        "user_agent": enrich_user_agent,
        "mac": enrich_mac,
    }
    fn = dispatch.get(ioc_type, enrich_unknown)
    return await fn(value)


async def _probe_port(loop, semaphore, ip: str, p: int) -> int | None:
    try:
        if not ipaddress.ip_address(ip).is_global:
            return None
    except ValueError:
        return None

    def _check(p: int) -> bool:
        import socket as _socket
        from contextlib import closing

        with closing(_socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)) as s:
            s.settimeout(1.5)
            try:
                return s.connect_ex((ip, p)) == 0
            except OSError:
                return False

    async with semaphore:
        try:
            ok = await asyncio.wait_for(
                loop.run_in_executor(None, _check, p), timeout=2.0
            )
            return p if ok else None
        except (asyncio.TimeoutError, OSError):
            return None


async def _quick_port_scan(ip: str) -> list[int]:
    try:
        if not ipaddress.ip_address(ip).is_global:
            return []
    except ValueError:
        return []
    COMMON_PORTS = [21, 22, 25, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
    loop = asyncio.get_running_loop()
    semaphore = asyncio.Semaphore(4)

    try:
        async with asyncio.timeout(8):
            results = await asyncio.gather(
                *(_probe_port(loop, semaphore, ip, p) for p in COMMON_PORTS)
            )
    except asyncio.TimeoutError:
        return []
    return [p for p in results if p is not None]


class RDAPNoRecordError(Exception):
    """The authoritative RDAP registry responded but holds no record for the
    target. This is a data gap (reported as ``unavailable``), not a failure
    (reported as ``error``)."""


def _completeness_label(val, none_status: str = "unavailable") -> str:
    """Map an enrichment result to an honest completeness status.

    - ``ok``: data was produced.
    - ``unavailable``: no data exists for this target (no RDAP record, no PTR,
      HTTP-only site without a certificate) — a data gap, not a bug.
    - ``error``: the lookup itself failed (timeout, transport, parse).
    """
    if isinstance(val, RDAPNoRecordError):
        return "unavailable"
    if isinstance(val, Exception):
        return "error"
    if val is None:
        return none_status
    return "ok"


_PORT_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 123: "NTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "Submission", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2086: "WHM", 2087: "WHM-SSL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8880: "HTTP-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}


async def _fetch_internetdb(ip: str) -> HostIntelligence | None:
    """Fetch free Shodan InternetDB host intelligence (ports, CVEs, CPEs, tags, hostnames). Zero API key needed."""
    try:
        c = _get_http_client()
        r = await c.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
        if r.status_code == 200:
            d = r.json()
            raw_ports = d.get("ports", []) or []
            ports = [int(p) for p in raw_ports if isinstance(p, (int, str)) and str(p).isdigit()]
            cpes = list(d.get("cpes", []) or [])
            vulns = list(d.get("vulns", []) or [])
            tags = list(d.get("tags", []) or [])
            hostnames = list(d.get("hostnames", []) or [])
            port_services = {p: _PORT_SERVICES.get(p, "Unknown") for p in ports}
            return HostIntelligence(
                open_ports=ports,
                port_services=port_services,
                unpatched_cves=vulns,
                cpes=cpes,
                tags=tags,
                hostnames=hostnames,
                source="internetdb",
            )
    except Exception as exc:
        logger.debug("InternetDB query failed for %s: %s", ip, exc)
    return None


async def _pivot_domain_to_hosting_ip(a_records: list[str]) -> dict:
    """Safe pivot from domain's A records to hosting IP context with CDN short-circuiting."""
    results: dict[str, dict] = {}
    client = _get_http_client()
    for ip in a_records[:2]:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_global:
                results[ip] = {"is_private": True, "name": "Private/Internal IP"}
                continue
        except ValueError:
            continue

        # Check GreyNoise RIOT first (free keyless check for CDNs)
        riot_status = False
        riot_name = ""
        try:
            gn_resp = await client.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=4)
            if gn_resp.status_code == 200:
                gn_data = gn_resp.json()
                riot_status = gn_data.get("riot", False)
                riot_name = gn_data.get("name", "")
        except Exception:
            pass

        # Check GeoIP & hosting/datacenter classification
        geo_info = {}
        try:
            ip_resp = await client.get(
                f"https://ipwho.is/{ip}",
                timeout=4,
            )
            if ip_resp.status_code == 200:
                d = ip_resp.json()
                if d.get("success", True):
                    connection = d.get("connection", {}) or {}
                    geo_info = {
                        "country": d.get("country", ""),
                        "isp": connection.get("isp", ""),
                        "org": connection.get("org", ""),
                        "asn_name": connection.get("asn", ""),
                        "is_datacenter": False,
                    }
        except Exception:
            pass

        results[ip] = {
            "riot": riot_status,
            "riot_name": riot_name,
            **geo_info,
        }
    return results


async def enrich_ip(value: str) -> EnrichmentData:
    completeness: dict[str, str] = {}

    geoip, rdns, whois = await asyncio.gather(
        _geoip_ipapi(value),
        _reverse_dns(value),
        _rdap_lookup(value),
        return_exceptions=True,
    )

    completeness["geoip"] = _completeness_label(geoip)
    completeness["reverse_dns"] = _completeness_label(rdns)
    completeness["whois"] = _completeness_label(whois)

    from app.backend.config import settings
    host_intel: HostIntelligence | None = None
    open_ports_result: list[int] = []
    ip_version = ipaddress.ip_address(value).version

    # Tier 1: Shodan InternetDB (Keyless, instant, rich)
    internetdb_res = await _fetch_internetdb(value)
    if internetdb_res and internetdb_res.open_ports:
        host_intel = internetdb_res
        open_ports_result = internetdb_res.open_ports
        completeness["host_intel"] = "ok"
        completeness["port_scan"] = "ok"
    elif internetdb_res:
        host_intel = internetdb_res
        completeness["host_intel"] = "ok"
        completeness["port_scan"] = "not_found"
    else:
        completeness["host_intel"] = "unavailable"

    # Tier 2: Optional active port scan (fallback). Shodan's paid host API is
    # deliberately never used as a fallback for missing free InternetDB data.
    if not open_ports_result and ip_version == 4 and settings.enable_active_port_scan:
        open_ports_result = await _quick_port_scan(value)
        if open_ports_result:
            completeness["port_scan"] = "ok"
            port_services = {p: _PORT_SERVICES.get(p, "Unknown") for p in open_ports_result}
            host_intel = HostIntelligence(
                open_ports=open_ports_result,
                port_services=port_services,
                source="active_scan",
            )
        else:
            completeness["port_scan"] = "not_available"
    elif not open_ports_result:
        completeness["port_scan"] = "disabled" if not settings.enable_active_port_scan else "not_available"

    geoip_val = geoip if not isinstance(geoip, Exception) else None
    rdns_val = rdns if not isinstance(rdns, Exception) else None
    whois_val = whois if not isinstance(whois, Exception) else None

    return EnrichmentData(
        geoip=geoip_val,
        reverse_dns=rdns_val,
        whois=whois_val,
        host_intel=host_intel,
        relationships=_rdns_relationships(value, rdns_val) if rdns_val else [],
        completeness=completeness,
        open_ports=open_ports_result if open_ports_result else [],
    )


async def enrich_domain(value: str) -> EnrichmentData:
    completeness: dict[str, str] = {}

    whois, dns_records, ssl_info, subdomains, favicon = await asyncio.gather(
        _rdap_lookup(value),
        _dns_lookup(value),
        _ssl_cert(value),
        _crt_sh_subdomains(value),
        _favicon_hash(value),
        return_exceptions=True,
    )

    completeness["whois"] = _completeness_label(whois)
    completeness["dns"] = _completeness_label(dns_records, none_status="error")
    completeness["ssl"] = _completeness_label(ssl_info)
    completeness["subdomains"] = _completeness_label(subdomains, none_status="not_found")
    completeness["favicon"] = "not_found" if isinstance(favicon, Exception) or favicon is None else "ok"

    dns_val = dns_records if not isinstance(dns_records, Exception) else None
    hosting_intel = {}
    if dns_val and dns_val.a:
        try:
            hosting_intel = await _pivot_domain_to_hosting_ip(dns_val.a)
        except Exception as exc:
            logger.debug("Domain to hosting IP pivot failed: %s", exc)

    return EnrichmentData(
        whois=whois if not isinstance(whois, Exception) else None,
        dns=dns_val,
        ssl=ssl_info if not isinstance(ssl_info, Exception) else None,
        subdomains=subdomains if not isinstance(subdomains, Exception) else None,
        favicon=favicon if not isinstance(favicon, Exception) else None,
        hosting_ip_intel=hosting_intel,
        completeness=completeness,
    )


async def _is_public_fetch_target(url: str) -> bool:
    return await resolve_public_url(url) is not None


async def _url_redirect_chain(url: str) -> list[dict]:
    try:
        client = _get_http_client()
        chain = []
        seen = set()
        current = url
        for _ in range(6):
            pinned_target = await resolve_public_url(current)
            if pinned_target is None:
                logger.warning("Blocked unsafe URL enrichment target: %s", current)
                break
            seen.add(current)
            pinned_url, pin_headers, extensions = pinned_target
            r = await client.get(
                pinned_url,
                headers=pin_headers,
                extensions=extensions,
                follow_redirects=False,
                timeout=10,
            )
            status = r.status_code
            location = r.headers.get("Location", "")
            chain.append({"url": current, "status": status, "location": location})
            if status in (301, 302, 303, 307, 308) and location and location not in seen:
                from urllib.parse import urljoin
                current = urljoin(current, location)
            else:
                break
            if len(chain) >= 5:
                break
        return chain
    except Exception:
        return []


async def _url_content_preview(url: str) -> dict:
    import re
    try:
        if not await _is_public_fetch_target(url):
            logger.warning("Blocked unsafe URL enrichment target: %s", url)
            return {}
        client = _get_http_client()
        # SSRF-safe manual redirect handling (validate each hop)
        r = None
        current = url
        seen_urls = set()
        for _ in range(6):
            pinned_target = await resolve_public_url(current)
            if pinned_target is None:
                logger.warning("Blocked unsafe URL enrichment target: %s", current)
                return {}
            if current in seen_urls:
                break
            seen_urls.add(current)
            pinned_url, pin_headers, extensions = pinned_target
            r = await client.get(
                pinned_url,
                headers=pin_headers,
                extensions=extensions,
                timeout=10,
                follow_redirects=False,
            )
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if loc:
                    from urllib.parse import urljoin
                    nxt = urljoin(current, loc)
                    if nxt not in seen_urls:
                        current = nxt
                        continue
            break
        if r is None or r.status_code != 200:
            return {}
        if r.status_code != 200:
            return {}
        text = r.text
        title = ""
        m = re.search(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip()[:200]
        meta_desc = ""
        m = re.search(r'<meta\s+[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', text, re.IGNORECASE)
        if not m:
            m = re.search(r'<meta\s+[^>]*content=["\']([^"\']*)["\'][^>]*name=["\']description["\']', text, re.IGNORECASE)
        if m:
            meta_desc = m.group(1).strip()[:300]
        text_content = re.sub(r'<[^>]+>', ' ', text)
        text_content = re.sub(r'\s+', ' ', text_content).strip()[:500]
        return {
            "url": url,
            "title": title,
            "meta_description": meta_desc,
            "text_preview": text_content,
        }
    except Exception:
        return {}


async def enrich_url(value: str) -> EnrichmentData:
    from urllib.parse import urlparse
    domain = urlparse(value).hostname or value
    result = await enrich_domain(domain)
    result.completeness["domain_extraction"] = "ok" if domain != value else "error"
    result.relationships = [{"source_ioc": value, "target_ioc": domain, "relationship": "extracted_host", "via_source": "url_parse"}]

    from app.backend.config import settings

    # Fetching an analyst-supplied URL makes the IOC workstation an SSRF
    # primitive. Keep that active behavior opt-in; reputation adapters and
    # passive domain enrichment remain available by default.
    if not settings.enable_url_content_fetch:
        result.completeness["redirect_chain"] = "disabled"
        result.completeness["url_preview"] = "disabled"
        result.analysis_notes.append(
            "Active URL retrieval is disabled to protect the analyst workstation. "
            "Enable ENABLE_URL_CONTENT_FETCH only in an isolated environment."
        )
        return result

    redirect_chain, url_preview = await asyncio.gather(
        _url_redirect_chain(value),
        _url_content_preview(value),
        return_exceptions=True,
    )
    result.redirect_chain = redirect_chain if not isinstance(redirect_chain, Exception) else []
    result.url_preview = url_preview if not isinstance(url_preview, Exception) else {}
    result.completeness["redirect_chain"] = "ok" if result.redirect_chain else "error"
    result.completeness["url_preview"] = "ok" if result.url_preview.get("title") else "error"
    return result


async def enrich_hash(value: str) -> EnrichmentData:
    completeness: dict[str, str] = {}
    results = []
    from app.backend.config import settings

    if not settings.hashlookup_enabled:
        completeness["hash_lookup"] = "not_applicable"
        return EnrichmentData(completeness=completeness, extra={"hash_results": results})
    c = _get_http_client()
    try:
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value), "sha256")
        r = await c.get(f"https://hashlookup.circl.lu/lookup/{hash_type}/{value}")
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict):
                results.append({
                    "filename": data.get("FileName", ""),
                    "size": data.get("FileSize", ""),
                    "mime": data.get("mimetype", ""),
                    "source": data.get("source", ""),
                    "database": data.get("db", ""),
                    "trust": data.get("hashlookup:trust"),
                    "md5": data.get("MD5", ""),
                    "sha1": data.get("SHA-1", ""),
                    "sha256": data.get("SHA-256", ""),
                    "ssdeep": data.get("SSDEEP", ""),
                    "tlsh": data.get("TLSH", ""),
                })
            completeness["hash_lookup"] = "ok"
        else:
            completeness["hash_lookup"] = "not_found"
    except Exception:
        completeness["hash_lookup"] = "error"
    return EnrichmentData(completeness=completeness, extra={"hash_results": results})


async def _dnsbl_check(email: str) -> list[dict]:
    domain = email.split("@")[-1] if "@" in email else email
    dnsbls = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
    ]
    results = []
    import socket
    loop = asyncio.get_running_loop()

    def _get_ip():
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    try:
        ip = await asyncio.wait_for(loop.run_in_executor(None, _get_ip), timeout=2.5)
    except Exception:
        ip = None

    if not ip:
        return results

    parts = ip.split(".")
    rev = ".".join(reversed(parts))

    def _query_bl(bl: str):
        query = f"{rev}.{bl}"
        try:
            socket.gethostbyname(query)
            return {"blacklist": bl, "listed": True, "ip": ip}
        except socket.gaierror:
            return None

    bl_coros = [
        asyncio.wait_for(loop.run_in_executor(None, _query_bl, bl), timeout=2.0)
        for bl in dnsbls
    ]
    bl_results = await asyncio.gather(*bl_coros, return_exceptions=True)
    for r in bl_results:
        if isinstance(r, dict) and r.get("listed"):
            results.append(r)
    return results


async def enrich_email(value: str) -> EnrichmentData:
    completeness: dict[str, str] = {}
    domain = value.split("@")[-1] if "@" in value else value

    domain_result, xposed, proxynova, email_sec, dnsbl = await asyncio.gather(
        _enrich_domain_for_email(domain),
        _xposedornot_lookup(value),
        _proxynova_comb_lookup(value),
        _email_security(domain),
        _dnsbl_check(value),
        return_exceptions=True,
    )

    completeness["domain_extraction"] = "ok" if domain != value else "error"

    completeness["xposedornot"] = "ok" if not isinstance(xposed, Exception) and xposed is not None else "error"

    if isinstance(proxynova, Exception) or proxynova is None:
        completeness["proxynova_comb"] = "unavailable"
    else:
        completeness["proxynova_comb"] = "ok"

    completeness["email_security"] = "ok" if not isinstance(email_sec, Exception) and email_sec is not None else "error"
    # An empty DNSBL result is a successful negative lookup, not a provider
    # outage.  The UI must not present it as an error.
    completeness["dnsbl"] = "ok" if isinstance(dnsbl, list) and dnsbl else "not_found"

    # Merge breach results
    all_sources = [xposed, proxynova]
    all_failed = all(isinstance(r, Exception) or r is None for r in all_sources)

    if all_failed:
        merged_breach = BreachInfo(breach_count=None, source="none")
    else:
        all_names: list[str] = []
        all_dates: list[str] = []
        all_exposed: list[str] = []
        for r in all_sources:
            if isinstance(r, Exception) or r is None:
                continue
            br: BreachInfo = r
            all_names.extend(br.breach_names)
            if br.most_recent_breach:
                all_dates.append(br.most_recent_breach)
            all_exposed.extend(br.exposed_data_types)

        seen: set[str] = set()
        deduped_names: list[str] = []
        for name in all_names:
            key = name.lower().strip()
            if key not in seen:
                seen.add(key)
                deduped_names.append(name)

        merged_breach = BreachInfo(
            breach_count=len(deduped_names),
            breach_names=deduped_names,
            most_recent_breach=max(all_dates) if all_dates else "",
            exposed_data_types=list(dict.fromkeys(all_exposed)),
            source="multiple",
        )

    result = domain_result if not isinstance(domain_result, Exception) else EnrichmentData()
    result.completeness.update(completeness)
    result.breach = merged_breach
    result.email_security = email_sec if not isinstance(email_sec, Exception) else None
    result.extra = result.extra or {}
    result.extra["dnsbl_result"] = dnsbl if not isinstance(dnsbl, Exception) else None
    result.relationships = [{"source_ioc": value, "target_ioc": domain, "relationship": "email_domain", "via_source": "email_parse"}]
    return result


async def _enrich_domain_for_email(domain: str) -> EnrichmentData:
    try:
        whois, dns_records, ssl_info = await asyncio.wait_for(
            asyncio.gather(
                _rdap_lookup(domain),
                _dns_lookup(domain),
                _ssl_cert(domain),
                return_exceptions=True,
            ),
            timeout=8.0,
        )
    except Exception:
        whois, dns_records, ssl_info = None, None, None
    return EnrichmentData(
        whois=whois if not isinstance(whois, Exception) else None,
        dns=dns_records if not isinstance(dns_records, Exception) else None,
        ssl=ssl_info if not isinstance(ssl_info, Exception) else None,
    )


async def _exploitdb_lookup(cve_id: str) -> list[dict]:
    import re
    try:
        c = _get_http_client()
        r = await c.get(f"https://www.exploit-db.com/search?cve={cve_id}", timeout=10)
        if r.status_code != 200:
            return []
        results = []
        for m in re.finditer(r'/exploits/(\d+)', r.text):
            eid = m.group(1)
            results.append({"id": eid, "url": f"https://www.exploit-db.com/exploits/{eid}"})
            if len(results) >= 5:
                break
        dates = [m.group(1) for m in re.finditer(r'<td[^>]*>(\d{4}-\d{2}-\d{2})</td>', r.text)]
        for i, date in enumerate(dates):
            if i < len(results):
                results[i]["date"] = date
        return results
    except Exception:
        return []


async def _poc_github_check(cve_id: str) -> list[dict]:
    try:
        c = _get_http_client()
        r = await c.get(f"https://api.github.com/search/repositories?q={cve_id}+poC&sort=stars&order=desc", timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
        items = data.get("items", [])[:5]
        return [
            {"name": item["full_name"], "url": item["html_url"], "stars": item.get("stargazers_count", 0)}
            for item in items
        ]
    except Exception:
        return []


async def enrich_cve(value: str) -> EnrichmentData:
    completeness: dict[str, str] = {}

    in_kev, kev_date = await _cisa_kev(value)
    epss_score, epss_percentile = await _first_epss(value)
    nvd_data = await _nvd_cve(value)

    completeness["cisa_kev"] = "ok"
    completeness["epss"] = "ok" if epss_score is not None else "error"
    completeness["nvd"] = "ok" if nvd_data else "error"

    exploits, poc = await asyncio.gather(
        _exploitdb_lookup(value),
        _poc_github_check(value),
        return_exceptions=True,
    )

    exploit_list = exploits if not isinstance(exploits, Exception) else []
    poc_list = poc if not isinstance(poc, Exception) else []

    completeness["exploitdb"] = "ok" if exploit_list else "not_found"
    completeness["poc_github"] = "ok" if poc_list else "not_found"

    return EnrichmentData(
        cve=CVEInfo(
            is_in_kev=in_kev,
            kev_date_added=kev_date,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            cvss_score=nvd_data.get("baseScore"),
            cvss_severity=nvd_data.get("baseSeverity", ""),
            cvss_vector=nvd_data.get("vectorString", ""),
            vulnerability_status=nvd_data.get("vulnerabilityStatus") or None,
            published_at=nvd_data.get("publishedAt"),
            modified_at=nvd_data.get("modifiedAt"),
            exploit_status="known_exploited" if in_kev else ("reported" if exploit_list or poc_list else "unknown"),
            cwe=nvd_data.get("cwe", []),
            references=nvd_data.get("references", []),
            public_exploits_exist=len(exploit_list) > 0,
            poc_available=len(poc_list) > 0,
            affected_products=nvd_data.get("affectedProducts", []),
            cvss_breakdown=nvd_data.get("cvssBreakdown", {}),
        ),
        completeness=completeness,
        extra={"exploitdb": exploit_list, "poc_github": poc_list},
    )


async def enrich_ssdeep(value: str) -> EnrichmentData:
    """Parse fuzzy-hash structure; threat matching requires a corpus/search API."""
    parts = value.split(":", 2)
    block_size = int(parts[0]) if parts and parts[0].isdigit() else None
    first_chunk = parts[1] if len(parts) > 1 else ""
    second_chunk = parts[2] if len(parts) > 2 else ""
    return EnrichmentData(
        completeness={"structural_analysis": "ok", "fuzzy_match_corpus": "unavailable"},
        extra={
            "ssdeep": {
                "block_size": block_size,
                "first_chunk_length": len(first_chunk),
                "second_chunk_length": len(second_chunk),
                "alphabet": "".join(sorted(set(first_chunk + second_chunk))),
            }
        },
    )


async def enrich_btc(value: str) -> EnrichmentData:
    """Fetch public Bitcoin address statistics from blockchain.info."""
    try:
        client = _get_http_client()
        response = await client.get(
            f"https://blockchain.info/rawaddr/{value}",
            params={"limit": 5},
            timeout=15,
        )
        if response.status_code == 404:
            return EnrichmentData(completeness={"blockchain_address": "not_found"})
        if response.status_code != 200:
            return EnrichmentData(completeness={"blockchain_address": f"http_{response.status_code}"})
        data = response.json()
        transactions = data.get("txs", []) if isinstance(data, dict) else []
        return EnrichmentData(
            completeness={"blockchain_address": "ok"},
            extra={
                "bitcoin": {
                    "address": value,
                    "hash160": data.get("hash160", ""),
                    "n_tx": data.get("n_tx", 0),
                    "total_received_btc": (data.get("total_received", 0) or 0) / 100_000_000,
                    "total_sent_btc": (data.get("total_sent", 0) or 0) / 100_000_000,
                    "final_balance_btc": (data.get("final_balance", 0) or 0) / 100_000_000,
                    "recent_transactions": [
                        {
                            "hash": tx.get("hash", ""),
                            "time": tx.get("time"),
                            "result_btc": (tx.get("result", 0) or 0) / 100_000_000,
                        }
                        for tx in transactions[:5]
                        if isinstance(tx, dict)
                    ],
                }
            },
        )
    except Exception as exc:
        logger.debug("Bitcoin enrichment failed for %s: %s", value, exc)
        return EnrichmentData(completeness={"blockchain_address": "error"})


async def _etherscan_api_summary(value: str) -> dict:
    """Balance and latest transactions from the Etherscan V2 API."""
    client = _get_http_client()
    base = "https://api.etherscan.io/v2/api"
    common = {"address": value, "apikey": settings.etherscan_api_key, "chainid": 1}
    balance_response, tx_response = await asyncio.gather(
        client.get(base, params={"module": "account", "action": "balance", **common}, timeout=15),
        client.get(
            base,
            params={"module": "account", "action": "txlist", "startblock": 0, "endblock": 99999999, "page": 1, "offset": 25, "sort": "desc", **common},
            timeout=15,
        ),
    )
    balance = balance_response.json() if balance_response.status_code == 200 else {}
    payload = tx_response.json() if tx_response.status_code == 200 else {}
    if not isinstance(balance, dict) or balance.get("status") != "1":
        raise RuntimeError(str((balance or {}).get("result") or f"http_{balance_response.status_code}")[:120])
    transactions = payload.get("result", []) if isinstance(payload, dict) else []
    transactions = [tx for tx in transactions if isinstance(tx, dict)] if isinstance(transactions, list) else []

    def _int(raw) -> int:
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0

    lowered = value.lower()
    recent = []
    for tx in transactions:
        sender, receiver = str(tx.get("from") or ""), str(tx.get("to") or "")
        direction = "SELF" if sender.lower() == receiver.lower() == lowered else "OUT" if sender.lower() == lowered else "IN"
        function = str(tx.get("functionName") or "").split("(")[0]
        recent.append({
            "hash": tx.get("hash"),
            "method": function or ("Transfer" if tx.get("input") in ("0x", "", None) else tx.get("methodId")),
            "block": _int(tx.get("blockNumber")) or None,
            "time": _int(tx.get("timeStamp")) or None,
            "direction": direction,
            "from": {"address": sender},
            "to": {"address": receiver or tx.get("contractAddress")},
            "value_eth": _int(tx.get("value")) / 10**18,
            "fee_eth": _int(tx.get("gasUsed")) * _int(tx.get("gasPrice")) / 10**18,
            "failed": tx.get("isError") == "1",
        })
    return {"balance_eth": _int(balance.get("result")) / 10**18, "recent_transactions": recent}


# Chains queried for native balances through the Etherscan V2 API when the
# address page omits its Blockscan multichain portfolio (Etherscan does not
# always render it). (chainid, name, native symbol). BNB Chain, Optimism, Base,
# Avalanche and Gnosis are left out: the free API tier rejects them.
_ETHERSCAN_V2_CHAINS = [
    (1, "Ethereum", "ETH"), (42161, "Arbitrum One", "ETH"), (59144, "Linea", "ETH"),
    (81457, "Blast", "ETH"), (167000, "Taiko", "ETH"), (480, "World Chain", "ETH"),
    (130, "Unichain", "ETH"), (2741, "Abstract", "ETH"), (137, "Polygon", "POL"),
    (5000, "Mantle", "MNT"), (204, "opBNB", "BNB"), (252, "Fraxtal", "FRAX"),
    (33139, "ApeChain", "APE"), (146, "Sonic", "S"), (80094, "Berachain", "BERA"),
]
_ETHERSCAN_V2_PAID_CHAINS = ["BNB Chain", "Optimism", "Base", "Avalanche C-Chain", "Gnosis"]
_NATIVE_PRICE_TTL = 600
_native_prices: dict[str, tuple[float, float]] = {}  # symbol -> (usd, fetched_at)


async def _etherscan_multichain_native(
    value: str, eth_balance: float | None = None, eth_price: float | None = None,
) -> dict:
    """Native-coin balance per chain from the Etherscan V2 API, valued in USD.

    Token balances per chain need a paid plan, so this is a native-only view;
    the caller labels it that way. A known Ethereum balance/price is reused
    instead of spending calls on it."""
    client = _get_http_client()
    base = "https://api.etherscan.io/v2/api"
    key = settings.etherscan_api_key
    if eth_price:
        _native_prices["ETH"] = (eth_price, time.time())
    # The free tier allows only a few calls per second, shared with the
    # Etherscan adapter running in parallel.
    semaphore = asyncio.Semaphore(2)

    async def _call(chain_id: int, **params) -> str | None:
        for attempt in range(3):
            async with semaphore:
                response = await client.get(base, params={"chainid": chain_id, "apikey": key, **params}, timeout=15)
                await asyncio.sleep(0.5)
            payload = response.json() if response.status_code == 200 else {}
            if isinstance(payload, dict) and payload.get("status") == "1":
                return payload.get("result")
            if "rate limit" not in str((payload or {}).get("result", "")).lower() and response.status_code != 429:
                return None
            await asyncio.sleep(1.2 * (attempt + 1))
        return None

    async def _price(chain_id: int, symbol: str) -> float | None:
        cached = _native_prices.get(symbol)
        if cached and time.time() - cached[1] < _NATIVE_PRICE_TTL:
            return cached[0]
        result = await _call(chain_id, module="stats", action="ethprice")
        try:
            usd = float(result["ethusd"]) if isinstance(result, dict) else None
        except (KeyError, TypeError, ValueError):
            usd = None
        if usd is not None:
            _native_prices[symbol] = (usd, time.time())
        return usd

    async def _balance(chain_id: int) -> float | None:
        if chain_id == 1 and eth_balance is not None:
            return float(eth_balance)
        result = await _call(chain_id, module="account", action="balance", address=value)
        try:
            return int(result) / 10**18
        except (TypeError, ValueError):
            return None

    balances = await asyncio.gather(*(_balance(chain_id) for chain_id, _, _ in _ETHERSCAN_V2_CHAINS), return_exceptions=True)
    price_chains = {symbol: chain_id for chain_id, _, symbol in reversed(_ETHERSCAN_V2_CHAINS)}
    held = {symbol for (_, _, symbol), balance in zip(_ETHERSCAN_V2_CHAINS, balances) if isinstance(balance, float) and balance > 0}
    prices = dict(zip(held, await asyncio.gather(*(_price(price_chains[s], s) for s in held), return_exceptions=True)))

    chains, failed = [], []
    for (chain_id, name, symbol), balance in zip(_ETHERSCAN_V2_CHAINS, balances):
        if not isinstance(balance, float):
            failed.append(name)
            continue
        if balance <= 0:
            continue
        price = prices.get(symbol)
        chains.append({
            "chain": name,
            "chain_id": str(chain_id),
            "native_symbol": symbol,
            "native_balance": balance,
            "value_usd": round(balance * price, 2) if isinstance(price, float) else 0.0,
        })
    total = sum(chain["value_usd"] for chain in chains)
    for chain in chains:
        share = chain["value_usd"] / total * 100 if total else 0.0
        chain["share_pct"] = round(share) if share >= 1 else 1.0
        chain["share_below_pct"] = share < 1
    chains.sort(key=lambda chain: chain["value_usd"], reverse=True)
    return {
        "chains": chains,
        "multichain_portfolio_usd": round(total, 2),
        "active_chain_count": len(chains),
        "multichain_source": "etherscan_v2_native",
        "multichain_chains_checked": len(_ETHERSCAN_V2_CHAINS) - len(failed),
        "multichain_chains_failed": failed,
        "multichain_chains_unsupported": _ETHERSCAN_V2_PAID_CHAINS,
    }


def _eth_relationships(value: str, ethereum: dict) -> list[dict]:
    relationships = []

    def _add(target: dict | None, relationship: str, **details) -> None:
        address = (target or {}).get("address")
        if not address or address.lower() == value.lower():
            return
        relationships.append({
            "source_ioc": value,
            "target_ioc": address,
            "target_type": "eth",
            "relationship": relationship,
            "via_source": "Etherscan",
            "confidence": "high",
            "evidence_type": "observed_relationship",
            "label": (target or {}).get("label"),
            **details,
        })

    _add(ethereum.get("funded_by"), "funded_by", tx_hash=(ethereum.get("funded_by") or {}).get("tx_hash"))
    _add(ethereum.get("contract_creator"), "created_by", tx_hash=(ethereum.get("contract_creator") or {}).get("tx_hash"))
    for counterparty in ethereum.get("risky_counterparties", [])[:10]:
        _add(counterparty, "transacted_with_flagged", tx_count=counterparty.get("tx_count"))
    return relationships


async def enrich_eth(value: str) -> EnrichmentData:
    """Ethereum wallet context for the enrichment tab.

    The Etherscan address page supplies labels, warnings, USD valuation, token
    holdings, the multichain portfolio, funding source, total transaction count
    and counterparty tags; the V2 API (when a key is configured) supplies an
    exact balance and a transaction list, and is the fallback when the page is
    unavailable."""
    from app.backend import etherscan_page
    from app.backend.adapters.base import is_valid_api_key

    if not etherscan_page.ETH_ADDRESS_RE.fullmatch(value):
        return EnrichmentData(completeness={"ethereum_address": "invalid"})
    use_page = settings.etherscan_page_enrichment
    use_api = is_valid_api_key(settings.etherscan_api_key)
    if not use_page and not use_api:
        return EnrichmentData(
            completeness={"ethereum_address": "not_configured"},
            analysis_notes=["Ethereum enrichment requires ETHERSCAN_API_KEY or ETHERSCAN_PAGE_ENRICHMENT=true; provider results may still be available."],
        )

    async def _skip():
        return None

    page, api = await asyncio.gather(
        etherscan_page.scrape_address(value) if use_page else _skip(),
        _etherscan_api_summary(value) if use_api else _skip(),
        return_exceptions=True,
    )
    completeness: dict[str, str] = {}
    notes: list[str] = []
    ethereum: dict = {"address": value}
    sources: list[str] = []

    if isinstance(page, dict):
        ethereum.update(page)
        sources.append("etherscan_page")
        completeness["etherscan_page"] = "ok"
    elif use_page:
        logger.info("Etherscan page enrichment unavailable for %s: %s", value, page)
        completeness["etherscan_page"] = "unavailable"
        notes.append(f"Etherscan address page unavailable ({str(page)[:80]}); labels, holdings and multichain data are missing.")
    else:
        completeness["etherscan_page"] = "disabled"

    if isinstance(api, dict):
        sources.append("etherscan_api")
        completeness["etherscan_api"] = "ok"
        # The API balance is exact; the page renders a rounded figure.
        ethereum["balance_eth"] = api["balance_eth"]
        if not ethereum.get("recent_transactions"):
            ethereum["recent_transactions"] = api["recent_transactions"]
        if ethereum.get("transaction_count") is None:
            ethereum["transaction_count"] = len(api["recent_transactions"])
            ethereum["transaction_count_is_lower_bound"] = len(api["recent_transactions"]) >= 25
    elif use_api:
        logger.info("Etherscan API enrichment failed for %s: %s", value, api)
        completeness["etherscan_api"] = "error"
    else:
        completeness["etherscan_api"] = "not_configured"

    # Etherscan does not always embed the Blockscan multichain portfolio in the
    # page; fall back to per-chain native balances from the V2 API.
    if ethereum.get("chains"):
        ethereum["multichain_source"] = "etherscan_page"
        completeness["multichain_holdings"] = "ok"
    elif use_api:
        try:
            multichain = await _etherscan_multichain_native(
                value, ethereum.get("balance_eth"), ethereum.get("eth_price_usd"),
            )
        except Exception as exc:
            logger.info("Etherscan multichain lookup failed for %s: %s", value, exc)
            multichain = None
        if multichain and multichain["multichain_chains_checked"]:
            ethereum.update(multichain)
            completeness["multichain_holdings"] = "partial"
            notes.append(
                f"Multichain holdings are native-coin balances on {multichain['multichain_chains_checked']} chains "
                "(Etherscan V2 API); token holdings on other chains and "
                + ", ".join(_ETHERSCAN_V2_PAID_CHAINS) + " need a paid Etherscan plan."
            )
        else:
            completeness["multichain_holdings"] = "error"
    else:
        completeness["multichain_holdings"] = "unavailable"
        if isinstance(page, dict):
            notes.append("Etherscan did not include the multichain portfolio for this address; set ETHERSCAN_API_KEY to load per-chain balances.")

    if not sources:
        completeness["ethereum_address"] = "error"
        return EnrichmentData(completeness=completeness, analysis_notes=notes)

    ethereum["data_sources"] = sources
    completeness["ethereum_address"] = "ok"
    if ethereum.get("public_name_tag"):
        notes.append(f"Etherscan public name tag: {ethereum['public_name_tag']}.")
    if ethereum.get("risk_labels"):
        notes.append("Etherscan flags this address: " + ", ".join(ethereum["risk_labels"]) + ".")
    for warning in ethereum.get("warnings", [])[:3]:
        notes.append(f"Etherscan warning: {warning}")
    risky = ethereum.get("risky_counterparties") or []
    if risky:
        notes.append(f"{len(risky)} recent counterparties carry threat-related Etherscan tags (e.g. {risky[0]['label']}).")
    return EnrichmentData(
        completeness=completeness,
        extra={"ethereum": ethereum},
        relationships=_eth_relationships(value, ethereum),
        analysis_notes=notes,
    )


async def enrich_asn(value: str) -> EnrichmentData:
    """Enrich an ASN with holder and announced-prefix data from RIPEstat."""
    try:
        client = _get_http_client()
        overview, prefixes = await asyncio.gather(
            client.get(
                "https://stat.ripe.net/data/as-overview/data.json",
                params={"resource": value}, timeout=15,
            ),
            client.get(
                "https://stat.ripe.net/data/announced-prefixes/data.json",
                params={"resource": value}, timeout=15,
            ),
            return_exceptions=True,
        )
        data = overview.json() if not isinstance(overview, Exception) and overview.status_code == 200 else {}
        prefix_data = prefixes.json() if not isinstance(prefixes, Exception) and prefixes.status_code == 200 else {}
        overview_data = data.get("data", {}) if isinstance(data, dict) else {}
        announced = prefix_data.get("data", {}).get("prefixes", []) if isinstance(prefix_data, dict) else []
        announced = [p for p in announced if isinstance(p, dict)][:100]
        if not overview_data and not announced:
            return EnrichmentData(completeness={"ripestat": "not_found"})
        return EnrichmentData(
            completeness={"ripestat": "ok"},
            extra={"asn": {
                "resource": value,
                "holder": overview_data.get("holder", ""),
                "announced_prefix_count": len(announced),
                "announced_prefixes": announced,
                "block": overview_data.get("block", {}),
            }},
        )
    except Exception as exc:
        logger.debug("ASN enrichment failed for %s: %s", value, exc)
        return EnrichmentData(completeness={"ripestat": "error"})


async def enrich_mitre_attack(value: str) -> EnrichmentData:
    """Fetch the public ATT&CK page metadata for a tactic or technique ID."""
    try:
        is_tactic = value.upper().startswith("TA")
        path = "tactics" if is_tactic else "techniques"
        client = _get_http_client()
        response = await client.get(f"https://attack.mitre.org/{path}/{value.upper()}/", timeout=15)
        if response.status_code != 200:
            return EnrichmentData(completeness={"mitre_attack": f"http_{response.status_code}"})
        html = response.text
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        desc_match = re.search(
            r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)',
            html, re.IGNORECASE,
        )
        title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else value
        description = re.sub(r"\s+", " ", desc_match.group(1)).strip() if desc_match else ""
        return EnrichmentData(
            completeness={"mitre_attack": "ok"},
            extra={"mitre_attack": {
                "id": value.upper(),
                "kind": "tactic" if is_tactic else "technique",
                "title": title,
                "description": description,
                "url": f"https://attack.mitre.org/{path}/{value.upper()}/",
            }},
        )
    except Exception as exc:
        logger.debug("MITRE enrichment failed for %s: %s", value, exc)
        return EnrichmentData(completeness={"mitre_attack": "error"})


async def enrich_host_artifact(value: str, ioc_type: str = "") -> EnrichmentData:
    """Return useful structural context for host artifacts without a sandbox corpus."""
    artifact_type = ioc_type
    if not artifact_type:
        if value.lower().startswith("\\\\") and "\\pipe\\" in value.lower():
            artifact_type = "named_pipe"
        elif "\\" in value and re.match(r"^[A-Za-z_][A-Za-z0-9_]*\\", value):
            artifact_type = "registry_key"
        else:
            artifact_type = "mutex"

    details: dict[str, object] = {"value": value, "type": artifact_type}
    if artifact_type == "named_pipe":
        match = re.match(r"^\\\\([^\\]+)\\pipe\\(.+)$", value, re.IGNORECASE)
        if match:
            details.update({"server": match.group(1), "pipe_name": match.group(2)})
    elif artifact_type == "registry_key":
        hive, _, key = value.partition("\\")
        details.update({"hive": hive, "key_path": key, "depth": len([p for p in key.split("\\") if p])})
    elif artifact_type == "mutex":
        details.update({"namespace": value.split("\\", 1)[0] if "\\" in value else "global", "name": value.rsplit("\\", 1)[-1]})
    else:
        details["name"] = value

    return EnrichmentData(
        completeness={"structural_analysis": "ok", "threat_corpus": "unavailable"},
        extra={"host_artifact": details},
    )


async def enrich_filename(value: str) -> EnrichmentData:
    """Local structural context for a filename artifact (keyless, no corpus).

    Surfaces the extension, a coarse category, and double-extension /
    executable-masquerade heuristics so the analyst sees *something* structured
    instead of an empty panel."""
    name = value.strip().strip('"')
    dot = name.rfind(".")
    ext = name[dot + 1:].lower() if dot > 0 else ""
    stem = name[:dot] if dot > 0 else name

    executable = {"exe", "dll", "sys", "scr", "com", "msi", "elf", "so", "dylib", "bin"}
    script = {"bat", "cmd", "ps1", "vbs", "js", "sh", "py", "pl", "php", "hta", "jar", "wsf"}
    office = {"doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "pdf", "rtf"}
    archive = {"zip", "rar", "7z", "tar", "gz", "iso", "img", "vhd", "cab"}
    if ext in executable:
        category = "executable"
    elif ext in script:
        category = "script"
    elif ext in office:
        category = "document"
    elif ext in archive:
        category = "archive"
    else:
        category = "other"

    # Double-extension masquerade (e.g. invoice.pdf.exe) is a classic lure.
    inner = re.findall(r"\.([A-Za-z0-9]{1,5})", stem)
    masq_office = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "jpg", "png", "txt"}
    double_extension = bool(inner and ext in (executable | script) and inner[-1].lower() in masq_office)

    notes: list[str] = []
    if double_extension:
        notes.append(
            f"Double-extension masquerade: a '{inner[-1].lower()}' file name that is actually a .{ext} "
            f"{category} — a common social-engineering lure."
        )
    if category in {"executable", "script"}:
        notes.append("Executable/script artifact; correlate the associated file hash with malware feeds for a verdict.")

    return EnrichmentData(
        completeness={"structural_analysis": "ok", "threat_corpus": "unavailable"},
        analysis_notes=notes,
        extra={"filename": {
            "value": name,
            "extension": ext,
            "category": category,
            "double_extension": double_extension,
            "component_extensions": [e.lower() for e in inner] + ([ext] if ext else []),
        }},
    )


async def enrich_filepath(value: str, os_family: str) -> EnrichmentData:
    """Local structural context for a Windows or Linux path (keyless).

    Extracts the directory, leaf filename, and a suspicious-location flag for
    the common malware staging directories."""
    raw = value.strip().strip('"')
    if os_family == "windows":
        sep = "\\"
        normalized = raw.replace("/", "\\")
        drive = normalized[:2] if re.match(r"^[A-Za-z]:", normalized) else ""
        suspicious_markers = [
            r"\appdata\local\temp", r"\appdata\roaming", r"\windows\temp",
            r"\programdata", r"\users\public", r"\$recycle.bin", r"\perflogs",
        ]
    else:
        sep = "/"
        normalized = raw
        drive = ""
        suspicious_markers = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/var/www/"]

    leaf = normalized.rstrip(sep).rsplit(sep, 1)[-1] if sep in normalized.rstrip(sep) else normalized
    directory = normalized[: len(normalized) - len(leaf)].rstrip(sep) or (drive or sep)
    low = normalized.lower()
    hit = next((m for m in suspicious_markers if m in low), "")

    notes: list[str] = []
    if hit:
        notes.append(
            f"Path resides in a common malware staging location ({hit.strip(sep)}); "
            "execution from here is frequently associated with dropped payloads."
        )

    file_ext = leaf.rsplit(".", 1)[-1].lower() if "." in leaf else ""
    return EnrichmentData(
        completeness={"structural_analysis": "ok", "threat_corpus": "unavailable"},
        analysis_notes=notes,
        extra={"file_path": {
            "value": raw,
            "os": os_family,
            "directory": directory,
            "filename": leaf,
            "extension": file_ext,
            "suspicious_location": bool(hit),
            "location_marker": hit.strip(sep) if hit else "",
        }},
    )


async def enrich_user_agent(value: str) -> EnrichmentData:
    """Local structural parse of a User-Agent string (keyless).

    Identifies the declared client family and flags the automation/scripting
    clients that rarely represent a human browser."""
    ua = value.strip()
    low = ua.lower()
    client = ua.split("/", 1)[0].strip() if "/" in ua else ua

    automation = {
        "curl": "curl", "wget": "wget", "python-requests": "python-requests",
        "go-http-client": "Go net/http", "java": "Java", "python-urllib": "urllib",
        "libwww-perl": "libwww-perl", "okhttp": "OkHttp", "axios": "axios",
        "postmanruntime": "Postman", "aiohttp": "aiohttp",
    }
    tool = next((label for key, label in automation.items() if low.startswith(key) or key in low), "")
    is_automation = bool(tool)

    if not is_automation and ("mozilla" in low or "applewebkit" in low or "gecko" in low):
        client = "Browser (Mozilla-compatible)"

    platform = ""
    for token, label in (("windows nt", "Windows"), ("mac os x", "macOS"), ("android", "Android"),
                         ("iphone", "iOS"), ("linux", "Linux"), ("x11", "Unix/X11")):
        if token in low:
            platform = label
            break

    notes: list[str] = []
    if is_automation:
        notes.append(
            f"Automation/scripting client ({tool}); rarely a human browser — common in scanners, "
            "scrapers, and C2 beacons. Correlate with the source IP's request pattern."
        )
    return EnrichmentData(
        completeness={"structural_analysis": "ok", "threat_corpus": "unavailable"},
        analysis_notes=notes,
        extra={"user_agent": {
            "value": ua,
            "client": tool or client,
            "platform": platform,
            "is_automation": is_automation,
        }},
    )


# OUI prefixes for common virtualization / hypervisor vendors — a MAC in one of
# these ranges usually indicates a VM or sandbox rather than physical hardware.
_MAC_VENDOR_OUIS = {
    "00:05:69": "VMware", "00:0c:29": "VMware", "00:1c:14": "VMware", "00:50:56": "VMware",
    "08:00:27": "VirtualBox (Oracle)", "0a:00:27": "VirtualBox (Oracle)",
    "00:03:ff": "Microsoft Hyper-V", "00:15:5d": "Microsoft Hyper-V",
    "00:16:3e": "Xen", "52:54:00": "QEMU/KVM", "00:1c:42": "Parallels",
    "00:e0:4c": "Realtek", "00:0f:4b": "Oracle VM",
}


async def enrich_mac(value: str) -> EnrichmentData:
    """Local structural context for a MAC address (keyless).

    Decodes the OUI, the locally-administered / multicast bits, and flags known
    virtualization vendor ranges (VMware, VirtualBox, Hyper-V, QEMU, ...)."""
    norm = value.lower().replace("-", ":")
    octets = norm.split(":")
    oui = ":".join(octets[:3]) if len(octets) >= 3 else norm
    vendor = _MAC_VENDOR_OUIS.get(oui, "")

    locally_administered = False
    multicast = False
    if octets and re.fullmatch(r"[0-9a-f]{2}", octets[0]):
        first = int(octets[0], 16)
        locally_administered = bool(first & 0b10)
        multicast = bool(first & 0b01)

    notes: list[str] = []
    if vendor:
        notes.append(f"OUI belongs to {vendor}; this endpoint is likely a virtual machine or sandbox, not physical hardware.")
    if locally_administered:
        notes.append("Locally-administered address (not a burned-in vendor MAC) — may be spoofed or randomized.")

    return EnrichmentData(
        completeness={"structural_analysis": "ok", "vendor_lookup": "ok" if vendor else "unknown_oui"},
        analysis_notes=notes,
        extra={"mac": {
            "value": norm,
            "oui": oui,
            "vendor": vendor or "Unknown",
            "locally_administered": locally_administered,
            "multicast": multicast,
            "virtualization": bool(vendor),
        }},
    )


async def enrich_unknown(value: str) -> EnrichmentData:
    return EnrichmentData(completeness={"enrichment": "skipped"})


# ─── Existing helpers ─────────────────────────────────


async def _geoip_ipapi(ip: str) -> GeoIPInfo | None:
    try:
        c = _get_http_client()
        r = await c.get(
            f"https://ipwho.is/{ip}",
            timeout=5,
        )
        if r.status_code != 200:
            return None
        d = r.json()
        if not d.get("success", True):
            return None
        connection = d.get("connection", {}) or {}
        security = d.get("security", {}) or {}
        return GeoIPInfo(
            country=d.get("country"),
            country_code=d.get("country_code"),
            city=d.get("city"),
            region=d.get("region"),
            timezone=(d.get("timezone") or {}).get("id"),
            asn=connection.get("asn"),
            asn_name=connection.get("org"),
            isp=connection.get("isp"),
            org=connection.get("org"),
            latitude=d.get("latitude"),
            longitude=d.get("longitude"),
            is_proxy=bool(security.get("proxy", False)),
            is_vpn=bool(security.get("vpn", False)),
            is_datacenter=bool(security.get("hosting", False)),
        )
    except Exception:
        return None


async def _reverse_dns(ip: str) -> ReverseDNSInfo | None:
    try:
        hostname = await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyaddr, ip)
        return ReverseDNSInfo(hostnames=[hostname[0]])
    except Exception:
        return None


_rdap_bootstrap: dict | None = None


async def _get_rdap_url(domain: str) -> str | None:
    global _rdap_bootstrap
    try:
        if _rdap_bootstrap is None:
            c = _get_http_client()
            r = await c.get("https://data.iana.org/rdap/dns.json", timeout=10)
            if r.status_code == 200:
                _rdap_bootstrap = r.json()
        tld = domain.rsplit(".", 1)[-1].lower()
        if _rdap_bootstrap and "services" in _rdap_bootstrap:
            for svc in _rdap_bootstrap["services"]:
                if isinstance(svc, list) and len(svc) >= 2:
                    tlds, urls = svc[0], svc[1]
                    if isinstance(tlds, list) and tld in tlds:
                        if isinstance(urls, list) and urls:
                            base = urls[0].rstrip("/")
                            return f"{base}/domain/{domain}"
    except Exception as exc:
        logger.debug("RDAP bootstrap lookup failed for %s: %s", domain, exc)
    fallbacks = {
        "com": "https://rdap.verisign.com/com/v1/domain",
        "net": "https://rdap.verisign.com/net/v1/domain",
        "org": "https://rdap.publicinterestregistry.org/rdap/domain",
        "info": "https://rdap.afilias.net/rdap/domain",
        "io": "https://rdap.nic.io/domain",
        "me": "https://rdap.nic.me/domain",
        "co": "https://rdap.nic.co/domain",
    }
    base = fallbacks.get(tld)
    if base:
        return f"{base}/{domain}"
    return None


def _rdap_registrar(data: dict) -> str:
    """Extract the registrar name from RDAP entities (role 'registrar' vCard fn)."""
    try:
        for ent in data.get("entities") or []:
            roles = ent.get("roles") or []
            if "registrar" not in roles:
                continue
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) >= 2:
                for field in vcard[1] or []:
                    if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                        return str(field[3]).strip()[:100]
    except Exception:
        pass
    return ""


async def _rdap_lookup(target: str) -> WhoisInfo | None:
    try:
        if _is_ip(target):
            url = f"https://rdap.arin.net/registry/ip/{target}"
        else:
            url = await _get_rdap_url(target)
        if not url:
            return await _whois_fallback(target)
        c = _get_http_client()
        r = await c.get(url, timeout=8)
        if r.status_code == 404 and _is_ip(target):
            raise RDAPNoRecordError(target)
        if r.status_code != 200:
            return await _whois_fallback(target)
        d = r.json()
        port43 = d.get("port43") or ""
        registrar = _rdap_registrar(d)
        if not registrar and port43:
            return await _whois_fallback(target, server=port43)

        # Extract nameservers
        nameservers: list[str] = []
        for ns in d.get("nameservers", []) or []:
            if isinstance(ns, dict):
                ns_name = ns.get("ldhName", "")
                if ns_name:
                    nameservers.append(ns_name.lower())

        status_codes = [s for s in d.get("status", []) if isinstance(s, str)]
        created = _rdap_date(d, "registration") or _rdap_date(d, "registrationDate") or ""
        updated = _rdap_date(d, "last changed") or _rdap_date(d, "last update") or ""
        expires = _rdap_date(d, "expiration") or _rdap_date(d, "expirationDate") or ""
        org_name = d.get("name", d.get("handle", ""))

        # Privacy protection detection
        privacy_protected = False
        text_corpus = f"{registrar} {org_name} {json.dumps(d.get('entities', []))}".lower()
        if any(term in text_corpus for term in ("privacy", "proxy", "redacted", "gdpr", "withheld", "whoisguard")):
            privacy_protected = True

        # Domain age & newly registered calculation
        domain_age_days = None
        is_newly_registered = False
        if created:
            try:
                from datetime import timezone
                dt_str = created.replace("Z", "+00:00")
                created_dt = datetime.fromisoformat(dt_str)
                diff = datetime.now(timezone.utc) - created_dt
                domain_age_days = max(0, diff.days)
                if domain_age_days < 30:
                    is_newly_registered = True
            except Exception:
                pass

        return WhoisInfo(
            registrar=registrar,
            creation_date=created,
            expiration_date=expires,
            updated_date=updated,
            nameservers=nameservers,
            status_codes=status_codes,
            domain_age_days=domain_age_days,
            is_newly_registered=is_newly_registered,
            abuse_email=_extract_abuse_email(d),
            org=org_name,
            privacy_protected=privacy_protected,
            fallback_tier_used=1,
        )
    except RDAPNoRecordError:
        raise
    except Exception:
        return await _whois_fallback(target)


_WHOIS_SERVERS: dict[str, str] = {}


async def _whois_tld_servers() -> dict[str, str]:
    global _WHOIS_SERVERS
    if _WHOIS_SERVERS:
        return _WHOIS_SERVERS
    try:
        c = _get_http_client()
        r = await c.get("https://www.iana.org/domains/root/db")
        if r.status_code == 200:
            import re
            for m in re.finditer(r'/domains/root/db/([^.]+)\.html[^>]*>([^<]+)</a>', r.text):
                tld = m.group(1).lower()
                whois = m.group(2).strip()
                if whois.endswith(".whois-servers.net"):
                    _WHOIS_SERVERS[tld] = whois
    except Exception:
        pass
    fallbacks = {
        "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
        "org": "whois.pir.org", "info": "whois.afilias.net",
        "me": "whois.nic.me", "co": "whois.nic.co",
        "io": "whois.nic.io", "uk": "whois.nic.uk",
        "de": "whois.denic.de", "fr": "whois.nic.fr",
        "eu": "whois.eu", "ru": "whois.tcinet.ru",
    }
    for tld, server in fallbacks.items():
        if tld not in _WHOIS_SERVERS:
            _WHOIS_SERVERS[tld] = server
    return _WHOIS_SERVERS


async def _resolve_public_tcp_hosts(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = await asyncio.get_running_loop().run_in_executor(
            None,
            socket.getaddrinfo,
            host,
            43,
            0,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
        addresses = []
        for info in infos:
            address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
            if address not in addresses:
                addresses.append(address)
    except (OSError, ValueError):
        return []
    if not addresses or any(not address.is_global for address in addresses):
        return []
    return addresses


async def _is_public_tcp_host(host: str) -> bool:
    return bool(await _resolve_public_tcp_hosts(host))


async def _whois_raw_query(domain: str, server: str | None = None) -> str | None:
    tld = domain.rsplit(".", 1)[-1].lower()
    if not server:
        servers = await _whois_tld_servers()
        server = servers.get(tld)
    if not server:
        return None
    addresses = await _resolve_public_tcp_hosts(server)
    if not addresses:
        return None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(addresses[0]), 43), timeout=5
        )
        writer.write(f"{domain}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024 * 1024), timeout=10)
        writer.close()
        await writer.wait_closed()
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None


async def _parse_whois_text(text: str) -> WhoisInfo | None:
    result = WhoisInfo()
    nameservers: list[str] = []
    status_codes: list[str] = []
    for line in text.splitlines():
        low = line.lower().strip()
        if "registrar:" in low and ":" in line:
            result.registrar = (result.registrar or "") + line.split(":", 1)[1].strip()[:100]
        if "creation date:" in low or "created:" in low or "created on:" in low:
            val = line.split(":", 1)[1].strip()[:30]
            if not result.creation_date:
                result.creation_date = val
        if "updated date:" in low or "last updated:" in low or "changed:" in low:
            val = line.split(":", 1)[1].strip()[:30]
            if not result.updated_date:
                result.updated_date = val
        if "registry expiry date:" in low or "expiration date:" in low or "expire:" in low or "registry expiration date:" in low:
            val = line.split(":", 1)[1].strip()[:30]
            if not result.expiration_date:
                result.expiration_date = val
        if "name server:" in low or "nserver:" in low:
            ns = line.split(":", 1)[1].strip().split()[0].lower()
            if ns and ns not in nameservers:
                nameservers.append(ns)
        if "domain status:" in low or "status:" in low:
            st = line.split(":", 1)[1].strip().split()[0]
            if st and st not in status_codes:
                status_codes.append(st)
        if "abuse" in low and "email" in low and "@" in line:
            result.abuse_email = line.split(":", 1)[1].strip()
        if "org name:" in low or "organisation:" in low or "org:" in low or "registrant organization:" in low:
            result.org = result.org or line.split(":", 1)[1].strip()[:100]
        if "registrant country:" in low or "country:" in low:
            if not result.registrant_country:
                result.registrant_country = line.split(":", 1)[1].strip()[:30]

    result.nameservers = nameservers
    result.status_codes = status_codes
    low_text = text.lower()
    if any(term in low_text for term in ("privacy", "proxy", "redacted", "gdpr", "withheld", "whoisguard")):
        result.privacy_protected = True

    if result.creation_date:
        try:
            for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%d-%b-%Y"):
                try:
                    from datetime import timezone
                    c_dt = datetime.strptime(result.creation_date[:10], fmt[:8]).replace(tzinfo=timezone.utc)
                    diff = datetime.now(timezone.utc) - c_dt
                    result.domain_age_days = max(0, diff.days)
                    if result.domain_age_days < 30:
                        result.is_newly_registered = True
                    break
                except Exception:
                    continue
        except Exception:
            pass

    result.fallback_tier_used = 2

    if any([result.registrar, result.creation_date, result.org, result.nameservers]):
        return result
    return None


async def _whois_discover_server(tld: str) -> str | None:
    addresses = await _resolve_public_tcp_hosts("whois.iana.org")
    if not addresses:
        return None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(addresses[0]), 43), timeout=5
        )
        writer.write(f"{tld}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), timeout=10)
        writer.close()
        await writer.wait_closed()
        for line in data.decode("utf-8", errors="replace").splitlines():
            low = line.lower().strip()
            if low.startswith("whois:"):
                server = line.split(":", 1)[1].strip()
                if server:
                    return server
    except Exception:
        return None
    return None


async def _whois_fallback(target: str, server: str | None = None) -> WhoisInfo | None:
    import re
    if not re.match(r'^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', target):
        return None

    # Tier 2: Port 43 TCP direct query
    raw = await _whois_raw_query(target, server=server)
    if raw:
        parsed = await _parse_whois_text(raw)
        if parsed:
            parsed.fallback_tier_used = 2
            return parsed
    if server:
        return None
    tld = target.rsplit(".", 1)[-1].lower()
    discovered = await _whois_discover_server(tld)
    if discovered:
        raw = await _whois_raw_query(target, server=discovered)
        if raw:
            parsed = await _parse_whois_text(raw)
            if parsed:
                parsed.fallback_tier_used = 2
                return parsed

    # Tier 2b: Local whois CLI (if installed on Unix/Linux)
    if os.name != "nt":
        try:
            proc = await asyncio.create_subprocess_exec(
                "whois", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            parsed = await _parse_whois_text(stdout.decode("utf-8", errors="replace"))
            if parsed:
                parsed.fallback_tier_used = 2
                return parsed
        except Exception:
            pass

    # Tier 3: VirusTotal Domain Attributes WHOIS fallback
    from app.backend.config import settings
    from app.backend.adapters.base import is_valid_api_key
    if is_valid_api_key(settings.virustotal_api_key):
        try:
            c = _get_http_client()
            vt_resp = await c.get(
                f"https://www.virustotal.com/api/v3/domains/{target}",
                headers={"x-apikey": settings.virustotal_api_key},
                timeout=6,
            )
            if vt_resp.status_code == 200:
                vt_attrs = vt_resp.json().get("data", {}).get("attributes", {})
                vt_whois = vt_attrs.get("whois", "")
                if vt_whois:
                    parsed = await _parse_whois_text(vt_whois)
                    if parsed:
                        parsed.fallback_tier_used = 3
                        return parsed
        except Exception as exc:
            logger.debug("VirusTotal WHOIS fallback failed: %s", exc)

    return None


async def _dns_lookup(domain: str) -> DNSInfo | None:
    try:
        result = DNSInfo()
        loop = asyncio.get_event_loop()

        async def doh(record_type: str) -> list[str]:
            client = _get_http_client()
            response = await client.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": record_type},
                headers={"Accept": "application/dns-json"},
                timeout=10,
            )
            if response.status_code != 200:
                return []
            answers = response.json().get("Answer", [])
            values = []
            for answer in answers:
                if not isinstance(answer, dict):
                    continue
                value = str(answer.get("data", "")).strip().strip('"')
                if record_type == "MX":
                    value = value.split(maxsplit=1)[-1] if value else ""
                if value:
                    values.append(value.rstrip("."))
            return list(dict.fromkeys(values))

        records = await asyncio.gather(
            *(doh(record_type) for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME")),
            return_exceptions=True,
        )
        for record_type, values in zip(("a", "aaaa", "mx", "ns", "txt", "cname"), records):
            if isinstance(values, list):
                setattr(result, record_type, values)

        if not result.a and not result.aaaa:
            try:
                info = await loop.run_in_executor(None, socket.getaddrinfo, domain, 80)
                for entry in info:
                    addr = entry[4][0]
                    if entry[0] == socket.AF_INET and addr not in result.a:
                        result.a.append(addr)
                    elif entry[0] == socket.AF_INET6 and addr not in result.aaaa:
                        result.aaaa.append(addr)
            except Exception:
                pass

        if not result.cname:
            try:
                hostname, aliases, _ = await loop.run_in_executor(None, socket.gethostbyname_ex, domain)
                if aliases:
                    result.cname = [a for a in aliases if a.lower() != domain.lower()]
            except Exception:
                pass

        return result
    except Exception:
        return None


def _san_is_wildcard(san: str) -> bool:
    value = str(san)
    if value.lower().startswith("dns:"):
        value = value[4:]
    return value.startswith("*.")


def _resolve_public_addresses(hostname: str, port: int) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for info in infos:
            address = ipaddress.ip_address(info[4][0])
            if not address.is_global:
                return []
            addresses.append(address)
        return addresses
    except (OSError, ValueError):
        return []


async def _ssl_cert(hostname: str) -> SSLInfo | None:
    try:
        loop = asyncio.get_event_loop()

        def _fetch():
            addresses = _resolve_public_addresses(hostname, 443)
            if not addresses:
                return None
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((str(addresses[0]), 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return None
                    sans = []
                    for entry in cert.get("subjectAltName", []):
                        if len(entry) == 2:
                            sans.append(f"{entry[0]}:{entry[1]}")
                    subj_list = cert.get("subject", [])
                    subject = dict(subj_list) if isinstance(subj_list, dict) else (
                        {k: v for arr in subj_list for k, v in arr} if subj_list else {}
                    )
                    iss_list = cert.get("issuer", [])
                    issuer = dict(iss_list) if isinstance(iss_list, dict) else (
                        {k: v for arr in iss_list for k, v in arr} if iss_list else {}
                    )

                    not_after_str = str(cert.get("notAfter", ""))
                    is_expired = False
                    days_remaining = None
                    from datetime import datetime, timezone
                    for fmt in ["%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ"]:
                        try:
                            parsed = datetime.strptime(not_after_str, fmt)
                            parsed = parsed.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            is_expired = parsed < now
                            days_remaining = (parsed - now).days
                            break
                        except (ValueError, TypeError):
                            continue

                    common_name = subject.get("commonName", "")
                    is_wildcard = str(common_name).startswith("*.") or any(
                        _san_is_wildcard(san) for san in sans
                    )
                    issuer_cn = str(issuer.get("commonName", ""))
                    is_self_signed = str(subject.get("commonName", "")) == issuer_cn

                    return SSLInfo(
                        subject=str(subject.get("commonName", "")),
                        issuer=str(issuer.get("commonName", "")),
                        serial=str(cert.get("serialNumber", "")),
                        not_before=str(cert.get("notBefore", "")),
                        not_after=not_after_str,
                        fingerprint="",
                        subject_alt_names=sans,
                        is_expired=is_expired,
                        is_self_signed=is_self_signed,
                        is_wildcard=is_wildcard,
                        days_remaining=days_remaining,
                    )

        return await loop.run_in_executor(None, _fetch)
    except Exception:
        return None


def _rdns_relationships(ip: str, rdns: ReverseDNSInfo | None) -> list[dict]:
    if not rdns or not rdns.hostnames:
        return []
    return [{"source_ioc": ip, "target_ioc": h, "relationship": "resolves_to", "via_source": "reverse_dns"} for h in rdns.hostnames]


def _extract_abuse_email(data: dict) -> str:
    for entity in data.get("entities", []):
        if isinstance(entity, dict):
            for vcard_arr in entity.get("vcardArray", []):
                if isinstance(vcard_arr, list):
                    for item in vcard_arr:
                        if isinstance(item, list) and len(item) > 3 and item[0] == "email":
                            return item[3]
    return ""


def _rdap_date(data: dict, key: str) -> str | None:
    for event in data.get("events", []):
        if isinstance(event, dict) and event.get("eventAction") == key:
            return event.get("eventDate", "")
    return None


def _is_ip(v: str) -> bool:
    parts = v.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p)


# ─── 1. crt.sh Certificate Transparency ────────────


async def _crt_sh_subdomains(domain: str) -> SubdomainInfo | None:
    subs: list[str] = []
    seen: set[str] = set()
    dot_domain = "." + domain.lower()
    c = _get_http_client()

    # Tier 1: crt.sh Certificate Transparency
    try:
        for attempt in range(2):
            r = await c.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                headers={"User-Agent": "IOC-Lookup-Platform/1.0", "Accept": "application/json"},
                timeout=10,
            )
            if r.status_code == 502 and attempt < 1:
                await asyncio.sleep(1)
                continue
            if r.status_code == 200:
                entries = r.json()
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict):
                            name = entry.get("name_value", "")
                            for n in name.split("\n"):
                                n = n.strip().lower()
                                if n.endswith(dot_domain) and n not in seen:
                                    seen.add(n)
                                    subs.append(n)
            break
    except Exception as exc:
        logger.debug("crt.sh lookup failed for %s: %s", domain, exc)

    # Tier 2: HackerTarget hostsearch fallback if crt.sh yielded nothing
    if not subs:
        try:
            r = await c.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=6)
            if r.status_code == 200 and r.text and "error" not in r.text.lower():
                for line in r.text.splitlines():
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip().lower()
                        if sub.endswith(dot_domain) and sub not in seen:
                            seen.add(sub)
                            subs.append(sub)
        except Exception as exc:
            logger.debug("HackerTarget hostsearch fallback failed for %s: %s", domain, exc)

    return SubdomainInfo(subdomains=subs[:100]) if subs else None


# ─── 2. CISA Known Exploited Vulnerabilities ───────


_cisa_cache: dict | None = None
_cisa_cache_time: float = 0
_CISA_TTL: float = 3600
_cisa_lock: asyncio.Lock | None = None
_cisa_refresh_task: asyncio.Task | None = None


async def _fetch_cisa_feed() -> dict | None:
    c = _get_http_client()
    try:
        r = await c.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15.0,
        )
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        logger.warning("CISA feed fetch failed: %s", exc)
    return None


async def _refresh_cisa_cache(force: bool = False) -> None:
    global _cisa_cache, _cisa_cache_time
    if not force and _cisa_cache is not None and time.time() - _cisa_cache_time < _CISA_TTL:
        return
    data = await _fetch_cisa_feed()
    if data:
        _cisa_cache = data
        _cisa_cache_time = time.time()


async def start_cisa_background_refresh() -> None:
    global _cisa_lock, _cisa_refresh_task
    if _cisa_lock is None:
        _cisa_lock = asyncio.Lock()
    if _cisa_refresh_task is None or _cisa_refresh_task.done():
        async def _loop():
            while True:
                try:
                    async with _cisa_lock:
                        await _refresh_cisa_cache(force=True)
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.warning("CISA background refresh error: %s", exc)
                await asyncio.sleep(_CISA_TTL)
        _cisa_refresh_task = asyncio.create_task(_loop())


async def stop_cisa_background_refresh() -> None:
    global _cisa_refresh_task
    task = _cisa_refresh_task
    _cisa_refresh_task = None
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def _cisa_kev(cve_id: str) -> tuple[bool, str]:
    global _cisa_lock
    try:
        if _cisa_lock is None:
            _cisa_lock = asyncio.Lock()
        async with _cisa_lock:
            await _refresh_cisa_cache()
            if _cisa_cache and "vulnerabilities" in _cisa_cache:
                for vuln in _cisa_cache["vulnerabilities"]:
                    if isinstance(vuln, dict) and vuln.get("cveID", "").upper() == cve_id.upper():
                        return True, vuln.get("dateAdded", "")
            return False, ""
    except Exception:
        return False, ""


# ─── 3. FIRST EPSS ─────────────────────────────────


async def _first_epss(cve_id: str) -> tuple[float | None, float | None]:
    try:
        c = _get_http_client()
        r = await c.get(f"https://api.first.org/data/v1/epss?cve={cve_id}")
        if r.status_code != 200:
            return None, None
        data = r.json()
        entries = data.get("data", [])
        if entries:
            epss = float(entries[0].get("epss", 0))
            pct = float(entries[0].get("percentile", 0))
            return epss, pct
        return 0.0, 0.0
    except Exception:
        return None, None


# ─── 4. NVD CVE API ────────────────────────────────


async def _nvd_cve(cve_id: str) -> dict:
    from app.backend.config import settings

    try:
        headers = {"User-Agent": "IOC-Lookup-Platform/1.0"}
        if settings.nvd_api_key:
            headers["X-Api-Key"] = settings.nvd_api_key
        c = _get_http_client()
        r = await c.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            headers=headers,
        )
        if r.status_code != 200:
            return {}
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        cve_data = vulns[0].get("cve", {})
        metrics = cve_data.get("metrics", {})

        cvss_data = {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            group = metrics.get(key, [])
            if group:
                cvss_data = group[0].get("cvssData", {})
                break

        weaknesses = cve_data.get("weaknesses", [])
        cwe_list = []
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val:
                    cwe_list.append(val)

        refs = []
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            if url:
                refs.append(url)

        return {
            "vectorString": cvss_data.get("vectorString", ""),
            "baseScore": cvss_data.get("baseScore"),
            "baseSeverity": cvss_data.get("baseSeverity", ""),
            "cvssBreakdown": cvss_data,
            "cwe": cwe_list,
            "references": refs,
            "vulnerabilityStatus": cve_data.get("vulnStatus", ""),
            "publishedAt": cve_data.get("published"),
            "modifiedAt": cve_data.get("lastModified"),
        }
    except Exception:
        return {}


# ─── 5. XposedOrNot (free, no key — rate-limited, now parallel-safe) ─


_xon_semaphore = asyncio.Semaphore(5)


async def _xposedornot_lookup(email: str) -> BreachInfo | None:
    async with _xon_semaphore:
        for attempt in range(2):
            try:
                c = _get_http_client()
                r = await c.get(
                    f"https://api.xposedornot.com/v1/check-email/{email}?details=true",
                    timeout=5.0,
                )
                if r.status_code == 404:
                    return BreachInfo(breach_count=0, breach_names=[])
                if r.status_code == 429:
                    if attempt < 2:
                        await asyncio.sleep(1.5 * (attempt + 1))
                        continue
                    return None
                if r.status_code != 200:
                    return None
                data = r.json()
                breaches = data.get("breaches", [])
                if not breaches:
                    return BreachInfo(breach_count=0, breach_names=[])
                names: list[str] = []
                all_dates: list[str] = []
                all_exposed: list[str] = []
                for b in breaches:
                    # XposedOrNot has returned both object records and a
                    # compact nested list of breach names over time.
                    if isinstance(b, list):
                        names.extend(str(name) for name in b if name)
                        continue
                    if isinstance(b, str):
                        names.append(b)
                        continue
                    if not isinstance(b, dict):
                        continue
                    name = b.get("name", "")
                    if name:
                        names.append(name)
                    d = b.get("breach_date", "")
                    if d:
                        all_dates.append(d)
                    exposed = b.get("exposed_data", [])
                    if isinstance(exposed, list):
                        all_exposed.extend(exposed)
                all_dates.sort(reverse=True)
                return BreachInfo(
                    breach_count=len(names),
                    breach_names=names[:50],
                    most_recent_breach=all_dates[0] if all_dates else "",
                    exposed_data_types=list(dict.fromkeys(all_exposed)),
                    source="xposedornot",
                )
            except httpx.TimeoutException:
                return None
            except Exception:
                return None
    return None


# ─── 5c. ProxyNova Comb (best-effort fallback, unofficial — 5s timeout + label) ─


async def _proxynova_comb_lookup(email: str) -> BreachInfo | None:
    """Unofficial ProxyNova Comb endpoint. Best-effort fallback only — 5s timeout.

    Marked as proxynova_comb_unofficial so UI can label it stale/unofficial.
    """
    try:
        c = _get_http_client()
        r = await c.post(
            "https://proxynova.com/tools/comb/",
            data={"email": email},
            timeout=5,
        )
        if r.status_code != 200:
            return None
        try:
            payload = r.json()
        except Exception:
            return None
        records = payload.get("records", [])
        if not records:
            return BreachInfo(breach_count=0, breach_names=[])
        return BreachInfo(
            breach_count=len(records),
            breach_names=[f"proxynova_comb_{i+1}" for i in range(min(len(records), 50))],
            most_recent_breach="",
            source="proxynova_comb_unofficial",
        )
    except Exception:
        return None


# ─── 6. Favicon hash (mmh3) ────────────────────────


async def _favicon_hash(domain: str) -> FaviconInfo | None:
    try:
        favicon_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=64"
        c = _get_http_client()
        r = await c.get(favicon_url)
        if r.status_code == 200 and len(r.content) > 100:
            b64 = base64.b64encode(r.content).decode()
            hash_val = mmh3.hash(b64)
            return FaviconInfo(favicon_hash=hash_val, favicon_url=favicon_url)
        return None
    except Exception:
        return None


# ─── 7. SPF/DKIM/DMARC via DNS TXT ─────────────────


async def _dns_txt_query(name: str) -> list[str]:
    try:
        c = _get_http_client()
        r = await c.get(
            f"https://cloudflare-dns.com/dns-query?name={name}&type=TXT",
            headers={"Accept": "application/dns-json"},
        )
        if r.status_code != 200:
            return []
        data = r.json()
        answers = data.get("Answer", [])
        return [a.get("data", "").strip('"') for a in answers if a.get("type") == 16]
    except Exception:
        return []


async def _email_security(domain: str) -> EmailSecurityInfo | None:
    try:
        spf_records, dkim_records, dmarc_records = await asyncio.gather(
            _dns_txt_query(domain),
            _dns_txt_query(f"default._domainkey.{domain}"),
            _dns_txt_query(f"_dmarc.{domain}"),
            return_exceptions=True,
        )

        spf_records = spf_records if not isinstance(spf_records, Exception) else []
        dkim_records = dkim_records if not isinstance(dkim_records, Exception) else []
        dmarc_records = dmarc_records if not isinstance(dmarc_records, Exception) else []

        spf = "pass" if any(r.startswith("v=spf1") for r in spf_records) else "missing"
        dkim = "pass" if any("v=DKIM1" in r for r in dkim_records) else "missing"
        dmarc = "pass" if any(r.startswith("v=DMARC1") for r in dmarc_records) else "missing"

        return EmailSecurityInfo(spf=spf, dkim=dkim, dmarc=dmarc)
    except Exception:
        return None


def normalize_cve_enrichment(cve: CVEInfo, cve_id: str) -> NormalizedResult:
    # Enrichment is a vulnerability observation.  EPSS/KEV/CVSS are never
    # converted into a reputation verdict here; the vulnerability assessor
    # consumes the typed fields below.
    raw_score = None
    verdict = "unknown"
    confidence = "high" if (cve.cvss_score is not None or cve.epss_score is not None or cve.is_in_kev) else "low"
    tags: list[str] = []

    if cve.is_in_kev:
        tags.append("cisa_kev")
        if cve.kev_date_added:
            tags.append(f"kev_added:{cve.kev_date_added}")

    if (cve.epss_score or 0) > 0:
        if (cve.epss_percentile or 0) > 0:
            tags.append(f"epss_p{int((cve.epss_percentile or 0) * 100)}")

    if cve.cvss_vector:
        tags.append("cvss_scored")
        try:
            parts = cve.cvss_vector.split("/")
            for p in parts:
                if p.startswith("CVSS:") or p.startswith("3."):
                    continue
                if ":" in p and p.split(":")[0] in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
                    tags.append(p.replace(":", "_").lower())
        except Exception:
            pass

    if cve.cwe:
        tags.extend(f"cwe:{w.split(':')[-1].strip() if ':' in w else w}" for w in cve.cwe)

    categories = [w.split(":")[-1].strip() if ":" in w else w for w in cve.cwe if w]

    return NormalizedResult(
        ioc=cve_id,
        ioc_type="cve",
        source="CVE",
        verdict=verdict,
        assessment_domain="vulnerability",
        provider_verdict="vulnerability_record",
        normalized_verdict="unknown",
        raw_score=raw_score,
        confidence=confidence,
        tags=tags,
        categories=categories,
        source_link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        vulnerability_status=cve.vulnerability_status,
        severity=(cve.cvss_severity or "informational").lower(),
        cvss_score=cve.cvss_score,
        cvss_vector=cve.cvss_vector or None,
        epss_score=cve.epss_score,
        cwe=list(cve.cwe),
        affected_products=list(cve.affected_products),
        published_at=cve.published_at,
        modified_at=cve.modified_at,
        exploit_status="known_exploited" if cve.is_in_kev else cve.exploit_status,
        references=list(cve.references),
        source_record_id=cve_id,
        source_independence_group="cve_record",
        raw_data={
            "cve_id": cve_id,
            "vulnerability_status": cve.vulnerability_status,
            "severity": (cve.cvss_severity or "informational").lower(),
            "cvss_score": cve.cvss_score,
            "cvss_vector": cve.cvss_vector,
            "epss_score": cve.epss_score,
            "cwe": list(cve.cwe),
            "affected_products": list(cve.affected_products),
            "published_at": cve.published_at,
            "modified_at": cve.modified_at,
            "exploit_status": "known_exploited" if cve.is_in_kev else cve.exploit_status,
            "references": list(cve.references),
        },
    )
