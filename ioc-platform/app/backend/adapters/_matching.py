"""Exact indicator matching for search-based provider APIs.

Search endpoints (ThreatFox ``search_ioc``, urlscan.io search, OTX pulses,
sandbox searches, ...) return records that merely *mention* or *relate to*
the query: a URL on a subdomain, a parent domain, an ``ip:port`` pair, a
scan that redirected to the queried page.  A verdict may only be taken from
a record whose indicator is the queried IOC.  Everything else is at most
context/relationship data.

Normalization is deliberately conservative:

* hashes: case-insensitive
* domains: case-insensitive, trailing root dot ignored
* IPs: canonical ``ipaddress`` form (so IPv6 compression does not matter)
* URLs: scheme and host case-insensitive, ``http``/``https`` and a missing
  scheme treated alike, default ports dropped, fragment dropped, a trailing
  ``/`` on the path ignored.  Path and query stay case-sensitive.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

_HASH_TYPES = {"md5", "sha1", "sha256", "sha512", "ssdeep", "tlsh"}
_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_domain(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def normalize_ip(value: str) -> str:
    text = str(value or "").strip().strip("[]")
    try:
        return str(ipaddress.ip_address(text.split("%", 1)[0]))
    except ValueError:
        return text.lower()


def normalize_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = f"http://{text}"
    try:
        parts = urlsplit(text)
        host = normalize_domain(parts.hostname or "")
        port = parts.port
    except ValueError:
        return text.lower().rstrip("/")
    scheme = parts.scheme.lower()
    if scheme in {"http", "https"}:
        # The same resource served over http and https is the same IOC for
        # reputation purposes; phishing feeds routinely drop the scheme.
        if port == _DEFAULT_PORTS.get(scheme):
            port = None
        scheme = "http"
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    path = parts.path.rstrip("/")
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def normalize_indicator(value: str, ioc_type: str) -> str:
    if ioc_type in _HASH_TYPES:
        return str(value or "").strip().lower()
    if ioc_type == "domain":
        return normalize_domain(value)
    if ioc_type in {"ipv4", "ipv6"}:
        return normalize_ip(value)
    if ioc_type == "url":
        return normalize_url(value)
    if ioc_type == "email":
        return str(value or "").strip().lower()
    return str(value or "").strip()


def indicator_equals(candidate: str, target: str, ioc_type: str) -> bool:
    """True only when ``candidate`` *is* the queried indicator."""
    if not candidate or not target:
        return False
    return normalize_indicator(candidate, ioc_type) == normalize_indicator(target, ioc_type)


def host_of(value: str) -> str:
    """Hostname of a URL, ``host:port`` pair or bare host (lower-case)."""
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        try:
            return normalize_domain(urlsplit(text).hostname or "")
        except ValueError:
            return ""
    if text.startswith("["):
        return normalize_ip(text.split("]", 1)[0])
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return normalize_domain(text.split("/", 1)[0])


def ip_port_equals(candidate: str, target_ip: str) -> bool:
    """ThreatFox-style ``ip:port`` records describe the IP itself."""
    text = str(candidate or "").strip()
    if not text:
        return False
    if text.startswith("["):
        host = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        host = text.split(":", 1)[0]
    else:
        host = text
    return normalize_ip(host) == normalize_ip(target_ip)
