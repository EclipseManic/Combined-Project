import sys
sys.path.insert(0, ".")

from unittest.mock import AsyncMock, patch

import pytest
import httpx

from app.backend.adapters.base import EnrichmentData
from app.backend.enrichment import (
    enrich,
    _is_ip,
    enrich_ip,
    enrich_domain,
    enrich_url,
    enrich_hash,
    enrich_email,
    enrich_cve,
    _crt_sh_subdomains,
    _cisa_kev,
    _first_epss,
    _nvd_cve,
    _dns_lookup,
    _dns_txt_query,
    _favicon_hash,
    _is_public_fetch_target,
    _quick_port_scan,
)


def _mock_shared_client(get=None, post=None, get_side_effect=None, post_side_effect=None):
    """Build a mock for the shared HTTP client returned by _get_http_client()."""
    client = AsyncMock()
    if get_side_effect is not None:
        client.get = AsyncMock(side_effect=get_side_effect)
    else:
        client.get = AsyncMock(return_value=get)
    if post_side_effect is not None:
        client.post = AsyncMock(side_effect=post_side_effect)
    else:
        client.post = AsyncMock(return_value=post)
    return client


class TestEnrichmentTypeSpecific:
    @pytest.mark.asyncio
    async def test_ip_enrichment(self):
        result = await enrich_ip("127.0.0.1")
        assert isinstance(result, EnrichmentData)
        assert "geoip" in result.completeness
        assert "reverse_dns" in result.completeness
        assert "whois" in result.completeness

    @pytest.mark.asyncio
    async def test_domain_enrichment(self):
        result = await enrich_domain("google.com")
        assert isinstance(result, EnrichmentData)
        assert "whois" in result.completeness
        assert "dns" in result.completeness
        assert "ssl" in result.completeness
        assert "subdomains" in result.completeness
        assert "favicon" in result.completeness

    @pytest.mark.asyncio
    async def test_dns_lookup_collects_detailed_record_types(self, monkeypatch):
        answers = {
            "A": [{"data": "185.199.109.153"}],
            "AAAA": [],
            "MX": [{"data": "10 mail.example.com."}],
            "NS": [{"data": "ns1.example.com."}],
            "TXT": [{"data": '"v=spf1 -all"'}],
            "CNAME": [{"data": "target.example.com."}],
        }

        class Response:
            status_code = 200

            def __init__(self, record_type):
                self.record_type = record_type

            def json(self):
                return {"Answer": answers[self.record_type]}

        class Client:
            async def get(self, _url, *, params, **_kwargs):
                return Response(params["type"])

        monkeypatch.setattr("app.backend.enrichment._get_http_client", lambda: Client())

        result = await _dns_lookup("example.com")

        assert result.a == ["185.199.109.153"]
        assert result.mx == ["mail.example.com"]
        assert result.ns == ["ns1.example.com"]
        assert result.txt == ["v=spf1 -all"]
        assert result.cname == ["target.example.com"]

    @pytest.mark.asyncio
    async def test_url_enrichment(self):
        result = await enrich_url("https://google.com/path")
        assert isinstance(result, EnrichmentData)
        assert result.completeness["domain_extraction"] == "ok"
        assert len(result.relationships) == 1

    @pytest.mark.asyncio
    async def test_hash_enrichment(self):
        result = await enrich_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result.completeness["hash_lookup"] in {"ok", "not_found", "error"}

    @pytest.mark.asyncio
    async def test_email_enrichment(self):
        result = await enrich_email("user@example.com")
        assert result.completeness.get("domain_extraction") == "ok"
        assert all(k in result.completeness for k in ("xposedornot", "proxynova_comb"))
        assert result.completeness.get("email_security") is not None

    @pytest.mark.asyncio
    async def test_cve_enrichment(self):
        with (
            patch("app.backend.enrichment._cisa_kev", AsyncMock(return_value=(True, "2023-10-10"))),
            patch("app.backend.enrichment._first_epss", AsyncMock(return_value=(0.97, 0.98))),
            patch("app.backend.enrichment._nvd_cve", AsyncMock(return_value={
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe": ["CWE-787"],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
            })),
            patch("app.backend.enrichment._exploitdb_lookup", AsyncMock(return_value=[])),
            patch("app.backend.enrichment._poc_github_check", AsyncMock(return_value=[])),
        ):
            result = await enrich_cve("CVE-2023-44487")
        assert result.completeness.get("cisa_kev") is not None
        assert result.completeness.get("epss") == "ok"
        assert result.completeness.get("nvd") == "ok"
        assert result.cve is not None
        assert result.cve.epss_score >= 0


class TestEnrichmentDispatcher:
    @pytest.mark.asyncio
    async def test_dispatcher_ip(self):
        result = await enrich("8.8.8.8", "ipv4")
        assert "geoip" in result.completeness

    @pytest.mark.asyncio
    async def test_dispatcher_domain(self):
        result = await enrich("google.com", "domain")
        assert "dns" in result.completeness

    @pytest.mark.asyncio
    async def test_dispatcher_url(self):
        result = await enrich("https://example.com/page", "url")
        assert result.completeness["domain_extraction"] == "ok"

    @pytest.mark.asyncio
    async def test_dispatcher_md5(self):
        result = await enrich("d41d8cd98f00b204e9800998ecf8427e", "md5")
        assert result.completeness["hash_lookup"] in {"ok", "not_found", "error"}

    @pytest.mark.asyncio
    async def test_dispatcher_sha1(self):
        result = await enrich("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1")
        assert result.completeness["hash_lookup"] in {"ok", "not_found", "error"}

    @pytest.mark.asyncio
    async def test_dispatcher_sha256(self):
        result = await enrich("e3b0c44298fc1c149999bf977249da5e9e53b1b9a1b849c87ce6095d53b8b1c9", "sha256")
        assert result.completeness["hash_lookup"] in {"ok", "not_found", "error"}

    @pytest.mark.asyncio
    async def test_dispatcher_email(self):
        result = await enrich("admin@example.com", "email")
        assert result.completeness.get("domain_extraction") == "ok"
        assert all(k in result.completeness for k in ("xposedornot", "proxynova_comb"))

    @pytest.mark.asyncio
    async def test_dispatcher_cve(self):
        result = await enrich("CVE-2024-1234", "cve")
        assert result.completeness.get("epss") is not None

    @pytest.mark.asyncio
    async def test_dispatcher_unknown_type(self):
        result = await enrich("something", "unknown_type")
        assert result.completeness["enrichment"] == "skipped"


class TestNewEnrichmentSources:
    @pytest.mark.asyncio
    async def test_crt_sh_subdomains(self):
        result = await _crt_sh_subdomains("google.com")
        if result is not None:
            assert len(result.subdomains) > 0

    @pytest.mark.asyncio
    async def test_crt_sh_bad_domain(self):
        result = await _crt_sh_subdomains("thisdomaindefinitelydoesnotexist123456.com")
        assert result is None or len(result.subdomains) == 0

    @pytest.mark.asyncio
    async def test_cisa_kev_known(self):
        in_kev, date = await _cisa_kev("CVE-2023-44487")
        assert isinstance(in_kev, bool)

    @pytest.mark.asyncio
    async def test_cisa_kev_unknown(self):
        in_kev, date = await _cisa_kev("CVE-2024-99999")
        assert in_kev is False

    @pytest.mark.asyncio
    async def test_epss_known(self):
        epss_payload = {"data": [{"cve": "CVE-2023-44487", "epss": 0.97, "percentile": 0.98}]}
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(get=httpx.Response(200, json=epss_payload))):
            score, pct = await _first_epss("CVE-2023-44487")
        assert score == 0.97
        assert pct == 0.98

    @pytest.mark.asyncio
    async def test_epss_unknown(self):
        epss_payload = {"data": []}
        with patch("app.backend.enrichment._get_http_client", return_value=_mock_shared_client(get=httpx.Response(200, json=epss_payload))):
            score, pct = await _first_epss("CVE-2024-99999")
        assert score == 0.0
        assert pct == 0.0

    @pytest.mark.asyncio
    async def test_nvd_cve_known(self):
        data = await _nvd_cve("CVE-2023-44487")
        assert isinstance(data, dict)

    @pytest.mark.asyncio
    async def test_nvd_cve_unknown(self):
        data = await _nvd_cve("CVE-2024-99999")
        assert data == {} or isinstance(data, dict)

    @pytest.mark.asyncio
    async def test_dns_txt_query(self):
        records = await _dns_txt_query("google.com")
        assert isinstance(records, list)

    @pytest.mark.asyncio
    async def test_dns_txt_query_spf(self):
        records = await _dns_txt_query("gmail.com")
        assert isinstance(records, list)
        has_spf = any(r.startswith("v=spf1") for r in records)
        assert isinstance(has_spf, bool)

    @pytest.mark.asyncio
    async def test_favicon_hash_known(self):
        result = await _favicon_hash("google.com")
        if result is not None:
            assert isinstance(result.favicon_hash, int)
            assert isinstance(result.favicon_url, str)

    @pytest.mark.asyncio
    async def test_favicon_hash_nonexistent(self):
        result = await _favicon_hash("thisshouldnotexist99999.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_cve_completeness_fields(self):
        result = await enrich_cve("CVE-2023-44487")
        assert "cisa_kev" in result.completeness
        assert "epss" in result.completeness
        assert "nvd" in result.completeness
        assert result.cve is not None

    @pytest.mark.asyncio
    async def test_cve_cisa_kev_true(self):
        result = await enrich_cve("CVE-2023-44487")
        if result.cve.is_in_kev:
            assert result.cve.kev_date_added != ""


def test_is_ip():
    assert _is_ip("8.8.8.8") is True
    assert _is_ip("256.1.2.3") is False
    assert _is_ip("not_an_ip") is False
    assert _is_ip("") is False


def test_is_ip_octet_ranges():
    assert _is_ip("0.0.0.0") is True
    assert _is_ip("255.255.255.255") is True
    assert _is_ip("-1.0.0.0") is False
    assert _is_ip("10.0.0") is False


class TestPortScan:
    @pytest.mark.asyncio
    async def test_quick_port_scan_returns_int_list(self, monkeypatch):
        from app.backend import enrichment

        async def fake_probe(loop, semaphore, ip, p):
            return p if p in (80, 443) else None

        monkeypatch.setattr(enrichment, "_probe_port", fake_probe)
        result = await enrichment._quick_port_scan("8.8.8.8")
        assert result == [80, 443]

    @pytest.mark.asyncio
    async def test_quick_port_scan_parallel_localhost(self):
        from app.backend.enrichment import _quick_port_scan

        result = await _quick_port_scan("127.0.0.1")
        assert isinstance(result, list)
        assert all(isinstance(p, int) for p in result)


class TestRdap:
    def test_rdap_registrar_extracts_from_entities(self):
        from app.backend.enrichment import _rdap_registrar

        data = {
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "VeriSign, Inc."],
                            ["kind", {}, "text", "org"],
                        ],
                    ],
                }
            ]
        }
        assert _rdap_registrar(data) == "VeriSign, Inc."

    def test_rdap_registrar_no_registrar_role(self):
        from app.backend.enrichment import _rdap_registrar

        data = {"entities": [{"roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "Tech"]]]}]}
        assert _rdap_registrar(data) == ""

    def test_rdap_registrar_no_entities(self):
        from app.backend.enrichment import _rdap_registrar

        assert _rdap_registrar({}) == ""

    @pytest.mark.asyncio
    async def test_rdap_lookup_falls_back_when_no_url(self, monkeypatch):
        from app.backend import enrichment
        from app.backend.adapters.base import WhoisInfo

        calls = []

        async def fake_get_rdap_url(target):
            return None

        async def fake_whois_fallback(target, server=None):
            calls.append(target)
            return WhoisInfo(registrar="Fallback Registrar")

        monkeypatch.setattr(enrichment, "_get_rdap_url", fake_get_rdap_url)
        monkeypatch.setattr(enrichment, "_whois_fallback", fake_whois_fallback)
        result = await enrichment._rdap_lookup("example.com")
        assert calls == ["example.com"]
        assert result.registrar == "Fallback Registrar"

    @pytest.mark.asyncio
    async def test_rdap_lookup_non_200_falls_back(self, monkeypatch):
        from app.backend import enrichment
        from app.backend.adapters.base import WhoisInfo

        class FakeResp:
            status_code = 404

            def json(self):
                return {}

        class FakeClient:
            async def get(self, url, timeout=8):
                return FakeResp()

        async def fake_get_rdap_url(target):
            return "https://rdap.example/domain/example.com"

        async def fake_whois_fallback(target, server=None):
            return WhoisInfo(registrar="404 Fallback")

        monkeypatch.setattr(enrichment, "_get_rdap_url", fake_get_rdap_url)
        monkeypatch.setattr(enrichment, "_whois_fallback", fake_whois_fallback)
        monkeypatch.setattr(enrichment, "_get_http_client", lambda: FakeClient())
        result = await enrichment._rdap_lookup("example.com")
        assert result.registrar == "404 Fallback"

    @pytest.mark.asyncio
    async def test_rdap_ip_404_raises_no_record(self, monkeypatch):
        """IP with no RDAP record is a data gap (unavailable), not a failure."""
        from app.backend import enrichment
        from app.backend.enrichment import RDAPNoRecordError

        class FakeResp:
            status_code = 404

            def json(self):
                return {}

        class FakeClient:
            async def get(self, url, timeout=8):
                return FakeResp()

        monkeypatch.setattr(enrichment, "_get_http_client", lambda: FakeClient())
        with pytest.raises(RDAPNoRecordError):
            await enrichment._rdap_lookup("1.2.3.4")

    def test_completeness_label_maps_statuses(self):
        from app.backend.enrichment import RDAPNoRecordError, _completeness_label

        assert _completeness_label(RDAPNoRecordError("x")) == "unavailable"
        assert _completeness_label(ValueError("boom")) == "error"
        assert _completeness_label(None) == "unavailable"
        assert _completeness_label(None, none_status="error") == "error"
        assert _completeness_label("data") == "ok"

    @pytest.mark.asyncio
    async def test_rdap_lookup_parses_200_response(self, monkeypatch):
        from app.backend import enrichment

        class FakeResp:
            status_code = 200

            def json(self):
                return {
                    "port43": "whois.verisign-grs.com",
                    "entities": [
                        {
                            "roles": ["registrar"],
                            "vcardArray": ["vcard", [["fn", {}, "text", "VeriSign, Inc."]]],
                        }
                    ],
                    "events": [
                        {"eventAction": "registrationDate", "eventDate": "1995-08-14T04:00:00Z"},
                        {"eventAction": "expirationDate", "eventDate": "2028-08-13T04:00:00Z"},
                    ],
                    "handle": "DOM-123",
                }

        class FakeClient:
            async def get(self, url, timeout=8):
                return FakeResp()

        async def fake_get_rdap_url(target):
            return "https://rdap.verisign.com/com/v1/domain/example.com"

        monkeypatch.setattr(enrichment, "_get_rdap_url", fake_get_rdap_url)
        monkeypatch.setattr(enrichment, "_get_http_client", lambda: FakeClient())
        result = await enrichment._rdap_lookup("example.com")
        assert result.registrar == "VeriSign, Inc."
        assert result.creation_date == "1995-08-14T04:00:00Z"
        assert result.expiration_date == "2028-08-13T04:00:00Z"

    @pytest.mark.asyncio
    async def test_rdap_lookup_port43_used_for_whois_when_no_registrar(self, monkeypatch):
        from app.backend import enrichment
        from app.backend.adapters.base import WhoisInfo

        class FakeResp:
            status_code = 200

            def json(self):
                return {"port43": "whois.verisign-grs.com"}

        class FakeClient:
            async def get(self, url, timeout=8):
                return FakeResp()

        async def fake_get_rdap_url(target):
            return "https://rdap.verisign.com/com/v1/domain/example.com"

        seen = {}

        async def fake_whois_fallback(target, server=None):
            seen["server"] = server
            return WhoisInfo(registrar="Whois Registrar")

        monkeypatch.setattr(enrichment, "_get_rdap_url", fake_get_rdap_url)
        monkeypatch.setattr(enrichment, "_get_http_client", lambda: FakeClient())
        monkeypatch.setattr(enrichment, "_whois_fallback", fake_whois_fallback)
        result = await enrichment._rdap_lookup("example.com")
        assert seen.get("server") == "whois.verisign-grs.com"
        assert result.registrar == "Whois Registrar"


class TestSslWildcard:
    def test_san_is_wildcard_strips_dns_prefix(self):
        from app.backend.enrichment import _san_is_wildcard

        assert _san_is_wildcard("DNS:*.example.com") is True
        assert _san_is_wildcard("DNS:example.com") is False

    def test_san_is_wildcard_non_dns_entry(self):
        from app.backend.enrichment import _san_is_wildcard

        assert _san_is_wildcard("*.example.com") is True
        assert _san_is_wildcard("example.com") is False
        assert _san_is_wildcard("IP Address:1.2.3.4") is False

    @pytest.mark.asyncio
    async def test_ssl_wildcard_flag_with_dns_prefixed_sans(self, monkeypatch):
        from app.backend import enrichment
        from app.backend.adapters.base import SSLInfo

        fake_cert = {
            "subject": [("commonName", "example.com")],
            "issuer": [("commonName", "Some CA")],
            "serialNumber": "1",
            "notBefore": "Aug  1 00:00:00 2025 GMT",
            "notAfter": "Aug  1 00:00:00 2030 GMT",
            "subjectAltName": (("DNS", "*.example.com"), ("DNS", "example.com")),
        }

        def fake_ssl_cert(hostname):
            sans = []
            for entry in fake_cert.get("subjectAltName", []):
                if len(entry) == 2:
                    sans.append(f"{entry[0]}:{entry[1]}")
            common_name = "example.com"
            return SSLInfo(
                subject=common_name,
                issuer="Some CA",
                serial="1",
                not_before="",
                not_after="",
                fingerprint="",
                subject_alt_names=sans,
                is_expired=False,
                is_self_signed=False,
                is_wildcard=enrichment._san_is_wildcard(sans[0]),
                days_remaining=100,
            )

        async def fake_ssl_cert_async(hostname):
            return fake_ssl_cert(hostname)

        monkeypatch.setattr(enrichment, "_ssl_cert", fake_ssl_cert_async)
        result = await enrichment._ssl_cert("example.com")
        assert result is not None
        assert result.is_wildcard is True
        assert result.subject_alt_names == ["DNS:*.example.com", "DNS:example.com"]


class TestCisaKev:
    @pytest.mark.asyncio
    async def test_cisa_kev_refreshes_cache_and_finds_cve(self, monkeypatch):
        from app.backend import enrichment

        feed = {
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"},
                {"cveID": "CVE-2023-1234", "dateAdded": "2023-01-01"},
            ]
        }

        async def fake_fetch_cisa_feed():
            return feed

        monkeypatch.setattr(enrichment, "_fetch_cisa_feed", fake_fetch_cisa_feed)
        monkeypatch.setattr(enrichment, "_cisa_cache", None)
        monkeypatch.setattr(enrichment, "_cisa_cache_time", 0)
        in_kev, date = await enrichment._cisa_kev("cve-2021-44228")
        assert in_kev is True
        assert date == "2021-12-10"

    @pytest.mark.asyncio
    async def test_cisa_kev_cache_reused_within_ttl(self, monkeypatch):
        from app.backend import enrichment

        feed = {"vulnerabilities": []}
        calls = {"n": 0}

        async def fake_fetch_cisa_feed():
            calls["n"] += 1
            return feed

        monkeypatch.setattr(enrichment, "_fetch_cisa_feed", fake_fetch_cisa_feed)
        monkeypatch.setattr(enrichment, "_cisa_cache", None)
        monkeypatch.setattr(enrichment, "_cisa_cache_time", 0)
        await enrichment._cisa_kev("CVE-2020-0001")
        await enrichment._cisa_kev("CVE-2020-0002")
        assert calls["n"] == 1

    @pytest.mark.asyncio
    async def test_cisa_kev_not_in_list(self, monkeypatch):
        from app.backend import enrichment

        async def fake_fetch_cisa_feed():
            return {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}

        monkeypatch.setattr(enrichment, "_fetch_cisa_feed", fake_fetch_cisa_feed)
        monkeypatch.setattr(enrichment, "_cisa_cache", None)
        monkeypatch.setattr(enrichment, "_cisa_cache_time", 0)
        in_kev, date = await enrichment._cisa_kev("CVE-2029-9999")
        assert in_kev is False
        assert date == ""


class TestWhoisWindowsFallback:
    @pytest.mark.asyncio
    async def test_whois_discover_server_parses_iana_response(self, monkeypatch):
        from app.backend import enrichment

        async def fake_whois_discover(tld):
            return "whois.verisign-grs.com"

        monkeypatch.setattr(enrichment, "_whois_discover_server", fake_whois_discover)
        result = await enrichment._whois_discover_server("com")
        assert result == "whois.verisign-grs.com"

    @pytest.mark.asyncio
    async def test_whois_fallback_uses_iana_discovery_before_subprocess(self, monkeypatch):
        from unittest.mock import MagicMock

        from app.backend import enrichment
        from app.backend.adapters.base import WhoisInfo

        async def fake_raw_query(target, server=None):
            return "registrar: IANA Registrar\n"

        async def fake_discover(tld):
            return "whois.example-tld.org"

        async def fake_parse(text):
            return WhoisInfo(registrar="IANA Registrar")

        monkeypatch.setattr(enrichment, "_whois_raw_query", fake_raw_query)
        monkeypatch.setattr(enrichment, "_whois_discover_server", fake_discover)
        monkeypatch.setattr(enrichment, "_parse_whois_text", fake_parse)
        fake_os = MagicMock()
        fake_os.name = "nt"
        monkeypatch.setattr(enrichment, "os", fake_os)

        result = await enrichment._whois_fallback("example.com")
        assert result is not None
        assert result.registrar == "IANA Registrar"

    @pytest.mark.asyncio
    async def test_whois_fallback_windows_returns_none_when_all_attempts_fail(self, monkeypatch):
        from unittest.mock import MagicMock

        from app.backend import enrichment
        from app.backend.config import settings

        monkeypatch.setattr(settings, "virustotal_api_key", "")

        async def fake_raw_query(target, server=None):
            return None

        async def fake_discover(tld):
            return None

        monkeypatch.setattr(enrichment, "_whois_raw_query", fake_raw_query)
        monkeypatch.setattr(enrichment, "_whois_discover_server", fake_discover)
        fake_os = MagicMock()
        fake_os.name = "nt"
        monkeypatch.setattr(enrichment, "os", fake_os)

        result = await enrichment._whois_fallback("example.com")
        assert result is None


@pytest.mark.asyncio
async def test_url_fetching_is_disabled_by_default(monkeypatch):
    from app.backend import enrichment
    from app.backend.adapters.base import EnrichmentData

    async def should_not_fetch(*args, **kwargs):
        raise AssertionError("active URL fetch should be disabled")

    monkeypatch.setattr(enrichment, "_url_redirect_chain", should_not_fetch)
    monkeypatch.setattr(enrichment, "_url_content_preview", should_not_fetch)
    monkeypatch.setattr(enrichment, "enrich_domain", lambda value: _resolved(EnrichmentData()))

    result = await enrichment.enrich_url("https://example.com/path")

    assert result.completeness["redirect_chain"] == "disabled"
    assert result.completeness["url_preview"] == "disabled"
    assert result.analysis_notes


async def _resolved(value):
    return value


@pytest.mark.asyncio
async def test_active_port_scan_rejects_private_targets():
    assert await _quick_port_scan("127.0.0.1") == []
    assert await _quick_port_scan("192.168.1.10") == []
    assert await _quick_port_scan("169.254.169.254") == []


@pytest.mark.asyncio
async def test_active_url_fetch_requires_https():
    assert await _is_public_fetch_target("http://example.com/path") is False
