import pytest

from app.backend import enrichment


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_ssdeep_enrichment_is_structured():
    result = await enrichment.enrich("3:abc:def", "ssdeep")

    assert result.completeness["structural_analysis"] == "ok"
    assert result.extra["ssdeep"]["block_size"] == 3
    assert result.extra["ssdeep"]["first_chunk_length"] == 3


@pytest.mark.asyncio
async def test_host_artifact_enrichment_is_structured():
    result = await enrichment.enrich(r"\\host\pipe\mypipe", "named_pipe")

    assert result.extra["host_artifact"]["server"] == "host"
    assert result.extra["host_artifact"]["pipe_name"] == "mypipe"
    assert result.completeness["threat_corpus"] == "unavailable"


@pytest.mark.asyncio
async def test_btc_enrichment_returns_public_address_details(monkeypatch):
    class Client:
        async def get(self, url, **_kwargs):
            assert "blockchain.info/rawaddr/" in url
            return FakeResponse(payload={
                "hash160": "abc",
                "n_tx": 2,
                "total_received": 250000000,
                "total_sent": 100000000,
                "final_balance": 150000000,
                "txs": [{"hash": "tx1", "time": 1700000000, "result": 150000000}],
            })

    monkeypatch.setattr(enrichment, "_get_http_client", lambda: Client())
    result = await enrichment.enrich("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "btc")

    assert result.completeness["blockchain_address"] == "ok"
    assert result.extra["bitcoin"]["final_balance_btc"] == 1.5
    assert result.extra["bitcoin"]["recent_transactions"][0]["hash"] == "tx1"


@pytest.mark.asyncio
async def test_asn_enrichment_returns_holder_and_prefixes(monkeypatch):
    class Client:
        async def get(self, url, **_kwargs):
            if "as-overview" in url:
                return FakeResponse(payload={"data": {"holder": "Google LLC", "block": {"resource": "AS15169"}}})
            return FakeResponse(payload={"data": {"prefixes": [{"prefix": "8.8.8.0/24"}]}})

    monkeypatch.setattr(enrichment, "_get_http_client", lambda: Client())
    result = await enrichment.enrich("AS15169", "asn")

    assert result.completeness["ripestat"] == "ok"
    assert result.extra["asn"]["holder"] == "Google LLC"
    assert result.extra["asn"]["announced_prefix_count"] == 1


@pytest.mark.asyncio
async def test_mitre_enrichment_returns_public_page_metadata(monkeypatch):
    class Client:
        async def get(self, url, **_kwargs):
            assert url.endswith("/techniques/T1059/")
            return FakeResponse(text='<title>Command and Scripting Interpreter</title><meta name="description" content="Adversaries may abuse command interpreters.">')

    monkeypatch.setattr(enrichment, "_get_http_client", lambda: Client())
    result = await enrichment.enrich("T1059", "mitre_attack")

    assert result.completeness["mitre_attack"] == "ok"
    assert result.extra["mitre_attack"]["title"] == "Command and Scripting Interpreter"
    assert "command interpreters" in result.extra["mitre_attack"]["description"]
