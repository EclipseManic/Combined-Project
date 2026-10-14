"""Etherscan address-page parsing and the enrich_eth merge.

The fixture below is a trimmed copy of the real etherscan.io address page
markup (Ronin Bridge Exploiter, captured 2026-09-29): only the elements the
parser reads are kept, with their original ids/classes/attributes.
"""

import pytest

from app.backend import enrichment, etherscan_page
from app.backend.config import settings
from app.backend.etherscan_page import EtherscanPageUnavailable, parse_address_page

SELF = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
FUNDER = "0x4976A4A02f38326660D17bf34b431dC6e2eb2327"
PHISHER = "0x087238209BaC1D2985b12d7A4bE5bd75daA17243"
TX1 = "0x1b25e6ad8a3344a18a23cffeda2759e8e7d7848115d7196045a5cff0ad2c77fa"
TX2 = "0x3ea22b4718f60851bdf4e54a2529bf9759775a419d7d8343f1b4381b2e151796"

PAGE = f"""
<html><head><title>Ronin Bridge Exploiter | Address: 0x098B716B...2383E2f96 | Etherscan</title></head>
<body><main id="content"><section class="container-xxl">
  <div class="d-flex"><h1 class="h5">Address</h1>
    <span id="mainaddress">{SELF}</span>
  </div>
  <div class="d-flex flex-wrap align-items-center gap-1">
    <div class="d-flex flex-wrap align-items-center gap-1">
      <span class="badge bg-secondary rounded-pill" title="Public Name Tag (viewable by anyone) &lt;br/&gt; Ronin Bridge Exploiter"><div class="d-flex"><span class="hash-tag">Ronin Bridge Exploiter</span></div></span>
      <span class="badge bg-danger"><div class="d-flex"><span class="hash-tag">Exploit</span></div></span>
      <a class="badge bg-secondary" href="/accounts/label/ofac-sanctioned"><div class="d-flex gap-1">OFAC-Sanctioned</div></a>
      <a class="badge bg-secondary" href="/accounts/label/blocked" title="This address has been blocked by a custodial stablecoin provider."><div class="d-flex gap-1">Blocked</div></a>
    </div>
    <span class="badge">Beta</span>
  </div>
</section>
<div class="container-xxl"><div class="alert alert-danger alert-dismissible fade show mb-3">This address is reported to be involved in a hack targeting the <a href="#">Ronin bridge</a> .</div></div>
<div class="modal fade" id="myModalCompilerWarning"><div class="modal-body"><div class="alert alert-warning">Compiler specific version warnings</div></div></div>
<div class="card-body">
  <div><h4 class="text-cap mb-1">ETH Balance</h4><div><div class="d-flex">101<span>.</span>80248678376705535 ETH</div></div></div>
  <div><h4 class="text-cap mb-1">
      Eth Value
    </h4>$271,933.78 <span class="small">(@ $2,671.19/ETH)</span></div>
  <div><h4 class="text-cap mb-1">Token Holdings</h4>
    <button id="dropdownMenuBalance">$0.01 <span>(40 Tokens)</span></button>
    <ul class="list">
      <li class="nav-item list-custom-divider-ERC20">ERC-20 Tokens (2)
      <li class="nav-item list-custom-ERC20"><a class="nav-link" href="/token/0x3301ee63fb29f863f2333bd4466acb46cd8323e6?a={SELF}">
        <div><div class="d-flex"><span class="list-name hash-tag"><span>Akita Inu (AKITA)</span></span></div><span class="text-muted">13,300,000 AKITA</span></div>
        <div class="text-end"><div class="list-usd-value">$0.00</div><div class="list-usd-rate small text-muted">@0.0001</div></div></a></li>
      <li class="nav-item list-custom-ERC20"><a class="nav-link" href="/token/0x59d1e836f7b7210a978b25a855085cc46fd090b5?a={SELF}">
        <div><div class="d-flex"><span class="list-name hash-tag"><span>AssangeDAO ( JUSTICE )</span></span></div><span class="text-muted">100 JUSTICE</span></div>
        <div class="text-end"><div class="list-usd-value">$0.01</div></div></a></li>
    </ul>
  </div>
</div>
<div class="card-body">
  <div><h4 class="text-cap mb-1">Multichain Info</h4>
    <div><a id="multichain-button" href="#">$271,954.63 (Multichain Portfolio)</a></div>
    <div>2 addresses found via Blockscan</div>
  </div>
  <div><span>Net Worth in ETH</span><span>101<span>.</span>810292</span></div>
  <div class="js-chain col-6" data-chain="ETH"><a class="card"><div class="d-flex"><span class="text-muted small">Ethereum <span class="text-muted">(1)</span></span></div>
    <div><div class="text-dark">$271,934 <span class="text-muted small">(100%)</span></div></div></a></div>
  <div class="js-chain col-6" data-chain="BSC"><a class="card"><div class="d-flex"><span class="text-muted small">BNB Chain <span class="text-muted">(4)</span></span></div>
    <div><div class="text-dark">$15 <span class="text-muted small">(&lt;1%)</span></div></div></a></div>
  <div class="js-chain col-6" data-chain="OP"><a class="card"><div class="d-flex"><span class="text-muted small">Optimism <span class="text-muted">(0)</span></span></div>
    <div><div class="text-dark">0 <span class="text-muted small">(0%)</span></div></div></a></div>
</div>
<div class="card-body">
  <div><h4 class="text-cap mb-1">Transactions Sent</h4><div class="d-flex">
    <div><span class="text-muted">Latest:</span><a href="/tx/0x{'c' * 64}"><span>3 yrs 191 days ago</span></a></div>
    <div><span class="text-muted">First:</span><a href="/tx/0x{'d' * 64}"><span>4 yrs 189 days ago</span></a></div>
  </div></div>
  <div><h4 class="text-cap mb-1">Funded By</h4>
    <div id="conFundedMainChain"><a href="/address/{FUNDER}"><span title="Binance 20">Binance 20</span></a><span>|</span>
      <a href="/tx/0x{'e' * 64}"><span>4 yrs 189 days ago</span></a></div></div>
</div>
<div id="ContentPlaceHolder1_divTxDataInfo"><p>Latest 25 from a total of <a href="/txs?a={SELF}">430</a> transactions (+ <a href="#">1 Pending</a> )</p></div>
<div id="transactions"><table><thead><tr><th></th><th>Transaction Hash</th></tr></thead><tbody>
  <tr><td></td><td><a class="hash-tag" href="/tx/{TX1}">{TX1}</a></td>
    <td class="td_functionNameOri"><span class="badge" title="Transfer">Transfer</span></td>
    <td class="td_functionNameCustom"><span class="badge">Transfer</span></td>
    <td class="d-none"><a href="/block/25623480">25623480</a></td>
    <td class="showDate">2026-07-27 10:14:47</td><td class="showAge">63 days ago</td><td class="showLocalDate">1785147287</td>
    <td><a href="/address/{PHISHER}" data-clipboard-text="{PHISHER}">Fake_Phishing5370992</a></td>
    <td><span class="badge">IN</span></td>
    <td><span class="hash-tag" data-highlight-target="{SELF}" title="Ronin Bridge Exploiter">Ronin Bridge Exploiter</span></td>
    <td class="text-nowrap">0.000011 ETH <span>$0.03</span></td>
    <td class="small text-muted showTxnFee">0<b>.</b>00000196</td></tr>
  <tr><td></td><td><a class="hash-tag" href="/tx/{TX2}">{TX2}</a></td>
    <td class="td_functionNameOri"><span class="badge">Swap</span></td><td class="td_functionNameCustom"></td>
    <td class="d-none"><a href="/block/24842123">24842123</a></td>
    <td class="showDate">2026-04-09 12:21:35</td><td class="showAge">172 days ago</td><td class="showLocalDate">1775737295</td>
    <td><span class="hash-tag" data-highlight-target="{SELF}">Ronin Bridge Exploiter</span></td>
    <td><span class="badge">OUT</span></td>
    <td><a href="/address/0x8C75aD518Dce956b488AB65E36aB229d8664BF29">0x8C75aD51...8664BF29</a></td>
    <td class="text-nowrap">2.5 ETH <span>$6,677.97</span></td>
    <td class="small text-muted showTxnFee">0.00000559</td></tr>
</tbody></table></div>
</main></body></html>
"""


def test_parses_identity_labels_and_warnings():
    data = parse_address_page(PAGE, SELF)

    assert data["address"] == SELF
    assert data["account_type"] == "address"
    assert data["public_name_tag"] == "Ronin Bridge Exploiter"
    assert [label["name"] for label in data["labels"]] == ["Exploit", "OFAC-Sanctioned", "Blocked"]
    assert data["labels"][1]["slug"] == "ofac-sanctioned"
    assert "custodial stablecoin" in data["labels"][2]["description"]
    assert data["risk_labels"][0] == "Ronin Bridge Exploiter"
    assert "OFAC-Sanctioned" in data["risk_labels"]
    # The compiler notice inside a modal is not an address warning.
    assert data["warnings"] == ["This address is reported to be involved in a hack targeting the Ronin bridge ."]


def test_parses_valuation_holdings_and_multichain():
    data = parse_address_page(PAGE, SELF)

    assert data["balance_eth"] == pytest.approx(101.80248678376705)
    assert data["balance_usd"] == 271933.78
    assert data["eth_price_usd"] == 2671.19
    assert data["token_holdings_usd"] == 0.01
    assert data["token_holdings_is_lower_bound"] is False
    assert data["token_count"] == 40
    # The divider <li> nests the next token under lxml; it must not duplicate it.
    assert data["token_list_size"] == 2
    assert data["tokens"][0]["symbol"] == "JUSTICE"  # sorted by USD value
    assert data["tokens"][1] == {
        "name": "Akita Inu", "symbol": "AKITA", "standard": "ERC20",
        "contract": "0x3301ee63fb29f863f2333bd4466acb46cd8323e6",
        "amount": 13300000.0, "value_usd": 0.0, "price_usd": 0.0001,
    }
    assert data["multichain_portfolio_usd"] == 271954.63
    assert data["multichain_address_count"] == 2
    assert data["net_worth_eth"] == pytest.approx(101.810292)
    # Zero-value chains with no tokens are dropped.
    assert [chain["chain"] for chain in data["chains"]] == ["Ethereum", "BNB Chain"]
    assert data["chains"][1]["share_below_pct"] is True
    assert data["chains"][1]["token_count"] == 4


def test_parses_funding_activity_and_transactions():
    data = parse_address_page(PAGE, SELF)

    assert data["funded_by"]["address"] == FUNDER
    assert data["funded_by"]["label"] == "Binance 20"
    assert data["funded_by"]["tx_hash"] == "0x" + "e" * 64
    assert data["latest_tx_sent"]["age"] == "3 yrs 191 days ago"
    assert data["first_tx_sent"]["tx_hash"] == "0x" + "d" * 64
    assert data["transaction_count"] == 430
    assert data["pending_transactions"] == 1

    inbound, outbound = data["recent_transactions"]
    assert inbound["hash"] == TX1
    assert inbound["direction"] == "IN"
    assert inbound["block"] == 25623480
    assert inbound["time"] == 1785147287
    assert inbound["from"] == {"address": PHISHER, "label": "Fake_Phishing5370992"}
    assert inbound["to"]["address"] == SELF
    assert inbound["value_eth"] == pytest.approx(0.000011)
    assert inbound["fee_eth"] == pytest.approx(0.00000196)
    assert outbound["direction"] == "OUT"
    assert outbound["value_usd"] == 6677.97
    assert "label" not in outbound["to"]  # a shortened hex address is not a tag

    assert data["unique_counterparties"] == 2
    assert data["risky_counterparties"] == [{"address": PHISHER, "label": "Fake_Phishing5370992", "tx_count": 1}]


def test_dust_balance_in_wei_and_contract_page():
    page = f"""<html><body><h1>Contract</h1><span id="mainaddress">{SELF}</span>
    <div><h4>ETH Balance</h4><div>42 wei</div></div>
    <div><h4>Eth Value</h4>Less Than $0.01 <span>(@ $2,670.05/ETH)</span></div>
    <div><h4>Contract Creator</h4><div><a href="/address/{FUNDER}">Bitfinex: Deployer 5</a> |
      <a href="/tx/0x{'2' * 64}">8 yrs 305 days ago</a></div></div>
    <div><h4>Token Tracker</h4><div>Tether USD (USDT)</div></div></body></html>"""
    data = parse_address_page(page, SELF)

    assert data["account_type"] == "contract"
    assert data["balance_eth"] == pytest.approx(42 / 10**18)
    assert data["balance_usd"] == 0.0
    assert data["contract_creator"]["label"] == "Bitfinex: Deployer 5"
    assert data["token_tracker"] == "Tether USD (USDT)"


def test_challenge_page_is_reported_as_unavailable():
    with pytest.raises(EtherscanPageUnavailable):
        parse_address_page("<html><head><title>Just a moment...</title></head><body></body></html>", SELF)


@pytest.mark.asyncio
async def test_fetch_rejects_non_address_input():
    with pytest.raises(ValueError):
        await etherscan_page.fetch_address_page("https://evil.example/")


@pytest.mark.asyncio
async def test_enrich_eth_merges_page_and_api(monkeypatch):
    async def fake_scrape(address):
        return parse_address_page(PAGE, address)

    async def fake_api(address):
        return {"balance_eth": 101.80248678376705535, "recent_transactions": []}

    monkeypatch.setattr(settings, "etherscan_page_enrichment", True)
    monkeypatch.setattr(settings, "etherscan_api_key", "A" * 34)
    monkeypatch.setattr(etherscan_page, "scrape_address", fake_scrape)
    monkeypatch.setattr(enrichment, "_etherscan_api_summary", fake_api)

    result = await enrichment.enrich_eth(SELF)

    wallet = result.extra["ethereum"]
    assert result.completeness["ethereum_address"] == "ok"
    assert result.completeness["etherscan_page"] == "ok"
    # The page carried the multichain portfolio, so no API fallback ran.
    assert wallet["multichain_source"] == "etherscan_page"
    assert result.completeness["multichain_holdings"] == "ok"
    assert result.completeness["etherscan_api"] == "ok"
    assert wallet["data_sources"] == ["etherscan_page", "etherscan_api"]
    assert wallet["transaction_count"] == 430  # page total, not the 25-row API sample
    assert len(wallet["recent_transactions"]) == 2  # API list is empty; page rows kept
    assert any("OFAC-Sanctioned" in note for note in result.analysis_notes)
    relationships = {(rel["relationship"], rel["target_ioc"]) for rel in result.relationships}
    assert ("funded_by", FUNDER) in relationships
    assert ("transacted_with_flagged", PHISHER) in relationships


@pytest.mark.asyncio
async def test_enrich_eth_falls_back_to_api_when_page_blocked(monkeypatch):
    async def blocked(address):
        raise EtherscanPageUnavailable("http_403")

    async def fake_api(address):
        return {
            "balance_eth": 1.5,
            "recent_transactions": [{"hash": TX1, "direction": "IN", "from": {"address": PHISHER}, "to": {"address": SELF}}] * 25,
        }

    monkeypatch.setattr(settings, "etherscan_page_enrichment", True)
    monkeypatch.setattr(settings, "etherscan_api_key", "A" * 34)
    monkeypatch.setattr(etherscan_page, "scrape_address", blocked)
    monkeypatch.setattr(enrichment, "_etherscan_api_summary", fake_api)

    async def fake_multichain(address, eth_balance=None, eth_price=None):
        assert eth_balance == 1.5  # the API balance is reused for Ethereum
        return {
            "chains": [{"chain": "Polygon", "chain_id": "137", "native_symbol": "POL", "native_balance": 10.0, "value_usd": 1.2}],
            "multichain_portfolio_usd": 1.2, "active_chain_count": 1, "multichain_source": "etherscan_v2_native",
            "multichain_chains_checked": 15, "multichain_chains_failed": [], "multichain_chains_unsupported": ["Base"],
        }

    monkeypatch.setattr(enrichment, "_etherscan_multichain_native", fake_multichain)

    result = await enrichment.enrich_eth(SELF)

    wallet = result.extra["ethereum"]
    assert result.completeness["multichain_holdings"] == "partial"
    assert wallet["multichain_source"] == "etherscan_v2_native"
    assert wallet["chains"][0]["native_symbol"] == "POL"
    assert result.completeness["etherscan_page"] == "unavailable"
    assert wallet["balance_eth"] == 1.5
    assert wallet["transaction_count"] == 25
    assert wallet["transaction_count_is_lower_bound"] is True
    assert any("page unavailable" in note for note in result.analysis_notes)


@pytest.mark.asyncio
async def test_page_without_multichain_falls_back_to_v2_native_balances(monkeypatch):
    """Etherscan sometimes omits the multichain block; per-chain native
    balances then come from the V2 API, valued with native coin prices."""
    page = PAGE.split('<div class="card-body">\n  <div><h4 class="text-cap mb-1">Multichain Info</h4>')[0] + "</main></body></html>"

    class Response:
        status_code = 200

        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    balances = {"137": 500 * 10**18, "42161": 0}
    prices = {"137": "0.2"}
    calls: list[tuple[str, str]] = []
    rate_limited_once = {"42161"}

    class Client:
        async def get(self, _url, *, params, **_kwargs):
            chain = str(params["chainid"])
            calls.append((chain, params["action"]))
            if params["action"] == "balance":
                if chain == "59144":
                    return Response({"status": "0", "result": "Invalid API Key"})
                if chain in rate_limited_once:
                    rate_limited_once.discard(chain)
                    return Response({"status": "0", "result": "Max rate limit reached"})
                return Response({"status": "1", "result": str(balances.get(chain, 0))})
            return Response({"status": "1", "result": {"ethusd": prices.get(chain, "1")}})

    async def fake_scrape(address):
        return parse_address_page(page, address)

    async def fake_api(address):
        return {"balance_eth": 2.0, "recent_transactions": []}

    monkeypatch.setattr(settings, "etherscan_page_enrichment", True)
    monkeypatch.setattr(settings, "etherscan_api_key", "A" * 34)
    monkeypatch.setattr(etherscan_page, "scrape_address", fake_scrape)
    monkeypatch.setattr(enrichment, "_etherscan_api_summary", fake_api)
    monkeypatch.setattr(enrichment, "_get_http_client", lambda: Client())
    monkeypatch.setattr(enrichment.asyncio, "sleep", _no_sleep)
    enrichment._native_prices.clear()

    result = await enrichment.enrich_eth(SELF)

    wallet = result.extra["ethereum"]
    assert wallet["multichain_source"] == "etherscan_v2_native"
    # Ethereum reuses the known balance (2 ETH) and the page's ETH price.
    assert [(c["chain"], c["value_usd"]) for c in wallet["chains"]] == [("Ethereum", 5342.38), ("Polygon", 100.0)]
    assert ("1", "balance") not in calls and ("1", "ethprice") not in calls
    assert wallet["multichain_portfolio_usd"] == 5442.38
    assert wallet["chains"][0]["share_pct"] == 98
    # A rate-limited chain is retried; a hard error is reported as failed.
    assert calls.count(("42161", "balance")) == 2
    assert wallet["multichain_chains_failed"] == ["Linea"]
    assert result.completeness["multichain_holdings"] == "partial"
    assert any("native-coin balances" in note for note in result.analysis_notes)


async def _no_sleep(_seconds):
    return None


@pytest.mark.asyncio
async def test_enrich_eth_without_page_or_key_is_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "etherscan_page_enrichment", False)
    monkeypatch.setattr(settings, "etherscan_api_key", "")

    result = await enrichment.enrich_eth(SELF)

    assert result.completeness["ethereum_address"] == "not_configured"
    assert not result.extra


@pytest.mark.asyncio
async def test_enrich_eth_total_failure_is_error_not_empty_wallet(monkeypatch):
    async def blocked(address):
        raise EtherscanPageUnavailable("http_503")

    monkeypatch.setattr(settings, "etherscan_page_enrichment", True)
    monkeypatch.setattr(settings, "etherscan_api_key", "")
    monkeypatch.setattr(etherscan_page, "scrape_address", blocked)

    result = await enrichment.enrich_eth(SELF)

    # No wallet payload, so the pipeline neither caches it nor overwrites a
    # previous good snapshot.
    assert result.completeness["ethereum_address"] == "error"
    assert not result.extra
