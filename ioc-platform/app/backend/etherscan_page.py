"""Etherscan address-page scraper.

The free Etherscan API only exposes a balance and a raw transaction list. The
public address page additionally shows the fields an analyst actually pivots
on: public name tag and labels (``Exploit``, ``OFAC-Sanctioned``, ``Phish/Hack``
...), warning banners, USD valuation, ERC-20 holdings, the multichain
portfolio, the funding source, the true total transaction count and
counterparty tags on recent transactions. This module fetches that one page
and turns it into a structured dict for ``enrichment.enrich_eth``.

Parsing works from element ids/classes and ``href`` targets, never from
free-text heuristics over the whole document. Every field is optional: a
layout change degrades to missing keys rather than wrong values. A response
without ``#mainaddress`` (Cloudflare challenge, error page, redesign) raises
``EtherscanPageUnavailable`` so the caller can fall back to the API.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from bs4 import BeautifulSoup, Tag

from app.backend.http_client import get_client

ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
ETHERSCAN_BASE = "https://etherscan.io"

# Etherscan serves the HTML page only to browser-like clients.
PAGE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "max-age=0",
    "Referer": f"{ETHERSCAN_BASE}/",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"
    ),
}

# Label/tag keywords that mark an address as threat-relevant.
RISK_LABEL_PATTERN = re.compile(
    r"phish|hack|exploit|heist|scam|fraud|drainer|sanction|ofac|blocked|"
    r"lazarus|ransom|mixer|tornado|stolen|laundering|malicious|attacker",
    re.I,
)

MAX_TOKENS = 25
MAX_CHAINS = 40
MAX_TRANSACTIONS = 25

# Serialize page fetches and space them out: enrichment is not wrapped by the
# provider rate limiter, and a batch of ETH lookups must not hammer the site.
_MIN_FETCH_INTERVAL = 1.5
_fetch_lock = asyncio.Lock()
_last_fetch = 0.0


class EtherscanPageUnavailable(Exception):
    """The address page could not be fetched or did not look like one."""


async def fetch_address_page(address: str, timeout: float = 20.0) -> str:
    if not ETH_ADDRESS_RE.fullmatch(address):
        raise ValueError(f"not an Ethereum address: {address!r}")
    global _last_fetch
    async with _fetch_lock:
        wait = _MIN_FETCH_INTERVAL - (time.monotonic() - _last_fetch)
        if wait > 0:
            await asyncio.sleep(wait)
        try:
            response = await get_client().get(
                f"{ETHERSCAN_BASE}/address/{address}",
                headers=PAGE_HEADERS,
                follow_redirects=True,
                timeout=timeout,
            )
        finally:
            _last_fetch = time.monotonic()
    if response.status_code != 200:
        raise EtherscanPageUnavailable(f"http_{response.status_code}")
    return response.text


async def scrape_address(address: str) -> dict[str, Any]:
    html = await fetch_address_page(address)
    # A full page is ~1 MB; keep the parse off the event loop.
    return await asyncio.to_thread(parse_address_page, html, address)


# ─── parsing helpers ────────────────────────────────────────────────────────

def _text(node: Tag | None, sep: str = " ") -> str:
    if node is None:
        return ""
    return re.sub(r"\s+", " ", node.get_text(sep, strip=True)).strip()


def _compact(node: Tag | None) -> str:
    """Text with all whitespace removed ("5 . 72 ETH" -> "5.72ETH")."""
    return re.sub(r"\s+", "", node.get_text("", strip=True)) if node is not None else ""


def _number(text: str | None) -> float | None:
    if not text:
        return None
    match = re.search(r"-?\d[\d,]*(?:\.\d+)?|-?\.\d+", text)
    if not match:
        return None
    try:
        return float(match.group(0).replace(",", ""))
    except ValueError:
        return None


def _int(text: str | None) -> int | None:
    value = _number(text)
    return int(value) if value is not None else None


def _address_from_href(href: str | None) -> str | None:
    match = re.search(r"/address/(0x[a-fA-F0-9]{40})", href or "")
    return match.group(1) if match else None


def _tx_from_href(href: str | None) -> str | None:
    match = re.search(r"/tx/(0x[a-fA-F0-9]{64})", href or "")
    return match.group(1) if match else None


def _labelled_value(soup: BeautifulSoup, label: str) -> Tag | None:
    """Return the value container of an ``<h4>`` card label: its sibling
    ``<div>``, or the parent block when the value sits inline after it."""
    for heading in soup.find_all("h4"):
        if _text(heading).lower() == label.lower():
            return heading.find_next_sibling("div") or heading.parent
    return None


def _party(cell: Tag | None) -> dict[str, Any]:
    """Address + display tag from a From/To cell of the transactions table."""
    if cell is None:
        return {}
    address = None
    link = cell.find("a", href=re.compile(r"^/address/0x"))
    if link is not None:
        address = _address_from_href(link.get("href"))
    if address is None:
        for node in cell.find_all(attrs={"data-highlight-target": True}):
            candidate = node.get("data-highlight-target")
            if candidate and ETH_ADDRESS_RE.fullmatch(candidate):
                address = candidate
                break
    if address is None:
        clip = cell.find(attrs={"data-clipboard-text": re.compile(r"^0x[a-fA-F0-9]{40}$")})
        if clip is not None:
            address = clip.get("data-clipboard-text")
    shown = _text(cell)
    party: dict[str, Any] = {"address": address}
    if shown and address and shown.lower() != address.lower() and not shown.startswith("0x"):
        party["label"] = shown
    return party


# ─── section parsers ────────────────────────────────────────────────────────

def _parse_identity(soup: BeautifulSoup, result: dict[str, Any]) -> None:
    heading = soup.find("h1")
    if heading is not None:
        result["account_type"] = "contract" if _text(heading).lower() == "contract" else "address"
    container = heading.find_next("div", class_="flex-wrap") if heading is not None else None
    if container is not None:
        # The outer wrapper also holds unrelated badges ("Beta"); the inner
        # flex-wrap is the tag/label row itself.
        container = container.find("div", class_="flex-wrap") or container

    labels: list[dict[str, Any]] = []
    seen: set[str] = set()
    for badge in container.find_all(["a", "span"]) if container is not None else []:
        if "badge" not in (badge.get("class") or []):
            continue
        name = _text(badge)
        tooltip = badge.get("title") or badge.get("data-bs-title") or ""
        if not name:
            continue
        if tooltip.startswith("Public Name Tag"):
            result["public_name_tag"] = name
            href = badge.get("href") or ""
            if href.startswith("http"):
                result["website"] = href
            continue
        if badge.find("img", alt="ENS Name") is not None or re.fullmatch(r"[\w.-]+\.eth", name):
            result["ens_name"] = name
            continue
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        entry: dict[str, Any] = {"name": name}
        slug = re.search(r"/accounts/label/([\w-]+)", badge.get("href") or "")
        if slug:
            entry["slug"] = slug.group(1)
        if tooltip:
            entry["description"] = re.sub(r"<[^>]+>", " ", tooltip).strip()
        labels.append(entry)
    result["labels"] = labels

    warnings = []
    for alert in soup.select("div.alert-danger, div.alert-warning"):
        # Skip modal/tab content such as the compiler-bug notice on contracts.
        if alert.find_parent(class_=["modal", "tab-pane"]) is not None:
            continue
        message = _text(alert)
        if message and message not in warnings:
            warnings.append(message)
    result["warnings"] = warnings

    risk = [item["name"] for item in labels if RISK_LABEL_PATTERN.search(item["name"])]
    if result.get("public_name_tag") and RISK_LABEL_PATTERN.search(result["public_name_tag"]):
        risk.insert(0, result["public_name_tag"])
    result["risk_labels"] = risk


def _parse_balances(soup: BeautifulSoup, result: dict[str, Any]) -> None:
    balance = _labelled_value(soup, "ETH Balance")
    if balance is not None:
        compact = _compact(balance)
        amount = _number(compact)
        # Dust balances are rendered in smaller units ("42 wei", "3.1 Gwei").
        if amount is not None and re.search(r"\d\s*gwei", compact, re.I):
            amount /= 10**9
        elif amount is not None and re.search(r"\d\s*wei", compact, re.I):
            amount /= 10**18
        result["balance_eth"] = amount

    value = _labelled_value(soup, "Eth Value")
    if value is not None:
        text = _text(value)
        amounts = re.findall(r"\$\s*([\d,]+(?:\.\d+)?)", text)
        if amounts:
            result["balance_usd"] = 0.0 if text.lower().startswith(("less than", "eth value less than")) else _number(amounts[0])
        if len(amounts) > 1:
            result["eth_price_usd"] = _number(amounts[1])

    holdings = soup.select_one("#dropdownMenuBalance")
    if holdings is not None:
        text = _text(holdings)
        usd = re.search(r"(>?)\s*\$\s*([\d,]+(?:\.\d+)?)", text)
        if usd:
            result["token_holdings_usd"] = _number(usd.group(2))
            result["token_holdings_is_lower_bound"] = bool(usd.group(1))
        count = re.search(r"\((>?)\s*([\d,]+)\s+Tokens?\)", text)
        if count:
            result["token_count"] = _int(count.group(2))

    tokens = []
    for item in soup.select('li[class*="list-custom-"]'):
        standard = next(
            (match.group(1).upper() for cls in item.get("class", []) if (match := re.fullmatch(r"list-custom-(erc\d+)", cls, re.I))),
            None,
        )
        link = item.find("a", href=True)
        # Section dividers ("ERC-20 Tokens (23)") are list items too, and lxml
        # nests the following token inside them.
        if standard is None or link is None:
            continue
        name_node = item.select_one(".list-name")
        amount_node = link.select_one("span.text-muted")
        contract = re.search(r"/(?:token|nft)/(0x[a-fA-F0-9]{40})", link["href"])
        name = _text(name_node)
        symbol = re.search(r"\(([^()]+)\)\s*$", name)
        tokens.append({
            "name": re.sub(r"\s*\([^()]+\)\s*$", "", name) or name,
            "symbol": symbol.group(1).strip() if symbol else None,
            "standard": standard,
            "contract": contract.group(1) if contract else None,
            "amount": _number(_text(amount_node)),
            "value_usd": _number(_text(item.select_one(".list-usd-value"))),
            "price_usd": _number(_text(item.select_one(".list-usd-rate"))),
        })
    if tokens:
        result["token_list_size"] = len(tokens)
        tokens.sort(key=lambda token: token["value_usd"] or 0.0, reverse=True)
        result["tokens"] = tokens[:MAX_TOKENS]


def _parse_multichain(soup: BeautifulSoup, result: dict[str, Any]) -> None:
    button = soup.select_one("#multichain-button")
    if button is not None:
        result["multichain_portfolio_usd"] = _number(_text(button))
        container = button.find_parent("div")
        container = container.parent if container is not None and container.parent is not None else container
        found = re.search(r"([\d,]+)\s+address(?:es)?\s+found", _text(container))
        if found:
            result["multichain_address_count"] = _int(found.group(1))

    net_eth = soup.find(string=re.compile(r"Net Worth in ETH"))
    if net_eth is not None:
        value_node = net_eth.find_parent().find_next_sibling()
        if value_node is not None:
            result["net_worth_eth"] = _number(_compact(value_node))

    chains = []
    for chain in soup.select(".js-chain"):
        label = chain.select_one("span.text-muted.small")
        count_node = label.find("span") if label is not None else None
        token_count = _int(_text(count_node))
        if count_node is not None:
            count_node.extract()
        value_text = _text(chain.select_one("div.text-dark"))
        pct = re.search(r"\((<?)\s*([\d.]+)%\)", value_text)
        usd_text = re.sub(r"\(.*?\)", "", value_text)
        chains.append({
            "chain": _text(label) or chain.get("data-chain"),
            "chain_id": chain.get("data-chain"),
            "token_count": token_count,
            "value_usd": _number(usd_text) or 0.0,
            "share_pct": float(pct.group(2)) if pct else None,
            "share_below_pct": bool(pct and pct.group(1)),
        })
    active = [chain for chain in chains if chain["value_usd"] or chain["token_count"]]
    if active:
        active.sort(key=lambda chain: chain["value_usd"], reverse=True)
        result["chains"] = active[:MAX_CHAINS]
        result["active_chain_count"] = len(active)


def _parse_activity(soup: BeautifulSoup, result: dict[str, Any]) -> None:
    funded = soup.select_one("#conFundedMainChain")
    if funded is not None:
        address_link = funded.find("a", href=re.compile(r"^/address/0x"))
        tx_link = funded.find("a", href=re.compile(r"^/tx/0x"))
        funder: dict[str, Any] = {}
        if address_link is not None:
            funder["address"] = _address_from_href(address_link.get("href"))
            label = _text(address_link)
            if label and not label.startswith("0x"):
                funder["label"] = label
        if tx_link is not None:
            funder["tx_hash"] = _tx_from_href(tx_link.get("href"))
            funder["age"] = _text(tx_link)
        if funder.get("address"):
            result["funded_by"] = funder

    sent = _labelled_value(soup, "Transactions Sent")
    if sent is not None:
        for marker in sent.find_all("span", class_="text-muted"):
            key = _text(marker).rstrip(":").lower()
            link = marker.find_next_sibling("a")
            if key in {"latest", "first"} and link is not None:
                result[f"{key}_tx_sent"] = {"tx_hash": _tx_from_href(link.get("href")), "age": _text(link)}

    creator = _labelled_value(soup, "Contract Creator")
    if creator is not None:
        address_link = creator.find("a", href=re.compile(r"^/address/0x"))
        tx_link = creator.find("a", href=re.compile(r"^/tx/0x"))
        info: dict[str, Any] = {}
        if address_link is not None:
            info["address"] = _address_from_href(address_link.get("href"))
            label = _text(address_link)
            if label and not label.startswith("0x"):
                info["label"] = label
        if tx_link is not None:
            info["tx_hash"] = _tx_from_href(tx_link.get("href"))
            info["age"] = _text(tx_link)
        if info:
            result["contract_creator"] = info

    tracker = _labelled_value(soup, "Token Tracker")
    if tracker is not None and _text(tracker):
        result["token_tracker"] = _text(tracker)

    info = soup.select_one("#ContentPlaceHolder1_divTxDataInfo")
    if info is not None:
        text = _text(info)
        total = re.search(r"total of\s+([\d,]+)\s+transactions", text)
        if total:
            result["transaction_count"] = _int(total.group(1))
        pending = re.search(r"\(\s*\+\s*([\d,]+)\s+Pending", text) or re.search(r"More than\s+([\d,]+)\s+Pending", text)
        if pending:
            result["pending_transactions"] = _int(pending.group(1))

    transactions = []
    for row in soup.select("#transactions table tbody tr"):
        cells = row.find_all("td", recursive=False)
        hash_link = row.find("a", href=re.compile(r"^/tx/0x"))
        if hash_link is None:
            continue
        direction_index = next(
            (index for index, cell in enumerate(cells) if _text(cell).upper() in {"IN", "OUT", "SELF"}),
            None,
        )
        block_link = row.find("a", href=re.compile(r"^/block/\d+"))
        method = row.select_one("td.td_functionNameOri") or row.select_one("td.td_functionNameCustom")
        unix = _int(_text(row.select_one("td.showLocalDate")))
        value_text = _text(row.select_one("td.text-nowrap"))
        eth_value = re.search(r"([\d,]*\.?\d+)\s*ETH", value_text.replace(" . ", "."))
        usd_value = re.search(r"\$\s*([\d,]+(?:\.\d+)?)", value_text)
        transactions.append({
            "hash": _tx_from_href(hash_link.get("href")),
            "method": _text(method) or None,
            "block": _int(_text(block_link)),
            "time": unix,
            "datetime_utc": _text(row.select_one("td.showDate")) or None,
            "direction": _text(cells[direction_index]).upper() if direction_index is not None else None,
            "from": _party(cells[direction_index - 1]) if direction_index else {},
            "to": _party(cells[direction_index + 1]) if direction_index is not None and direction_index + 1 < len(cells) else {},
            "value_eth": _number(eth_value.group(1)) if eth_value else None,
            "value_usd": _number(usd_value.group(1)) if usd_value else None,
            "fee_eth": _number(_compact(row.select_one("td.showTxnFee"))),
            "failed": bool(row.select_one(".text-danger, [data-bs-title*='Error']")),
        })
        if len(transactions) >= MAX_TRANSACTIONS:
            break
    if transactions:
        result["recent_transactions"] = transactions
        counterparties: dict[str, dict[str, Any]] = {}
        for tx in transactions:
            other = tx["to"] if tx["direction"] == "OUT" else tx["from"]
            addr = (other or {}).get("address")
            if not addr or addr.lower() == str(result.get("address", "")).lower():
                continue
            entry = counterparties.setdefault(addr.lower(), {"address": addr, "label": other.get("label"), "tx_count": 0})
            entry["tx_count"] += 1
        tagged = [entry for entry in counterparties.values() if entry.get("label")]
        result["unique_counterparties"] = len(counterparties)
        if tagged:
            result["tagged_counterparties"] = tagged
            risky = [entry for entry in tagged if RISK_LABEL_PATTERN.search(entry["label"])]
            if risky:
                result["risky_counterparties"] = risky


def parse_address_page(html: str, address: str) -> dict[str, Any]:
    soup = BeautifulSoup(html, "lxml")
    main = soup.select_one("#mainaddress")
    if main is None:
        title = _text(soup.title) if soup.title else ""
        raise EtherscanPageUnavailable(f"address page not recognised ({title[:60] or 'no title'})")
    result: dict[str, Any] = {"address": _text(main) or address}
    for parser in (_parse_identity, _parse_balances, _parse_multichain, _parse_activity):
        try:
            parser(soup, result)
        except Exception:  # one broken section must not drop the rest
            continue
    result["source_link"] = f"{ETHERSCAN_BASE}/address/{result['address']}"
    return result
