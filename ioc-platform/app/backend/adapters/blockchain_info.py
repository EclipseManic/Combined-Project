import asyncio
from datetime import datetime, timezone

from app.backend.adapters.base import NormalizedResult, RateLimitConfig, SourceAdapter, retry_after_seconds


class BlockchainInfoAdapter(SourceAdapter):
    """Keyless Bitcoin address statistics from blockchain.info."""

    name = "Blockchain.info"
    supported_types = ["btc"]
    public_without_key = True
    rate_limit = RateLimitConfig(
        requests_per_minute=6, requests_per_day=500,
        minimum_interval_seconds=10.0,
    )
    produces_reputation = False
    produces_infrastructure_context = True
    produces_metadata = True

    @staticmethod
    def _timestamp(value):
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        except (TypeError, ValueError, OSError, OverflowError):
            return None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        client = self._get_client()
        balance_response, address_response = await asyncio.gather(
            client.get(
                "https://blockchain.info/balance", params={"active": ioc_value}, timeout=15,
            ),
            client.get(
                f"https://blockchain.info/rawaddr/{ioc_value}", params={"limit": 25}, timeout=15,
            ),
            return_exceptions=True,
        )
        if isinstance(balance_response, Exception) and isinstance(address_response, Exception):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["request_error"],
            )
        responses = [item for item in (balance_response, address_response) if not isinstance(item, Exception)]
        if any(item.status_code == 429 for item in responses):
            limited = next(item for item in responses if item.status_code == 429)
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"], http_status=429,
                retry_after_seconds=retry_after_seconds(limited),
            )
        payloads = {}
        for name, response in (("balance", balance_response), ("address", address_response)):
            if isinstance(response, Exception):
                payloads[name] = {"error": str(response)}
            else:
                try:
                    payloads[name] = response.json()
                except Exception:
                    payloads[name] = {"error": "malformed_response"}

        if all(item.status_code in (400, 404) for item in responses):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", status="not_found", tags=["not_found"], http_status=404,
                raw_data=payloads,
            )

        balance_payload = payloads.get("balance", {})
        address_payload = payloads.get("address", {})
        if not isinstance(balance_payload, dict):
            balance_payload = {}
        if not isinstance(address_payload, dict):
            address_payload = {}

        # If both payloads returned errors, or address is explicitly invalid / not found
        msg = f"{balance_payload.get('message', '')} {address_payload.get('message', '')}".lower()
        if (balance_payload.get("error") and address_payload.get("error")) or "invalid" in msg or "not found" in msg:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", status="not_found", tags=["not_found"],
                raw_data=payloads,
            )

        if ioc_value not in balance_payload and "address" not in address_payload:
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", status="not_found", tags=["not_found"],
                raw_data=payloads,
            )
        balance_record = balance_payload.get(ioc_value) if isinstance(balance_payload.get(ioc_value), dict) else balance_payload
        transactions = address_payload.get("txs", []) if isinstance(address_payload.get("txs"), list) else []
        final_balance = address_payload.get("final_balance", balance_record.get("final_balance", 0) if isinstance(balance_record, dict) else 0) or 0
        received = address_payload.get("total_received", balance_record.get("total_received", 0) if isinstance(balance_record, dict) else 0) or 0
        sent = address_payload.get("total_sent", balance_record.get("total_sent", 0) if isinstance(balance_record, dict) else 0) or 0
        timestamps = [self._timestamp(item.get("time")) for item in transactions if isinstance(item, dict)]
        timestamps = [item for item in timestamps if item is not None]
        raw_data = {
            **payloads,
            "balance_btc": final_balance / 100_000_000,
            "total_received_btc": received / 100_000_000,
            "total_sent_btc": sent / 100_000_000,
            "transaction_count": address_payload.get("n_tx", len(transactions)),
        }
        tx_count = int(raw_data["transaction_count"] or 0)
        # Balance and transaction count are typed values (raw_data, reports_count).
        tags = ["active_address"] if tx_count or final_balance or received else ["empty_address"]
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", status="found", tags=tags, reports_count=tx_count,
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
            source_link=f"https://www.blockchain.com/explorer/addresses/btc/{ioc_value}",
            raw_data=raw_data,
        )
