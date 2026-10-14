import asyncio
from datetime import datetime, timezone

from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
    retry_after_seconds,
)
from app.backend.config import settings


class EtherscanAdapter(SourceAdapter):
    """Ethereum address balance and transaction context."""

    name = "Etherscan"
    supported_types = ["eth"]
    rate_limit = RateLimitConfig(requests_per_minute=5, requests_per_day=10000)
    produces_reputation = False
    produces_infrastructure_context = True
    produces_metadata = True

    def __init__(self):
        self.api_key = settings.etherscan_api_key

    @staticmethod
    def _timestamp(value):
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        except (TypeError, ValueError, OSError, OverflowError):
            return None

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if not is_valid_api_key(self.api_key):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["no_api_key_configured"],
            )

        client = self._get_client()
        base = "https://api.etherscan.io/v2/api"
        common = {"address": ioc_value, "apikey": self.api_key, "chainid": 1}
        balance_request = client.get(
            base, params={"module": "account", "action": "balance", **common}, timeout=15,
        )
        transaction_request = client.get(
            base,
            params={
                "module": "account", "action": "txlist", "startblock": 0,
                "endblock": 99999999, "page": 1, "offset": 25,
                "sort": "desc", **common,
            },
            timeout=15,
        )
        balance_resp, transaction_resp = await asyncio.gather(
            balance_request, transaction_request, return_exceptions=True,
        )
        responses = (balance_resp, transaction_resp)
        if all(isinstance(item, Exception) for item in responses):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["request_error"],
            )

        payloads: dict[str, object] = {}
        for name, response in (("balance", balance_resp), ("transactions", transaction_resp)):
            if isinstance(response, Exception):
                payloads[name] = {"error": str(response)}
                continue
            try:
                payloads[name] = response.json()
            except Exception:
                payloads[name] = {"error": "malformed_response"}

        statuses = [
            response.status_code for response in responses
            if not isinstance(response, Exception)
        ]
        if any(status == 429 for status in statuses):
            response = next(response for response in responses if not isinstance(response, Exception) and response.status_code == 429)
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="unknown", tags=["rate_limited"], http_status=429,
                retry_after_seconds=retry_after_seconds(response), raw_data=payloads,
            )
        if any(status in (401, 403) for status in statuses):
            return NormalizedResult(
                ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                verdict="error", tags=["unauthorized"], http_status=401, raw_data=payloads,
            )

        balance_data = payloads.get("balance") if isinstance(payloads.get("balance"), dict) else {}
        transaction_data = payloads.get("transactions") if isinstance(payloads.get("transactions"), dict) else {}
        balance_raw = balance_data.get("result")
        balance_wei = int(balance_raw) if isinstance(balance_raw, str) and balance_raw.isdigit() else 0
        transactions = transaction_data.get("result", [])
        if not isinstance(transactions, list):
            transactions = []
        valid_transactions = [item for item in transactions if isinstance(item, dict)]
        has_record = bool(
            balance_data.get("status") == "1"
            or transaction_data.get("status") == "1"
            or valid_transactions
        )
        if not has_record:
            message = str(transaction_data.get("message") or balance_data.get("message") or "").lower()
            result_str = str(balance_data.get("result") or "").lower()
            if "deprecated" in result_str or "invalid api key" in result_str or "unauthorized" in result_str:
                return NormalizedResult(
                    ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                    verdict="error", tags=["api_error"], raw_data=payloads,
                )
            if "invalid" in message or "not found" in message or "notok" in message or not (balance_data or transaction_data):
                return NormalizedResult(
                    ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                    verdict="unknown", status="not_found", raw_data=payloads,
                )

        timestamps = [self._timestamp(item.get("timeStamp")) for item in valid_transactions]
        timestamps = [item for item in timestamps if item is not None]
        raw_data = {
            **payloads,
            "balance_wei": balance_wei,
            "balance_eth": balance_wei / 10**18,
            "transaction_count": len(valid_transactions),
        }
        # Balance and transaction count are typed values (raw_data, reports_count).
        tags = ["active_address"] if valid_transactions or balance_wei else ["empty_address"]
        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict="unknown", status="found", tags=tags,
            reports_count=len(valid_transactions),
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
            source_link=f"https://etherscan.io/address/{ioc_value}",
            raw_data=raw_data,
        )
