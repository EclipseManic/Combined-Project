"""Shared HTTP-outcome helpers for provider adapters.

Adapters own the parsing of their provider's payload; these helpers only make
the *non-answer* outcomes uniform so every provider reports the same
``execution_state`` for the same kind of failure:

* 401/403            -> ``unavailable`` (credential rejected / not entitled)
* 404                -> ``not_found``
* 429                -> ``rate_limited`` (with ``Retry-After`` when sent)
* 400/422/other 4xx  -> ``invalid_request``
* 5xx                -> ``error`` (tagged ``http_5xx`` so the pipeline retries)
* malformed / empty JSON body -> ``error``

A configuration problem or a failed request is never reported as
``success``, and a failure is never reported as a clean verdict.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.backend.adapters.base import NormalizedResult, retry_after_seconds


def describe_exception(exc: BaseException) -> str:
    """Return a log-safe description that is never empty.

    Several httpx exceptions (``ConnectError``, ``ReadError``,
    ``RemoteProtocolError``) stringify to an empty message, which previously
    produced log lines such as ``"connection failed: "``.
    """
    return f"{type(exc).__name__}: {exc!r}"


def failure(
    adapter_name: str,
    ioc: str,
    ioc_type: str,
    state: str,
    tags: list[str] | str,
    summary: str,
    *,
    http_status: int | None = None,
    retry_after: float | None = None,
    raw_data: dict | None = None,
    request_made: bool = True,
    **extra: Any,
) -> NormalizedResult:
    """Build an explicit non-success provider observation."""
    tag_list = [tags] if isinstance(tags, str) else list(tags)
    return NormalizedResult(
        ioc=ioc,
        ioc_type=ioc_type,
        source=adapter_name,
        verdict="unknown",
        provider_verdict=state,
        normalized_verdict="unknown",
        execution_state=state,
        status="not_found" if state == "not_found" else ("unavailable" if state == "unavailable" else "error"),
        tags=tag_list,
        provider_summary=summary,
        http_status=http_status,
        retry_after_seconds=retry_after,
        raw_data=raw_data or {},
        request_made=request_made,
        **extra,
    )


def not_configured(adapter_name: str, ioc: str, ioc_type: str, detail: str = "no API key configured") -> NormalizedResult:
    return failure(
        adapter_name, ioc, ioc_type, "unavailable", ["no_api_key_configured"],
        f"{adapter_name} unavailable: {detail}", request_made=False,
    )


def exception_result(adapter_name: str, ioc: str, ioc_type: str, exc: BaseException) -> NormalizedResult:
    """Map a transport exception raised inside an adapter to a result."""
    if isinstance(exc, httpx.TimeoutException):
        return failure(adapter_name, ioc, ioc_type, "timeout", ["timeout"], f"{adapter_name} timed out ({type(exc).__name__})")
    return failure(
        adapter_name, ioc, ioc_type, "error", ["request_error"],
        f"{adapter_name} request failed ({type(exc).__name__})",
        raw_data={"exception_type": type(exc).__name__},
    )


def http_failure(
    adapter_name: str,
    ioc: str,
    ioc_type: str,
    resp: Any,
    *,
    key_sent: bool = True,
    not_found_summary: str = "No matching record",
) -> NormalizedResult | None:
    """Return a failure result for a non-2xx response, else ``None``."""
    code = getattr(resp, "status_code", None)
    if not isinstance(code, int) or 200 <= code < 300:
        return None
    if code == 404:
        return failure(adapter_name, ioc, ioc_type, "not_found", [], not_found_summary, http_status=404)
    if code == 429:
        retry_after = retry_after_seconds(resp)
        wait = f"; retry after {retry_after:.0f}s" if retry_after is not None else ""
        return failure(
            adapter_name, ioc, ioc_type, "rate_limited", ["rate_limited"],
            f"{adapter_name} rate limit reached (HTTP 429{wait})",
            http_status=429, retry_after=retry_after,
        )
    if code in (401, 403):
        if key_sent:
            tags = ["unauthorized", "invalid_api_key"] if code == 401 else ["forbidden", "invalid_api_key"]
            summary = f"{adapter_name} rejected the configured API key (HTTP {code})"
        else:
            tags = ["unauthorized" if code == 401 else "forbidden", "no_api_key_configured"]
            summary = f"{adapter_name} requires an API key (HTTP {code})"
        return failure(adapter_name, ioc, ioc_type, "unavailable", tags, summary, http_status=code)
    if code >= 500:
        return failure(
            adapter_name, ioc, ioc_type, "error", [f"http_{code}"],
            f"{adapter_name} server error (HTTP {code})", http_status=code,
        )
    if 300 <= code < 400:
        return failure(
            adapter_name, ioc, ioc_type, "error", [f"http_{code}", "unexpected_response"],
            f"{adapter_name} returned an unexpected redirect (HTTP {code})", http_status=code,
        )
    return failure(
        adapter_name, ioc, ioc_type, "invalid_request", [f"http_{code}", "invalid_request"],
        f"{adapter_name} rejected the request (HTTP {code})", http_status=code,
    )


class MalformedResponse(Exception):
    """Raised by :func:`read_json` when a 2xx body is not usable JSON."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def read_json(resp: Any) -> Any:
    """Decode a JSON body, distinguishing empty bodies from malformed ones."""
    text = getattr(resp, "text", None)
    if isinstance(text, str) and not text.strip():
        raise MalformedResponse("empty_response")
    try:
        return resp.json()
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MalformedResponse("malformed_response") from exc


def malformed(adapter_name: str, ioc: str, ioc_type: str, reason: str = "malformed_response", http_status: int | None = None) -> NormalizedResult:
    label = "an empty response" if reason == "empty_response" else "a malformed response"
    return failure(
        adapter_name, ioc, ioc_type, "error", [reason],
        f"{adapter_name} returned {label}", http_status=http_status,
    )
