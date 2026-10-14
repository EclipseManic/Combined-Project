"""IPQualityScore adapters.

One key unlocks three products from the same vendor, and all three return a
numeric ``fraud_score`` (0-100) that the platform's other sources do not have:

  phone  ->  ipqualityscore.com/api/json/phone/{key}/{number}
  ip     ->  ipqualityscore.com/api/json/ip/{key}/{ip}
  email  ->  ipqualityscore.com/api/json/email/{key}/{address}

The most important thing to know about this API: **it answers HTTP 200 to
everything, including an invalid API key.** There is no status code to branch
on. Every response carries a ``success`` boolean and a human-readable
``message``, and the adapter has to read those instead:

    "Invalid or unauthorized key..."                -> unauthorized (not 401)
    "Invalid/nonexistent phone number..."           -> not found
    "Invalid IPv4 address, IPv6 address..."         -> not found
    "Your account must be Enterprise Mini or higher"-> paywalled field

A response can also be ``success: true`` *and* paywalled, in which case the
fields that were returned are still worth keeping and the rest arrive as null
or as a nested object carrying its own status string. Both are handled here so
a plan limitation is never recorded as "no risk found".

``strictness`` is sent explicitly rather than left to the default: at 0 the
service returns ``accurate_country_code: false``, at 1 it returns true, so the
default silently yields worse data.
"""

import httpx

from app.backend.adapters._http import failure, not_configured
from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
    retry_after_seconds,
)
from app.backend.config import settings
from app.backend.logger import get_logger

logger = get_logger("adapter.ipquality")

API_ROOT = "https://ipqualityscore.com/api/json"

# Free keys are metered per day; this is deliberately well under the documented
# allowance so a burst of lookups cannot exhaust the month.
RATE_LIMIT = RateLimitConfig(
    requests_per_minute=60,
    requests_per_day=1000,
    minimum_interval_seconds=0.1,
)

# Ordered most specific first: the first matching prefix wins.
_ERROR_RULES: tuple[tuple[str, str], ...] = (
    ("invalid or unauthorized key", "unauthorized"),
    ("unauthorized", "unauthorized"),
    ("no api key", "unauthorized"),
    ("enterprise mini or higher to score domains", "paywalled"),
    ("enterprise plus or higher", "paywalled"),
    ("enterprise l4 or higher", "paywalled"),
    ("upgraded plan required", "paywalled"),
    ("enterprise plan required", "paywalled"),
    ("please specify a country", "invalid_request"),
    ("specify a country", "invalid_request"),
    ("exceeded", "rate_limited"),
    ("quota", "rate_limited"),
    ("rate limit", "rate_limited"),
    ("invalid/nonexistent phone number", "not_found"),
    ("invalid ipv4 address", "not_found"),
    ("invalid/nonexistent", "not_found"),
    ("not a valid", "not_found"),
)


def classify_message(message: str) -> str:
    lowered = (message or "").strip().lower()
    for needle, kind in _ERROR_RULES:
        if needle in lowered:
            return kind
    return "error"


def _number(value: float | int | None) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _yes(value: object) -> bool:
    return value is True


def _nested(data: dict, *path: str) -> object:
    current: object = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _status_marker(data: dict, *path: str) -> str | None:
    """Read a nested ``status`` string, e.g. "Enterprise Plus or higher required"."""
    value = _nested(data, *path, "status")
    return value if isinstance(value, str) else None


async def _request(
    client: httpx.AsyncClient,
    source: str,
    ioc: str,
    ioc_type: str,
    kind: str,
    value: str,
    key: str,
) -> tuple[NormalizedResult | None, dict | None]:
    """Perform one IPQS call. Returns ``(failure_result, None)`` or ``(None, data)``."""
    url = f"{API_ROOT}/{kind}/{key}/{value}"
    params = {"strictness": 1} if kind in ("phone", "ip") else None

    try:
        resp = await client.get(url, params=params, timeout=15)
    except httpx.TimeoutException:
        return NormalizedResult(ioc=ioc, ioc_type=ioc_type, source=source,
                                verdict="error", tags=["timeout"]), None
    except httpx.HTTPError as exc:
        logger.warning("IPQualityScore request error (%s): %s", source, type(exc).__name__)
        return NormalizedResult(ioc=ioc, ioc_type=ioc_type, source=source,
                                verdict="error", tags=["http_error"]), None

    if resp.status_code == 429:
        return NormalizedResult(
            ioc=ioc, ioc_type=ioc_type, source=source,
            verdict="unknown", status="rate_limited", tags=["rate_limited"],
            retry_after_seconds=retry_after_seconds(resp) or 60.0,
        ), None
    if resp.status_code >= 500:
        return NormalizedResult(ioc=ioc, ioc_type=ioc_type, source=source,
                                verdict="error", tags=[f"http_{resp.status_code}"]), None

    try:
        data = resp.json()
    except Exception:
        data = None
    if not isinstance(data, dict):
        return NormalizedResult(ioc=ioc, ioc_type=ioc_type, source=source,
                                verdict="error", tags=["malformed_response"]), None

    # HTTP 200 means nothing here; success is the only success signal.
    if not data.get("success", False):
        message = str(data.get("message") or "")
        kind_result = classify_message(message)
        if kind_result == "unauthorized":
            return failure(source, ioc, ioc_type, "unavailable",
                           ["unauthorized", "invalid_api_key"],
                           "IPQualityScore rejected the key: " + message[:160]), None
        if kind_result == "rate_limited":
            return NormalizedResult(
                ioc=ioc, ioc_type=ioc_type, source=source,
                verdict="unknown", status="rate_limited", tags=["rate_limited"],
                retry_after_seconds=60.0,
            ), None
        if kind_result == "invalid_request":
            return NormalizedResult(
                ioc=ioc, ioc_type=ioc_type, source=source,
                verdict="unknown", tags=["invalid_request"],
                provider_summary=message[:200] or None,
            ), None
        if kind_result == "not_found":
            return NormalizedResult(
                ioc=ioc, ioc_type=ioc_type, source=source,
                verdict="unknown", status="not_found", tags=["not_found"],
            ), None
        if kind_result == "paywalled":
            return NormalizedResult(
                ioc=ioc, ioc_type=ioc_type, source=source,
                verdict="unknown", status="unavailable", tags=["plan_limitation"],
                provider_summary=message[:200],
            ), None
        return NormalizedResult(
            ioc=ioc, ioc_type=ioc_type, source=source,
            verdict="error", tags=["provider_error"],
            provider_summary=message[:200] or None,
        ), None

    return None, data


def _blocked_fields(data: dict) -> list[str]:
    """Nested objects that came back as a paywall notice rather than data."""
    blocked = []
    for key, value in data.items():
        if isinstance(value, dict) and isinstance(value.get("status"), str) and "required" in value["status"].lower():
            blocked.append(key)
    return blocked


def _clean(value: object) -> str | None:
    """A short usable string, or None. The service uses 'N/A' for absent values."""
    return value if isinstance(value, str) and value and value != "N/A" else None


def _score_phrase(score: float | None) -> str:
    return "fraud score unavailable" if score is None else f"fraud score {int(score)}/100"


class _IPQualityBase(SourceAdapter):
    def __init__(self) -> None:
        self.api_key = settings.ipquality_api_key
        self.rate_limit = RATE_LIMIT

    def _keyed(self) -> str | None:
        return self.api_key if is_valid_api_key(self.api_key) else None

    def _common_tags(self, data: dict) -> list[str]:
        tags: list[str] = []
        score = _number(data.get("fraud_score"))
        if score is not None:
            tags.append(f"ipqs:fraud_score:{int(score)}")
        if _yes(data.get("risky")):
            tags.append("ipqs:risky")
        if _yes(data.get("recent_abuse")):
            tags.append("ipqs:recent_abuse")
        if _yes(data.get("spammer")):
            tags.append("ipqs:spammer")
        for field in _blocked_fields(data):
            tags.append(f"ipqs:blocked:{field}")
        return tags


class IPQualityPhoneAdapter(_IPQualityBase):
    """Phone reputation, carrier and messaging identity from IPQualityScore."""

    name = "IPQualityScore Phone"
    supported_types = ["phone"]
    public_without_key = False
    kind = "phone"

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type != "phone":
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                                    verdict="unknown", tags=["unsupported_type"])
        key = self._keyed()
        if not key:
            return not_configured(self.name, ioc_value, ioc_type)

        failure_result, data = await _request(
            self._get_client(), self.name, ioc_value, ioc_type,
            self.kind, ioc_value.lstrip("+"), key,
        )
        if failure_result is not None:
            return failure_result

        score = _number(data.get("fraud_score"))
        risky = _yes(data.get("risky"))
        is_voip = _yes(data.get("VOIP"))
        spammer = _yes(data.get("spammer"))
        recent_abuse = _yes(data.get("recent_abuse"))
        leaked = _yes(data.get("leaked"))
        valid = _yes(data.get("valid"))
        carrier = data.get("carrier")
        line_type = data.get("line_type")
        holder = data.get("name")
        sms_email = data.get("sms_email")

        tags = self._common_tags(data)
        for flag_name, flag_value in (
            ("voip", is_voip), ("prepaid", _yes(data.get("prepaid"))),
            ("leaked", leaked), ("do_not_call", _yes(data.get("do_not_call"))),
            ("tcpa_blacklist", _yes(data.get("tcpa_blacklist"))),
            ("active", _yes(data.get("active"))),
        ):
            tags.append(f"ipqs:{flag_name}:{'true' if flag_value else 'false'}")
        for key_name, value in (
            ("carrier", carrier), ("line_type", line_type),
            ("country", data.get("country")), ("name", holder),
            ("sms_email", sms_email), ("sms_domain", data.get("sms_domain")),
        ):
            if isinstance(value, str) and value and value != "N/A":
                tags.append(f"ipqs:{key_name}:{value}")

        if not valid:
            verdict, raw_score, confidence = "unknown", 0.0, "low"
        elif spammer or recent_abuse or (score is not None and score >= 75):
            verdict, raw_score, confidence = "malicious", 0.80, "high"
        elif risky or (score is not None and score >= 40):
            verdict, raw_score, confidence = "suspicious", 0.50, "medium"
        elif is_voip and (score is not None and score >= 20):
            verdict, raw_score, confidence = "suspicious", 0.30, "low"
        elif not risky and score is not None and score <= 5:
            # The vendor actively checked and returned its own low-risk verdict.
            verdict, raw_score, confidence = "clean", 0.0, "medium"
        else:
            verdict, raw_score, confidence = "unknown", 0.0, "low"

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=raw_score, confidence=confidence,
            tags=tags, raw_data=data,
            provider_summary=self._summary(data, verdict),
            source_link="https://www.ipqualityscore.com/phone-number-validator/lookup",
        )

    def _summary(self, data: dict, verdict: str) -> str:
        parts = [_score_phrase(_number(data.get("fraud_score")))]
        if _yes(data.get("VOIP")):
            parts.append("VoIP line")
        if _yes(data.get("spammer")):
            parts.append("flagged as spammer")
        elif _yes(data.get("recent_abuse")):
            parts.append("recent abuse reported")
        carrier = _clean(data.get("carrier"))
        if carrier:
            parts.append(f"carrier {carrier}")
        line_type = _clean(data.get("line_type"))
        if line_type:
            parts.append(line_type.lower())
        parts.append(f"provider verdict {verdict}")
        return "; ".join(parts)


class IPQualityIPAdapter(_IPQualityBase):
    """IP reputation: fraud score, anonymiser flags and hosting context."""

    name = "IPQualityScore IP"
    supported_types = ["ipv4", "ipv6"]
    public_without_key = False
    produces_infrastructure_context = True
    kind = "ip"

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type not in ("ipv4", "ipv6"):
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                                    verdict="unknown", tags=["unsupported_type"])
        key = self._keyed()
        if not key:
            return not_configured(self.name, ioc_value, ioc_type)

        failure_result, data = await _request(
            self._get_client(), self.name, ioc_value, ioc_type,
            self.kind, ioc_value, key,
        )
        if failure_result is not None:
            return failure_result

        score = _number(data.get("fraud_score"))
        is_tor = _yes(data.get("tor")) or _yes(data.get("active_tor"))
        is_vpn = _yes(data.get("vpn")) or _yes(data.get("active_vpn"))
        is_proxy = _yes(data.get("proxy"))
        recent_abuse = _yes(data.get("recent_abuse"))
        abuse_velocity = data.get("abuse_velocity")
        organization = data.get("organization")
        isp = data.get("isp")
        asn = data.get("ASN")
        connection_type = data.get("connection_type")

        tags = self._common_tags(data)
        for flag_name, flag_value in (
            ("tor", is_tor), ("vpn", is_vpn), ("proxy", is_proxy),
            ("mobile", _yes(data.get("mobile"))), ("crawler", _yes(data.get("is_crawler"))),
        ):
            tags.append(f"ipqs:{flag_name}:{'true' if flag_value else 'false'}")
        if isinstance(abuse_velocity, str):
            tags.append(f"ipqs:abuse_velocity:{abuse_velocity}")
        if isinstance(connection_type, str):
            tags.append(f"ipqs:connection_type:{connection_type}")
        if asn:
            tags.append(f"asn:{asn}")
        if organization:
            tags.append(f"org:{organization}")
        if isp:
            tags.append(f"isp:{isp}")

        if is_tor or recent_abuse or (score is not None and score >= 75):
            verdict, raw_score, confidence = "malicious", 0.80, "high"
        elif is_proxy or (is_vpn and (score is not None and score >= 40)):
            verdict, raw_score, confidence = "suspicious", 0.50, "medium"
        elif is_vpn or (score is not None and score >= 25):
            verdict, raw_score, confidence = "suspicious", 0.30, "low"
        else:
            # A residential address with no flags is absence of data, not safety.
            verdict, raw_score, confidence = "unknown", 0.0, "low"

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=raw_score, confidence=confidence,
            tags=tags, raw_data=data,
            provider_summary=self._summary(data, verdict),
            source_link="https://www.ipqualityscore.com/ip-reputation-api/lookup",
        )

    def _summary(self, data: dict, verdict: str) -> str:
        parts = [_score_phrase(_number(data.get("fraud_score")))]
        flags = []
        if _yes(data.get("tor")) or _yes(data.get("active_tor")):
            flags.append("TOR exit")
        if _yes(data.get("vpn")) or _yes(data.get("active_vpn")):
            flags.append("VPN")
        if _yes(data.get("proxy")):
            flags.append("proxy")
        if flags:
            parts.append("+".join(flags))
        if _yes(data.get("recent_abuse")):
            parts.append("recent abuse reported")
        organization = _clean(data.get("organization")) or _clean(data.get("ISP"))
        if organization:
            asn = data.get("ASN")
            parts.append(f"{organization} (AS{asn})" if asn else organization)
        parts.append(f"provider verdict {verdict}")
        return "; ".join(parts)


class IPQualityEmailAdapter(_IPQualityBase):
    """Email deliverability and fraud scoring with DNS policy checks."""

    name = "IPQualityScore Email"
    supported_types = ["email"]
    public_without_key = False
    kind = "email"

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type != "email":
            return NormalizedResult(ioc=ioc_value, ioc_type=ioc_type, source=self.name,
                                    verdict="unknown", tags=["unsupported_type"])
        key = self._keyed()
        if not key:
            return not_configured(self.name, ioc_value, ioc_type)

        failure_result, data = await _request(
            self._get_client(), self.name, ioc_value, ioc_type,
            self.kind, ioc_value, key,
        )
        if failure_result is not None:
            return failure_result

        score = _number(data.get("fraud_score"))
        deliverability = data.get("deliverability")
        is_valid = _yes(data.get("valid"))
        is_disposable = _yes(data.get("disposable"))
        is_honeypot = _yes(data.get("honeypot"))
        is_catchall = _yes(data.get("catch_all"))
        is_suspect = _yes(data.get("suspect"))
        is_risky_tld = _yes(data.get("risky_tld"))
        spam_trap = data.get("spam_trap_score")
        has_dmarc = _yes(data.get("dmarc_record"))
        has_spf = _yes(data.get("spf_record"))
        dns_valid = _yes(data.get("dns_valid"))

        tags = self._common_tags(data)
        for flag_name, flag_value in (
            ("disposable", is_disposable), ("honeypot", is_honeypot),
            ("catchall", is_catchall), ("suspect", is_suspect),
            ("risky_tld", is_risky_tld), ("dns_valid", dns_valid),
            ("dmarc", has_dmarc), ("spf", has_spf),
            ("frequent_complainer", _yes(data.get("frequent_complainer"))),
        ):
            tags.append(f"ipqs:{flag_name}:{'true' if flag_value else 'false'}")
        if isinstance(deliverability, str) and deliverability:
            tags.append(f"ipqs:deliverability:{deliverability}")
        if isinstance(spam_trap, str) and spam_trap and spam_trap != "none":
            tags.append(f"ipqs:spam_trap:{spam_trap}")

        if is_honeypot or (score is not None and score >= 75):
            verdict, raw_score, confidence = "malicious", 0.80, "high"
        elif is_disposable or is_risky_tld or is_suspect or (score is not None and score >= 40):
            verdict, raw_score, confidence = "suspicious", 0.50, "medium"
        elif not is_valid or is_catchall or deliverability == "low":
            verdict, raw_score, confidence = "suspicious", 0.30, "low"
        elif is_valid and deliverability == "high" and not is_disposable:
            verdict, raw_score, confidence = "clean", 0.0, "medium"
        else:
            verdict, raw_score, confidence = "unknown", 0.0, "low"

        return NormalizedResult(
            ioc=ioc_value, ioc_type=ioc_type, source=self.name,
            verdict=verdict, raw_score=raw_score, confidence=confidence,
            tags=tags, raw_data=data,
            provider_summary=self._summary(data, verdict),
            source_link="https://www.ipqualityscore.com/email-verifier-api/lookup",
        )

    def _summary(self, data: dict, verdict: str) -> str:
        parts = [_score_phrase(_number(data.get("fraud_score")))]
        if _yes(data.get("honeypot")):
            parts.append("listed as a spam honeypot")
        deliverability = _clean(data.get("deliverability"))
        if deliverability:
            parts.append(f"deliverability {deliverability}")
        missing = [label for label, present in
                   (("MX", _yes(data.get("dns_valid"))), ("SPF", _yes(data.get("spf_record"))),
                    ("DMARC", _yes(data.get("dmarc_record")))) if not present]
        if missing:
            parts.append("no " + "/".join(missing))
        parts.append(f"provider verdict {verdict}")
        return "; ".join(parts)
