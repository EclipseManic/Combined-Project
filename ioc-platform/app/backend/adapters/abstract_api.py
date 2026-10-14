"""AbstractAPI adapters.

AbstractAPI issues **one key per product**, and a key issued for one product is
rejected by the others with ``401 Invalid API key provided``.  Each product is
therefore a separate adapter with its own credential:

===========================  ==========================  =============================
Adapter                      Credential                  Endpoint
===========================  ==========================  =============================
``AbstractAPI``              ``ABSTRACTAPI_EMAIL_KEY``   Email Reputation
``AbstractAPI IP``           ``ABSTRACTAPI_IP_KEY``      IP Intelligence
``AbstractAPI Phone``        ``ABSTRACTAPI_No_KEY``      Phone Intelligence
===========================  ==========================  =============================

Note the product hostnames are not derivable from the product names:
``ip-intelligence`` and ``phoneintelligence`` are hyphen-less/hyphenated
inconsistently, so they are spelled out per adapter below.
"""

import httpx

from app.backend.adapters.base import (
    NormalizedResult,
    RateLimitConfig,
    SourceAdapter,
    is_valid_api_key,
    retry_after_seconds,
)
from app.backend.config import settings
from app.backend.logger import describe_exception, get_logger

logger = get_logger("adapter.abstract_api")

EMAIL_REPUTATION_URL = "https://emailreputation.abstractapi.com/v1/"
IP_INTELLIGENCE_URL = "https://ip-intelligence.abstractapi.com/v1/"
PHONE_INTELLIGENCE_URL = "https://phoneintelligence.abstractapi.com/v1/"

# Shared documented error contract for all three products.
#   401 unauthorized | 422 quota reached (free plans) | 429 too many requests
_ABSTRACT_QUOTA_STATUSES = (422,)


def _nested(data, *path):
    """Read a value from a nested dict, tolerating missing/None intermediates."""
    current = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _flag(data, *path) -> bool:
    return bool(_nested(data, *path))


async def _get_abstract(client, source, ioc, ioc_type, url, params, key) -> tuple[NormalizedResult | None, dict | None]:
    """Perform one AbstractAPI request and normalize its failure modes.

    Returns ``(failure_result, None)`` for anything that is not a usable 200
    payload, or ``(None, data)`` on success.  The three products share one HTTP
    error contract, so the branching lives here rather than in each adapter.
    """
    try:
        resp = await client.get(url, params={"api_key": key, **params}, timeout=12)
    except httpx.TimeoutException:
        return NormalizedResult(
            ioc=ioc, ioc_type=ioc_type, source=source,
            verdict="error", tags=["timeout"],
        ), None
    except httpx.HTTPError as exc:
        logger.warning("AbstractAPI request error (%s): %s", source, describe_exception(exc))
        return NormalizedResult(
            ioc=ioc, ioc_type=ioc_type, source=source,
            verdict="error", tags=["http_error"],
        ), None

    if resp.status_code in (429,) + _ABSTRACT_QUOTA_STATUSES:
        # 429 is per-second throttling; 422 means the monthly free-plan
        # allowance is spent.  The platform's tag vocabulary treats a spent
        # plan allowance as an exhausted monthly quota (-> unavailable) rather
        # than a transient rate limit, so the credential is kept but the
        # provider is left alone until the allowance resets.
        quota = resp.status_code in _ABSTRACT_QUOTA_STATUSES
        retry_after = retry_after_seconds(resp) or (86400.0 if quota else 60.0)
        return NormalizedResult(
            ioc=ioc, ioc_type=ioc_type, source=source,
            verdict="unknown",
            status="unavailable" if quota else "rate_limited",
            tags=["monthly_quota_exhausted"] if quota else ["rate_limited"],
            retry_after_seconds=retry_after,
        ), None

    if resp.status_code in (401, 403):
        # AbstractAPI keys are per-product, so this is also what a key issued
        # for a different product looks like from the wrong endpoint.
        return NormalizedResult(
            ioc=ioc, ioc_type=ioc_type, source=source,
            verdict="unknown", status="unavailable",
            tags=["unauthorized", "invalid_api_key"],
        ), None

    if resp.status_code != 200:
        return NormalizedResult(
            ioc=ioc, ioc_type=ioc_type, source=source,
            verdict="error", tags=[f"http_{resp.status_code}"],
        ), None

    try:
        data = resp.json()
    except Exception:
        data = None
    if not isinstance(data, dict):
        return NormalizedResult(
            ioc=ioc, ioc_type=ioc_type, source=source,
            verdict="error", tags=["malformed_response"],
            provider_summary="AbstractAPI returned a malformed response",
        ), None
    return None, data


def _no_key(source, ioc, ioc_type) -> NormalizedResult:
    return NormalizedResult(
        ioc=ioc, ioc_type=ioc_type, source=source,
        verdict="unknown", status="unavailable",
        tags=["no_api_key_configured"],
    )


def _unsupported_type(source, ioc, ioc_type) -> NormalizedResult:
    return NormalizedResult(
        ioc=ioc, ioc_type=ioc_type, source=source,
        verdict="unknown", tags=["unsupported_type"],
    )


class AbstractAPIAdapter(SourceAdapter):
    """Email reputation from the AbstractAPI Email Reputation product.

    Covers deliverability, disposable/catchall/role detection, domain risk and
    breach history for an address.  Free tier allows 100 requests/month at
    1 request/second.
    """

    name = "AbstractAPI"
    supported_types = ["email"]
    public_without_key = False
    rate_limit = RateLimitConfig(
        requests_per_minute=60,
        requests_per_day=100,
        minimum_interval_seconds=1.0,
    )

    def __init__(self):
        self.api_key = settings.abstractapi_email_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type != "email":
            return _unsupported_type(self.name, ioc_value, ioc_type)
        if not is_valid_api_key(self.api_key):
            return _no_key(self.name, ioc_value, ioc_type)

        failure, data = await _get_abstract(
            self._get_client(), self.name, ioc_value, ioc_type,
            EMAIL_REPUTATION_URL, {"email": ioc_value}, self.api_key,
        )
        if failure is not None:
            return failure

        deliverability = str(_nested(data, "email_deliverability", "status") or "").lower()
        address_risk = str(_nested(data, "email_risk", "address_risk_status") or "").lower()
        domain_risk = str(_nested(data, "email_risk", "domain_risk_status") or "").lower()
        total_breaches = _nested(data, "email_breaches", "total_breaches") or 0

        try:
            quality_score = float(_nested(data, "email_quality", "score"))
        except (TypeError, ValueError):
            quality_score = None

        is_disposable = _flag(data, "email_quality", "is_disposable")
        is_free = _flag(data, "email_quality", "is_free_email")
        is_role = _flag(data, "email_quality", "is_role")
        is_catchall = _flag(data, "email_quality", "is_catchall")
        is_subaddress = _flag(data, "email_quality", "is_subaddress")
        is_username_suspicious = _flag(data, "email_quality", "is_username_suspicious")
        is_dmarc = _flag(data, "email_quality", "is_dmarc_enforced")
        is_format_valid = _flag(data, "email_deliverability", "is_format_valid")
        is_mx_valid = _flag(data, "email_deliverability", "is_mx_valid")
        is_smtp_valid = _flag(data, "email_deliverability", "is_smtp_valid")
        is_risky_tld = _flag(data, "email_domain", "is_risky_tld")

        tags = []
        if deliverability:
            tags.append(f"deliverability:{deliverability}")
        if address_risk:
            tags.append(f"abstract:address_risk:{address_risk}")
        if domain_risk:
            tags.append(f"abstract:domain_risk:{domain_risk}")
        if is_disposable:
            tags.append("abstract:disposable_email")
        if is_free:
            tags.append("abstract:free_provider")
        if is_role:
            tags.append("abstract:role_account")
        if is_catchall:
            tags.append("abstract:catchall")
        if is_subaddress:
            tags.append("abstract:subaddress")
        if is_username_suspicious:
            tags.append("abstract:suspicious_username")
        if is_risky_tld:
            tags.append("abstract:risky_tld")
        if not is_format_valid:
            tags.append("abstract:invalid_format")
        if not is_mx_valid:
            tags.append("abstract:no_mx_record")
        if not is_smtp_valid:
            tags.append("abstract:smtp_invalid")
        if is_dmarc:
            tags.append("abstract:dmarc_enforced")
        if total_breaches:
            tags.append("abstract:breached")

        if is_disposable or address_risk == "high":
            verdict, raw_score, confidence = "suspicious", 0.70, "high"
        elif is_catchall or is_username_suspicious or deliverability == "undeliverable" or not is_mx_valid:
            verdict, raw_score, confidence = "suspicious", 0.45, "medium"
        elif deliverability == "risky" or domain_risk == "high":
            verdict, raw_score, confidence = "suspicious", 0.35, "medium"
        elif deliverability == "deliverable" and address_risk == "low" and domain_risk == "low":
            verdict, raw_score, confidence = "clean", 0.0, "medium"
        else:
            # Absence of a risk flag is not proof of a legitimate mailbox.
            verdict, raw_score, confidence = "unknown", 0.0, "low"

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            raw_score=raw_score,
            confidence=confidence,
            tags=tags,
            raw_data=data,
            provider_summary=self._summary(data, verdict),
            source_link="https://app.abstractapi.com/api/email-reputation",
        )

    def _summary(self, data, verdict: str) -> str:
        parts = []
        deliverability = _nested(data, "email_deliverability", "status")
        if isinstance(deliverability, str) and deliverability:
            parts.append(f"deliverability {deliverability}")
        for label, path in (
            ("disposable provider", ("email_quality", "is_disposable")),
            ("role account", ("email_quality", "is_role")),
            ("catch-all", ("email_quality", "is_catchall")),
            ("no MX record", ("email_deliverability", "is_mx_valid")),
        ):
            if _nested(data, *path) is False:
                parts.append(label)
        domain_risk = _nested(data, "email_risk", "domain_risk_status")
        if isinstance(domain_risk, str) and domain_risk:
            parts.append(f"domain risk {domain_risk}")
        breaches = _nested(data, "email_breaches", "total_breaches")
        if isinstance(breaches, int) and breaches:
            parts.append(f"{breaches} breach(es)")
        parts.append(f"provider verdict {verdict}")
        return "; ".join(parts)


class AbstractAPIIPAdapter(SourceAdapter):
    """IP reputation and geolocation from the AbstractAPI IP Intelligence product.

    Returns anonymizer/proxy/abuse flags alongside ASN, company and location
    context.  Absence of a risk flag is reported as ``unknown`` rather than
    ``clean``: a residential IP with no flags is not evidence of safety.
    """

    name = "AbstractAPI IP"
    supported_types = ["ipv4", "ipv6"]
    public_without_key = False
    produces_infrastructure_context = True
    rate_limit = RateLimitConfig(
        requests_per_minute=60,
        requests_per_day=100,
        minimum_interval_seconds=1.0,
    )

    def __init__(self):
        self.api_key = settings.abstractapi_ip_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type not in ("ipv4", "ipv6"):
            return _unsupported_type(self.name, ioc_value, ioc_type)
        if not is_valid_api_key(self.api_key):
            return _no_key(self.name, ioc_value, ioc_type)

        failure, data = await _get_abstract(
            self._get_client(), self.name, ioc_value, ioc_type,
            IP_INTELLIGENCE_URL, {"ip_address": ioc_value}, self.api_key,
        )
        if failure is not None:
            return failure

        security = data.get("security") or {}
        is_vpn = bool(security.get("is_vpn"))
        is_proxy = bool(security.get("is_proxy"))
        is_tor = bool(security.get("is_tor"))
        is_hosting = bool(security.get("is_hosting"))
        is_relay = bool(security.get("is_relay"))
        is_mobile = bool(security.get("is_mobile"))
        is_abuse = bool(security.get("is_abuse"))

        asn = _nested(data, "asn", "asn")
        asn_name = _nested(data, "asn", "name")
        company = _nested(data, "company", "name")
        country_code = _nested(data, "location", "country_code")
        city = _nested(data, "location", "city")

        tags = []
        for flag_name, flag_value in (
            ("vpn", is_vpn), ("proxy", is_proxy), ("tor", is_tor),
            ("hosting", is_hosting), ("relay", is_relay),
            ("mobile", is_mobile), ("abuse", is_abuse),
        ):
            tags.append(f"abstractip:{flag_name}:{'true' if flag_value else 'false'}")
        if asn:
            tags.append(f"asn:{asn}")
        if asn_name:
            tags.append(f"org:{asn_name}")
        if country_code:
            tags.append(f"country:{country_code}")

        if is_tor:
            verdict, raw_score, confidence = "malicious", 0.90, "high"
        elif is_abuse:
            verdict, raw_score, confidence = "malicious", 0.80, "high"
        elif is_proxy:
            verdict, raw_score, confidence = "suspicious", 0.55, "medium"
        elif is_vpn:
            verdict, raw_score, confidence = "suspicious", 0.40, "medium"
        else:
            # Hosting, relay and mobile are context, not risk in themselves,
            # and a flag-free IP is absence of evidence rather than a clean bill.
            verdict, raw_score, confidence = "unknown", 0.0, "low"

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            raw_score=raw_score,
            confidence=confidence,
            tags=tags,
            raw_data=data,
            provider_summary=self._summary(data, verdict),
            source_link="https://app.abstractapi.com/api/ip-intelligence",
        )

    def _summary(self, data, verdict: str) -> str:
        security = data.get("security") or {}
        parts = []
        for label, flag in (
            ("TOR exit", security.get("is_tor")),
            ("VPN", security.get("is_vpn")),
            ("proxy", security.get("is_proxy")),
            ("abuse reported", security.get("is_abuse")),
            ("datacenter", security.get("is_hosting")),
        ):
            if flag is True:
                parts.append(label)
        asn = _nested(data, "asn", "asn")
        name = _nested(data, "asn", "name")
        if name or asn:
            parts.append(f"{name} (AS{asn})" if name and asn else (str(name) if name else f"AS{asn}"))
        country = _nested(data, "location", "country_code")
        if country:
            parts.append(str(country))
        if not parts:
            parts.append("no risk flags returned")
        parts.append(f"provider verdict {verdict}")
        return "; ".join(parts)


class AbstractAPIPhoneAdapter(SourceAdapter):
    """Phone intelligence from the AbstractAPI Phone Intelligence product.

    Returns validity, line type, carrier, registration location, messaging
    address, disposable/abuse risk and breach history for a number in E.164
    form.
    """

    name = "AbstractAPI Phone"
    supported_types = ["phone"]
    public_without_key = False
    rate_limit = RateLimitConfig(
        requests_per_minute=60,
        requests_per_day=100,
        minimum_interval_seconds=1.0,
    )

    def __init__(self):
        self.api_key = settings.abstractapi_phone_api_key

    async def lookup(self, ioc_value: str, ioc_type: str) -> NormalizedResult:
        if ioc_type != "phone":
            return _unsupported_type(self.name, ioc_value, ioc_type)
        if not is_valid_api_key(self.api_key):
            return _no_key(self.name, ioc_value, ioc_type)

        failure, data = await _get_abstract(
            self._get_client(), self.name, ioc_value, ioc_type,
            PHONE_INTELLIGENCE_URL, {"phone": ioc_value.lstrip("+")}, self.api_key,
        )
        if failure is not None:
            return failure

        is_valid = _flag(data, "phone_validation", "is_valid")
        line_status = str(_nested(data, "phone_validation", "line_status") or "").lower()
        is_voip = _flag(data, "phone_validation", "is_voip")
        risk_level = str(_nested(data, "phone_risk", "risk_level") or "").lower()
        is_disposable = _flag(data, "phone_risk", "is_disposable")
        is_abuse = _flag(data, "phone_risk", "is_abuse_detected")
        line_type = str(_nested(data, "phone_carrier", "line_type") or "").lower()
        carrier = _nested(data, "phone_carrier", "name")
        country_code = _nested(data, "phone_location", "country_code")
        region = _nested(data, "phone_location", "region")
        total_breaches = _nested(data, "phone_breaches", "total_breaches") or 0

        tags = []
        if is_valid:
            tags.append("abstractphone:valid")
        if line_status:
            tags.append(f"abstractphone:line_status:{line_status}")
        if line_type:
            tags.append(f"abstractphone:line_type:{line_type}")
        if risk_level:
            tags.append(f"abstractphone:risk:{risk_level}")
        if is_disposable:
            tags.append("abstractphone:disposable")
        if is_abuse:
            tags.append("abstractphone:abuse")
        if is_voip:
            tags.append("abstractphone:voip")
        if carrier:
            tags.append(f"carrier:{carrier}")
        if country_code:
            tags.append(f"country:{country_code}")
        if region:
            tags.append(f"region:{region}")
        if total_breaches:
            tags.append("abstractphone:breached")

        if is_abuse:
            verdict, raw_score, confidence = "malicious", 0.80, "high"
        elif is_disposable or risk_level == "high":
            verdict, raw_score, confidence = "suspicious", 0.65, "high"
        elif not is_valid:
            # An invalid number yields no intelligence at all; it is not a
            # negative reputation signal.
            verdict, raw_score, confidence = "unknown", 0.0, "low"
        elif risk_level == "medium" or line_status in ("inactive", "not_active", "porting"):
            verdict, raw_score, confidence = "suspicious", 0.35, "medium"
        else:
            verdict, raw_score, confidence = "unknown", 0.0, "low"

        return NormalizedResult(
            ioc=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            verdict=verdict,
            raw_score=raw_score,
            confidence=confidence,
            tags=tags,
            raw_data=data,
            provider_summary=self._summary(data, verdict),
            source_link="https://app.abstractapi.com/api/phone-intelligence",
        )

    def _summary(self, data, verdict: str) -> str:
        parts = []
        risk = _nested(data, "phone_risk", "risk_level")
        if isinstance(risk, str) and risk:
            parts.append(f"risk level {risk}")
        for label, path in (
            ("abuse detected", ("phone_risk", "is_abuse_detected")),
            ("disposable number", ("phone_risk", "is_disposable")),
        ):
            if _nested(data, *path) is True:
                parts.append(label)
        carrier = _nested(data, "phone_carrier", "name")
        if carrier:
            parts.append(f"carrier {carrier}")
        line_type = _nested(data, "phone_carrier", "line_type")
        if line_type:
            parts.append(str(line_type))
        breaches = _nested(data, "phone_breaches", "total_breaches")
        if isinstance(breaches, int) and breaches:
            parts.append(f"{breaches} breach(es)")
        if not parts:
            parts.append("no risk data returned")
        parts.append(f"provider verdict {verdict}")
        return "; ".join(parts)
