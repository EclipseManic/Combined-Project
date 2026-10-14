"""Provider-independent semantic evidence normalization.

Adapters preserve raw payloads.  This module turns nested detections and
provider metadata into auditable evidence items before scoring.  A provider's
top-level response is never allowed to bypass this step.
"""

import ast
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.backend.adapters.base import NormalizedResult, normalize_provider_verdict


# Structured detection is read from typed fields, never from a substring scan
# of the stringified payload. A numeric value in one of these fields is a
# detection tally (VirusTotal-style ``{"malicious": 12}``); the count itself,
# not the key name, decides promotion.
_POSITIVE_COUNT_FIELDS = frozenset({
    "malicious", "malicious_count", "positives", "detections",
    "detection_count", "detected_count",
})
_SUSPICIOUS_COUNT_FIELDS = frozenset({"suspicious", "suspicious_count"})
# Typed verdict/classification fields whose *value* is normalized through the
# shared provider vocabulary. ``normalize_provider_verdict`` maps exact tokens
# only ("malware"/"phishing" -> malicious), so descriptive prose such as
# "no malware detected" or "trojan removal" resolves to ``unknown`` and never
# promotes.
_VERDICT_FIELDS = frozenset({
    "verdict", "normalized_verdict", "classification", "result",
    "status", "conclusion", "category", "threat_verdict", "detection",
})
_NEGATIVE_VERDICTS = frozenset({"clean", "benign", "harmless", "whitelisted", "undetected"})
# Typed fields that name a detected threat. A non-empty, non-placeholder value
# here is a vendor's positive classification, not free-text prose.
_THREAT_NAME_FIELDS = frozenset({
    "malware_family", "threat_name", "signature", "family", "detection_name",
})
_BENIGN_NAME_VALUES = frozenset({
    "none", "null", "n/a", "na", "-", "unknown", "clean", "benign",
    "undetected", "not detected", "no specific threat detected", "goodware",
})
_SIGNAL_ORDER = {None: 0, "clean": 1, "suspicious": 2, "malicious": 3}


def _jsonish(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return value
    for loader in (json.loads, ast.literal_eval):
        try:
            return loader(text)
        except (ValueError, SyntaxError, TypeError):
            continue
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).lower()


def _value_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key} { _value_text(item) }" for key, item in value.items())
    if isinstance(value, list):
        return " ".join(_value_text(item) for item in value)
    return str(value or "")


def _iter_vendor_payloads(result: NormalizedResult) -> list[tuple[str, Any]]:
    raw = result.raw_data if isinstance(result.raw_data, dict) else {}
    candidates: list[tuple[str, Any]] = []
    for key in ("vendor_intel", "vendor_intelligence", "vendors", "vendor_detections"):
        payload = raw.get(key)
        if isinstance(payload, dict):
            candidates.extend((str(name), value) for name, value in payload.items())
        elif isinstance(payload, list):
            candidates.extend(("vendor", value) for value in payload)
    for tag in result.tags or []:
        match = re.match(r"vendor[_:](?:([^:]+)):\s*(.*)$", str(tag), re.I | re.S)
        if match:
            candidates.append((match.group(1).strip(), _jsonish(match.group(2))))
    return candidates


def _as_count(value: Any) -> int | None:
    """Return a non-negative integer detection tally, or None if not numeric.

    Booleans are rejected here so a ``{"malicious": true}`` flag is not silently
    read as the integer ``1``; boolean detection flags are handled separately in
    :func:`_structured_signal`.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    count = int(value)
    return count if count >= 0 else None


def _structured_signal(payload: Any) -> str | None:
    """Derive a detection signal from typed fields only.

    Returns ``"malicious"``, ``"suspicious"``, ``"clean"`` or ``None`` (no
    structured signal). Never inspects the stringified blob: a signal must come
    from an explicit positive detection COUNT (or boolean flag), a typed verdict
    FIELD whose VALUE normalizes to a malicious/suspicious class, or a typed
    threat-name FIELD carrying a real detection. This is what makes "no malware
    detected", "trojan removal" and ``{"malicious": 0}`` inert.
    """
    if isinstance(payload, list):
        return _reduce_signal(_structured_signal(item) for item in payload)
    if not isinstance(payload, dict):
        return None
    signals: list[str | None] = []
    for key, value in payload.items():
        field = str(key).strip().lower()
        if field in _POSITIVE_COUNT_FIELDS:
            if isinstance(value, bool):
                signals.append("malicious" if value else "clean")
            else:
                count = _as_count(value)
                if count is not None and count > 0:
                    signals.append("malicious")
                elif count == 0:
                    signals.append("clean")
        elif field in _SUSPICIOUS_COUNT_FIELDS:
            if isinstance(value, bool):
                if value:
                    signals.append("suspicious")
            else:
                count = _as_count(value)
                if count is not None and count > 0:
                    signals.append("suspicious")
        elif field in _VERDICT_FIELDS and isinstance(value, str) and value.strip():
            mapped = normalize_provider_verdict(value)
            if mapped == "malicious":
                signals.append("malicious")
            elif mapped == "suspicious":
                signals.append("suspicious")
            elif mapped in _NEGATIVE_VERDICTS:
                signals.append("clean")
        elif field in _THREAT_NAME_FIELDS and isinstance(value, str) and value.strip():
            if value.strip().lower() not in _BENIGN_NAME_VALUES:
                signals.append("malicious")
        elif isinstance(value, (dict, list)):
            signals.append(_structured_signal(value))
    return _reduce_signal(signals)


def _reduce_signal(signals: Any) -> str | None:
    """Collapse many structured signals into the strongest one seen."""
    strongest: str | None = None
    for signal in signals:
        if _SIGNAL_ORDER.get(signal, 0) > _SIGNAL_ORDER.get(strongest, 0):
            strongest = signal
    return strongest


def _classify_payload(payload: Any) -> tuple[str, str, float]:
    """Classify a vendor payload from structured detection signals only.

    The previous implementation ran a keyword regex over the whole stringified
    blob, so a key name (``"malicious": 0``), a benign description ("no malware
    detected", "trojan removal") or a zero count all falsely promoted to a
    malicious detection. Promotion now fires only on a typed positive count, a
    typed verdict value, or a typed threat name.
    """
    signal = _structured_signal(payload)
    if signal == "malicious":
        return "direct_positive", "Nested vendor intelligence records a positive malicious detection (count or verdict field).", 0.9
    if signal == "suspicious":
        return "behavioral", "Nested vendor intelligence records a suspicious detection in a structured field.", 0.65
    if signal == "clean":
        return "weak_negative", "Nested vendor intelligence records a negative (clean/zero-detection) classification.", 0.3
    return "metadata", "Nested vendor metadata was preserved for analyst review.", 0.2


def extract_nested_evidence(result: NormalizedResult) -> list[dict[str, Any]]:
    """Extract structured vendor evidence and deduplicate exact records."""
    seen: dict[str, dict[str, Any]] = {}
    for vendor, payload in _iter_vendor_payloads(result):
        payload = _jsonish(payload)
        evidence_class, reason, confidence = _classify_payload(payload)
        fingerprint = hashlib.sha256(_canonical({"vendor": vendor, "payload": payload}).encode()).hexdigest()
        source_record_id = None
        if isinstance(payload, dict):
            source_record_id = next((str(payload[key]) for key in ("id", "record_id", "link", "url", "sha256_hash") if payload.get(key)), None)
        source_record_id = source_record_id or f"{result.source}:{vendor}:{fingerprint[:16]}"
        item = {
            "evidence_id": f"{result.source}:{fingerprint[:20]}",
            "source": vendor,
            "provider": result.source,
            "provenance_family": f"{result.source}:{vendor}".lower(),
            "source_record_id": source_record_id,
            "record_fingerprint": fingerprint,
            "source_independence_group": vendor.lower(),
            "evidence_hash": hashlib.sha256(_canonical(payload).encode()).hexdigest(),
            "evidence_class": evidence_class,
            "confidence": confidence,
            "contribution_eligible": evidence_class in {"direct_positive", "behavioral", "weak_negative"},
            "reason": reason,
            "observed_at": result.observed_at.isoformat() if result.observed_at else None,
            "source_timestamp": result.source_timestamp.isoformat() if result.source_timestamp else None,
            "details": payload,
        }
        key = item["evidence_hash"]
        if key not in seen:
            seen[key] = item
        else:
            item["duplicate_of"] = seen[key]["evidence_id"]
    return list(seen.values())


def normalize_provider_result(result: NormalizedResult, assessment_domain: str = "ioc_reputation") -> NormalizedResult:
    """Normalize semantics and nested evidence in-place, retaining provenance."""
    result.assessment_domain = assessment_domain
    if assessment_domain == "vulnerability":
        # Some legacy/provider adapters used reputation vocabulary for a CVE
        # record. Preserve that native claim inside raw_data, but prevent it
        # from reaching the canonical provider observation as malicious or
        # suspicious evidence. CVSS/EPSS/severity are assessed separately.
        native_verdict = str(result.provider_verdict or result.verdict or "").strip().lower()
        if native_verdict in {"malicious", "suspicious", "benign", "clean", "harmless", "whitelisted"}:
            raw_payload = result.raw_data if isinstance(result.raw_data, dict) else {}
            raw_payload.setdefault("provider_native_verdict", result.provider_verdict or result.verdict)
            result.raw_data = raw_payload
            result.provider_verdict = "vulnerability_record" if result.execution_state == "success" else result.execution_state
            result.verdict = "unknown"
            result.normalized_verdict = "unknown"
    # Recover HTTP semantics at the shared boundary. A few adapters expose
    # only an ``http_###`` tag and older adapters incorrectly mapped some
    # client errors to not-found.
    if result.http_status is None:
        for tag in result.tags or []:
            match = re.fullmatch(r"http_(\d{3})", str(tag).strip().lower())
            if match:
                result.http_status = int(match.group(1))
                break
    if result.http_status is not None:
        code = int(result.http_status)
        if code == 404:
            result.execution_state = "not_found"
            result.status = "not_found"
        elif code == 429:
            result.execution_state = "rate_limited"
            result.status = "error"
            result.tags = list(dict.fromkeys([*(result.tags or []), "rate_limited"]))
        elif code in {401, 403}:
            result.execution_state = "unavailable"
            result.status = "error"
            result.tags = list(dict.fromkeys([*(result.tags or []), "provider_auth_failure"]))
        elif 400 <= code < 500:
            result.execution_state = "invalid_request"
            result.status = "error"
            result.tags = list(dict.fromkeys([*(result.tags or []), "invalid_request"]))
        elif code >= 500:
            result.execution_state = "error"
            result.status = "error"
            result.tags = list(dict.fromkeys([*(result.tags or []), "provider_http_error"]))
    result.provenance_family = result.provenance_family or result.source
    result.source_independence_group = result.source_independence_group or result.provenance_family
    result.provider_verdict = result.provider_verdict or result.verdict or "unknown"
    result.normalized_verdict = normalize_provider_verdict(result.normalized_verdict or result.verdict)
    raw = result.raw_data if isinstance(result.raw_data, dict) else {}
    detection_ratio = raw.get("detection_ratio")
    if (result.detection_count is None or result.total_engines is None) and isinstance(detection_ratio, str):
        match = re.fullmatch(r"\s*(\d+)\s*/\s*(\d+)\s*", detection_ratio)
        if match:
            result.detection_count = int(match.group(1))
            result.total_engines = int(match.group(2))
    if result.detection_count is None:
        for key in ("malicious", "detection_count", "detections"):
            if isinstance(raw.get(key), (int, float)):
                result.detection_count = int(raw[key])
                break
    if result.total_engines is None:
        counts = [raw.get(key) for key in ("malicious", "suspicious", "harmless", "undetected")]
        if all(isinstance(value, (int, float)) for value in counts if value is not None) and any(value is not None for value in counts):
            result.total_engines = sum(int(value or 0) for value in counts)
    result.source_timestamp = result.source_timestamp or result.last_seen or result.first_seen
    if result.record_fingerprint is None:
        result.record_fingerprint = hashlib.sha256(_canonical({"source": result.source, "ioc": result.ioc, "raw": result.raw_data, "tags": result.tags}).encode()).hexdigest()
    items = extract_nested_evidence(result)
    if items:
        result.evidence_items = items
        positive = [item for item in items if item["evidence_class"] == "direct_positive"]
        suspicious = [item for item in items if item["evidence_class"] in {"behavioral", "direct_positive"}]
        if assessment_domain in {"ioc_reputation", "security_test_artifact"} and result.execution_state == "success":
            if positive and result.normalized_verdict in {"unknown", "not_found", "undetected", "unrated"}:
                result.normalized_verdict = "malicious"
                result.verdict = "malicious"
                result.confidence = "high"
            elif suspicious and result.normalized_verdict in {"unknown", "not_found", "undetected", "unrated"}:
                result.normalized_verdict = "suspicious"
                result.verdict = "suspicious"
                result.confidence = "medium"
        families: list[str] = []
        for item in items:
            details = item.get("details")
            if isinstance(details, dict):
                for key in ("family", "malware_family", "threat_name", "signature", "detection"):
                    value = details.get(key)
                    if isinstance(value, str) and value.strip() and value.strip().lower() not in {x.lower() for x in families}:
                        families.append(value.strip())
            text = _value_text(details)
            for match in re.findall(r"(?:family|malware_family|threat_name|signature|detection)\s*['\"]?[:=]\s*['\"]?([A-Za-z][A-Za-z0-9_. -]{2,40})", text, re.I):
                candidate = match.strip(" '\"")
                if candidate and candidate.lower() not in {x.lower() for x in families}:
                    families.append(candidate)
        if families and not result.malware_family:
            result.malware_family = families[0]
        result.tags = list(dict.fromkeys([*(result.tags or []), f"nested_evidence:{len(items)}"]))
    return result


# ---------------------------------------------------------------------------
# Evidence semantics
#
# A provider's verdict vocabulary is not the same thing as the role its record
# plays for the queried indicator. Infostealer exposure of an IP is context,
# Tor-exit membership is anonymization risk, community votes are crowd
# opinion, and a feed record for ``https://sites.google.com/x`` is not a
# record for ``google.com``. These helpers derive that meaning from typed
# fields / raw_data first and fall back to the legacy ``key: value`` tags that
# older adapters emit.
# ---------------------------------------------------------------------------

CREDENTIAL_IOC_TYPES = frozenset({"email", "username", "password"})
HASH_IOC_TYPES = frozenset({"md5", "sha1", "sha256", "sha512"})
# Sources whose positive record describes credential/infostealer exposure.
EXPOSURE_SOURCES = frozenset({"Hudson Rock", "LeakCheck.io", "HIBP Pwned Passwords"})
# Sources whose positive record means "part of an anonymization network".
ANONYMIZATION_SOURCES = frozenset({"Tor Exit"})
# Email/identity reputation signals (spam reports, disposable mailboxes,
# deliverability risk). They are abuse reputation, not credential exposure.
IDENTITY_REPUTATION_SOURCES = frozenset({"StopForumSpam", "Hunter.io", "AbstractAPI"})

_EXPOSURE_TAGS = frozenset({
    "infostealer_compromised", "compromised_credential", "pwned_password",
    "breached", "pwned", "credential_leak", "leaked_credentials",
})


def _raw(result: NormalizedResult) -> dict:
    return result.raw_data if isinstance(result.raw_data, dict) else {}


def tag_value(tags: Any, *keys: str) -> str | None:
    """Return the value of a legacy ``key:value`` / ``key: value`` tag."""
    wanted = {key.strip().lower() for key in keys}
    for tag in tags or []:
        text = str(tag)
        if ":" not in text:
            continue
        key, value = text.split(":", 1)
        if key.strip().lower() in wanted and value.strip():
            return value.strip()
    return None


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        try:
            return int(float(text))
        except ValueError:
            return None
    return None


def typed_number(result: NormalizedResult, raw_keys: tuple[str, ...], tag_keys: tuple[str, ...] = ()) -> int | None:
    """Read a count from raw_data first, then from legacy tags."""
    raw = _raw(result)
    for key in raw_keys:
        number = _to_int(raw.get(key))
        if number is not None:
            return number
    if tag_keys:
        return _to_int(tag_value(result.tags, *tag_keys))
    return None


def community_votes(result: NormalizedResult) -> dict[str, int] | None:
    """Community (crowd) votes, e.g. VirusTotal ``total_votes``.

    Votes are opinions, not detections; scoring treats them as a weak signal.
    """
    raw = _raw(result)
    nested = raw.get("community_votes") or raw.get("total_votes")
    malicious = harmless = None
    if isinstance(nested, dict):
        malicious = _to_int(nested.get("malicious"))
        harmless = _to_int(nested.get("harmless"))
    if malicious is None:
        malicious = typed_number(result, ("votes_malicious",), ("votes_malicious",))
    if harmless is None:
        harmless = typed_number(result, ("votes_harmless",), ("votes_harmless",))
    if malicious is None and harmless is None:
        return None
    return {"malicious": malicious or 0, "harmless": harmless or 0}


def infostealer_exposure(result: NormalizedResult) -> dict[str, int] | None:
    """Positive credential/infostealer exposure recorded by an exposure source."""
    if result.execution_state != "success":
        return None
    tags = {str(tag).strip().lower() for tag in result.tags or []}
    infections = typed_number(result, ("total_infections", "infections"), ("infections",))
    occurrences = typed_number(result, ("breach_occurrences", "breach_count"), ("breach_occurrences", "breaches"))
    credentials = typed_number(result, ("credentials_at_risk",), ("credentials_at_risk",))
    if credentials is None:
        raw = _raw(result)
        parts = [_to_int(raw.get(key)) for key in ("total_corporate_services", "total_user_services")]
        if any(part is not None for part in parts):
            credentials = sum(part or 0 for part in parts)
    flagged = bool(tags & _EXPOSURE_TAGS) or (infections or 0) > 0 or (occurrences or 0) > 0
    if not flagged and result.source in EXPOSURE_SOURCES:
        flagged = normalize_provider_verdict(result.normalized_verdict or result.verdict) == "malicious"
    if not flagged:
        return None
    exposure = {"infections": infections or 0, "credentials_at_risk": credentials or 0, "occurrences": occurrences or 0}
    if not any(exposure.values()):
        exposure["infections"] = max(0, int(result.reports_count or 0))
    return exposure


def is_anonymization_record(result: NormalizedResult) -> bool:
    """True when the record states the IP is a Tor exit / anonymizer node."""
    if result.execution_state != "success":
        return False
    raw = _raw(result)
    tags = {str(tag).strip().lower() for tag in result.tags or []}
    if raw.get("is_tor") is True or raw.get("isTor") is True or raw.get("tor_exit") is True:
        return True
    if "tor_exit_node" in tags or "tor_exit" in tags:
        return True
    return result.source in ANONYMIZATION_SOURCES and normalize_provider_verdict(result.normalized_verdict or result.verdict) in {"malicious", "suspicious"}


def _strip_url(value: str) -> tuple[str, str]:
    """Return (host, rest) for a URL-ish or bare indicator string."""
    text = value.strip().lower()
    scheme_split = text.split("://", 1)
    body = scheme_split[1] if len(scheme_split) == 2 else text
    host, _, rest = body.partition("/")
    for sep in ("?", "#"):
        if sep in host:
            host, extra = host.split(sep, 1)
            rest = sep + extra + rest
    return host, rest


def _same_indicator(entry: str, ioc: str, ioc_type: str) -> bool:
    candidate = str(entry or "").strip().lower()
    target = str(ioc or "").strip().lower()
    if not candidate or not target:
        return False
    if candidate == target:
        return True
    if ioc_type in {"ipv4", "ipv6"}:
        host, rest = _strip_url(candidate)
        if rest.strip("/"):
            return False
        host = host.strip("[]")
        if host == target:
            return True
        # ThreatFox records ip:port pairs; the port does not change the IP.
        return ioc_type == "ipv4" and host.rsplit(":", 1)[0] == target
    if ioc_type == "domain":
        host, rest = _strip_url(candidate)
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        return host == target and not rest.strip("/")
    if ioc_type == "url":
        return candidate.rstrip("/") == target.rstrip("/")
    return False


def _record_indicators(raw: dict) -> list[str]:
    """Indicator values of the records a search-style provider matched."""
    values: list[str] = []
    for key in ("data", "matches", "records"):
        entries = raw.get(key)
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    value = entry.get("ioc") or entry.get("indicator")
                    if isinstance(value, str) and value.strip():
                        values.append(value.strip())
    if not values and raw.get("_truncated") is True and isinstance(raw.get("_json_fragment"), str):
        values = re.findall(r'"(?:ioc|indicator)"\s*:\s*"((?:[^"\\]|\\.)+)"', raw["_json_fragment"])
        values = [value.replace("\\/", "/") for value in values]
    return values


def indicator_match(result: NormalizedResult, ioc: str, ioc_type: str) -> str:
    """Classify how a provider record relates to the queried indicator.

    ``exact``      the record is about this indicator,
    ``related``    the provider matched other indicators (a URL on this domain,
                   a subdomain, another IP:port) and not this one,
    ``unverified`` the record does not expose enough structure to check; the
                   adapter's own matching is trusted.
    Hash lookups are exact by construction.
    """
    raw = _raw(result)
    declared = raw.get("match_type")
    if isinstance(declared, str) and declared.strip():
        return "exact" if declared.strip().lower() == "exact" else "related"
    if isinstance(raw.get("exact_match"), bool):
        return "exact" if raw["exact_match"] else "related"
    if ioc_type in HASH_IOC_TYPES:
        return "exact"
    if ioc_type not in {"ipv4", "ipv6", "domain", "url"}:
        return "unverified"
    records = _record_indicators(raw)
    if not records:
        return "unverified"
    if any(_same_indicator(value, ioc, ioc_type) for value in records):
        return "exact"
    if raw.get("_truncated") is True:
        # Only a prefix of the payload survived truncation. The adapter lists
        # every non-identical matched record in related_iocs; if that list
        # covers every record it kept, none of them was the indicator itself.
        reports = result.reports_count
        if reports is None or len(result.related_iocs or []) < reports:
            return "unverified"
    return "related"


def _identity_detail(result: NormalizedResult) -> str | None:
    """Short description of an email/identity abuse-reputation finding."""
    raw = _raw(result)
    tags = {str(tag).strip().lower() for tag in result.tags or []}
    parts: list[str] = []
    frequency = typed_number(result, ("frequency",), ("frequency",))
    if frequency:
        parts.append(f"{frequency} spam report{'s' if frequency != 1 else ''}")
    elif "spam_report" in tags:
        parts.append("spam reports")
    disposable = raw.get("disposable") is True or raw.get("is_disposable_email") is True or any(
        tag in tags for tag in ("hunter:disposable", "abstract:disposable_email", "disposable")
    )
    if disposable:
        parts.append("disposable mailbox")
    status = str(raw.get("result") or raw.get("status") or tag_value(result.tags, "hunter:result") or "").strip().lower()
    if status in {"risky", "undeliverable", "invalid"}:
        parts.append(f"{status} address")
    deliverability = str(raw.get("deliverability") or tag_value(result.tags, "deliverability") or "").strip().lower()
    if deliverability in {"risky", "undeliverable"} and f"{deliverability} address" not in parts:
        parts.append(f"{deliverability} address")
    return ", ".join(dict.fromkeys(parts)) or None


def evidence_semantics(result: NormalizedResult, ioc: str, ioc_type: str, assessment_domain: str) -> dict[str, Any]:
    """Describe what a provider record means for this indicator.

    ``kind`` is one of: ``reputation`` (ordinary threat/reputation evidence),
    ``anonymization`` (Tor exit / anonymizer membership: risk context),
    ``exposure_context`` (infostealer/breach exposure for a non-credential
    indicator: context only), ``credential_exposure`` (exposure of the
    credential itself), ``identity_reputation`` (spam/disposable signals).
    """
    semantics: dict[str, Any] = {"kind": "reputation"}
    exposure = infostealer_exposure(result) if result.source in EXPOSURE_SOURCES or ioc_type in CREDENTIAL_IOC_TYPES else None
    if result.source in EXPOSURE_SOURCES:
        semantics["kind"] = "credential_exposure" if ioc_type in CREDENTIAL_IOC_TYPES else "exposure_context"
    elif ioc_type in CREDENTIAL_IOC_TYPES and exposure is not None:
        semantics["kind"] = "credential_exposure"
    elif result.source in ANONYMIZATION_SOURCES:
        semantics["kind"] = "anonymization"
    elif ioc_type in CREDENTIAL_IOC_TYPES and result.source in IDENTITY_REPUTATION_SOURCES:
        semantics["kind"] = "identity_reputation"
    if exposure is not None:
        semantics["exposure"] = exposure
    if semantics["kind"] == "identity_reputation" and result.execution_state == "success":
        detail = _identity_detail(result)
        if detail:
            semantics["detail"] = detail
    if ioc_type in {"ipv4", "ipv6"} and is_anonymization_record(result):
        semantics["anonymization"] = True
    votes = community_votes(result)
    if votes is not None:
        semantics["community_votes"] = votes
    if result.execution_state == "success" and assessment_domain in {"ioc_reputation", "infrastructure"}:
        semantics["match_type"] = indicator_match(result, ioc, ioc_type)
        if semantics["match_type"] == "related":
            examples = [str(value) for value, _ in (result.related_iocs or [])][:3]
            if not examples:
                examples = [value for value in _record_indicators(_raw(result)) if not _same_indicator(value, ioc, ioc_type)][:3]
            semantics["related_examples"] = examples
    return semantics


def evidence_freshness(result: NormalizedResult, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    timestamp = result.source_timestamp or result.last_seen or result.first_seen or result.observed_at
    if timestamp is None:
        return "unavailable"
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    age_days = max(0.0, (now - timestamp.astimezone(timezone.utc)).total_seconds() / 86400)
    if result.stale or age_days > 90:
        return "historical"
    if result.cached:
        return "cached"
    return "fresh"
