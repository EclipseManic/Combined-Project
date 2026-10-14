import csv
import io
import uuid
from datetime import datetime, timezone

_STIX_IOC_MAP: dict[str, str] = {
    "ipv4": "ipv4-addr",
    "ipv6": "ipv6-addr",
    "domain": "domain-name",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
    "email": "email-addr",
    "cve": "vulnerability",
}

_HASH_KEYS: dict[str, str] = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
}


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _fmt_ts(value) -> str:
    if value is None:
        return _ts()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return str(value)


def _observed_window(results: list[dict]) -> tuple[str, str]:
    firsts = [_fmt_ts(r.get("first_seen")) for r in results if r.get("first_seen")]
    lasts = [_fmt_ts(r.get("last_seen")) for r in results if r.get("last_seen")]
    return (min(firsts) if firsts else _ts(), max(lasts) if lasts else _ts())


def _stix_id(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


def _execution_state(result: dict) -> str:
    state = result.get("execution_state")
    if state:
        return str(state)
    status = str(result.get("status") or "found")
    if status == "not_found":
        return "not_found"
    if status in {"error", "unavailable", "not_applicable"}:
        return status
    return "success"


def provider_evidence_rows(response: dict) -> list[tuple[dict, str]]:
    """Provider results that actually answered, with their assessed meaning.

    Returns ``(result, effective_verdict)``. Not-found, rate-limited,
    unavailable and other non-answers are dropped: they are absence of data,
    not sightings. When the final assessment is present the provider's role
    in it decides the verdict, so context (infostealer exposure of an IP,
    related-indicator matches, test-artifact detections) is never exported as
    maliciousness, and Tor membership is exported as anonymization.
    """
    assessment = response.get("final_assessment") or {}
    observations = {
        str(item.get("source")): item
        for item in (assessment.get("provider_breakdown") or [])
        if isinstance(item, dict)
    }
    rows: list[tuple[dict, str]] = []
    for result in response.get("results") or []:
        if not isinstance(result, dict) or _execution_state(result) != "success":
            continue
        observation = observations.get(str(result.get("source")))
        if observation is None:
            rows.append((result, str(result.get("verdict") or "unknown")))
            continue
        contribution = observation.get("contribution")
        evidence_class = observation.get("evidence_class")
        if evidence_class == "credential_exposure":
            verdict = "compromised"
        elif contribution == "positive":
            verdict = observation.get("verdict") if observation.get("verdict") in {"malicious", "suspicious"} else "suspicious"
        elif contribution == "context_risk":
            verdict = "anonymization"
        elif contribution == "negative":
            verdict = "benign"
        else:
            verdict = "unknown"
        rows.append((result, verdict))
    return rows


def _verdict_to_labels(verdict: str) -> list[str]:
    if verdict in {"breached", "compromised"}:
        return ["compromised"]
    if verdict == "anonymization":
        return ["anonymization"]
    if verdict in {"malicious", "critical", "high"}:
        return ["malicious-activity"]
    if verdict in {"suspicious", "medium", "low"}:
        return ["suspicious-activity"]
    if verdict in {"clean", "benign", "not_breached", "harmless", "whitelisted"}:
        return ["benign"]
    return ["unknown"]


def _escape_stix(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _build_pattern(value: str, ioc_type: str) -> str:
    esc = _escape_stix(value)
    obj_type = _STIX_IOC_MAP.get(ioc_type, "observed-data")
    if obj_type == "file":
        key = _HASH_KEYS.get(ioc_type, "SHA-256")
        return f"[file:hashes.{key} = '{esc}']"
    if obj_type == "ipv4-addr":
        return f"[ipv4-addr:value = '{esc}']"
    if obj_type == "ipv6-addr":
        return f"[ipv6-addr:value = '{esc}']"
    if obj_type == "domain-name":
        return f"[domain-name:value = '{esc}']"
    if obj_type == "url":
        return f"[url:value = '{esc}']"
    if obj_type == "email-addr":
        return f"[email-addr:value = '{esc}']"
    if obj_type == "vulnerability":
        return f"[vulnerability:name = '{esc}']"
    return f"[observed-data:value = '{esc}']"


def _ioc_to_observable(value: str, ioc_type: str) -> dict:
    obj_type = _STIX_IOC_MAP.get(ioc_type, "observed-data")
    if obj_type == "file":
        key = _HASH_KEYS.get(ioc_type, "SHA-256")
        return {"type": "file", "hashes": {key: value}}
    if obj_type == "email-addr":
        return {"type": "email-addr", "value": value}
    if obj_type == "vulnerability":
        return {"type": "vulnerability", "name": value}
    return {"type": obj_type, "value": value}


def _build_identity(source: str) -> dict:
    return {
        "type": "identity",
        "id": _stix_id("identity"),
        "created": _ts(),
        "modified": _ts(),
        "name": source,
        "identity_class": "organization",
    }


def build_stix_bundle(response: dict) -> dict:
    objects = []
    ioc_value = response.get("normalized", response.get("input", ""))
    ioc_type = response.get("ioc_type", "unknown")
    composite = response.get("composite", {})
    assessment = response.get("final_assessment") or {}
    score = assessment.get("normalized_score", composite.get("score", 0))
    verdict = assessment.get("final_verdict", composite.get("verdict", "unknown"))
    results = response.get("results", [])
    enrichment = response.get("enrichment", {})

    indicator_id = _stix_id("indicator")
    objects.append({
        "type": "indicator",
        "id": indicator_id,
        "created": _ts(),
        "modified": _ts(),
        "name": ioc_value,
        "description": f"{ioc_type} indicator with {verdict} verdict (score: {score})",
        "indicator_types": _verdict_to_labels(verdict),
        "pattern": _build_pattern(ioc_value, ioc_type),
        "pattern_type": "stix",
        "valid_from": _ts(),
        "score": int(score),
    })
    if assessment:
        objects[-1]["x_ioc_platform_assessment"] = {
            "domain": assessment.get("assessment_domain"),
            "verdict": assessment.get("final_verdict"),
            "score": assessment.get("normalized_score"),
            "confidence": assessment.get("confidence"),
        }

    main_obs_id = _stix_id("observed-data")
    window_first, window_last = _observed_window([row for row, _ in provider_evidence_rows(response)])
    objects.append({
        "type": "observed-data",
        "id": main_obs_id,
        "created": _ts(),
        "modified": _ts(),
        "first_observed": window_first,
        "last_observed": window_last,
        "number_observed": 1,
        "objects": {"0": _ioc_to_observable(ioc_value, ioc_type)},
    })

    relationship_ids: list[str] = []
    evidence_rows = provider_evidence_rows(response)
    for r, effective_verdict in evidence_rows:
        source_name = r.get("source", "Unknown")
        r_indicator_id = _stix_id("indicator")
        # The label follows what the provider's record means in the final
        # assessment; confidence never promotes a record to malicious-activity.
        indicator_types = _verdict_to_labels(effective_verdict)

        objects.append({
            "type": "indicator",
            "id": r_indicator_id,
            "created": _ts(),
            "modified": _ts(),
            "name": f"{ioc_value} — {source_name}",
            "description": f"{source_name}: {effective_verdict} (provider verdict: {r.get('verdict', 'unknown')}, score: {r.get('raw_score', 'N/A')})",
            "indicator_types": indicator_types,
            "pattern": _build_pattern(ioc_value, ioc_type),
            "pattern_type": "stix",
            "valid_from": _ts(),
        })

        identity = _build_identity(source_name)
        objects.append(identity)

        r_obs_id = _stix_id("observed-data")
        objects.append({
            "type": "observed-data",
            "id": r_obs_id,
            "created": _ts(),
            "modified": _ts(),
            "first_observed": _fmt_ts(r.get("first_seen")),
            "last_observed": _fmt_ts(r.get("last_seen")),
            "number_observed": 1,
            "objects": {"0": _ioc_to_observable(ioc_value, ioc_type)},
        })

        for src_ref, tgt_ref, rtype in [(r_indicator_id, r_obs_id, "indicates"), (identity["id"], r_indicator_id, "attributed-to")]:
            rel_id = _stix_id("relationship")
            objects.append({
                "type": "relationship",
                "id": rel_id,
                "created": _ts(),
                "modified": _ts(),
                "relationship_type": rtype,
                "source_ref": src_ref,
                "target_ref": tgt_ref,
                "description": f"{source_name}: {effective_verdict}",
            })
            relationship_ids.append(rel_id)

    # A sighting counts only providers that actually reported this indicator
    # as malicious/suspicious; not-found and unavailable providers are not
    # sightings.
    sighting_count = len([1 for _, effective_verdict in evidence_rows if effective_verdict in {"malicious", "suspicious"}])
    if sighting_count:
        objects.append({
            "type": "sighting",
            "id": _stix_id("sighting"),
            "created": _ts(),
            "modified": _ts(),
            "sighting_of_ref": indicator_id,
            "where_sighted_refs": [],
            "count": sighting_count,
            "summary": True,
        })

    geoip = enrichment.get("geoip", {})
    if geoip and geoip.get("country"):
        loc_id = _stix_id("location")
        objects.append({
            "type": "location",
            "id": loc_id,
            "created": _ts(),
            "modified": _ts(),
            "country": geoip["country"],
            "administrative_area": geoip.get("city", ""),
        })
        for obj in objects:
            if obj["type"] == "sighting" and obj["sighting_of_ref"] == indicator_id:
                obj["where_sighted_refs"].append(loc_id)
                break

    for rel in response.get("relationships", []):
        rel_id = _stix_id("relationship")
        objects.append({
            "type": "relationship",
            "id": rel_id,
            "created": _ts(),
            "modified": _ts(),
            "relationship_type": rel.get("relationship", "related-to"),
            "source_ref": indicator_id,
            "target_ref": main_obs_id,
            "description": f"{rel.get('source_ioc', '')} → {rel.get('target_ioc', '')} via {rel.get('via_source', '')}",
        })

    objects.append({
        "type": "identity",
        "id": _stix_id("identity"),
        "created": _ts(),
        "modified": _ts(),
        "name": "IOC Lookup Platform",
        "identity_class": "system",
    })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _csv_safe(value):
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def results_to_csv(results: list[dict]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Source", "IOC Type", "Verdict", "Score", "Confidence", "Malware Family",
                     "Reports Count", "Tags", "Categories", "MITRE ATT&CK", "Source Link"])
    for r in results:
        writer.writerow([
            _csv_safe(r.get("source", "")), _csv_safe(r.get("ioc_type", "")), _csv_safe(r.get("verdict", "")),
            _csv_safe(r.get("raw_score", "")), _csv_safe(r.get("confidence", "")), _csv_safe(r.get("malware_family", "")),
            _csv_safe(r.get("reports_count", "")), _csv_safe("; ".join(r.get("tags", []))),
            _csv_safe("; ".join(r.get("categories", []))), _csv_safe("; ".join(r.get("mitre_attck", []))),
            _csv_safe(r.get("source_link", "")),
        ])
    return output.getvalue()
