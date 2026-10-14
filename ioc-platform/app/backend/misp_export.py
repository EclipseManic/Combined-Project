import uuid
from datetime import datetime, timezone

from app.backend.stix_export import provider_evidence_rows

_MISP_ATTR_TYPE_MAP = {
    "ipv4": "ip-dst",
    "ipv6": "ip-dst",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email": "email-dst",
    "cve": "vulnerability",
}


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _fmt_ts(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def _observed_window(results: list[dict]) -> tuple[str | None, str | None]:
    firsts = [_fmt_ts(r.get("first_seen")) for r in results if r.get("first_seen")]
    lasts = [_fmt_ts(r.get("last_seen")) for r in results if r.get("last_seen")]
    return (min(firsts) if firsts else None, max(lasts) if lasts else None)


def _misp_id(prefix: str = "") -> str:
    return f"{prefix or 'MISP'}--{uuid.uuid4()}"


def _tag_from_verdict(verdict: str) -> str:
    if verdict in {"malicious", "breached", "compromised", "critical", "high"}:
        return "tlp:red"
    if verdict in {"suspicious", "medium", "low"}:
        return "tlp:amber"
    if verdict in {"clean", "benign", "not_breached", "harmless", "whitelisted"}:
        return "tlp:green"
    return "tlp:white"


def build_misp_event(response: dict) -> dict:
    ioc_value = response.get("normalized", response.get("input", ""))
    ioc_type = response.get("ioc_type", "unknown")
    composite = response.get("composite", {})
    assessment = response.get("final_assessment") or {}
    score = assessment.get("normalized_score", composite.get("score", 0))
    verdict = assessment.get("final_verdict", composite.get("verdict", "unknown"))
    results = response.get("results", [])
    enrichment = response.get("enrichment", {})

    event_id = uuid.uuid4().hex
    attributes: list[dict] = []
    objects: list[dict] = []
    evidence_rows = provider_evidence_rows(response)
    window_first, window_last = _observed_window([row for row, _ in evidence_rows])

    attr_id = _misp_id("Attribute")
    attributes.append({
        "id": attr_id,
        "type": _MISP_ATTR_TYPE_MAP.get(ioc_type, "text"),
        "category": "Network activity",
        "value": ioc_value,
        "comment": f"IOC Lookup Platform lookup — {verdict} (score: {score})",
        # Only indicators assessed as threats are flagged for IDS use; a
        # benign/unknown/context result must not end up in detection rules.
        "to_ids": verdict in {"malicious", "suspicious"},
        "timestamp": _ts(),
        "first_seen": window_first,
        "last_seen": window_last,
    })

    # Not-found / rate-limited / unavailable providers are absence of data and
    # are not exported as attributes.
    for r, r_verdict in evidence_rows:
        source = r.get("source", "Unknown")
        r_score = r.get("raw_score", "")

        atype = _MISP_ATTR_TYPE_MAP.get(ioc_type, "text")
        category = "External analysis" if atype in ("md5", "sha1", "sha256") else "Network activity"
        if r_verdict == "malicious":
            category = "Payload delivery"

        attributes.append({
            "id": _misp_id("Attribute"),
            "type": atype,
            "category": category,
            "value": ioc_value,
            "comment": f"{source}: {r_verdict}" + (f" (score: {r_score})" if r_score else ""),
            # Per-provider rows annotate the same value; the IDS flag lives on
            # the assessed attribute above.
            "to_ids": False,
            "timestamp": _ts(),
            "first_seen": _fmt_ts(r.get("first_seen")),
            "last_seen": _fmt_ts(r.get("last_seen")),
        })

    geoip = enrichment.get("geoip", {})
    if geoip and geoip.get("country"):
        obj_id = _misp_id("Object")
        geo_obj = {
            "id": obj_id,
            "name": "geo-ip",
            "meta-category": "network",
            "description": f"GeoIP: {geoip.get('country', '')}",
            "attributes": [],
        }
        if geoip.get("country"):
            geo_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "text", "object_relation": "country",
                "value": geoip["country"],
            })
        if geoip.get("city"):
            geo_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "text", "object_relation": "city",
                "value": geoip["city"],
            })
        if geoip.get("asn"):
            geo_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "text", "object_relation": "asn",
                "value": geoip["asn"],
            })
        objects.append(geo_obj)

    whois = enrichment.get("whois", {})
    if whois and whois.get("registrar"):
        obj_id = _misp_id("Object")
        whois_obj = {
            "id": obj_id,
            "name": "whois",
            "meta-category": "network",
            "description": "WHOIS record",
            "attributes": [],
        }
        if whois.get("registrar"):
            whois_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "text", "object_relation": "registrar",
                "value": whois["registrar"],
            })
        if whois.get("creation_date"):
            whois_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "datetime", "object_relation": "creation-date",
                "value": whois["creation_date"],
            })
        if whois.get("org"):
            whois_obj["attributes"].append({
                "id": _misp_id("Attribute"), "type": "text", "object_relation": "org",
                "value": whois["org"],
            })
        objects.append(whois_obj)

    tags = [_tag_from_verdict(verdict)]
    if assessment:
        tags.extend([
            f"ioc-platform:assessment_domain:{assessment.get('assessment_domain', 'unknown')}",
            f"ioc-platform:final_verdict:{assessment.get('final_verdict', 'unknown')}",
        ])

    event = {
        "Event": {
            "id": event_id,
            "uuid": event_id,
            "info": f"IOC Lookup Platform lookup: {ioc_value} ({ioc_type})",
            "published": False,
            "analysis": 2,
            "timestamp": _ts(),
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "threat_level_id": 1 if verdict in {"malicious", "breached", "compromised", "critical", "high"} else 2 if verdict in {"suspicious", "medium", "low"} else 4,
            "distribution": 3,
            "Tag": [{"name": tag} for tag in tags],
            "Attribute": attributes,
            "Object": objects,
        }
    }
    return event
