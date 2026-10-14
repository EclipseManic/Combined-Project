import json
from datetime import datetime, timezone

from jsonschema import Draft202012Validator

from app.backend.stix_export import provider_evidence_rows

_ECS_EVENT_SCHEMA = {
    "type": "object",
    "required": ["@timestamp", "event", "threat"],
    "properties": {
        "@timestamp": {"type": "string"},
        "event": {"type": "object"},
        "threat": {"type": "object"},
    },
}


def _validate_ecs_events(events: list[dict]) -> None:
    validator = Draft202012Validator(_ECS_EVENT_SCHEMA)
    for event in events:
        errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
        if errors:
            raise ValueError(f"Invalid ECS event: {errors[0].message}")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _verdict_severity(verdict: str) -> int:
    if verdict in {"malicious", "breached", "compromised", "critical", "high"}:
        return 10
    if verdict == "anonymization":
        return 3
    if verdict in {"suspicious", "medium", "low"}:
        return 6
    if verdict in {"clean", "benign", "not_breached", "harmless", "whitelisted"}:
        return 1
    return 0


def _escape_splunk(val: str) -> str:
    if val is None:
        return ""
    return str(val).replace("=", "\\=").replace('"', '\\"').replace("\n", " ")


def export_splunk(response: dict) -> str:
    ioc_value = response.get("normalized", response.get("input", ""))
    ioc_type = response.get("ioc_type", "unknown")
    composite = response.get("composite", {})
    assessment = response.get("final_assessment") or {}
    score = assessment.get("normalized_score", composite.get("score", 0))
    verdict = assessment.get("final_verdict", composite.get("verdict", "unknown"))
    results = response.get("results", [])

    lines = []
    # Only providers that answered are exported; the per-provider verdict is
    # the provider's assessed role (context is not exported as malicious).
    for r, r_verdict in provider_evidence_rows(response):
        source = r.get("source", "unknown")
        r_score = r.get("raw_score", 0)
        fields = [
            f"source={_escape_splunk(source)}",
            f"ioc_value={_escape_splunk(ioc_value)}",
            f"ioc_type={_escape_splunk(ioc_type)}",
            f"verdict={_escape_splunk(r_verdict)}",
            f"provider_verdict={_escape_splunk(r.get('verdict', 'unknown'))}",
            f"composite_verdict={_escape_splunk(verdict)}",
            f"assessment_domain={_escape_splunk(assessment.get('assessment_domain', 'ioc_reputation'))}",
            f"final_assessment_verdict={_escape_splunk(assessment.get('final_verdict', verdict))}",
            f"raw_score={r_score or ''}",
            f"composite_score={score}",
            f"severity={_verdict_severity(r_verdict)}",
            f"confidence={_escape_splunk(r.get('confidence', ''))}",
            f"malware_family={_escape_splunk(r.get('malware_family', ''))}",
            f"tags={_escape_splunk(';'.join(r.get('tags', [])))}",
            f"mitre_attck={_escape_splunk(';'.join(r.get('mitre_attck', [])))}",
            "index=ioc_platform",
            f"time={_ts()}",
        ]
        lines.append(" ".join(fields))
    return "\n".join(lines)


def export_ecs(response: dict) -> str:
    ioc_value = response.get("normalized", response.get("input", ""))
    ioc_type = response.get("ioc_type", "unknown")
    composite = response.get("composite", {})
    assessment = response.get("final_assessment") or {}
    score = assessment.get("normalized_score", composite.get("score", 0))
    verdict = assessment.get("final_verdict", composite.get("verdict", "unknown"))
    results = response.get("results", [])
    enrichment = response.get("enrichment", {})

    events = []
    base = {
        "@timestamp": _ts(),
        "event": {"kind": "enrichment", "category": ["threat"], "type": ["indicator"]},
        "threat": {"indicator": {"type": ioc_type, "name": ioc_value}},
        "ioc_platform": {
            "composite_score": score,
            "composite_verdict": verdict,
            "assessment_domain": assessment.get("assessment_domain", "ioc_reputation"),
            "final_verdict": assessment.get("final_verdict", verdict),
        },
    }

    geoip = enrichment.get("geoip", {})
    if geoip:
        base["geo"] = {"country_name": geoip.get("country", "")}
        if geoip.get("city"):
            base["geo"]["city_name"] = geoip["city"]
        if geoip.get("asn"):
            base["as"] = {"number": geoip["asn"]}

    for r, r_verdict in provider_evidence_rows(response):
        event = {**base,
            "source": {"address": ioc_value},
            "threat": {
                **base["threat"],
                "indicator": {
                    **base["threat"]["indicator"],
                    "provider": r.get("source", "unknown"),
                },
            },
            "event": {
                **base["event"],
                "severity": _verdict_severity(r_verdict),
            },
            "ioc_platform": {
                **base["ioc_platform"],
                "source": r.get("source", ""),
                "source_verdict": r_verdict,
                "provider_verdict": r.get("verdict", ""),
                "source_score": r.get("raw_score"),
            },
        }
        if r.get("tags"):
            event["tags"] = [t for t in r["tags"] if t]
        if r.get("malware_family"):
            event["malware"] = {"family": r["malware_family"]}
        events.append(event)

    _validate_ecs_events(events)
    return "\n".join(json.dumps(e, default=str) for e in events)


def export_leef(response: dict) -> str:
    ioc_value = response.get("normalized", response.get("input", ""))
    ioc_type = response.get("ioc_type", "unknown")
    composite = response.get("composite", {})
    assessment = response.get("final_assessment") or {}
    score = assessment.get("normalized_score", composite.get("score", 0))
    verdict = assessment.get("final_verdict", composite.get("verdict", "unknown"))
    results = response.get("results", [])

    lines = []
    for r, r_verdict in provider_evidence_rows(response):
        src = r.get("source", "unknown")
        pairs = [
            ("devTime", _ts()),
            ("cat", "IOC Lookup"),
            ("severity", str(_verdict_severity(r_verdict))),
            ("iocValue", ioc_value),
            ("iocType", ioc_type),
            ("source", src),
            ("verdict", r_verdict),
            ("providerVerdict", r.get("verdict", "unknown")),
            ("compositeVerdict", verdict),
            ("assessmentDomain", assessment.get("assessment_domain", "ioc_reputation")),
            ("finalAssessmentVerdict", assessment.get("final_verdict", verdict)),
            ("compositeScore", str(score)),
            ("rawScore", str(r.get("raw_score", ""))),
            ("confidence", r.get("confidence", "")),
            ("malwareFamily", r.get("malware_family", "")),
        ]
        kv = "\t".join(f"{k}={v}" for k, v in pairs)
        lines.append(f"LEEF:2.0|IOC Lookup Platform|ioc-lookup-platform|0.2.0|IOC Lookup|{kv}")
    return "\n".join(lines)


SIEM_FORMATS = {"splunk": export_splunk, "ecs": export_ecs, "leef": export_leef}


def export_siem(response: dict, fmt: str = "splunk") -> str:
    exporter = SIEM_FORMATS.get(fmt)
    if not exporter:
        raise ValueError(f"Unsupported SIEM format: {fmt}. Use: {', '.join(SIEM_FORMATS)}")
    return exporter(response)
