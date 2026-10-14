"""Deterministic routing from a validated IOC to an assessment domain.

The router is deliberately independent of provider names.  A provider is
allowed to contribute only after the indicator has been classified and a
domain has been selected.
"""

from dataclasses import dataclass
import re


ASSESSMENT_DOMAINS = {
    "ioc_reputation",
    "vulnerability",
    "attack_technique",
    "security_test_artifact",
    "infrastructure",
    "identity_reputation",
    "artifact_metadata",
    "credential_exposure",
}

_EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
_EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"


@dataclass(frozen=True)
class DomainRoute:
    domain: str
    classification: str
    rationale: str
    recommended_action: str


def route_assessment_domain(ioc_type: str, normalized_ioc: str = "") -> DomainRoute:
    """Return the only semantically valid domain for an IOC type."""
    value = (normalized_ioc or "").strip().lower()
    if ioc_type == "password":
        return DomainRoute(
            "credential_exposure", "breached_credential", "Password credentials are checked for public breach exposure.",
            "Verify if the credential appears in public breach dumps (HIBP) and enforce password reset if compromised.",
        )
    if ioc_type in {"email", "username"}:
        return DomainRoute(
            "identity_reputation", "identity_exposure", "Identity and account identifiers are evaluated for credential breaches and infostealer exposure.",
            "Check for compromised credentials in breach dumps and infostealer malware logs (Hudson Rock, HIBP). Enforce password resets or MFA if breached.",
        )
    if ioc_type == "mac":
        return DomainRoute(
            "identity_reputation", "hardware_context", "Hardware MAC identifiers require local network and vendor contextual intelligence.",
            "Correlate vendor OUI, local network ownership, and device telemetry.",
        )
    if ioc_type == "cve":
        return DomainRoute(
            "vulnerability", "vulnerability_record", "CVE identifiers describe published vulnerabilities.",
            "Review severity, affected products, exploitability, and remediation references.",
        )
    if ioc_type == "mitre_attack":
        return DomainRoute(
            "attack_technique", "technique_metadata", "ATT&CK identifiers describe tactics and techniques.",
            "Review technique metadata, detections, mitigations, and relationships.",
        )
    if ioc_type in {"asn"}:
        return DomainRoute(
            "infrastructure", "infrastructure_context", "Network indicators need reputation plus ownership and infrastructure context.",
            "Enrich ownership, routing, hosting, DNS, and applicable threat feeds.",
        )
    if ioc_type in {"btc", "eth"}:
        chain = "Bitcoin" if ioc_type == "btc" else "Ethereum"
        return DomainRoute(
            "ioc_reputation", "cryptocurrency_wallet",
            f"{chain} wallet addresses are evaluated against public abuse reports and on-chain activity; "
            "the address itself carries no reputation until a source attributes abuse to it.",
            "Check the address against community abuse reports (ChainAbuse) and review on-chain balance and "
            "transaction history for links to known scams, ransomware, or sanctioned entities.",
        )
    if ioc_type in {
        "filename", "windows_path", "linux_path", "mutex", "named_pipe",
        "registry_key", "service_name", "user_agent",
    }:
        return DomainRoute(
            "artifact_metadata", "artifact_or_behavior_context", "This value is an artifact or behavioral token, not a portable reputation object.",
            "Parse structure, correlate with a sample or telemetry, and hash the file when available.",
        )
    if ioc_type in {"md5", "sha1", "sha256", "sha512"} and value in {_EICAR_MD5, _EICAR_SHA1}:
        return DomainRoute(
            "security_test_artifact", "known_security_test_artifact", "The EICAR MD5 identifies an intentional anti-malware test artifact.",
            "Treat detections as expected test behavior, not evidence of live malware.",
        )
    return DomainRoute(
        "ioc_reputation", "reputation", "This indicator can be evaluated against applicable reputation and threat-intelligence sources.",
        "Compare independent direct evidence, negative evidence, context, and freshness.",
    )


def assessment_domain_for(ioc_type: str, normalized_ioc: str = "") -> str:
    return route_assessment_domain(ioc_type, normalized_ioc).domain


def is_attack_identifier(value: str) -> bool:
    return bool(re.fullmatch(r"(?:TA\d{4}|T\d{4}(?:\.\d{3})?)", value.strip(), re.IGNORECASE))
