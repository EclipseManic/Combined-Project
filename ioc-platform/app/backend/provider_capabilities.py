"""Provider capability declarations and deterministic query planning."""

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from app.backend.domain_router import assessment_domain_for


@dataclass(frozen=True)
class ProviderCapability:
    provider: str
    supported_types: tuple[str, ...]
    operations: tuple[str, ...] = ("lookup",)
    evidence_roles: tuple[str, ...] = ("threat",)
    provenance_family: str = "independent"
    source_independence_group: str = "independent"
    reliability: float = 0.5
    direct_threat_evidence: bool = False
    reputation: bool = False
    vulnerability_intelligence: bool = False
    infrastructure_context: bool = False
    metadata: bool = False
    relationship_information: bool = False
    rate_limit_policy: dict[str, Any] = field(default_factory=dict)
    retry_policy: dict[str, Any] = field(default_factory=dict)
    cache_policy: dict[str, Any] = field(default_factory=dict)

    def supports(self, ioc_type: str, domain: str, operation: str = "lookup") -> bool:
        if ioc_type not in self.supported_types or operation not in self.operations:
            return False
        if domain == "credential_exposure":
            return self.provider == "HIBP Pwned Passwords"
        if self.provider == "HIBP Pwned Passwords":
            return domain == "credential_exposure" or ioc_type == "password"
        if domain == "vulnerability":
            return self.vulnerability_intelligence
        if domain == "attack_technique":
            return self.metadata or self.relationship_information
        if domain == "artifact_metadata":
            return self.metadata or self.infrastructure_context
        if domain in {"infrastructure", "identity_reputation"}:
            return self.reputation or self.infrastructure_context or self.metadata
        if domain == "security_test_artifact":
            return self.reputation or self.metadata
        # Infrastructure providers are applicable to reputation-oriented IP
        # lookups as context sources, even though their observations never
        # contribute maliciousness by themselves.
        return self.reputation or self.direct_threat_evidence or self.infrastructure_context or self.metadata


@dataclass(frozen=True)
class ProviderPlanItem:
    provider: str
    ioc_type: str
    assessment_domain: str
    applicable: bool
    operation: str = "lookup"
    reason: str = ""
    capability: ProviderCapability | None = None

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.capability:
            data["capability"] = asdict(self.capability)
        return data


def capability_for(adapter: Any) -> ProviderCapability:
    """Build a capability declaration from an adapter, with safe defaults."""
    config = getattr(adapter, "rate_limit", None)
    name = getattr(adapter, "name", adapter.__class__.__name__)
    context_sources = {"GreyNoise", "IPinfo", "Shodan", "Censys", "Team Cymru", "Tor Exit"}
    vulnerability_sources = {"CVE", "cve.org", "NVD"}
    direct_sources = {"ThreatFox", "MalwareBazaar", "URLhaus", "OpenPhish", "Tria.ge", "Hybrid Analysis"}
    direct_value = getattr(adapter, "direct_threat_evidence", None)
    reputation_value = getattr(adapter, "produces_reputation", None)
    vulnerability_value = getattr(adapter, "produces_vulnerability_intelligence", None)
    infrastructure_value = getattr(adapter, "produces_infrastructure_context", None)
    metadata_value = getattr(adapter, "produces_metadata", None)
    relationships_value = getattr(adapter, "produces_relationships", None)
    return ProviderCapability(
        provider=name,
        supported_types=tuple(getattr(adapter, "supported_types", ()) or ()),
        operations=tuple(getattr(adapter, "operations", ("lookup",)) or ("lookup",)),
        evidence_roles=tuple(getattr(adapter, "evidence_roles", ("threat",)) or ("threat",)),
        provenance_family=getattr(adapter, "provenance_family", "abuse_ch_feeds" if name in {"ThreatFox", "MalwareBazaar", "URLhaus"} else name.lower()),
        source_independence_group=getattr(adapter, "source_independence_group", "infrastructure" if name in context_sources else name.lower()),
        reliability=float(getattr(adapter, "reliability", 0.5)),
        direct_threat_evidence=bool(direct_value if direct_value is not None else name in direct_sources),
        reputation=bool(reputation_value if reputation_value is not None else name not in context_sources and name not in vulnerability_sources),
        vulnerability_intelligence=bool(vulnerability_value if vulnerability_value is not None else name in vulnerability_sources),
        infrastructure_context=bool(infrastructure_value if infrastructure_value is not None else name in context_sources),
        metadata=bool(metadata_value if metadata_value is not None else name in context_sources or name in vulnerability_sources),
        relationship_information=bool(relationships_value if relationships_value is not None else False),
        rate_limit_policy={
            "requests_per_minute": getattr(config, "requests_per_minute", 0),
            "requests_per_day": getattr(config, "requests_per_day", 0),
            "concurrency_limit": getattr(config, "concurrency_limit", 1),
            "minimum_interval_seconds": getattr(config, "minimum_interval_seconds", 0.0),
        },
        retry_policy={
            "max_retries": getattr(config, "max_retries", 0),
            "backoff_factor": getattr(config, "backoff_factor", 0.0),
            "max_backoff_seconds": getattr(config, "max_backoff_seconds", 0.0),
        },
        cache_policy={"ttl_seconds": getattr(config, "cache_ttl_seconds", None)},
    )


def build_provider_plan(
    adapters: Iterable[Any],
    ioc_type: str,
    normalized_ioc: str = "",
    *,
    operation: str = "lookup",
    include_not_applicable: bool = True,
) -> list[ProviderPlanItem]:
    domain = assessment_domain_for(ioc_type, normalized_ioc)
    plan: list[ProviderPlanItem] = []
    for adapter in sorted(adapters, key=lambda item: getattr(item, "name", "").lower()):
        capability = capability_for(adapter)
        applicable = capability.supports(ioc_type, domain, operation)
        reason = "Applicable capability" if applicable else f"{capability.provider} does not support {ioc_type}/{domain}"
        if applicable or include_not_applicable:
            plan.append(ProviderPlanItem(capability.provider, ioc_type, domain, applicable, operation, reason, capability))
    return plan
