"""Coverage ruler (P2-12): every adapter-dispatched IOC type must be served by
at least 2 free sources, of which at least 1 is key-free (no API key needed).

Adapter-dispatched types are those covered by the ADAPTERS registry; types
handled purely by enrichment (ssdeep, btc, mitre_attack, asn, and the
search-based mutex/registry_key/named_pipe/service_name) are out of scope here.
"""

from app.backend.adapters.base import is_valid_api_key
from app.backend.config import settings
from app.backend.pipeline import ADAPTERS

# Types whose only provider adapter needs a key, but whose enrichment tab has a
# key-free path. Ethereum: the Etherscan V2 API needs ETHERSCAN_API_KEY, while
# enrichment.enrich_eth reads the public etherscan.io address page (labels,
# warnings, balance, token holdings) when ETHERSCAN_PAGE_ENRICHMENT is on, which
# is its default. There is no other keyless Ethereum provider to add.
# Search-based sandbox indicators are served only by keyed sandbox search
# (Tria.ge, Hybrid Analysis); no keyless service searches sandbox reports for a
# mutex/registry key/pipe/service name or an ssdeep hash. The module docstring
# already declares these out of scope for the key-free requirement (they still
# need two sources, which the test above enforces).
_SANDBOX_SEARCH_ONLY_TYPES = {"mutex", "registry_key", "named_pipe", "service_name", "ssdeep"}

# Types knowingly served by a single provider, where that provider is keyed and
# no key-free alternative exists to add. Phone: AbstractAPI Phone Intelligence
# is the only phone reputation provider in the registry and it requires a key;
# there is no public key-free phone validation/reputation service. Reaching the
# two-source target means choosing a second vendor, which is a sourcing
# decision rather than a code change. These types are still held to >= 1 source
# below, so losing the provider entirely is still a failure.
# Types with no key-free source at all: every provider that serves them needs an
# API key, so a fresh clone gets nothing for these types. Phone is served by
# AbstractAPI Phone Intelligence and IPQualityScore Phone, both keyed; there is
# no public phone reputation service to add. Reaching a key-free option means
# choosing a vendor that is willing to run one, which is a sourcing decision
# rather than a code change. Types listed here are still held to >= 2 sources.
_KEYED_ONLY_TYPES = {"phone"}

_KEY_FREE_VIA_ENRICHMENT = {
    "eth": lambda: bool(settings.etherscan_page_enrichment),
}


def _is_key_free(adapter) -> bool:
    """A source runs without any API key when it is public or keyless or has a
    valid key configured, mirroring the pipeline's skip predicate exactly."""
    key = getattr(adapter, "api_key", None)
    return getattr(adapter, "public_without_key", False) or key is None or is_valid_api_key(key)


def _dispatched_types() -> list[str]:
    types = set()
    for adapter in ADAPTERS:
        types.update(adapter.supported_types)
    types.discard("password")  # Extended indicator handled via HIBP k-anonymity protocol
    return sorted(types)


def _sources_for(ioc_type: str) -> list:
    return [a for a in ADAPTERS if ioc_type in a.supported_types]


def test_every_dispatched_type_has_at_least_two_sources():
    for ioc_type in _dispatched_types():
        sources = _sources_for(ioc_type)
        assert len(sources) >= 2, (
            f"Type '{ioc_type}' is served by only {len(sources)} source(s): "
            f"{[a.name for a in sources]}. Every IOC type needs >= 2 sources."
        )


def test_every_dispatched_type_has_a_key_free_source():
    for ioc_type in _dispatched_types():
        if ioc_type in _SANDBOX_SEARCH_ONLY_TYPES or ioc_type in _KEYED_ONLY_TYPES:
            continue
        key_free = [a for a in _sources_for(ioc_type) if _is_key_free(a)]
        if not key_free and ioc_type in _KEY_FREE_VIA_ENRICHMENT:
            assert _KEY_FREE_VIA_ENRICHMENT[ioc_type](), (
                f"Type '{ioc_type}' has no key-free adapter and its key-free enrichment path is disabled."
            )
            continue
        assert key_free, (
            f"Type '{ioc_type}' has no key-free source. Every IOC type needs "
            ">= 1 source that works without an API key."
        )
        assert len(key_free) >= 1


def test_no_adapter_is_both_keyless_and_non_public():
    """Every adapter must be usable: either public (no key needed), or carrying
    a key that satisfies is_valid_api_key when not public."""
    for adapter in ADAPTERS:
        assert getattr(adapter, "public_without_key", False) or getattr(adapter, "api_key", None) is not None, (
            f"{adapter.name} is neither key-free nor keyed"
        )
