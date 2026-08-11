"""Threat-intel provider protocol and lookup keys. Spec: enrichment-05-spec.md §5.

The dummy -> real seam (Architecture §5.3): a VirusTotal/OTX/AbuseIPDB adapter
implements `lookup` and nothing else changes.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from soc_agent.extract.merge import canonical_value
from soc_agent.models import IOC_TYPES, Entity, TIVerdict


class TIProviderError(RuntimeError):
    """A provider-level failure: the lookup did not happen.

    Distinct from an `unknown` verdict, which means the lookup *did* happen and no
    source had an opinion (§5). Collapsing the two would make a dead provider
    indistinguishable from a clean environment.
    """


@runtime_checkable
class ThreatIntelProvider(Protocol):
    name: str

    async def lookup(self, entity: Entity) -> TIVerdict:
        """Dispatch on entity.type: ip | domain | url | hash_md5 | hash_sha1 | hash_sha256."""
        ...

    def supports(self, entity: Entity) -> bool:
        """False for types this provider cannot answer (e.g. an IP-only reputation feed)."""
        ...


def lookup_key(entity: Entity) -> tuple[str, str]:
    """(type, canonical value) — the provider index key and the cache key half (§5.1).

    `canonical_value` is spec 04's dedupe canonicalization, imported rather than
    re-implemented: a second copy would let the extraction dedupe key and the TI
    cache key drift apart, and the first symptom would be a cache that never hits
    on IPv6.
    """
    return entity.type, canonical_value(entity.type, entity.value)


def supports_ioc_types(entity: Entity) -> bool:
    """The default `supports`: anything in IOC_TYPES (spec 02 §4.4)."""
    return entity.type in IOC_TYPES
