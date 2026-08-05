"""Extraction config accessor + internal-range classification.

Spec: extraction-04-spec.md §8.1, §12.

Python's `ipaddress.is_private` classifies the RFC 5737 documentation ranges
(`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) as private. Every "external"
IP in the fixture corpus is drawn from those ranges (Architecture §7.1), so using
`is_private` here would mark all of them internal and silently empty the TI lookup
set on 8 of 10 fixtures. This module uses an explicit range set instead, and the
documentation ranges are deliberately absent from the default.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

from soc_agent.config import ExtractionConfig, get_config
from soc_agent.models import IOC_TYPES, Entity

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def extraction_config() -> ExtractionConfig:
    return get_config().extraction


def internal_ranges(cfg: ExtractionConfig | None = None) -> list[IPNetwork]:
    cfg = cfg or extraction_config()
    return [ipaddress.ip_network(cidr, strict=False) for cidr in cfg.internal_ranges]


def is_internal_ip(value: str, ranges: Sequence[IPNetwork] | None = None) -> bool:
    addr = ipaddress.ip_address(value)
    effective_ranges = ranges if ranges is not None else internal_ranges()
    return any(addr in net for net in effective_ranges if net.version == addr.version)


def ioc_entities(entities: Sequence[Entity]) -> list[Entity]:
    """The subset spec 05 may look up: type in IOC_TYPES and not is_internal."""
    return [e for e in entities if e.type in IOC_TYPES and not e.is_internal]
