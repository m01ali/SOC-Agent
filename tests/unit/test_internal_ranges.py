"""Internal-range classification + ioc_entities filter. Spec: extraction-04-spec.md §16.3."""

from __future__ import annotations

import ipaddress

from soc_agent.extract.config import internal_ranges, ioc_entities, is_internal_ip
from soc_agent.models import Entity, EntityProvenance


def _entity(**kwargs) -> Entity:
    defaults = dict(
        type="ip",
        value="1.2.3.4",
        role="unknown",
        confidence=1.0,
        provenance=EntityProvenance(method="field_map"),
    )
    defaults.update(kwargs)
    return Entity(**defaults)


def test_documentation_ranges_are_external() -> None:
    """The regression guard: ipaddress.is_private classifies RFC 5737 documentation
    ranges as private, which would silently empty the TI lookup set on 8 of 10
    fixtures (§8.1). Any implementation using is_private fails here."""
    assert is_internal_ip("203.0.113.66") is False
    assert is_internal_ip("198.51.100.23") is False
    assert is_internal_ip("192.0.2.1") is False


def test_private_and_reserved_ranges_are_internal() -> None:
    internal_ips = [
        "10.20.14.88",
        "172.16.5.5",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.1.1",
    ]
    for ip in internal_ips:
        assert is_internal_ip(ip) is True, ip
    for ip in ["::1", "fe80::1", "fc00::1"]:
        assert is_internal_ip(ip) is True, ip


def test_public_ip_is_external() -> None:
    assert is_internal_ip("8.8.8.8") is False


def test_custom_internal_ranges_override_default() -> None:
    custom = [ipaddress.ip_network("203.0.113.0/24")]
    assert is_internal_ip("203.0.113.66", custom) is True
    assert is_internal_ip("198.51.100.23", custom) is False


def test_internal_ranges_from_config_defaults() -> None:
    ranges = internal_ranges()
    assert any(str(net) == "10.0.0.0/8" for net in ranges)


def test_ioc_entities_excludes_internal_ips() -> None:
    entities = [
        _entity(type="ip", value="203.0.113.66", is_internal=False),
        _entity(type="ip", value="10.20.14.88", is_internal=True),
    ]
    result = ioc_entities(entities)
    assert [e.value for e in result] == ["203.0.113.66"]


def test_ioc_entities_excludes_non_ioc_types() -> None:
    entities = [
        _entity(type="user", value="l.hassan", is_internal=None),
        _entity(type="host", value="WS-FIN-0142", is_internal=None),
        _entity(type="process", value="powershell", is_internal=None),
        _entity(type="file_path", value="invoice.xlsm", is_internal=None),
        _entity(
            type="domain",
            value="evil.example.com",
            is_internal=None,
        ),
    ]
    result = ioc_entities(entities)
    assert [e.type for e in result] == ["domain"]


def test_ioc_entities_empty_when_no_external_iocs() -> None:
    """Fixture 05 (lateral movement) has no external IOCs at all."""
    entities = [
        _entity(type="ip", value="10.20.14.88", is_internal=True),
        _entity(type="ip", value="10.20.30.12", is_internal=True),
        _entity(type="host", value="WS-FIN-0142", is_internal=None),
        _entity(type="host", value="FS-CORP-03", is_internal=None),
        _entity(type="user", value="l.hassan", is_internal=None),
    ]
    assert ioc_entities(entities) == []
