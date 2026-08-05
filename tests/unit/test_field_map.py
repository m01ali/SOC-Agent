"""Field-map pass tests. Spec: extraction-04-spec.md §16.4."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from soc_agent.extract.field_map import CONTEXT_ONLY_KEYS, FIELD_MAP, field_map_pass
from soc_agent.models.alert import NormalizationInfo, NormalizedAlert

# The complete spec 03 §8 vocabulary table (context-only keys included).
_SPEC_03_VOCABULARY = {
    "src_ip",
    "dest_ip",
    "src_host",
    "dest_host",
    "host",
    "user",
    "src_user",
    "dest_user",
    "process",
    "process_hash_sha256",
    "process_hash_sha1",
    "process_hash_md5",
    "file_path",
    "url",
    "domain",
    "query",
    "src_port",
    "dest_port",
    "protocol",
    "app",
    "count",
    "bytes_in",
    "bytes_out",
    "action",
    "device_vendor",
    "device_product",
    "device_event_class_id",
}


def _alert(observed_fields: dict[str, str]) -> NormalizedAlert:
    return NormalizedAlert(
        alert_id="soc-agent-test",
        dedupe_key="a" * 64,
        source_system="generic",
        title="test alert",
        severity=50,
        ingested_at=datetime(2026, 7, 20, 12, tzinfo=UTC),
        observed_fields=observed_fields,
        raw={},
        normalization=NormalizationInfo(method="parser", confidence=1.0),
    )


def test_vocabulary_completeness() -> None:
    """Every spec 03 §8 key either has a FIELD_MAP rule or is documented context-only."""
    mapped_keys = {rule.key for rule in FIELD_MAP}
    covered = mapped_keys | CONTEXT_ONLY_KEYS
    missing = _SPEC_03_VOCABULARY - covered
    assert not missing, f"vocabulary keys with no FIELD_MAP rule and not context-only: {missing}"


def test_host_or_domain_fqdn_becomes_domain() -> None:
    alert = _alert({"dest_host": "transfer.example-cloudshare.net"})
    cands, _ = field_map_pass(alert)
    assert cands[0].type == "domain"
    assert cands[0].role == "destination"


def test_host_or_domain_single_label_becomes_host() -> None:
    alert = _alert({"src_host": "WS-FIN-0142"})
    cands, _ = field_map_pass(alert)
    assert cands[0].type == "host"


def test_host_or_domain_unlisted_tld_becomes_host() -> None:
    alert = _alert({"host": "WS.CORP"})
    cands, _ = field_map_pass(alert)
    assert cands[0].type == "host"
    assert cands[0].value == "WS.CORP"


@pytest.mark.parametrize("value", ["", "   ", "-", "unknown", "N/A", "null", "None"])
def test_placeholder_values_produce_nothing(value: str) -> None:
    alert = _alert({"user": value})
    cands, _ = field_map_pass(alert)
    assert cands == []


def test_defanged_field_values_are_refanged() -> None:
    alert = _alert(
        {
            "url": "hxxps://payroll-update[.]example-billing[.]net/login",
            "domain": "payroll-update[.]example-billing[.]net",
        }
    )
    cands, _ = field_map_pass(alert)
    by_type = {c.type: c for c in cands}
    assert by_type["url"].value == "https://payroll-update.example-billing.net/login"
    assert by_type["url"].original_text == "hxxps://payroll-update[.]example-billing[.]net/login"
    assert by_type["domain"].value == "payroll-update.example-billing.net"
    assert by_type["domain"].original_text == "payroll-update[.]example-billing[.]net"


def test_discovery_order_follows_field_map_table_not_dict_order() -> None:
    # Insert keys in reverse vocabulary order; output must still follow FIELD_MAP order.
    alert = _alert({"user": "l.hassan", "dest_ip": "203.0.113.66", "src_ip": "10.20.14.88"})
    cands, _ = field_map_pass(alert)
    assert [c.field for c in cands] == ["src_ip", "dest_ip", "user"]


def test_hash_auto_resolves_by_length() -> None:
    alert = _alert({"file_hash": "a" * 40})
    cands, _ = field_map_pass(alert)
    assert cands[0].type == "hash_sha1"


def test_hash_auto_bad_length_is_dropped() -> None:
    alert = _alert({"file_hash": "not-a-hash"})
    cands, dropped = field_map_pass(alert)
    assert cands == []
    assert dropped["hash_bad_length"] == 1


def test_unmapped_context_only_key_produces_nothing() -> None:
    alert = _alert({"dest_port": "443", "protocol": "tcp"})
    cands, _ = field_map_pass(alert)
    assert cands == []
