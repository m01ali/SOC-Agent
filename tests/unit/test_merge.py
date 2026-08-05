"""Merge, arbitration, derivation, finalization tests. Spec: extraction-04-spec.md §16.5."""

from __future__ import annotations

from datetime import UTC, datetime

from soc_agent.config import get_config
from soc_agent.extract.candidate import Candidate
from soc_agent.extract.merge import derive, merge
from soc_agent.models.alert import NormalizationInfo, NormalizedAlert


def _alert(category: str | None = None) -> NormalizedAlert:
    return NormalizedAlert(
        alert_id="soc-agent-test",
        dedupe_key="a" * 64,
        source_system="generic",
        title="test alert",
        category=category,
        severity=50,
        ingested_at=datetime(2026, 7, 20, 12, tzinfo=UTC),
        observed_fields={},
        raw={},
        normalization=NormalizationInfo(method="parser", confidence=1.0),
    )


def _cfg():
    return get_config().extraction


def test_precedence_field_map_beats_regex_beats_llm() -> None:
    candidates = [
        Candidate(type="ip", value="203.0.113.66", role="unknown", method="llm", order=2),
        Candidate(type="ip", value="203.0.113.66", role="unknown", method="regex", order=1),
        Candidate(
            type="ip",
            value="203.0.113.66",
            role="destination",
            method="field_map",
            field="dest_ip",
            order=0,
        ),
    ]
    entities, dropped = merge(candidates, _alert(), _cfg())
    assert len(entities) == 1
    assert entities[0].provenance.method == "field_map"
    assert entities[0].provenance.field == "dest_ip"
    assert dropped["duplicate"] == 2


def test_role_upgrade_from_lower_precedence() -> None:
    candidates = [
        Candidate(type="ip", value="203.0.113.66", role="unknown", method="field_map", order=0),
        Candidate(type="ip", value="203.0.113.66", role="destination", method="regex", order=1),
    ]
    entities, _ = merge(candidates, _alert(), _cfg())
    assert entities[0].role == "destination"
    assert entities[0].provenance.method == "field_map"


def test_specific_role_never_overwritten() -> None:
    candidates = [
        Candidate(type="ip", value="203.0.113.66", role="source", method="field_map", order=0),
        Candidate(type="ip", value="203.0.113.66", role="destination", method="regex", order=1),
    ]
    entities, _ = merge(candidates, _alert(), _cfg())
    assert entities[0].role == "source"


def test_cross_type_arbitration_process_vs_file_path() -> None:
    candidates = [
        Candidate(
            type="process",
            value="pskill.exe",
            method="field_map",
            field="process",
            order=0,
        ),
        Candidate(
            type="file_path",
            value="pskill.exe",
            method="regex",
            field="description",
            order=1,
        ),
    ]
    entities, dropped = merge(candidates, _alert(), _cfg())
    assert len(entities) == 1
    assert entities[0].type == "process"
    assert dropped["type_conflict"] == 1


def test_url_derives_domain() -> None:
    candidates = [
        Candidate(
            type="url",
            value="https://payroll-update.example-billing.net/login",
            role="destination",
            method="field_map",
            field="url",
            order=0,
        ),
    ]
    derived = derive(candidates, _cfg(), order_start=1)
    assert len(derived) == 1
    assert derived[0].type == "domain"
    assert derived[0].value == "payroll-update.example-billing.net"
    assert derived[0].role == "destination"
    assert derived[0].original_text == "https://payroll-update.example-billing.net/login"

    entities, _ = merge(candidates + derived, _alert(), _cfg())
    types = sorted(e.type for e in entities)
    assert types == ["domain", "url"]


def test_url_derives_ip_for_ip_literal_host() -> None:
    candidates = [
        Candidate(type="url", value="http://203.0.113.66/path", method="field_map", order=0),
    ]
    derived = derive(candidates, _cfg(), order_start=1)
    assert len(derived) == 1
    assert derived[0].type == "ip"
    assert derived[0].value == "203.0.113.66"


def test_email_domain_not_derived_by_default() -> None:
    candidates = [Candidate(type="email", value="a@evil.example.com", method="regex", order=0)]
    derived = derive(candidates, _cfg(), order_start=1)
    assert derived == []


def test_max_entities_cap_drops_lowest_precedence_first() -> None:
    cfg = _cfg().model_copy(update={"max_entities": 1})
    candidates = [
        Candidate(type="ip", value="10.0.0.1", method="field_map", order=0),
        Candidate(type="ip", value="10.0.0.2", method="llm", order=1),
    ]
    entities, dropped = merge(candidates, _alert(), cfg)
    assert len(entities) == 1
    assert entities[0].value == "10.0.0.1"
    assert dropped["entity_cap"] == 1


def test_invalid_entity_is_dropped_not_raised() -> None:
    candidates = [
        Candidate(type="hash_sha256", value="not-a-valid-hash-value", method="regex", order=0),
    ]
    entities, dropped = merge(candidates, _alert(), _cfg())
    assert entities == []
    assert dropped["invalid_value"] == 1


def test_victim_role_refinement_for_credential_access() -> None:
    candidates = [Candidate(type="user", value="admin", role="actor", method="field_map", order=0)]
    entities, _ = merge(candidates, _alert(category="credential_access"), _cfg())
    assert entities[0].role == "target"


def test_default_category_keeps_actor_role() -> None:
    candidates = [
        Candidate(type="user", value="l.hassan", role="actor", method="field_map", order=0)
    ]
    entities, _ = merge(candidates, _alert(category="command_and_control"), _cfg())
    assert entities[0].role == "actor"


def test_output_order_is_discovery_order() -> None:
    candidates = [
        Candidate(type="user", value="a", role="actor", method="field_map", order=5),
        Candidate(type="host", value="b", method="field_map", order=1),
        Candidate(type="ip", value="10.0.0.1", method="field_map", order=3),
    ]
    entities, _ = merge(candidates, _alert(), _cfg())
    assert [e.value for e in entities] == ["b", "10.0.0.1", "a"]
