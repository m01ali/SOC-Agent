"""Catalog integrity and tactic resolution. Spec: attack-mapping-06-spec.md §19.1."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_agent.attack.catalog import (
    CATALOG_SCHEMA,
    CATEGORY_TACTICS,
    catalog_from_dict,
    load_catalog,
)
from soc_agent.config import ConfigError
from soc_agent.models.attack import TECHNIQUE_ID_PATTERN

CATALOG_PATH = str(Path(__file__).parents[2] / "data" / "attack_catalog.json")

# Every technique labeled anywhere in fixtures/alerts/*.expected.yaml.
FIXTURE_TECHNIQUES = [
    "T1071.001",
    "T1573",
    "T1566.002",
    "T1204.001",
    "T1110",
    "T1021.002",
    "T1078",
    "T1071.004",
    "T1046",
    "T1048",
    "T1059.001",
]


@pytest.fixture(scope="module")
def catalog():
    return load_catalog(CATALOG_PATH)


def test_catalog_loads_with_expected_scale(catalog):
    assert 600 <= len(catalog.techniques) <= 800
    assert len(catalog.tactics) == 15
    assert catalog.bundle_version != "unknown"


def test_every_technique_is_well_formed(catalog):
    import re

    pattern = re.compile(TECHNIQUE_ID_PATTERN)
    for technique_id, technique in catalog.techniques.items():
        assert pattern.match(technique_id), technique_id
        assert technique.name
        assert technique.tactics, f"{technique_id} has no tactic"
        for tactic_id in technique.tactics:
            assert tactic_id in catalog.tactics
        if technique.parent_id is not None:
            assert technique.parent_id in catalog.techniques


@pytest.mark.parametrize("technique_id", FIXTURE_TECHNIQUES)
def test_fixture_labeled_techniques_are_present(catalog, technique_id):
    """A rebuild that drops one of these fails here, not in the metric."""
    assert technique_id in catalog


def test_subtechnique_names_are_composed(catalog):
    """§4.2 — STIX stores 'Web Protocols'; Appendix B uses the composed form."""
    assert catalog.techniques["T1071.001"].name == "Application Layer Protocol: Web Protocols"
    assert catalog.techniques["T1071"].name == "Application Layer Protocol"
    assert catalog.techniques["T1021.002"].name.startswith("Remote Services:")


def test_summaries_are_cleaned_and_capped(catalog):
    for technique_id, technique in catalog.techniques.items():
        assert len(technique.summary) <= 401, technique_id  # 400 + optional ellipsis
        assert "(Citation:" not in technique.summary
        assert "](" not in technique.summary
        assert "<code>" not in technique.summary


def test_no_revoked_or_deprecated_ids(catalog):
    """T1015 (Accessibility Features) was revoked in favour of T1546.008 — a valid-looking
    ID that must not be selectable (§4.1)."""
    assert "T1015" not in catalog
    assert "T1546.008" in catalog


# -- tactic resolution (§5) --------------------------------------------------


def test_multi_tactic_technique_prefers_the_category(catalog):
    """T1078 belongs to four tactics; the alert category is what disambiguates."""
    assert len(catalog.techniques["T1078"].tactics) > 1
    tactic_id, name = catalog.resolve_tactic("T1078", "initial_access")
    assert tactic_id == "TA0001"
    assert name == catalog.tactics["TA0001"]


def test_category_hint_is_a_preference_not_an_override(catalog):
    """T1046 + reconnaissance -> TA0007 Discovery, NOT TA0043 Reconnaissance.

    Scanning ports on a host you already reached is Discovery; ATT&CK reserves
    Reconnaissance for pre-compromise activity. The fallback getting this right is the
    reason the hint is a preference.
    """
    assert CATEGORY_TACTICS["reconnaissance"] == "TA0043"
    tactic_id, name = catalog.resolve_tactic("T1046", "reconnaissance")
    assert tactic_id == "TA0007"
    assert name == "Discovery"


def test_unhinted_category_falls_back_to_first_phase(catalog):
    tactic_id, _ = catalog.resolve_tactic("T1204.001", "phishing")
    assert tactic_id == "TA0002"  # Execution, the technique's own only phase


def test_resolve_tactic_on_unknown_technique(catalog):
    assert catalog.resolve_tactic("T9999", "malware") == (None, None)


@pytest.mark.parametrize(
    ("technique_id", "category", "expected"),
    [
        ("T1071.001", "command_and_control", "TA0011"),
        ("T1573", "command_and_control", "TA0011"),
        ("T1566.002", "phishing", "TA0001"),
        ("T1110", "credential_access", "TA0006"),
        ("T1021.002", "lateral_movement", "TA0008"),
        ("T1071.004", "command_and_control", "TA0011"),
        ("T1048", "exfiltration", "TA0010"),
        ("T1059.001", "malware", "TA0002"),
    ],
)
def test_tactic_resolution_across_the_corpus(catalog, technique_id, category, expected):
    assert catalog.resolve_tactic(technique_id, category)[0] == expected


# -- validation --------------------------------------------------------------


def _minimal() -> dict:
    return {
        "schema": CATALOG_SCHEMA,
        "tactics": {"TA0011": "Command and Control"},
        "techniques": {"T1071": {"name": "X", "tactics": ["TA0011"], "parent_id": None}},
    }


def test_bad_schema_is_rejected():
    payload = _minimal() | {"schema": "something-else"}
    with pytest.raises(ConfigError, match="expected schema"):
        catalog_from_dict(payload)


def test_dangling_parent_is_rejected():
    payload = _minimal()
    payload["techniques"]["T1071.001"] = {
        "name": "Y",
        "tactics": ["TA0011"],
        "parent_id": "T9999",
    }
    with pytest.raises(ConfigError, match="dangling parent"):
        catalog_from_dict(payload)


def test_unknown_tactic_reference_is_rejected():
    payload = _minimal()
    payload["techniques"]["T1071"]["tactics"] = ["TA9999"]
    with pytest.raises(ConfigError, match="unknown tactic"):
        catalog_from_dict(payload)


def test_bad_technique_id_is_rejected():
    payload = _minimal()
    payload["techniques"]["NOT-AN-ID"] = {"name": "Z", "tactics": ["TA0011"]}
    with pytest.raises(ConfigError, match="invalid technique id"):
        catalog_from_dict(payload)


def test_missing_file_names_the_make_target(tmp_path):
    with pytest.raises(ConfigError, match="make catalog"):
        load_catalog(str(tmp_path / "absent.json"))


def test_committed_catalog_is_valid_json_with_stable_key_order():
    payload = json.loads(Path(CATALOG_PATH).read_text())
    assert payload["schema"] == CATALOG_SCHEMA
    assert list(payload["techniques"]) == sorted(payload["techniques"])
