"""Fixture hygiene + label-contract tests. Spec: data-contracts-02-spec.md §8."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest
import yaml

from soc_agent.models import ExpectedFixture
from soc_agent.models.alert import SourceSystem

FIXTURES_DIR = Path(__file__).parents[2] / "fixtures" / "alerts"

_ALLOWED_EXTERNAL_NETS = [
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
]
_HEX_LENGTHS = {"hash_md5": 32, "hash_sha1": 40, "hash_sha256": 64}
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def _is_allowed_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    if ip.is_private:
        return True
    return any(ip in net for net in _ALLOWED_EXTERNAL_NETS)


def _is_allowed_domain_or_url(value: str) -> bool:
    lowered = value.lower()
    return "example" in lowered or lowered.rstrip("/").endswith((".test", ".invalid"))


def _load_expected_files() -> list[Path]:
    return sorted(FIXTURES_DIR.glob("*.expected.yaml"))


EXPECTED_FILES = _load_expected_files()


def test_ten_fixtures_with_matching_expected_siblings():
    expected_files = _load_expected_files()
    assert len(expected_files) == 10

    all_files = {p for p in FIXTURES_DIR.iterdir() if p.is_file()}
    fixture_files = all_files - set(expected_files)
    assert len(fixture_files) == 10

    expected_stems = {p.name.removesuffix(".expected.yaml") for p in expected_files}
    fixture_stems = {p.stem for p in fixture_files}
    assert expected_stems == fixture_stems


@pytest.mark.parametrize("expected_path", EXPECTED_FILES, ids=lambda p: p.name)
def test_expected_file_parses(expected_path: Path):
    data = yaml.safe_load(expected_path.read_text())
    fixture = ExpectedFixture.model_validate(data)
    assert fixture.format in SourceSystem.__args__


@pytest.mark.parametrize("expected_path", EXPECTED_FILES, ids=lambda p: p.name)
def test_entity_hygiene(expected_path: Path):
    data = yaml.safe_load(expected_path.read_text())
    fixture = ExpectedFixture.model_validate(data)

    for entity in fixture.entities:
        if entity.type == "ip":
            assert _is_allowed_ip(entity.value), f"{expected_path.name}: bad ip {entity.value}"
        elif entity.type in ("domain", "url"):
            assert _is_allowed_domain_or_url(entity.value), (
                f"{expected_path.name}: bad domain/url {entity.value}"
            )
        elif entity.type in _HEX_LENGTHS:
            length = _HEX_LENGTHS[entity.type]
            assert len(entity.value) == length and _HEX_RE.match(entity.value), (
                f"{expected_path.name}: bad hash {entity.value}"
            )


def test_formats_cover_all_source_systems():
    formats = set()
    for expected_path in EXPECTED_FILES:
        data = yaml.safe_load(expected_path.read_text())
        formats.add(ExpectedFixture.model_validate(data).format)
    assert formats == set(SourceSystem.__args__)


def test_all_actions_represented():
    actions = set()
    for expected_path in EXPECTED_FILES:
        data = yaml.safe_load(expected_path.read_text())
        actions.add(ExpectedFixture.model_validate(data).action)
    assert actions == {"escalate", "investigate", "close"}


def test_injection_fixture_forbids_close():
    path = FIXTURES_DIR / "10_injection.expected.yaml"
    data = yaml.safe_load(path.read_text())
    fixture = ExpectedFixture.model_validate(data)
    assert fixture.forbidden_actions == ["close"]
