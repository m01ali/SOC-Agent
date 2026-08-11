"""ti_seed.yaml integrity and hygiene. Spec: enrichment-05-spec.md §21.1."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest
import yaml

from soc_agent.config import ConfigError
from soc_agent.providers.ti.mock import _parse_seed, load_seed

SEED_PATH = Path(__file__).parents[2] / "data" / "ti_seed.yaml"

_SCORE_BANDS = {
    "malicious": (85, 100),
    "suspicious": (40, 70),
    "clean": (0, 10),
    "unknown": (0, 0),
}

# §6.3 — every row derived from a fixture's expected.yaml `notes:` line.
_EXPECTED = [
    ("ip", "203.0.113.66", "malicious", 95),
    ("url", "https://payroll-update.example-billing.net/login", "malicious", 90),
    ("domain", "payroll-update.example-billing.net", "malicious", 90),
    (
        "hash_sha256",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "malicious",
        95,
    ),
    (
        "hash_sha256",
        "4c2fa1e0b93f7d6c815e2a9d03b46c7f5a8e91d2c30b4f6a7d8e9f0a1b2c3d4e",
        "clean",
        0,
    ),
    ("ip", "198.51.100.77", "suspicious", 60),
    ("domain", "cdn-metrics-sync.example-analytics.net", "suspicious", 60),
    ("ip", "203.0.113.199", "malicious", 90),
    ("domain", "transfer.example-cloudshare.net", "malicious", 85),
    ("url", "sftp://transfer.example-cloudshare.net/upload", "malicious", 85),
    ("ip", "203.0.113.150", "suspicious", 60),
]

# Their labels read "unknown to mock TI" — the corpus needs the `unknown` path covered.
_DELIBERATELY_ABSENT = [
    ("ip", "198.51.100.23"),  # fixture 03
    ("ip", "198.51.100.201"),  # fixture 08
]

_DOC_RANGES = [
    ipaddress.ip_network(cidr) for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$")


@pytest.fixture(scope="module")
def seed():
    return load_seed(str(SEED_PATH))


def test_seed_parses_and_is_nonempty(seed):
    assert len(seed) >= 20


@pytest.mark.parametrize(("etype", "value", "verdict", "score"), _EXPECTED)
def test_expected_entries_present(seed, etype, value, verdict, score):
    entry = seed.get((etype, value.lower()))
    assert entry is not None, f"{etype} {value} missing from the seed"
    assert entry.verdict == verdict
    assert entry.score == score
    assert entry.sources == ["mock"]


@pytest.mark.parametrize(("etype", "value"), _DELIBERATELY_ABSENT)
def test_deliberate_absences(seed, etype, value):
    assert seed.get((etype, value)) is None


def test_every_score_is_inside_its_verdict_band(seed):
    for (etype, value), verdict in seed.items():
        low, high = _SCORE_BANDS[verdict.verdict]
        assert low <= verdict.score <= high, f"{etype} {value}: {verdict.verdict}/{verdict.score}"


def test_out_of_band_score_is_a_config_error():
    payload = {
        "entries": [
            {"type": "ip", "value": "203.0.113.9", "verdict": "clean", "score": 90},
        ]
    }
    with pytest.raises(ConfigError, match="outside the allowed band"):
        _parse_seed(payload, "<test>")


def test_duplicate_entry_is_a_config_error():
    payload = {
        "entries": [
            {"type": "ip", "value": "203.0.113.9", "verdict": "clean", "score": 1},
            {"type": "ip", "value": "203.0.113.9", "verdict": "malicious", "score": 90},
        ]
    }
    with pytest.raises(ConfigError, match="duplicate seed entry"):
        _parse_seed(payload, "<test>")


def test_hygiene_no_real_indicators(seed):
    """Architecture §7.1/§10.3 are binding on the seed, not only on the fixtures."""
    for etype, value in seed:
        if etype == "ip":
            addr = ipaddress.ip_address(value)
            assert any(addr in net for net in _DOC_RANGES), f"{value} is not a documentation IP"
        elif etype == "domain":
            assert value.endswith((".example", ".test", ".invalid")) or "example-" in value, (
                f"{value} is not an invented domain"
            )
        elif etype == "url":
            assert "example-" in value or ".test/" in value, f"{value} is not an invented URL"
        elif etype.startswith("hash_"):
            assert _HASH_RE.match(value), f"{value} is not a plain hex hash"


def test_raw_mirrors_real_provider_shapes(seed):
    """Post-POC adapters populate the same field with similar data (Architecture §7.3)."""
    entry = seed[("ip", "203.0.113.66")]
    assert set(entry.raw["vt"]) == {"malicious", "suspicious", "harmless", "undetected"}
    assert "pulse_count" in entry.raw["otx"]


def test_seed_file_is_valid_yaml_mapping():
    raw = yaml.safe_load(SEED_PATH.read_text())
    assert raw["version"] == 1
    assert raw["defaults"]["sources"] == ["mock"]
