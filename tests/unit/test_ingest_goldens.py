"""Fixture -> canonical alert golden comparisons. Spec: ingestion-03-spec.md §13.3."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from soc_agent.ingest import normalize

FIXTURES_DIR = Path(__file__).parents[2] / "fixtures" / "alerts"
GOLDENS_DIR = Path(__file__).parents[2] / "tests" / "data" / "normalized"
FROZEN_NOW = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)

_DETERMINISTIC_FIXTURES = [
    "01_c2_beacon.json",
    "03_brute_force.json",
    "04_malware_hash_fp.json",
    "05_lateral_movement.cef",
    "06_impossible_travel.json",
    "07_dns_newdomain.json",
    "08_portscan_noisy.json",
    "09_exfil_volume.cef",
]

# Free-text fixtures, added per extraction-04-spec.md §13.3: replayed from spec 03's
# committed LLM cache so all 10 fixtures normalize inside the API-free default run.
_FREETEXT_FIXTURES = ["02_phishing.txt", "10_injection.txt"]

# §8 canonical vocabulary keys — the interface spec 04's field-map pass keys off.
_VOCABULARY_KEYS = {
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
    "file_hash",
}

# Context-only keys (§8) — carried through but never produce entities.
_PASSTHROUGH_KEYS = {
    "app",
    "count",
    "protocol",
    "action",
    "bytes_in",
    "bytes_out",
    "detail",
    "volume",
    "device_vendor",
    "device_product",
    "device_event_class_id",
    "dest_port_count",
    "src_port",
    "dest_port",
}


def _dump(alert) -> str:
    return json.dumps(alert.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


@pytest.mark.parametrize("fname", _DETERMINISTIC_FIXTURES)
def test_golden_matches(fname: str, pytestconfig: pytest.Config):
    raw = (FIXTURES_DIR / fname).read_text()
    alert = normalize(raw, now=FROZEN_NOW)
    stem = fname.rsplit(".", 1)[0]
    golden_path = GOLDENS_DIR / f"{stem}.json"

    if pytestconfig.getoption("--update-goldens"):
        golden_path.write_text(_dump(alert))
        return

    expected = golden_path.read_text()
    assert _dump(alert) == expected

    labels = yaml.safe_load((FIXTURES_DIR / f"{stem}.expected.yaml").read_text())
    assert alert.category == labels["category"]
    assert alert.source_system == labels["format"]

    for key in alert.observed_fields:
        assert key in _VOCABULARY_KEYS or key in _PASSTHROUGH_KEYS, (
            f"{fname}: undocumented observed_fields key {key!r}"
        )


@pytest.mark.parametrize("fname", _FREETEXT_FIXTURES)
def test_freetext_golden_matches(fname: str, pytestconfig: pytest.Config, monkeypatch):
    """§13.3: forced replay, independent of whether a key is present in this session,
    so the golden stays reproducible for anyone running the default (API-free) suite."""
    monkeypatch.setenv("SOC_AGENT_LLM_CACHE", "replay")
    raw = (FIXTURES_DIR / fname).read_text()
    alert = normalize(raw, now=FROZEN_NOW)
    stem = fname.rsplit(".", 1)[0]
    golden_path = GOLDENS_DIR / f"{stem}.json"

    if pytestconfig.getoption("--update-goldens"):
        golden_path.write_text(_dump(alert))
        return

    expected = golden_path.read_text()
    assert _dump(alert) == expected

    labels = yaml.safe_load((FIXTURES_DIR / f"{stem}.expected.yaml").read_text())
    assert alert.category == labels["category"]
    assert alert.source_system == labels["format"]
