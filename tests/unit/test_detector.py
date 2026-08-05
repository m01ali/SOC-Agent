"""Format detector tests. Spec: ingestion-03-spec.md §13.1."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from soc_agent.ingest.base import WARN_UNRECOGNIZED_JSON_STRUCTURE
from soc_agent.ingest.detector import detect_format
from soc_agent.ingest.errors import UnparseableInputError

FIXTURES_DIR = Path(__file__).parents[2] / "fixtures" / "alerts"
_ALERT_FILES = sorted(
    p for p in FIXTURES_DIR.iterdir() if p.is_file() and not p.name.endswith(".expected.yaml")
)


@pytest.mark.parametrize("path", _ALERT_FILES, ids=lambda p: p.name)
def test_detect_matches_expected_label(path: Path):
    expected = yaml.safe_load((FIXTURES_DIR / f"{path.stem}.expected.yaml").read_text())
    result = detect_format(path.read_text())
    assert result.format == expected["format"]


def test_hint_overrides_signatures():
    cef_text = (FIXTURES_DIR / "05_lateral_movement.cef").read_text()
    result = detect_format(cef_text, hint="freetext")
    assert result.format == "freetext"


def test_unrecognized_json_falls_back_to_freetext_with_warning():
    result = detect_format('{"foo": 1}')
    assert result.format == "freetext"
    assert WARN_UNRECOGNIZED_JSON_STRUCTURE in result.warnings


def test_malformed_json_falls_back_to_freetext_no_crash():
    result = detect_format("{oops")
    assert result.format == "freetext"


@pytest.mark.parametrize("raw", ['["a", "b"]', "42", '"just a string"'])
def test_json_list_or_scalar_falls_back_to_freetext(raw: str):
    result = detect_format(raw)
    assert result.format == "freetext"


def test_bare_cef_no_syslog_prefix_detected():
    result = detect_format("CEF:0|Vendor|Product|1.0|100|Test Event|5|src=1.2.3.4")
    assert result.format == "cef"


@pytest.mark.parametrize("raw", ["", "   \n\t  "])
def test_empty_input_raises(raw: str):
    with pytest.raises(UnparseableInputError):
        detect_format(raw)


def test_splunk_signature_wins_over_elastic_when_both_present():
    raw = (
        '{"search_name": "test rule", "@timestamp": "2026-01-01T00:00:00Z", '
        '"kibana.alert.rule.name": "also elastic-shaped"}'
    )
    result = detect_format(raw)
    assert result.format == "splunk"
