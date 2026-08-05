"""Normalizer unit tests: severity, category, CEF parsing, elastic accessor,
dedupe/alert_id, clock injection. Spec: ingestion-03-spec.md §13.2.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from soc_agent.ingest import normalize
from soc_agent.ingest.base import (
    WARN_SEVERITY_DEFAULTED,
    WARN_YEAR_INFERRED,
    IngestContext,
    dedupe_key,
    generated_alert_id,
)
from soc_agent.ingest.category import infer_category
from soc_agent.ingest.errors import NormalizationError
from soc_agent.ingest.normalizers.cef import (
    _infer_year,
    _parse_extension,
    _resolve_custom_labels,
    _split_unescaped,
)
from soc_agent.ingest.normalizers.cef import (
    normalize as cef_normalize,
)
from soc_agent.ingest.normalizers.elastic import dotted_get
from soc_agent.ingest.severity import normalize_severity

FIXTURES_DIR = Path(__file__).parents[2] / "fixtures" / "alerts"
FROZEN_NOW = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)


def _ctx(raw: str = "") -> IngestContext:
    return IngestContext(raw=raw, now=FROZEN_NOW)


# --- severity ----------------------------------------------------------------


@pytest.mark.parametrize(
    "source,value,expected",
    [
        ("generic", "high", 75),
        ("generic", "critical", 95),
        ("splunk", "medium", 50),
        ("splunk", "low", 25),
        ("elastic", "high", 75),
        ("elastic", 47, 47),
        ("cef", "7", 70),
        ("cef", "8", 80),
        ("cef", "Very-High", 95),
        ("cef", "Low", 25),
    ],
)
def test_severity_table(source, value, expected):
    ctx = _ctx()
    severity, _ = normalize_severity(source, value, ctx)
    assert severity == expected


def test_severity_unknown_label_defaults_and_warns():
    ctx = _ctx()
    severity, original = normalize_severity("generic", "bogus-label", ctx)
    assert severity == 50
    assert original == "bogus-label"
    assert WARN_SEVERITY_DEFAULTED in ctx.warnings


def test_severity_none_defaults_and_warns():
    ctx = _ctx()
    severity, original = normalize_severity("generic", None, ctx)
    assert severity == 50
    assert original is None
    assert WARN_SEVERITY_DEFAULTED in ctx.warnings


# --- category ------------------------------------------------------------


def test_category_hex_digest_false_positive_guard():
    """A malware alert whose reason contains 'sha256=4c2fa1e0...' must not match
    the 'c2' keyword via substring — regression guard from spec §7."""
    result = infer_category(
        "Hash matched local blocklist",
        "process pskill.exe on WS-ENG-0231 matched blocklist entry sha256=4c2fa1e0b93f7d6c8",
    )
    assert result == "malware"


def test_category_impossible_travel_not_credential_access():
    result = infer_category(
        "Impossible travel - successful sign-ins from distant locations",
        "user m.silva signed in from two locations 5400 km apart",
        ecs_categories=["authentication"],
    )
    assert result == "initial_access"


def test_category_exfil_not_anomaly():
    result = infer_category("Unusual outbound data volume", "DLP")
    assert result == "exfiltration"


def test_category_bare_unusual_does_not_match_anomaly():
    assert infer_category("Unusual login volume") is None


def test_category_no_match_falls_back_to_ecs():
    result = infer_category("Some generic title", ecs_categories=["network"])
    assert result == "anomaly"


def test_category_no_match_anywhere_returns_none():
    assert infer_category("Totally unrelated title") is None


# --- CEF parsing -----------------------------------------------------------


def test_cef_split_unescaped_handles_escaped_pipe():
    parts = _split_unescaped(r"a\|b|c|d", "|", 2)
    assert parts == ["a|b", "c", "d"]


def test_cef_parse_extension_value_with_spaces():
    ext = _parse_extension("src=1.2.3.4 cs1=admin$ share access cs1Label=detail")
    assert ext["cs1"] == "admin$ share access"
    assert ext["src"] == "1.2.3.4"


def test_cef_parse_extension_escaped_equals():
    ext = _parse_extension(r"msg=key\=value pair act=blocked")
    assert ext["msg"] == "key=value pair"
    assert ext["act"] == "blocked"


def test_cef_resolve_custom_labels():
    resolved = _resolve_custom_labels({"cs1": "admin$ share access", "cs1Label": "detail"})
    assert resolved == {"detail": "admin$ share access"}


def test_cef_resolve_custom_labels_orphan_label_dropped():
    resolved = _resolve_custom_labels({"cs2Label": "orphan"})
    assert resolved == {}


def test_cef_header_too_short_raises():
    ctx = _ctx("CEF:0|Vendor|Product|Test Event|5|src=1.2.3.4")
    with pytest.raises(NormalizationError):
        cef_normalize(ctx)


def test_cef_year_inference_rollback():
    now = datetime(2026, 1, 3, 0, 0, 0, tzinfo=UTC)
    candidate, inferred = _infer_year("Dec 30 23:00:00", now)
    assert inferred is True
    assert candidate.year == 2025


def test_cef_year_inference_same_year():
    now = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
    candidate, inferred = _infer_year("Jul 19 22:31:02", now)
    assert candidate.year == 2026
    assert inferred is True


@pytest.mark.parametrize("fname", ["05_lateral_movement.cef", "09_exfil_volume.cef"])
def test_cef_fixtures_warn_year_inferred(fname):
    raw = (FIXTURES_DIR / fname).read_text()
    alert = normalize(raw, now=FROZEN_NOW)
    assert WARN_YEAR_INFERRED in alert.normalization.warnings


# --- elastic dotted_get ------------------------------------------------------


def test_dotted_get_flat_key():
    doc = {"kibana.alert.rule.name": "flat form"}
    assert dotted_get(doc, "kibana.alert.rule.name") == "flat form"


def test_dotted_get_nested_walk():
    doc = {"kibana": {"alert": {"rule": {"name": "nested form"}}}}
    assert dotted_get(doc, "kibana.alert.rule.name") == "nested form"


def test_dotted_get_missing_returns_default():
    assert dotted_get({}, "a.b.c", default="fallback") == "fallback"


def test_dotted_get_partial_path_not_dict_returns_default():
    doc = {"host": {"name": "WS-1"}}
    assert dotted_get(doc, "host.name.extra", default=None) is None


# --- dedupe_key / alert_id ---------------------------------------------------


def test_dedupe_key_stable_across_line_endings():
    assert dedupe_key("a\r\nb\r\n") == dedupe_key("a\nb\n")


def test_dedupe_key_stable_across_trailing_whitespace():
    assert dedupe_key("payload") == dedupe_key("payload\n\n  ")


def test_dedupe_key_differs_for_different_payloads():
    assert dedupe_key("a") != dedupe_key("b")


def test_dedupe_key_format():
    import re

    assert re.match(r"^[0-9a-f]{64}$", dedupe_key("anything"))


def test_generated_alert_id_deterministic():
    key = dedupe_key("same input")
    assert generated_alert_id(key) == generated_alert_id(key)


# --- clock injection ---------------------------------------------------------


def test_clock_injection_produces_identical_output():
    raw = (FIXTURES_DIR / "01_c2_beacon.json").read_text()
    a = normalize(raw, now=FROZEN_NOW).model_dump(mode="json")
    b = normalize(raw, now=FROZEN_NOW).model_dump(mode="json")
    assert a == b
