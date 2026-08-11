"""Multi-provider aggregation and the summary. Spec: enrichment-05-spec.md §21.3."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from soc_agent.models import TISummary, TIVerdict
from soc_agent.providers.ti.aggregate import VERDICT_RANK, aggregate_verdicts, summarize
from tests.unit.test_ti_mock import make_entity


def verdict(label: str, score: int, **kwargs) -> TIVerdict:
    return TIVerdict(verdict=label, score=score, **kwargs)


def test_max_score_wins_and_carries_its_own_verdict():
    entity = make_entity("ip", "203.0.113.66")
    result = aggregate_verdicts(
        entity,
        [("a", verdict("suspicious", 55)), ("b", verdict("malicious", 92))],
    )
    assert result.score == 92
    assert result.verdict == "malicious"


def test_rejected_policy_worst_label_does_not_win():
    """§7.1: a `malicious`/20 must not overrule a `clean`/95.

    Pinned so a future "worst label wins" rewrite fails here rather than shipping
    output where a malicious verdict carries a score below the investigate band.
    """
    entity = make_entity("ip", "203.0.113.66")
    result = aggregate_verdicts(
        entity, [("a", verdict("malicious", 20)), ("b", verdict("clean", 95))]
    )
    assert result.score == 95
    assert result.verdict == "clean"


def test_score_tie_breaks_on_severity_rank():
    entity = make_entity("ip", "203.0.113.66")
    result = aggregate_verdicts(entity, [("a", verdict("clean", 0)), ("b", verdict("unknown", 0))])
    assert result.verdict == "unknown"


def test_sources_tags_and_raw_are_unioned():
    entity = make_entity("domain", "transfer.example-cloudshare.net")
    result = aggregate_verdicts(
        entity,
        [
            ("a", verdict("malicious", 90, sources=["a"], tags=["exfil", "c2"], raw={"x": 1})),
            ("b", verdict("suspicious", 50, sources=["b"], tags=["c2", "tor"], raw={"y": 2})),
        ],
    )
    assert result.sources == ["a", "b"]
    assert result.tags == ["exfil", "c2", "tor"]  # first-seen order, deduplicated
    assert result.raw == {"a": {"x": 1}, "b": {"y": 2}}


def test_first_seen_is_min_and_last_seen_is_max():
    entity = make_entity("ip", "203.0.113.66")
    early, late = datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 7, 1, tzinfo=UTC)
    result = aggregate_verdicts(
        entity,
        [
            ("a", verdict("malicious", 90, first_seen=late, last_seen=late)),
            ("b", verdict("suspicious", 50, first_seen=early, last_seen=early)),
        ],
    )
    assert result.first_seen == early
    assert result.last_seen == late


def test_error_survives_only_when_every_provider_failed():
    entity = make_entity("ip", "203.0.113.66")
    partial = aggregate_verdicts(
        entity,
        [("a", verdict("unknown", 0, error="boom")), ("b", verdict("malicious", 90))],
    )
    assert partial.error is None

    total = aggregate_verdicts(
        entity,
        [("a", verdict("unknown", 0, error="boom")), ("b", verdict("unknown", 0, error="bang"))],
    )
    assert total.error == "boom; bang"


def test_no_providers_yields_unknown():
    result = aggregate_verdicts(make_entity("ip", "203.0.113.66"), [])
    assert result.verdict == "unknown"
    assert result.score == 0


def test_verdict_rank_places_unknown_above_clean():
    assert VERDICT_RANK["malicious"] > VERDICT_RANK["suspicious"] > VERDICT_RANK["unknown"]
    assert VERDICT_RANK["unknown"] > VERDICT_RANK["clean"]


def test_summary_counts_sum_to_iocs_checked():
    entity = make_entity("ip", "203.0.113.66")
    results = [
        aggregate_verdicts(entity, [("a", verdict("malicious", 90))]),
        aggregate_verdicts(entity, [("a", verdict("suspicious", 50))]),
        aggregate_verdicts(entity, [("a", verdict("clean", 0))]),
        aggregate_verdicts(entity, [("a", verdict("unknown", 0))]),
    ]
    summary = summarize(results)
    assert summary.iocs_checked == 4
    total = summary.malicious + summary.suspicious + summary.clean + summary.unknown
    assert total == summary.iocs_checked
    assert summary.worst_verdict == "malicious"


def test_empty_summary_has_no_worst_verdict():
    """The fixture-05 case; the spec-02 model validator is what enforces it."""
    summary = summarize([])
    assert summary.iocs_checked == 0
    assert summary.worst_verdict is None
    assert TISummary.model_validate(summary.model_dump()) == summary


def test_worst_verdict_none_with_nonzero_checked_is_rejected():
    with pytest.raises(ValueError, match="worst_verdict must be None iff"):
        TISummary(iocs_checked=1, unknown=1, worst_verdict=None)
