"""The deterministic scorer. Spec: triage-briefing-07-spec.md §17.1."""

from __future__ import annotations

import pytest

from soc_agent.config import ScoringBands, ScoringConfig, ScoringWeights
from soc_agent.models import EntityRef, RelatedAlertsBlock, ThreatIntelBlock, TIResult, TISummary
from soc_agent.models.alert import NormalizationInfo, NormalizedAlert
from soc_agent.scoring import (
    band_for,
    history_component,
    round_half_up,
    score_risk,
    ti_component,
)


def make_alert(severity: int = 50, **overrides) -> NormalizedAlert:
    defaults = dict(
        alert_id="TEST-1",
        dedupe_key="a" * 64,
        source_system="generic",
        title="test alert",
        severity=severity,
        ingested_at="2026-07-20T12:00:00Z",
        raw={},
        normalization=NormalizationInfo(method="parser", confidence=1.0),
    )
    return NormalizedAlert(**{**defaults, **overrides})


def ti(*scores: int) -> ThreatIntelBlock:
    results = [
        TIResult(
            entity=EntityRef(type="ip", value=f"203.0.113.{i + 1}"),
            verdict="malicious" if score >= 85 else "suspicious",
            score=score,
        )
        for i, score in enumerate(scores)
    ]
    return ThreatIntelBlock(
        summary=TISummary(
            iocs_checked=len(results), worst_verdict="malicious" if results else None
        ),
        results=results,
    )


def related(**overrides) -> RelatedAlertsBlock:
    defaults = dict(count=0, prior_true_positives=0, shared_entity_count=0)
    return RelatedAlertsBlock(**{**defaults, **overrides})


CFG = ScoringConfig()


# -- rounding (§4.3) ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(54.5, 55), (66.5, 67), (0.5, 1), (1.5, 2), (2.5, 3), (21.25, 21), (36.25, 36), (84.0, 84)],
)
def test_round_half_up_not_bankers(raw, expected):
    """§4.3 — Python's round() gives 54 for 54.5 and 66 for 66.5 (banker's rounding).

    Neither crosses a band today, but a weight tweak landing a score exactly on X.5 at
    a threshold would make the band depend on whether the integer part is even.
    """
    assert round_half_up(raw) == expected


def test_python_round_would_disagree():
    """Pinned so the distinction cannot be refactored away by accident."""
    assert round(54.5) == 54 and round_half_up(54.5) == 55
    assert round(66.5) == 66 and round_half_up(66.5) == 67


# -- ti component ------------------------------------------------------------


def test_ti_is_max_across_iocs():
    assert ti_component(ti(20, 95, 60)) == 95


def test_ti_is_zero_when_no_iocs_were_checked():
    """Fixture 05's case: 'nothing to check' must not become a neutral 50 (§4.1)."""
    assert ti_component(None) == 0
    assert ti_component(ti()) == 0


# -- history component (§4.2) ------------------------------------------------


def test_history_neutral_with_no_correlation():
    assert history_component(None) == 50
    assert history_component(related()) == 50


def test_prior_true_positive_adds_25():
    assert history_component(related(count=1, prior_true_positives=1)) == 75


def test_three_shared_entity_relations_add_10():
    assert history_component(related(count=3, shared_entity_count=3)) == 60


def test_both_bonuses_stack_to_the_maximum():
    assert history_component(related(count=4, prior_true_positives=1, shared_entity_count=3)) == 85


def test_noisy_rule_subtracts_25():
    block = related(count=12, rule_fp_rate=0.92, rule_fired_count=12)
    assert history_component(block) == 25


def test_noisy_rule_needs_both_thresholds():
    # High rate, too few firings.
    assert history_component(related(rule_fp_rate=0.95, rule_fired_count=9)) == 50
    # Enough firings, rate below the bar.
    assert history_component(related(rule_fp_rate=0.79, rule_fired_count=40)) == 50


def test_rule_fp_rate_none_contributes_nothing():
    """None means no dispositioned firings — no evidence, so no bonus and no penalty."""
    assert history_component(related(rule_fp_rate=None, rule_fired_count=0)) == 50


def test_bonuses_and_penalty_combine():
    """Fixture 08's shape: repeat bonus and a noisy rule at once."""
    block = related(count=40, shared_entity_count=5, rule_fp_rate=0.95, rule_fired_count=40)
    assert history_component(block) == 35


def test_history_reads_entity_scoped_fields_not_count():
    """§4.2 — the distinction spec 05 §12.5 introduced.

    A block where count and shared_entity_count differ (the fixture-08 shape): using
    `count` would award +10 for "this noisy rule fired again", the very thing the -25
    penalizes.
    """
    rule_only = related(count=40, shared_entity_count=2)
    assert history_component(rule_only) == 50  # not 60

    entity_linked = related(count=40, shared_entity_count=3)
    assert history_component(entity_linked) == 60


def test_history_range_is_25_to_85():
    """Never 0 or 100: history is corroboration, not proof."""
    lowest = history_component(related(rule_fp_rate=1.0, rule_fired_count=99))
    highest = history_component(related(prior_true_positives=9, shared_entity_count=9))
    assert lowest == 25
    assert highest == 85


# -- bands -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "close"),
        (34, "close"),
        (35, "investigate"),
        (69, "investigate"),
        (70, "escalate"),
        (100, "escalate"),
    ],
)
def test_band_boundaries_are_inclusive_at_the_floor(score, expected):
    assert band_for(score, CFG) == expected


def test_bands_come_from_config():
    strict = ScoringConfig(bands=ScoringBands(escalate=80, investigate=50))
    assert band_for(70, strict) == "investigate"
    assert band_for(80, strict) == "escalate"


# -- score_risk --------------------------------------------------------------


def test_score_risk_matches_the_worked_example():
    """Architecture Appendix B: ti 95, severity 75, history 75 -> 84."""
    assessment = score_risk(
        make_alert(severity=75),
        ti(95),
        related(count=2, prior_true_positives=1),
        config=CFG,
    )
    assert assessment.components.ti == 95
    assert assessment.components.severity == 75
    assert assessment.components.history == 75
    assert assessment.score == 84
    assert assessment.band == "escalate"


def test_weights_are_echoed_for_auditability():
    assessment = score_risk(make_alert(), None, None, config=CFG)
    assert assessment.weights.ti == 0.45
    assert assessment.weights.severity == 0.30
    assert assessment.weights.history == 0.25


def test_reweighting_changes_the_score():
    severity_heavy = ScoringConfig(weights=ScoringWeights(ti=0.1, severity=0.8, history=0.1))
    base = score_risk(make_alert(severity=90), ti(0), related(), config=CFG)
    tilted = score_risk(make_alert(severity=90), ti(0), related(), config=severity_heavy)
    assert tilted.score > base.score


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError, match="must sum to 1.0"):
        ScoringConfig(weights=ScoringWeights(ti=0.5, severity=0.5, history=0.5))


def test_band_is_derived_from_the_rounded_score():
    """A reader recomputing the band from the printed score must get the printed band."""
    for severity in range(0, 101):
        assessment = score_risk(make_alert(severity=severity), None, None, config=CFG)
        assert assessment.band == band_for(assessment.score, CFG)


def test_score_is_clamped_to_0_100():
    assessment = score_risk(
        make_alert(severity=100),
        ti(100),
        related(prior_true_positives=1, shared_entity_count=3),
        config=CFG,
    )
    assert 0 <= assessment.score <= 100


def test_scorer_is_pure():
    args = (make_alert(severity=75), ti(95), related(count=2, prior_true_positives=1))
    assert score_risk(*args, config=CFG) == score_risk(*args, config=CFG)
