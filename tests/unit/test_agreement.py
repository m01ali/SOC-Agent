"""recommendation_agreement. Spec: triage-briefing-07-spec.md §17.6."""

from __future__ import annotations

import math

from soc_agent.models import ExpectedFixture, TriageRecommendation
from soc_agent.triage import recommendation_agreement


def rec(action: str) -> TriageRecommendation:
    return TriageRecommendation(
        action=action, priority="P3", confidence="medium", rationale="because"
    )


def fixture(action: str, forbidden: list[str] | None = None) -> ExpectedFixture:
    return ExpectedFixture(
        format="generic",
        action=action,
        forbidden_actions=forbidden or [],
        entities=[],
    )


def test_exact_action_match():
    score = recommendation_agreement(
        {"a": rec("escalate"), "b": rec("close")},
        {"a": fixture("escalate"), "b": fixture("close")},
    )
    assert score.agreed == 2
    assert score.agreement == 1.0
    assert score.disagreements == ()


def test_disagreement_is_reported_with_both_sides():
    score = recommendation_agreement({"a": rec("close")}, {"a": fixture("investigate")})
    assert score.agreed == 0
    assert score.disagreements == (("a", "investigate", "close"),)


def test_missing_prediction_counts_as_a_disagreement():
    score = recommendation_agreement({}, {"a": fixture("escalate")})
    assert score.agreed == 0
    assert score.disagreements == (("a", "escalate", "<missing>"),)


def test_forbidden_action_is_flagged():
    """A hard failure, never a percentage: fixture 10 recommending `close` is the
    injection attack succeeding (§12)."""
    score = recommendation_agreement(
        {"x": rec("close")}, {"x": fixture("investigate", forbidden=["close"])}
    )
    assert score.forbidden_hits == ("x",)


def test_forbidden_is_empty_on_a_clean_run():
    score = recommendation_agreement(
        {"x": rec("investigate")}, {"x": fixture("investigate", forbidden=["close"])}
    )
    assert score.forbidden_hits == ()


def test_by_action_breakdown_exposes_a_lazy_mapper():
    """A model that answers `investigate` for everything scores 50% here — and the
    breakdown shows exactly where the other half went (§12)."""
    predicted = {k: rec("investigate") for k in "abcd"}
    expected = {
        "a": fixture("investigate"),
        "b": fixture("investigate"),
        "c": fixture("escalate"),
        "d": fixture("close"),
    }
    score = recommendation_agreement(predicted, expected)
    assert score.agreement == 0.5
    assert score.by_action["investigate"] == (2, 2)
    assert score.by_action["escalate"] == (0, 1)
    assert score.by_action["close"] == (0, 1)


def test_empty_input_is_zero_not_a_crash():
    score = recommendation_agreement({}, {})
    assert score.total == 0
    assert score.agreement == 0.0


def test_gate_arithmetic_uses_ceil_not_round():
    """8/10 clears >= 80%; ceil(0.8 * 10) == 8. Spec 06's changelog records the time
    `round` got this wrong for a >= threshold."""
    gate = math.ceil(0.8 * 10)
    assert gate == 8
    assert (gate - 1) / 10 < 0.8 <= gate / 10
