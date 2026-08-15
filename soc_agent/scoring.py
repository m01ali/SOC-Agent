"""Deterministic risk scoring. Spec: triage-briefing-07-spec.md §4 (Architecture §5.6).

Distinct from `soc_agent/models/scoring.py` (the contracts) — import explicitly.

Pure by construction: no clock, no I/O, no LLM. Same inputs, same RiskAssessment,
forever. That is what makes the band table a unit test rather than a fixture run, and
what lets spec 09 recompute scores without re-running the pipeline.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal
from typing import TYPE_CHECKING

from soc_agent.models import (
    RelatedAlertsBlock,
    RiskAssessment,
    RiskBand,
    RiskComponents,
    RiskWeights,
    ThreatIntelBlock,
)
from soc_agent.models.alert import NormalizedAlert

if TYPE_CHECKING:
    from soc_agent.config import ScoringConfig

HISTORY_NEUTRAL = 50
HISTORY_PRIOR_TP_BONUS = 25
HISTORY_REPEAT_BONUS = 10
HISTORY_NOISY_RULE_PENALTY = 25

# The two thresholds Architecture §5.6 attaches to the noisy-rule penalty.
NOISY_RULE_FP_RATE = 0.8
NOISY_RULE_MIN_FIRINGS = 10

# "+10 if >= 3 related alerts share entities" (§4.2).
REPEAT_MIN_SHARED = 3


def round_half_up(value: float) -> int:
    """Round half away from zero — NOT Python's round().

    Python uses banker's rounding: round(54.5) == 54 and round(66.5) == 66. On the
    current corpus that changes fixtures 07 and 10. Neither crosses a band today, but a
    weight tweak landing a score exactly on X.5 at a threshold would make the band
    depend on whether the integer part is even — an indefensible property for a number
    an analyst acts on (§4.3).
    """
    return int(Decimal(str(value)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def ti_component(threat_intel: ThreatIntelBlock | None) -> int:
    """Max TI score across looked-up IOCs; 0 when there are none.

    Not "neutral 50": fixture 05 has no external IOCs at all, and treating "nothing to
    check" as mid-range would invent evidence — an internal-only lateral-movement alert
    would score as though a threat feed had opined on it. Architecture §5.6: "0 if none".
    """
    if threat_intel is None or not threat_intel.results:
        return 0
    return max(result.score for result in threat_intel.results)


def history_component(related: RelatedAlertsBlock | None) -> int:
    """§4.2. Attainable range is 25-85 — never 0 or 100.

    The scorer cannot express "certainly benign history" or "certainly malicious
    history", which is correct: history is corroboration, not proof.
    """
    if related is None:
        return HISTORY_NEUTRAL

    value = HISTORY_NEUTRAL

    # Both conditions read the ENTITY-SCOPED fields spec 05 §12.5 introduced.
    # `related.count` includes rule-only matches: fixture 08 would read 40 instead of 5
    # and fixture 04 would read 12 instead of 1, awarding +10 for "this noisy rule fired
    # again" — the very thing the -25 penalizes.
    if related.prior_true_positives > 0:
        value += HISTORY_PRIOR_TP_BONUS
    if related.shared_entity_count >= REPEAT_MIN_SHARED:
        value += HISTORY_REPEAT_BONUS

    # `rule_fp_rate is None` means no dispositioned firings — no evidence, so neither
    # bonus nor penalty (spec 05 §13.1 is why it is None and not 0.0).
    if (
        related.rule_fp_rate is not None
        and related.rule_fp_rate >= NOISY_RULE_FP_RATE
        and (related.rule_fired_count or 0) >= NOISY_RULE_MIN_FIRINGS
    ):
        value -= HISTORY_NOISY_RULE_PENALTY

    return max(0, min(100, value))


def band_for(score: int, cfg: ScoringConfig) -> RiskBand:
    """Derived from the ROUNDED integer, so a reader who recomputes the band from the
    printed `score` gets the printed `band` (§4.3)."""
    if score >= cfg.bands.escalate:
        return "escalate"
    if score >= cfg.bands.investigate:
        return "investigate"
    return "close"


def score_risk(
    alert: NormalizedAlert,
    threat_intel: ThreatIntelBlock | None = None,
    related: RelatedAlertsBlock | None = None,
    *,
    config: ScoringConfig | None = None,
) -> RiskAssessment:
    """Architecture §5.6's weighted score. Pure: no clock, no I/O, no LLM."""
    if config is None:
        from soc_agent.config import get_config

        config = get_config().scoring

    ti = ti_component(threat_intel)
    severity = alert.severity
    history = history_component(related)
    weights = config.weights

    raw = weights.ti * ti + weights.severity * severity + weights.history * history
    score = max(0, min(100, round_half_up(raw)))

    return RiskAssessment(
        score=score,
        band=band_for(score, config),
        components=RiskComponents(ti=ti, severity=severity, history=history),
        weights=RiskWeights(ti=weights.ti, severity=weights.severity, history=weights.history),
    )
