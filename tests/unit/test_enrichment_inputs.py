"""The §16.1 projection, asserted on this phase's inputs to the scorer.

Spec: enrichment-05-spec.md §21.10. Deliberately asserts the *inputs* — max TI score,
relation counts, rule stats — and not a risk score: the scorer is spec 07's to
implement. The projected `risk` column is reproduced here as a comment-level check so
spec 07 meets a documented number rather than a surprise.
"""

from __future__ import annotations

import pytest

from soc_agent.config import HistoryConfig, ThreatIntelConfig
from soc_agent.providers.history import correlate
from soc_agent.providers.ti import enrich_ti_sync
from tests.unit.test_correlate import STEMS, load_alert, load_entities

# fixture -> (severity, max TI score, related count, shared-entity count, prior TP,
#             rule fp_rate, rule fired, expected history component, projected risk)
PROJECTION = {
    "01_c2_beacon": (75, 95, 2, 2, 1, None, None, 75, 84.00),
    "02_phishing": (85, 95, 4, 4, 3, None, None, 85, 89.50),
    "03_brute_force": (50, 0, 4, 4, 2, 0.5, 3, 85, 36.25),
    "04_malware_hash_fp": (50, 0, 12, 1, 0, 11 / 12, 12, 25, 21.25),
    "05_lateral_movement": (70, 0, 3, 3, 1, None, 0, 85, 42.25),
    "06_impossible_travel": (75, 60, 2, 2, 0, None, 0, 50, 62.00),
    "07_dns_newdomain": (50, 60, 1, 1, 0, None, None, 50, 54.50),
    "08_portscan_noisy": (25, 0, 40, 5, 0, 0.95, 40, 35, 16.25),
    "09_exfil_volume": (80, 90, 1, 1, 0, None, 0, 50, 77.00),
    "10_injection": (90, 60, 0, 0, 0, None, None, 50, 66.50),
}

LABELS = {
    "01_c2_beacon": "escalate",
    "02_phishing": "escalate",
    "03_brute_force": "investigate",
    "04_malware_hash_fp": "close",
    "05_lateral_movement": "investigate",
    "06_impossible_travel": "investigate",
    "07_dns_newdomain": "investigate",
    "08_portscan_noisy": "close",
    "09_exfil_volume": "escalate",
    "10_injection": "investigate",
}


def history_component(block) -> int:
    """Architecture §5.6's history term, evaluated on this phase's outputs.

    Reproduced here (not imported) because spec 07 owns the scorer. The one semantic
    decision spec 05 makes on its behalf: the +10 counts alerts sharing an *entity*,
    so a noisy rule's firings cannot both award +10 and trigger the -25 (§16).
    """
    value = 50
    if block.prior_true_positives:
        value += 25
    if block.shared_entity_count >= 3:
        value += 10
    if block.rule_fp_rate is not None and block.rule_fp_rate >= 0.8:
        if (block.rule_fired_count or 0) >= 10:
            value -= 25
    return max(0, min(100, value))


def band(risk: float) -> str:
    if risk >= 70:
        return "escalate"
    return "investigate" if risk >= 40 else "close"


@pytest.fixture(scope="module")
def ti_config():
    return ThreatIntelConfig(simulate_latency=False)


@pytest.mark.parametrize("stem", STEMS)
def test_scorer_inputs_match_the_projection(stem, history_store, ti_config):
    severity, ti_score, count, shared, tps, fp_rate, fired, history, risk = PROJECTION[stem]

    alert, entities = load_alert(stem), load_entities(stem)
    assert alert.severity == severity

    ti = enrich_ti_sync(entities, config=ti_config)
    assert max((r.score for r in ti.block.results), default=0) == ti_score

    block = correlate(alert, entities, store=history_store, config=HistoryConfig()).block
    assert block.count == count
    assert block.shared_entity_count == shared
    assert block.prior_true_positives == tps
    assert block.rule_fired_count == fired
    if fp_rate is None:
        assert block.rule_fp_rate is None
    else:
        assert block.rule_fp_rate == pytest.approx(fp_rate)

    assert history_component(block) == history

    projected = 0.45 * ti_score + 0.30 * severity + 0.25 * history
    assert projected == pytest.approx(risk, abs=0.005)


@pytest.mark.parametrize("stem", STEMS)
def test_projected_band_matches_the_label_except_fixture_03(stem, history_store, ti_config):
    """Nine of ten land on their labeled band from the deterministic score alone.

    Fixture 03 does not, and cannot from inside this phase: its TI component is 0 by
    label, its history component is already at the structural maximum of 85, and its
    severity is fixed by spec 03's frozen Splunk mapping. 0.45*0 + 0.30*50 + 0.25*85
    = 36.25 is the ceiling, 3.75 short of the 40 threshold. Spec 07 closes it — the
    recommended route is lowering bands.investigate to 35, which is side-effect-free
    because no other fixture projects into [35, 40) (asserted below).
    """
    *_, risk = PROJECTION[stem]
    projected_band = band(risk)

    if stem == "03_brute_force":
        assert projected_band == "close"
        assert LABELS[stem] == "investigate"
        assert 35 <= risk < 40
    else:
        assert projected_band == LABELS[stem]


def test_fixture_03_is_the_only_alert_in_the_proposed_band_gap():
    """The check that makes spec 07's recommended band change safe (§16.3)."""
    in_gap = [stem for stem, values in PROJECTION.items() if 35 <= values[-1] < 40]
    assert in_gap == ["03_brute_force"]


def test_fixture_05_margin_is_thin_and_depends_on_the_third_relation(history_store):
    """§16.2 — the corpus tripwire. 42.25 vs a 40 threshold, with no headroom left.

    Its TI component is structurally 0 (no external IOCs) and its history component
    is already the maximum 85, so if spec 07 re-weights, this is what breaks first.
    """
    stem = "05_lateral_movement"
    block = correlate(
        load_alert(stem), load_entities(stem), store=history_store, config=HistoryConfig()
    ).block
    assert block.shared_entity_count == 3, "the +10 depends on exactly this"
    assert block.prior_true_positives == 1
    assert history_component(block) == 85

    *_, risk = PROJECTION[stem]
    assert 40 < risk < 43


def test_fixture_01_reproduces_architecture_appendix_b(history_store, ti_config):
    """Appendix B: iocs_checked 1, malicious 1, count 2, one prior TP, components
    ti 95 / severity 75 / history 75. (Appendix B prints score 86 for those
    components; the stated formula yields 84. The document's arithmetic is off by
    two — flagged rather than reverse-engineered.)"""
    stem = "01_c2_beacon"
    alert, entities = load_alert(stem), load_entities(stem)

    ti = enrich_ti_sync(entities, config=ti_config)
    assert ti.block.summary.iocs_checked == 1
    assert ti.block.summary.malicious == 1
    assert ti.block.summary.worst_verdict == "malicious"
    assert ti.block.results[0].tags == ["c2", "cobalt-strike"]

    block = correlate(alert, entities, store=history_store, config=HistoryConfig()).block
    assert block.count == 2
    assert block.prior_true_positives == 1
    assert history_component(block) == 75

    appendix_b = next(a for a in block.alerts if a.alert_id == "SIEM-2026-017901")
    assert appendix_b.disposition == "true_positive"
    assert appendix_b.shared_entities == ["WS-FIN-0142"]
