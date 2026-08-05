"""Extraction scorer tests. Spec: extraction-04-spec.md §16.7."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from soc_agent.extract import extract_entities
from soc_agent.extract.score import extraction_f1
from soc_agent.models import Entity, EntityProvenance, ExpectedEntity, ExpectedFixture
from soc_agent.models.alert import NormalizedAlert

FIXTURES_DIR = Path(__file__).parents[2] / "fixtures" / "alerts"
NORMALIZED_DIR = Path(__file__).parents[2] / "tests" / "data" / "normalized"

_FIXTURE_STEMS = [
    "01_c2_beacon",
    "02_phishing",
    "03_brute_force",
    "04_malware_hash_fp",
    "05_lateral_movement",
    "06_impossible_travel",
    "07_dns_newdomain",
    "08_portscan_noisy",
    "09_exfil_volume",
    "10_injection",
]


def _entity(entity_type: str, value: str) -> Entity:
    return Entity(
        type=entity_type,
        value=value,
        confidence=1.0,
        provenance=EntityProvenance(method="field_map"),
    )


def _expected(entity_type: str, value: str) -> ExpectedEntity:
    return ExpectedEntity(type=entity_type, value=value)


def test_perfect_match() -> None:
    predicted = [_entity("ip", "203.0.113.66"), _entity("user", "l.hassan")]
    expected = [_expected("ip", "203.0.113.66"), _expected("user", "l.hassan")]
    score = extraction_f1(predicted, expected)
    assert score.precision == 1.0
    assert score.recall == 1.0
    assert score.f1 == 1.0
    assert score.false_positives == []
    assert score.false_negatives == []


def test_both_empty() -> None:
    score = extraction_f1([], [])
    assert (score.precision, score.recall, score.f1) == (1.0, 1.0, 1.0)


def test_empty_predicted_nonempty_expected() -> None:
    score = extraction_f1([], [_expected("ip", "203.0.113.66")])
    assert (score.precision, score.recall, score.f1) == (0.0, 0.0, 0.0)


def test_nonempty_predicted_empty_expected() -> None:
    score = extraction_f1([_entity("ip", "203.0.113.66")], [])
    assert (score.precision, score.recall, score.f1) == (0.0, 0.0, 0.0)


def test_partial_overlap() -> None:
    predicted = [_entity("ip", "203.0.113.66"), _entity("ip", "10.0.0.1")]
    expected = [_expected("ip", "203.0.113.66"), _expected("user", "admin")]
    score = extraction_f1(predicted, expected)
    # TP=1, FP=1 (10.0.0.1), FN=1 (admin) -> P=0.5, R=0.5, F1=0.5
    assert score.precision == 0.5
    assert score.recall == 0.5
    assert score.f1 == 0.5
    assert score.false_positives == [("ip", "10.0.0.1")]
    assert score.false_negatives == [("user", "admin")]


def test_case_insensitive_match() -> None:
    predicted = [_entity("host", "ws-fin-0142")]
    expected = [_expected("host", "WS-FIN-0142")]
    score = extraction_f1(predicted, expected)
    assert score.f1 == 1.0


def test_ip_canonicalization_match() -> None:
    predicted = [_entity("ip", "2001:0db8::0001")]
    expected = [_expected("ip", "2001:db8::1")]
    score = extraction_f1(predicted, expected)
    assert score.f1 == 1.0


def test_role_differences_do_not_affect_score() -> None:
    predicted = [
        Entity(
            type="user",
            value="admin",
            role="actor",
            confidence=1.0,
            provenance=EntityProvenance(method="field_map"),
        )
    ]
    expected = [ExpectedEntity(type="user", value="admin", role="target")]
    score = extraction_f1(predicted, expected)
    assert score.f1 == 1.0


def test_aggregate_f1_across_all_fixtures(monkeypatch) -> None:
    """The corpus-level number Architecture §1.4 sets a >= 0.90 target for.
    Prints a table with `-s` (`make f1`)."""
    monkeypatch.setenv("SOC_AGENT_LLM_CACHE", "replay")

    total_tp = total_fp = total_fn = 0
    rows: list[tuple[str, float, float, float]] = []

    for stem in _FIXTURE_STEMS:
        alert = NormalizedAlert.model_validate(
            json.loads((NORMALIZED_DIR / f"{stem}.json").read_text())
        )
        result = extract_entities(alert, llm_assist_mode="never")
        labels = yaml.safe_load((FIXTURES_DIR / f"{stem}.expected.yaml").read_text())
        expected = ExpectedFixture.model_validate(labels)

        score = extraction_f1(result.entities, expected.entities)
        rows.append((stem, score.precision, score.recall, score.f1))
        total_tp += len(score.true_positives)
        total_fp += len(score.false_positives)
        total_fn += len(score.false_negatives)

    print(f"\n{'fixture':<20}{'P':>6}{'R':>6}{'F1':>6}")
    for stem, precision, recall, f1 in rows:
        print(f"{stem:<20}{precision:>6.2f}{recall:>6.2f}{f1:>6.2f}")

    micro_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 1.0
    micro_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 1.0
    micro_f1 = (
        2 * micro_precision * micro_recall / (micro_precision + micro_recall)
        if (micro_precision + micro_recall)
        else 1.0
    )
    print(f"{'MICRO-AVERAGE':<20}{micro_precision:>6.2f}{micro_recall:>6.2f}{micro_f1:>6.2f}")

    assert micro_f1 == 1.0
