"""attack_top3_recall. Spec: attack-mapping-06-spec.md §19.6."""

from __future__ import annotations

import math

import pytest
import yaml

from soc_agent.attack.catalog import load_catalog
from soc_agent.attack.score import attack_top3_recall
from soc_agent.models import AttackMapping, ExpectedFixture
from tests.unit.test_attack_shortlist import CATALOG_PATH, FIXTURES_DIR, STEMS


@pytest.fixture(scope="module")
def catalog():
    return load_catalog(CATALOG_PATH)


def mapping(technique_id: str) -> AttackMapping:
    return AttackMapping(
        tactic_id="TA0011",
        tactic="Command and Control",
        technique_id=technique_id,
        technique_name="X",
        confidence="medium",
        evidence=["e"],
    )


def fixture(techniques: list[str]) -> ExpectedFixture:
    return ExpectedFixture(
        format="generic",
        action="investigate",
        entities=[],
        techniques=techniques,
    )


def test_hit_at_rank_three_counts():
    score = attack_top3_recall(
        {"a": [mapping("T1001"), mapping("T1002"), mapping("T1003")]},
        {"a": fixture(["T1003"])},
    )
    assert score.top3_hits == 1
    assert score.top3_recall == 1.0


def test_hit_at_rank_four_does_not_count():
    score = attack_top3_recall(
        {"a": [mapping("T1001"), mapping("T1002"), mapping("T1003"), mapping("T1004")]},
        {"a": fixture(["T1004"])},
    )
    assert score.top3_hits == 0
    assert score.misses == ("a",)
    # ...but it still counts as a label hit at any rank.
    assert score.label_hits == 1


def test_one_of_several_labels_is_enough_for_the_fixture():
    score = attack_top3_recall(
        {"a": [mapping("T1071.001")]},
        {"a": fixture(["T1071.001", "T1573"])},
    )
    assert score.top3_hits == 1
    assert score.label_hits == 1
    assert score.label_total == 2
    assert score.label_recall == 0.5


def test_family_match_is_not_an_exact_hit():
    """T1071 when T1071.001 is labeled: real tuning information, not a pass (§14)."""
    score = attack_top3_recall({"a": [mapping("T1071")]}, {"a": fixture(["T1071.001"])})
    assert score.top3_hits == 0
    assert score.label_hits == 0
    assert score.family_hits == 1


def test_fixtures_without_labels_are_excluded_from_the_denominator():
    score = attack_top3_recall(
        {"a": [mapping("T1001")], "b": [mapping("T1002")]},
        {"a": fixture(["T1001"]), "b": fixture([])},
    )
    assert score.fixtures_scored == 1
    assert score.top3_recall == 1.0


def test_hallucinated_counts_ids_absent_from_the_catalog(catalog):
    score = attack_top3_recall(
        {"a": [mapping("T1071.001"), mapping("T9999")]},
        {"a": fixture(["T1071.001"])},
        catalog=catalog,
    )
    assert score.hallucinated == 1


def test_hallucination_is_counted_even_for_unlabeled_fixtures(catalog):
    score = attack_top3_recall({"b": [mapping("T9999")]}, {"b": fixture([])}, catalog=catalog)
    assert score.fixtures_scored == 0
    assert score.hallucinated == 1


def test_missing_prediction_is_a_miss():
    score = attack_top3_recall({}, {"a": fixture(["T1001"])})
    assert score.top3_hits == 0
    assert score.top3_recall == 0.0


def test_empty_expected_is_zero_not_a_crash():
    score = attack_top3_recall({}, {})
    assert score.fixtures_scored == 0
    assert score.top3_recall == 0.0


def test_corpus_denominator_is_nine_fixtures_and_eleven_labels(capsys):
    """The gate is 7 of 9 (Architecture §1.4's >= 70%); fixture 04 carries no label."""
    expected = {}
    for stem in STEMS:
        payload = yaml.safe_load((FIXTURES_DIR / f"{stem}.expected.yaml").read_text())
        expected[stem] = ExpectedFixture.model_validate(payload)

    labeled = {k: v for k, v in expected.items() if v.techniques}
    total_labels = sum(len(v.techniques) for v in labeled.values())

    # ceil, not round: 6/9 is 66.7%, which does not clear ">= 70%".
    gate = math.ceil(0.7 * len(labeled))

    with capsys.disabled():
        print(f"\n[metric] labeled fixtures: {len(labeled)}/10, technique labels: {total_labels}")
        print(f"[metric] top-3 gate: >= {gate} of {len(labeled)} fixtures\n")

    assert len(labeled) == 9
    assert total_labels == 11
    assert "04_malware_hash_fp" not in labeled
    assert gate == 7
    assert (gate - 1) / len(labeled) < 0.7 <= gate / len(labeled)
