"""Entity extraction goldens, all 10 fixtures. Spec: extraction-04-spec.md §16.6."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from soc_agent.extract import extract_entities
from soc_agent.extract.score import extraction_f1
from soc_agent.models import ExpectedFixture
from soc_agent.models.alert import NormalizedAlert

FIXTURES_DIR = Path(__file__).parents[2] / "fixtures" / "alerts"
NORMALIZED_DIR = Path(__file__).parents[2] / "tests" / "data" / "normalized"
GOLDENS_DIR = Path(__file__).parents[2] / "tests" / "data" / "entities"

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


def _dump(entities) -> str:
    payload = [e.model_dump(mode="json") for e in entities]
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


@pytest.mark.parametrize("stem", _FIXTURE_STEMS)
def test_extract_golden_matches(stem: str, pytestconfig: pytest.Config, monkeypatch):
    monkeypatch.setenv("SOC_AGENT_LLM_CACHE", "replay")
    alert = NormalizedAlert.model_validate(
        json.loads((NORMALIZED_DIR / f"{stem}.json").read_text())
    )
    result = extract_entities(alert, llm_assist_mode="never")
    golden_path = GOLDENS_DIR / f"{stem}.json"

    if pytestconfig.getoption("--update-goldens"):
        golden_path.write_text(_dump(result.entities))
        return

    assert _dump(result.entities) == golden_path.read_text()

    labels = yaml.safe_load((FIXTURES_DIR / f"{stem}.expected.yaml").read_text())
    expected = ExpectedFixture.model_validate(labels)

    score = extraction_f1(result.entities, expected.entities)
    assert score.f1 == 1.0, f"{stem}: FP={score.false_positives} FN={score.false_negatives}"

    by_key = {(e.type, e.value.lower()): e for e in result.entities}
    for exp_entity in expected.entities:
        if exp_entity.role is None:
            continue
        actual = by_key.get((exp_entity.type, exp_entity.value.lower()))
        assert actual is not None, f"{stem}: missing {exp_entity.type}/{exp_entity.value}"
        assert actual.role == exp_entity.role, (
            f"{stem}: {exp_entity.type}/{exp_entity.value} role "
            f"expected {exp_entity.role!r}, got {actual.role!r}"
        )

    assert result.errors == []
    assert result.llm_used is False
