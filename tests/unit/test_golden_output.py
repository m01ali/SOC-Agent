"""Golden sample-output regression test. Spec: data-contracts-02-spec.md §8."""

from __future__ import annotations

from pathlib import Path

from soc_agent.models import EnrichmentOutput

SAMPLE_OUTPUT = Path(__file__).parents[2] / "tests" / "data" / "sample_output.json"


def test_golden_output_validates():
    raw = SAMPLE_OUTPUT.read_text()
    out = EnrichmentOutput.model_validate_json(raw)
    assert out.status == "success"


def test_golden_output_round_trips():
    raw = SAMPLE_OUTPUT.read_text()
    out = EnrichmentOutput.model_validate_json(raw)
    round_tripped = EnrichmentOutput.model_validate_json(out.model_dump_json())
    assert round_tripped == out
