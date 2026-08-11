"""TI + history context goldens, all 10 fixtures. Spec: enrichment-05-spec.md §21.9."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_agent.config import HistoryConfig, ThreatIntelConfig
from soc_agent.providers.history import correlate
from soc_agent.providers.ti import enrich_ti_sync
from tests.unit.test_correlate import STEMS, load_alert, load_entities

GOLDENS_DIR = Path(__file__).parents[1] / "data" / "context"


def build_context(stem: str, history_store) -> dict:
    alert, entities = load_alert(stem), load_entities(stem)
    ti = enrich_ti_sync(entities, config=ThreatIntelConfig(simulate_latency=False))
    correlation = correlate(alert, entities, store=history_store, config=HistoryConfig())
    return {
        "threat_intel": ti.block.model_dump(mode="json"),
        "related_alerts": correlation.block.model_dump(mode="json"),
    }


def dump(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


@pytest.mark.parametrize("stem", STEMS)
def test_context_golden_matches(stem, history_store, pytestconfig):
    payload = build_context(stem, history_store)
    golden_path = GOLDENS_DIR / f"{stem}.json"

    if pytestconfig.getoption("--update-goldens"):
        GOLDENS_DIR.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(dump(payload))
        return

    assert dump(payload) == golden_path.read_text()


@pytest.mark.parametrize("stem", ["01_c2_beacon", "08_portscan_noisy"])
def test_context_is_stable_across_repeated_calls(stem, history_store):
    """The cache changes timing, never results (§21.9)."""
    first = build_context(stem, history_store)
    second = build_context(stem, history_store)
    assert dump(first) == dump(second)
