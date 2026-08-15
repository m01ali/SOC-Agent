"""Risk + deterministic-triage goldens, all 10 fixtures. Spec: §17.5. API-free."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_agent.brief import brief
from soc_agent.config import AppConfig
from soc_agent.triage import triage
from tests.unit.test_attack_shortlist import STEMS, load_alert
from tests.unit.test_scoring_bands import load_entities

GOLDENS_DIR = Path(__file__).parents[1] / "data" / "risk"


@pytest.fixture(scope="module")
def pipeline(request):
    """Score + deterministic triage + deterministic briefing for every fixture."""
    from soc_agent.config import HistoryConfig, ThreatIntelConfig
    from soc_agent.providers.history import correlate
    from soc_agent.providers.history.seed import build_seeded_db
    from soc_agent.providers.history.sqlite import SqliteHistoryStore
    from soc_agent.providers.ti import enrich_ti_sync
    from soc_agent.scoring import score_risk

    tmp = request.config._tmp_path_factory.mktemp("risk-goldens")
    db = tmp / "history.db"
    build_seeded_db(str(db))
    store = SqliteHistoryStore(str(db))
    cfg = AppConfig()
    ti_cfg = ThreatIntelConfig(simulate_latency=False)
    try:
        out = {}
        for stem in STEMS:
            alert, entities = load_alert(stem), load_entities(stem)
            ti = enrich_ti_sync(entities, config=ti_cfg)
            related = correlate(alert, entities, store=store, config=HistoryConfig()).block
            risk = score_risk(alert, ti.block, related, config=cfg.scoring)
            triaged = triage(
                alert, entities, ti.block, related, (), risk, use_llm=False, config=cfg
            )
            briefed = brief(
                alert,
                entities,
                ti.block,
                related,
                (),
                risk,
                triaged.recommendation,
                use_llm=False,
                config=cfg,
            )
            out[stem] = (risk, triaged, briefed)
        return out
    finally:
        store.close()


def dump(risk, triaged, briefed) -> str:
    payload = {
        "risk": risk.model_dump(mode="json"),
        "recommendation": triaged.recommendation.model_dump(mode="json"),
        "briefing": briefed.briefing.model_dump(mode="json"),
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


@pytest.mark.parametrize("stem", STEMS)
def test_risk_golden_matches(stem, pipeline, pytestconfig):
    risk, triaged, briefed = pipeline[stem]
    golden_path = GOLDENS_DIR / f"{stem}.json"

    if pytestconfig.getoption("--update-goldens"):
        GOLDENS_DIR.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(dump(risk, triaged, briefed))
        return

    assert dump(risk, triaged, briefed) == golden_path.read_text()


@pytest.mark.parametrize("stem", STEMS)
def test_deterministic_path_is_clean(stem, pipeline):
    _risk, triaged, briefed = pipeline[stem]
    assert triaged.errors == []
    assert briefed.errors == []
    assert triaged.llm_used is False
    assert briefed.llm_used is False


@pytest.mark.parametrize("stem", STEMS)
def test_deterministic_briefings_are_within_the_cap(stem, pipeline):
    _risk, _triaged, briefed = pipeline[stem]
    assert 0 < briefed.word_count <= 200


@pytest.mark.parametrize("stem", STEMS)
def test_deterministic_action_always_equals_the_band(stem, pipeline):
    risk, triaged, _briefed = pipeline[stem]
    assert triaged.recommendation.action == risk.band
    assert triaged.recommendation.confidence == "low"
    assert triaged.recommendation.override_reason is None


def test_priority_distribution_is_not_flat(pipeline):
    """§6 — one alert at the top of the queue, not five."""
    priorities = [t.recommendation.priority for _r, t, _b in pipeline.values()]
    assert priorities.count("P1") == 1  # fixture 02 at 90
    assert len(set(priorities)) >= 3
