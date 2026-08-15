"""Shortlist goldens + the deterministic map_attack path. Spec: §19.4."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soc_agent.attack import map_attack
from soc_agent.attack.catalog import load_catalog
from soc_agent.config import AttackConfig
from soc_agent.models import Entity
from tests.unit.test_attack_shortlist import (
    CATALOG_PATH,
    FIXTURE_TI_TAGS,
    STEMS,
    load_alert,
    load_labels,
)

ENTITIES_DIR = Path(__file__).parents[1] / "data" / "entities"
GOLDENS_DIR = Path(__file__).parents[1] / "data" / "attack"


@pytest.fixture(scope="module")
def catalog():
    return load_catalog(CATALOG_PATH)


@pytest.fixture(scope="module")
def cfg():
    return AttackConfig()


def load_entities(stem: str) -> list[Entity]:
    return [
        Entity.model_validate(e) for e in json.loads((ENTITIES_DIR / f"{stem}.json").read_text())
    ]


def build(stem: str, catalog, cfg):
    """The deterministic path only — no LLM, so this runs in the default suite."""
    from soc_agent.models.ti import ThreatIntelBlock, TISummary

    tags = FIXTURE_TI_TAGS[stem]
    # A minimal TI block carrying just the tags the shortlister reads.
    block = ThreatIntelBlock(summary=TISummary(iocs_checked=0), results=[])
    result = map_attack(
        load_alert(stem),
        load_entities(stem),
        block,
        None,
        use_llm=False,
        catalog=catalog,
        config=cfg,
    )
    # Re-run through shortlist with tags for the golden (map_attack derives tags from
    # the TI block; the fixtures' real tags come from spec 05's seed).
    from soc_agent.attack.shortlist import shortlist

    candidates = shortlist(load_alert(stem), tags, catalog=catalog, cfg=cfg)
    return result, candidates


def dump(candidates, mappings) -> str:
    payload = {
        "candidates": [
            {"technique_id": c.technique_id, "score": c.score, "reasons": list(c.reasons)}
            for c in candidates
        ],
        "rule_hint_mappings": [m.model_dump(mode="json") for m in mappings],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


@pytest.mark.parametrize("stem", STEMS)
def test_attack_golden_matches(stem, catalog, cfg, pytestconfig):
    result, candidates = build(stem, catalog, cfg)
    golden_path = GOLDENS_DIR / f"{stem}.json"

    if pytestconfig.getoption("--update-goldens"):
        GOLDENS_DIR.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(dump(candidates, result.mappings))
        return

    assert dump(candidates, result.mappings) == golden_path.read_text()


@pytest.mark.parametrize("stem", STEMS)
def test_deterministic_path_never_errors(stem, catalog, cfg):
    result, _ = build(stem, catalog, cfg)
    assert result.errors == []
    assert result.llm_used is False


def test_rule_hint_mappings_are_catalog_resolved_and_low_confidence(catalog, cfg):
    result, _ = build("03_brute_force", catalog, cfg)
    assert [m.technique_id for m in result.mappings] == ["T1110"]
    mapping = result.mappings[0]
    assert mapping.technique_name == "Brute Force"
    assert mapping.tactic_id == "TA0006"
    assert mapping.confidence == "low"
    assert "matched rule hint" in mapping.evidence[0]


def test_alert_without_a_hinted_rule_yields_no_deterministic_mappings(catalog, cfg):
    """Fixtures 01, 02, 07 and 10 have no vendor_rule — the degraded path is empty for
    them, which is why §9's keyword table matters more than the hints."""
    result, candidates = build("01_c2_beacon", catalog, cfg)
    assert result.mappings == []
    assert candidates, "the shortlist is still populated"


def test_labeled_techniques_appear_in_every_shortlist(catalog, cfg):
    for stem in STEMS:
        _, candidates = build(stem, catalog, cfg)
        ids = {c.technique_id for c in candidates}
        for technique_id in load_labels(stem):
            assert technique_id in ids, f"{stem}: {technique_id} missing from the shortlist"


# -- degraded mode (§13) — API-free: the LLM layer is stubbed ------------------


def test_llm_failure_degrades_to_rule_hints(catalog, cfg, monkeypatch):
    """Architecture §11: ATT&CK LLM fails -> rule-hint mappings only, error recorded."""
    import soc_agent.attack.select as select_module

    def boom(*args, **kwargs):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(select_module, "get_llm", boom)

    alert = load_alert("03_brute_force")
    result = map_attack(
        alert,
        load_entities("03_brute_force"),
        None,
        None,
        use_llm=True,
        catalog=catalog,
        config=cfg,
    )

    assert [m.technique_id for m in result.mappings] == ["T1110"]
    assert result.mappings[0].confidence == "low"
    assert len(result.errors) == 1
    assert result.errors[0].stage == "map_attack"
    assert result.errors[0].type == "api_error"
    assert "model unavailable" in result.errors[0].detail
    assert result.llm_used is False


def test_llm_failure_without_a_hinted_rule_yields_nothing_but_still_records(
    catalog, cfg, monkeypatch
):
    import soc_agent.attack.select as select_module

    monkeypatch.setattr(
        select_module, "get_llm", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down"))
    )
    result = map_attack(
        load_alert("01_c2_beacon"), [], None, None, use_llm=True, catalog=catalog, config=cfg
    )
    assert result.mappings == []
    assert result.errors[0].type == "api_error"


def test_all_ids_rejected_records_schema_validation(catalog, cfg, monkeypatch):
    """§13: every returned item invalid -> error recorded, rule hints kept."""
    import soc_agent.attack.select as select_module
    from soc_agent.models import AttackSelection, AttackSelectionItem

    class Stub:
        def invoke(self, messages):
            return AttackSelection(
                techniques=[
                    AttackSelectionItem(
                        technique_id="T1566.002", confidence="high", evidence=["not a candidate"]
                    )
                ]
            )

    monkeypatch.setattr(select_module, "get_llm", lambda *a, **k: Stub())

    result = map_attack(
        load_alert("03_brute_force"), [], None, None, use_llm=True, catalog=catalog, config=cfg
    )
    assert result.dropped == {"not_in_candidates": 1}
    assert result.errors[0].type == "schema_validation"
    assert [m.technique_id for m in result.mappings] == ["T1110"]  # hint survives


def test_empty_shortlist_is_not_an_error(catalog, cfg):
    """An alert with no ATT&CK signal is a legitimate outcome (§13)."""
    from tests.unit.test_attack_shortlist import make_alert

    result = map_attack(
        make_alert(title="zzzz qqqq", category=None),
        [],
        None,
        None,
        use_llm=True,
        catalog=catalog,
        config=cfg,
    )
    assert result.mappings == []
    assert result.candidates == []
    assert result.errors == []
