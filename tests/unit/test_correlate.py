"""correlate() across the corpus. Spec: enrichment-05-spec.md §21.8."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from soc_agent.config import HistoryConfig
from soc_agent.models import Entity
from soc_agent.models.alert import NormalizedAlert
from soc_agent.providers.history import correlate
from soc_agent.providers.history.sqlite import SqliteHistoryStore

NORMALIZED_DIR = Path(__file__).parents[1] / "data" / "normalized"
ENTITIES_DIR = Path(__file__).parents[1] / "data" / "entities"

STEMS = [
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

# §16.1: count, shared_entity_count, prior TP, prior FP, rule_fp_rate, rule_fired_count
EXPECTED = {
    "01_c2_beacon": (2, 2, 1, 0, None, None),
    "02_phishing": (4, 4, 3, 1, None, None),
    "03_brute_force": (4, 4, 2, 1, 0.5, 3),
    "04_malware_hash_fp": (12, 1, 0, 1, 11 / 12, 12),
    "05_lateral_movement": (3, 3, 1, 0, None, 0),
    "06_impossible_travel": (2, 2, 0, 0, None, 0),
    "07_dns_newdomain": (1, 1, 0, 0, None, None),
    "08_portscan_noisy": (40, 5, 0, 5, 0.95, 40),
    "09_exfil_volume": (1, 1, 0, 0, None, 0),
    "10_injection": (0, 0, 0, 0, None, None),
}


def load_alert(stem: str) -> NormalizedAlert:
    return NormalizedAlert.model_validate(json.loads((NORMALIZED_DIR / f"{stem}.json").read_text()))


def load_entities(stem: str) -> list[Entity]:
    return [
        Entity.model_validate(e) for e in json.loads((ENTITIES_DIR / f"{stem}.json").read_text())
    ]


@pytest.mark.parametrize("stem", STEMS)
def test_correlation_matches_the_projection_table(stem, history_store):
    result = correlate(
        load_alert(stem), load_entities(stem), store=history_store, config=HistoryConfig()
    )
    block = result.block
    count, shared, tps, fps, fp_rate, fired = EXPECTED[stem]

    assert block.count == count
    assert block.shared_entity_count == shared
    assert block.prior_true_positives == tps
    assert block.prior_false_positives == fps
    assert block.rule_fired_count == fired
    if fp_rate is None:
        assert block.rule_fp_rate is None
    else:
        assert block.rule_fp_rate == pytest.approx(fp_rate)
    assert result.errors == []


def test_fixture_10_has_no_relations_and_is_time_invariant(history_store):
    """§4.3 — the only fixture whose window anchors on the wall clock."""
    alert = load_alert("10_injection")
    assert alert.occurred_at is None

    base = correlate(
        alert, load_entities("10_injection"), store=history_store, config=HistoryConfig()
    )
    assert base.block.count == 0

    a_year_later = alert.model_copy(update={"ingested_at": alert.ingested_at + timedelta(days=365)})
    drifted = correlate(
        a_year_later, load_entities("10_injection"), store=history_store, config=HistoryConfig()
    )
    assert drifted.block.model_dump(mode="json") == base.block.model_dump(mode="json")


def test_truncation_caps_the_list_but_never_the_counts(history_store):
    """§12.4 — a display limit must not change the risk score."""
    alert, entities = load_alert("08_portscan_noisy"), load_entities("08_portscan_noisy")
    full = correlate(alert, entities, store=history_store, config=HistoryConfig())
    capped = correlate(alert, entities, store=history_store, config=HistoryConfig(max_related=2))

    assert len(capped.block.alerts) == 2
    assert capped.block.count == full.block.count == 40
    assert capped.block.shared_entity_count == full.block.shared_entity_count == 5
    assert capped.block.prior_false_positives == full.block.prior_false_positives == 5
    assert capped.truncated == 38


def test_entity_matches_survive_the_cap(history_store):
    """Fixture 08's five entity matches are its five *oldest* of forty (§12.3)."""
    result = correlate(
        load_alert("08_portscan_noisy"),
        load_entities("08_portscan_noisy"),
        store=history_store,
        config=HistoryConfig(max_related=5),
    )
    assert all(a.shared_entities for a in result.block.alerts)


def test_ordering_is_deterministic(history_store):
    alert, entities = load_alert("03_brute_force"), load_entities("03_brute_force")
    first = correlate(alert, entities, store=history_store, config=HistoryConfig())
    second = correlate(alert, entities, store=history_store, config=HistoryConfig())
    assert [a.alert_id for a in first.block.alerts] == [a.alert_id for a in second.block.alerts]


def test_relation_reasons_use_the_fixed_vocabulary(history_store):
    result = correlate(
        load_alert("02_phishing"),
        load_entities("02_phishing"),
        store=history_store,
        config=HistoryConfig(),
    )
    assert all(a.relation_reason == "same user j.okafor" for a in result.block.alerts)
    assert all(a.shared_entities == ["j.okafor"] for a in result.block.alerts)


def test_narrow_window_drops_the_prior_true_positives(history_store):
    """The 30-day boundary is exercised, not assumed (§17).

    Group B's three phishing TPs sit 22, 15 and 8 days before the epoch, so a 7-day
    window leaves only the false positive — and fixture 02's history component would
    fall from 85 to 50. The window is a scoring input, not a display preference.
    """
    alert, entities = load_alert("02_phishing"), load_entities("02_phishing")
    wide = correlate(alert, entities, store=history_store, config=HistoryConfig(window_days=30))
    narrow = correlate(alert, entities, store=history_store, config=HistoryConfig(window_days=7))

    assert wide.block.count == 4
    assert wide.block.prior_true_positives == 3
    assert narrow.block.count == 1
    assert narrow.block.prior_true_positives == 0
    assert narrow.block.prior_false_positives == 1


def test_value_stoplist_removes_matches(history_store, seeded_db_path):
    """§12.1 — the knob works, and the corpus is redundantly linked.

    Stopping `admin` alone does not change fixture 03: every alert it reaches through
    that value is also reached through BASTION-01 or 10.20.7.5. Correlation degrades
    gracefully under a stoplist rather than falling off a cliff, which is why the
    default can ship empty without the corpus depending on that choice.
    """
    alert, entities = load_alert("03_brute_force"), load_entities("03_brute_force")
    baseline = correlate(alert, entities, store=history_store, config=HistoryConfig())
    assert baseline.block.count == 4

    with SqliteHistoryStore(seeded_db_path, value_stoplist=["admin"]) as stopped:
        redundant = correlate(alert, entities, store=stopped, config=HistoryConfig())
    assert redundant.block.count == 4

    with SqliteHistoryStore(seeded_db_path, value_stoplist=["admin", "BASTION-01"]) as stopped:
        reduced = correlate(alert, entities, store=stopped, config=HistoryConfig())
    # Only C4 still shares an entity (the destination IP); C2 and C3 survive as
    # rule-only context, which is exactly why the two counts are tracked separately.
    assert reduced.block.shared_entity_count == 1
    assert reduced.block.prior_true_positives == 0
    assert reduced.block.count == 3


def test_missing_store_degrades_without_raising(tmp_path):
    """Architecture §11: history store down -> empty correlation -> partial + error."""
    result = correlate(
        load_alert("01_c2_beacon"),
        load_entities("01_c2_beacon"),
        config=HistoryConfig(path=str(tmp_path / "absent.db")),
    )
    assert result.block.count == 0
    assert result.block.alerts == []
    assert len(result.errors) == 1
    assert result.errors[0].stage == "correlate"
    assert result.errors[0].type == "provider_error"
    assert result.errors[0].recoverable is True


def test_no_matches_is_not_an_error(history_store):
    """A fresh deployment must not report `partial` on every run (§15)."""
    result = correlate(
        load_alert("10_injection"),
        load_entities("10_injection"),
        store=history_store,
        config=HistoryConfig(),
    )
    assert result.errors == []


def test_alert_without_a_vendor_rule_reports_no_rule_stats(history_store):
    result = correlate(
        load_alert("01_c2_beacon"),
        load_entities("01_c2_beacon"),
        store=history_store,
        config=HistoryConfig(),
    )
    assert result.rule_stats is None
    assert result.block.rule_fp_rate is None
    assert result.block.rule_fired_count is None
    assert result.errors == []


def test_store_bug_is_caught_not_propagated(history_store):
    class Exploding:
        name = "boom"

        def find_related(self, *args, **kwargs):
            raise RuntimeError("index corrupted")

        def rule_stats(self, *args, **kwargs):  # pragma: no cover - never reached
            raise AssertionError

        def close(self):  # pragma: no cover - store is caller-owned here
            pass

    result = correlate(
        load_alert("01_c2_beacon"),
        load_entities("01_c2_beacon"),
        store=Exploding(),
        config=HistoryConfig(),
    )
    assert result.block.count == 0
    assert "index corrupted" in result.errors[0].detail


def test_store_name_is_reported_for_provenance(history_store):
    result = correlate(
        load_alert("01_c2_beacon"),
        load_entities("01_c2_beacon"),
        store=history_store,
        config=HistoryConfig(),
    )
    assert result.store_name == "sqlite"
