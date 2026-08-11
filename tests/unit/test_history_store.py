"""SqliteHistoryStore: schema, windows, rule stats, injection. Spec: §21.7."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from soc_agent.models import Entity, EntityProvenance
from soc_agent.models.alert import NormalizationInfo, NormalizedAlert
from soc_agent.providers.history.base import HistoryStoreError
from soc_agent.providers.history.seed import CORPUS_EPOCH, build_seeded_db
from soc_agent.providers.history.sqlite import (
    SqliteHistoryStore,
    build_rule_stats,
    fp_rate_or_none,
    parse_ts,
    to_utc_text,
    window_bounds,
)

RULE_PORT_SCAN = "Network - Port Scan Detected - Rule"
RULE_HASH_BLOCKLIST = "Hash matched local blocklist"


def make_alert(**overrides) -> NormalizedAlert:
    defaults = dict(
        alert_id="TEST-1",
        dedupe_key="a" * 64,
        source_system="generic",
        title="test alert",
        severity=50,
        occurred_at=CORPUS_EPOCH,
        ingested_at=CORPUS_EPOCH,
        raw={},
        normalization=NormalizationInfo(method="parser", confidence=1.0),
    )
    return NormalizedAlert(**{**defaults, **overrides})


def entity(etype: str, value: str) -> Entity:
    return Entity(
        type=etype,
        value=value,
        confidence=1.0,
        provenance=EntityProvenance(method="field_map"),
    )


# -- schema -----------------------------------------------------------------


def test_schema_and_indexes_exist(seeded_db_path):
    conn = sqlite3.connect(seeded_db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"alerts", "alert_entities", "meta"} <= tables

    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {
        "idx_entities_value",
        "idx_entities_type_value",
        "idx_alerts_rule_time",
        "idx_alerts_time",
    } <= indexes
    conn.close()


def test_meta_is_populated(history_store):
    assert history_store.epoch == "2026-07-20T12:00:00Z"


def test_schema_version_mismatch_is_rejected(tmp_path):
    path = tmp_path / "bad.db"
    build_seeded_db(str(path))
    conn = sqlite3.connect(path)
    conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    conn.commit()
    conn.close()

    with pytest.raises(HistoryStoreError, match="schema_version"):
        SqliteHistoryStore(str(path))


def test_missing_db_raises_rather_than_creating_an_empty_one(tmp_path):
    """§11.2: mode=ro. An auto-created empty DB would report 'no history' forever."""
    missing = tmp_path / "nope.db"
    with pytest.raises(HistoryStoreError, match="cannot open history store"):
        SqliteHistoryStore(str(missing))
    assert not missing.exists()


def test_store_is_read_only(history_store):
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        history_store._conn.execute("DELETE FROM alerts")


# -- windows ----------------------------------------------------------------


def test_window_bounds_are_inclusive_at_both_ends():
    anchor = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
    start, end = window_bounds(anchor, 30)
    assert start == "2026-06-20T12:00:00Z"
    assert end == "2026-07-20T12:00:00Z"


def test_alert_after_the_anchor_is_excluded(history_store):
    """The upper bound stops the seed leaking future TPs into a fixture's score (§4.2)."""
    alert = make_alert(occurred_at=CORPUS_EPOCH - timedelta(days=30))
    related = history_store.find_related(alert, [entity("host", "WS-FIN-0142")], 30)
    assert related == []

    alert_now = make_alert(occurred_at=CORPUS_EPOCH)
    assert history_store.find_related(alert_now, [entity("host", "WS-FIN-0142")], 30)


def test_narrower_window_drops_older_matches(history_store):
    alert = make_alert()
    ent = [entity("user", "j.okafor")]
    assert len(history_store.find_related(alert, ent, 30)) == 4
    assert len(history_store.find_related(alert, ent, 7)) == 1


def test_timestamps_round_trip():
    value = datetime(2026, 7, 15, 3, 22, 0, tzinfo=UTC)
    assert to_utc_text(value) == "2026-07-15T03:22:00Z"
    assert parse_ts(to_utc_text(value)) == value


# -- matching ---------------------------------------------------------------


def test_canonicalized_storage_makes_matching_case_insensitive(history_store):
    alert = make_alert()
    upper = history_store.find_related(alert, [entity("host", "WS-FIN-0142")], 30)
    lower = history_store.find_related(alert, [entity("host", "ws-fin-0142")], 30)
    assert [a.alert_id for a in upper] == [a.alert_id for a in lower]
    assert upper


def test_non_correlatable_types_never_match(history_store):
    """§12.1: `powershell` and `pskill.exe` are shared by construction."""
    alert = make_alert()
    assert history_store.find_related(alert, [entity("process", "powershell")], 30) == []
    assert history_store.find_related(alert, [entity("file_path", "invoice.xlsm")], 30) == []


def test_value_stoplist_removes_a_value_from_matching(seeded_db_path):
    alert = make_alert()
    ents = [entity("user", "admin"), entity("host", "BASTION-01")]

    with SqliteHistoryStore(seeded_db_path) as plain:
        baseline = len(plain.find_related(alert, ents, 30))
    with SqliteHistoryStore(seeded_db_path, value_stoplist=["admin"]) as stopped:
        reduced = len(stopped.find_related(alert, ents, 30))

    assert baseline == 4
    assert reduced == 3


def test_relation_reason_vocabulary(history_store):
    alert = make_alert()
    by_id = {
        a.alert_id: a
        for a in history_store.find_related(
            alert,
            [
                entity("host", "WS-FIN-0142"),
                entity("user", "l.hassan"),
                entity("ip", "10.20.14.88"),
            ],
            30,
        )
    }
    assert by_id["SIEM-2026-017901"].relation_reason == "same host WS-FIN-0142"
    # 017988 shares both an IP (IOC rank 0) and a user (rank 2); the IOC wins.
    assert by_id["SIEM-2026-017988"].relation_reason == "shared entity 10.20.14.88"
    assert sorted(by_id["SIEM-2026-017988"].shared_entities) == ["10.20.14.88", "l.hassan"]


def test_rule_only_match_has_a_rule_reason_and_no_shared_entities(history_store):
    alert = make_alert(vendor_rule=RULE_HASH_BLOCKLIST)
    related = history_store.find_related(alert, [], 30)
    assert related
    assert all(a.relation_reason == f'same rule "{RULE_HASH_BLOCKLIST}"' for a in related)
    assert all(a.shared_entities == [] for a in related)


def test_an_alert_matching_several_ways_appears_once(history_store):
    """Without the merge, fixture 03's four relations would report as nine (§12.2)."""
    alert = make_alert(vendor_rule="Access - Excessive Failed Logins - Rule")
    related = history_store.find_related(
        alert, [entity("host", "BASTION-01"), entity("user", "admin")], 30
    )
    assert len(related) == len({a.alert_id for a in related})


def test_ordering_is_entity_matches_then_recency(history_store):
    alert = make_alert(vendor_rule=RULE_PORT_SCAN)
    related = history_store.find_related(alert, [entity("ip", "10.20.0.15")], 30)

    shared_flags = [bool(a.shared_entities) for a in related]
    assert shared_flags == sorted(shared_flags, reverse=True), "entity matches must come first"

    entity_matches = [a for a in related if a.shared_entities]
    times = [a.occurred_at for a in entity_matches]
    assert times == sorted(times, reverse=True)


# -- injection --------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "' OR 1=1 --",
        "'; DROP TABLE alerts; --",
        '" UNION SELECT * FROM meta --',
    ],
)
def test_sql_injection_returns_nothing_and_raises_nothing(history_store, hostile):
    """§20.1: entity values are attacker-influenced text reaching a query engine."""
    alert = make_alert()
    assert history_store.find_related(alert, [entity("host", hostile)], 30) == []
    # And the table is still there.
    assert history_store.find_related(alert, [entity("host", "WS-FIN-0142")], 30)


# -- rule stats -------------------------------------------------------------


def test_rule_stats_math(history_store):
    stats = history_store.rule_stats(RULE_PORT_SCAN, 30, anchor=CORPUS_EPOCH)
    assert stats.fired_count == 40
    assert stats.true_positives == 2
    assert stats.false_positives == 38
    assert stats.fp_rate == pytest.approx(0.95)


def test_rule_stats_denominator_excludes_undispositioned():
    """§13.1: open/benign/undetermined are not evidence the rule was right."""
    stats = build_rule_stats(
        {"true_positive": 1, "false_positive": 3, "benign": 5, "undetermined": 4, "open": 2}
    )
    assert stats.fired_count == 15
    assert stats.fp_rate == pytest.approx(0.75)  # 3/4, not 3/15


def test_fp_rate_is_none_when_nothing_is_dispositioned():
    """None, not 0.0 — 0.0 would claim the rule has never false-positived."""
    stats = build_rule_stats({"open": 3, "undetermined": 2})
    assert stats.fired_count == 5
    assert fp_rate_or_none(stats) is None

    dispositioned = build_rule_stats({"false_positive": 1, "true_positive": 1})
    assert fp_rate_or_none(dispositioned) == pytest.approx(0.5)


def test_rule_stats_for_an_unseeded_rule_is_empty(history_store):
    stats = history_store.rule_stats("No Such Rule", 30, anchor=CORPUS_EPOCH)
    assert stats.fired_count == 0
    assert fp_rate_or_none(stats) is None
