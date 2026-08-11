"""Seed determinism, composition and hygiene. Spec: enrichment-05-spec.md §21.6."""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from collections import Counter
from datetime import timedelta

import pytest

from soc_agent.providers.history.seed import (
    CORPUS_EPOCH,
    RESERVED_FIXTURE_10_VALUES,
    build_seeded_db,
    corpus,
)
from soc_agent.providers.history.sqlite import parse_ts

TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_DOC_RANGES = [
    ipaddress.ip_network(c) for c in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
RULE_HASH_BLOCKLIST = "Hash matched local blocklist"
RULE_PORT_SCAN = "Network - Port Scan Detected - Rule"


def dump(path: str) -> tuple[list, list, list]:
    conn = sqlite3.connect(path)
    alerts = conn.execute("SELECT * FROM alerts ORDER BY alert_id").fetchall()
    entities = conn.execute(
        "SELECT * FROM alert_entities ORDER BY alert_id, type, value"
    ).fetchall()
    meta = conn.execute("SELECT * FROM meta ORDER BY key").fetchall()
    conn.close()
    return alerts, entities, meta


def test_two_builds_are_identical(tmp_path):
    """No now(), no uuid4(), no dict-order dependence (§14.1)."""
    first, second = tmp_path / "a.db", tmp_path / "b.db"
    build_seeded_db(str(first))
    build_seeded_db(str(second))
    assert dump(str(first)) == dump(str(second))


def test_corpus_size_and_summary(tmp_path):
    summary = build_seeded_db(str(tmp_path / "h.db"))
    assert summary.alerts == 75
    assert summary.epoch == "2026-07-20T12:00:00Z"
    assert summary.rules[RULE_PORT_SCAN] == 40
    assert summary.rules[RULE_HASH_BLOCKLIST] == 12


def test_alert_ids_are_unique():
    ids = [a.alert_id for a in corpus()]
    assert len(ids) == len(set(ids))


def test_every_timestamp_is_fixed_width_utc_and_before_the_epoch(seeded_db_path):
    conn = sqlite3.connect(seeded_db_path)
    rows = conn.execute("SELECT alert_id, occurred_at FROM alerts").fetchall()
    conn.close()
    assert rows
    for alert_id, occurred_at in rows:
        assert TS_RE.match(occurred_at), f"{alert_id}: {occurred_at!r}"
        assert parse_ts(occurred_at) <= CORPUS_EPOCH


def test_epoch_shifts_every_timestamp_by_exactly_the_delta(tmp_path):
    shifted_epoch = CORPUS_EPOCH + timedelta(days=365)
    base, shifted = tmp_path / "base.db", tmp_path / "shifted.db"
    build_seeded_db(str(base))
    build_seeded_db(str(shifted), epoch=shifted_epoch)

    def times(path):
        conn = sqlite3.connect(path)
        rows = dict(conn.execute("SELECT alert_id, occurred_at FROM alerts"))
        conn.close()
        return {k: parse_ts(v) for k, v in rows.items()}

    base_times, shifted_times = times(str(base)), times(str(shifted))
    assert base_times.keys() == shifted_times.keys()
    for alert_id, value in base_times.items():
        assert shifted_times[alert_id] - value == timedelta(days=365)


# -- group composition -------------------------------------------------------


@pytest.fixture(scope="module")
def by_id():
    return {a.alert_id: a for a in corpus()}


def test_group_a_reproduces_architecture_appendix_b(by_id):
    appendix_b = by_id["SIEM-2026-017901"]
    assert appendix_b.title == "EDR: suspicious rundll32 network activity"
    assert appendix_b.severity == 80
    assert appendix_b.disposition == "true_positive"
    assert (CORPUS_EPOCH - appendix_b.offset).isoformat() == "2026-07-15T03:22:00+00:00"
    assert appendix_b.entities == (("host", "WS-FIN-0142"),)


def test_group_a3_serves_fixture_05_only(by_id):
    """The split that gives fixture 01 two relations and fixture 05 three (§14.2)."""
    a3 = by_id["SIEM-2026-018050"]
    values = {value for _type, value in a3.entities}
    assert values == {"FS-CORP-03", "10.20.30.12"}
    # Neither value belongs to fixture 01.
    assert not values & {"203.0.113.66", "10.20.14.88", "WS-FIN-0142", "l.hassan"}


def test_group_b_has_three_phishing_true_positives():
    okafor = [a for a in corpus() if ("user", "j.okafor") in a.entities]
    assert len(okafor) == 4
    assert Counter(a.disposition for a in okafor)["true_positive"] == 3


def test_group_d_composition_and_disjoint_true_positive():
    group_d = [a for a in corpus() if a.vendor_rule == RULE_HASH_BLOCKLIST]
    assert len(group_d) == 12
    dispositions = Counter(a.disposition for a in group_d)
    assert dispositions["false_positive"] == 11
    assert dispositions["true_positive"] == 1

    # If the TP shared an entity with fixture 04 it would grant the +25 prior-TP
    # bonus and drift the fixture toward the wrong band (§14.2).
    tp = next(a for a in group_d if a.disposition == "true_positive")
    fixture_04_values = {"WS-ENG-0231", "d.chen", "pskill.exe"}
    assert not {v for _t, v in tp.entities} & fixture_04_values

    sharing = [a for a in group_d if ("host", "WS-ENG-0231") in a.entities]
    assert len(sharing) == 1
    assert sharing[0].disposition == "false_positive"


def test_group_f_is_forty_firings_at_95_percent():
    group_f = [a for a in corpus() if a.vendor_rule == RULE_PORT_SCAN]
    assert len(group_f) == 40
    dispositions = Counter(a.disposition for a in group_f)
    assert dispositions["false_positive"] == 38
    assert dispositions["true_positive"] == 2

    sharing = [a for a in group_f if ("ip", "10.20.0.15") in a.entities]
    assert len(sharing) == 5
    assert all(a.disposition == "false_positive" for a in sharing)


def test_group_e_stays_neutral_for_fixture_06():
    """<= 2 relations and no TP, or fixture 06 crosses into escalate (§16.2)."""
    related = [
        a
        for a in corpus()
        if {v for _t, v in a.entities} & {"sso-gateway", "m.silva", "198.51.100.77"}
    ]
    assert len(related) == 2
    assert all(a.disposition != "true_positive" for a in related)


def test_group_h_is_empty_so_fixture_10_is_time_invariant():
    """§4.3: fixture 10 is the only alert whose window anchors on the wall clock."""
    for alert in corpus():
        for _type, value in alert.entities:
            assert value.lower() not in RESERVED_FIXTURE_10_VALUES, (
                f"{alert.alert_id} seeds a reserved fixture-10 value: {value}"
            )


# -- hygiene -----------------------------------------------------------------


def test_hygiene_no_real_indicators():
    """Architecture §7.1/§10.3 bind the seed as much as the fixtures (§14.3)."""
    for alert in corpus():
        for entity_type, value in alert.entities:
            if entity_type == "ip":
                addr = ipaddress.ip_address(value)
                assert addr.is_private or any(addr in net for net in _DOC_RANGES), (
                    f"{alert.alert_id}: {value} is neither internal nor a documentation IP"
                )
            elif entity_type == "domain":
                assert value.endswith((".example", ".test", ".invalid")) or "example-" in value
