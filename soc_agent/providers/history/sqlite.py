"""SQLite alert-history store. Spec: enrichment-05-spec.md §11-§13.

Read-only at query time (§11.2). Values are stored already canonicalized (§11.1) so
the indexes are usable and the query side never needs LOWER().
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from soc_agent.extract.merge import canonical_value
from soc_agent.models import Entity, RelatedAlert, RuleStats
from soc_agent.models.alert import NormalizedAlert
from soc_agent.providers.history.base import CORRELATABLE_TYPES, HistoryStoreError

SCHEMA_VERSION = "1"

SCHEMA_SQL = """
CREATE TABLE alerts (
    alert_id     TEXT PRIMARY KEY,
    occurred_at  TEXT NOT NULL,
    title        TEXT NOT NULL,
    severity     INTEGER NOT NULL,
    vendor_rule  TEXT,
    category     TEXT,
    disposition  TEXT NOT NULL
);

CREATE TABLE alert_entities (
    alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    type     TEXT NOT NULL,
    value    TEXT NOT NULL,
    PRIMARY KEY (alert_id, type, value)
);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE INDEX idx_entities_value      ON alert_entities(value);
CREATE INDEX idx_entities_type_value ON alert_entities(type, value);
CREATE INDEX idx_alerts_rule_time    ON alerts(vendor_rule, occurred_at);
CREATE INDEX idx_alerts_time         ON alerts(occurred_at);
"""

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# §12.2 — analyst-facing strings that reach the briefing. Lower rank wins.
_IOC_TYPES_RANK = 0
_HOST_RANK = 1
_USER_RANK = 2
_RULE_RANK = 3


def to_utc_text(value: datetime) -> str:
    """Fixed-width UTC ISO-8601 (§4.4): lexicographic order == chronological order,
    so BETWEEN and ORDER BY work on the text column with no date functions."""
    return value.astimezone(UTC).strftime(TS_FORMAT)


def parse_ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def window_bounds(anchor: datetime, window_days: int) -> tuple[str, str]:
    """[anchor - window_days, anchor], both inclusive (§4.2).

    The upper bound matters as much as the lower one: an alert that happened *after*
    the one being triaged is not prior history, and including it would let the seed
    leak future true positives into a fixture's score.
    """
    return to_utc_text(anchor - timedelta(days=window_days)), to_utc_text(anchor)


def anchor_for(alert: NormalizedAlert) -> datetime:
    return alert.occurred_at or alert.ingested_at


class SqliteHistoryStore:
    name = "sqlite"

    def __init__(self, path: str, *, value_stoplist: Sequence[str] = ()) -> None:
        self.path = path
        self._stoplist = {v.lower() for v in value_stoplist}
        try:
            # mode=ro: correlation is a read, and it turns "file is missing" into an
            # immediate error instead of SQLite helpfully creating an empty database —
            # which would present as "this alert has no history" for every alert, forever.
            self._conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.OperationalError as e:
            raise HistoryStoreError(f"cannot open history store {path!r}: {e}") from e
        self._conn.row_factory = sqlite3.Row
        self._check_schema()

    def _check_schema(self) -> None:
        try:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.DatabaseError as e:
            raise HistoryStoreError(f"history store {self.path!r} is not readable: {e}") from e
        found = row["value"] if row else None
        if found != SCHEMA_VERSION:
            raise HistoryStoreError(
                f"history store {self.path!r} has schema_version {found!r}, "
                f"expected {SCHEMA_VERSION!r}"
            )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SqliteHistoryStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def epoch(self) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'epoch'").fetchone()
        return row["value"] if row else None

    # -- queries ------------------------------------------------------------

    def find_related(
        self, alert: NormalizedAlert, entities: Sequence[Entity], window_days: int
    ) -> list[RelatedAlert]:
        start, end = window_bounds(anchor_for(alert), window_days)

        # Entity values are attacker-influenced text and this is the one place in the
        # pipeline where they reach a query engine. Every value is bound as a
        # parameter; the IN list is built from placeholders, never from values (§20.1).
        targets: list[tuple[str, str]] = []  # (canonical, display)
        for entity in entities:
            if entity.type not in CORRELATABLE_TYPES:
                continue
            canonical = canonical_value(entity.type, entity.value)
            if canonical in self._stoplist:
                continue
            targets.append((canonical, entity.value))

        # alert_id -> (best reason rank, reason text, shared display values in order)
        matches: dict[str, tuple[int, str, list[str]]] = {}
        rows_by_id: dict[str, sqlite3.Row] = {}

        if targets:
            placeholders = ",".join("?" * len(targets))
            sql = (
                "SELECT a.alert_id, a.occurred_at, a.title, a.severity, a.disposition, "
                "e.type AS shared_type, e.value AS shared_value "
                "FROM alerts a JOIN alert_entities e ON e.alert_id = a.alert_id "
                f"WHERE e.value IN ({placeholders}) AND a.occurred_at BETWEEN ? AND ? "
                "ORDER BY a.occurred_at DESC, a.alert_id ASC"
            )
            params = [canonical for canonical, _ in targets] + [start, end]
            display_by_canonical = dict(targets)
            for row in self._safe_execute(sql, params):
                rows_by_id.setdefault(row["alert_id"], row)
                display = display_by_canonical.get(row["shared_value"], row["shared_value"])
                rank, reason = self._entity_reason(row["shared_type"], display)
                current = matches.get(row["alert_id"])
                if current is None:
                    matches[row["alert_id"]] = (rank, reason, [display])
                else:
                    best_rank, best_reason, shared = current
                    if display not in shared:
                        shared.append(display)
                    if rank < best_rank:
                        matches[row["alert_id"]] = (rank, reason, shared)

        if alert.vendor_rule:
            sql = (
                "SELECT alert_id, occurred_at, title, severity, disposition "
                "FROM alerts WHERE vendor_rule = ? AND occurred_at BETWEEN ? AND ? "
                "ORDER BY occurred_at DESC, alert_id ASC"
            )
            for row in self._safe_execute(sql, [alert.vendor_rule, start, end]):
                rows_by_id.setdefault(row["alert_id"], row)
                if row["alert_id"] not in matches:
                    matches[row["alert_id"]] = (
                        _RULE_RANK,
                        f'same rule "{alert.vendor_rule}"',
                        [],
                    )

        related = [
            RelatedAlert(
                alert_id=alert_id,
                occurred_at=parse_ts(rows_by_id[alert_id]["occurred_at"]),
                title=rows_by_id[alert_id]["title"],
                severity=rows_by_id[alert_id]["severity"],
                disposition=rows_by_id[alert_id]["disposition"],
                shared_entities=shared,
                relation_reason=reason,
            )
            for alert_id, (_rank, reason, shared) in matches.items()
        ]
        # §12.3 — entity-linked matches first, then most recent, ties broken by ID.
        # Stable sorts applied in reverse key order. Relevance outranks recency because
        # the cap (§12.4) truncates the tail: an analyst wants the alerts that touch
        # this host or user, not "the noisy rule fired again" forty times.
        related.sort(key=lambda r: r.alert_id)
        related.sort(key=lambda r: r.occurred_at, reverse=True)
        related.sort(key=lambda r: not r.shared_entities)
        return related

    def rule_stats(self, vendor_rule: str, window_days: int, *, anchor: datetime) -> RuleStats:
        start, end = window_bounds(anchor, window_days)
        sql = (
            "SELECT disposition, COUNT(*) AS n FROM alerts "
            "WHERE vendor_rule = ? AND occurred_at BETWEEN ? AND ? GROUP BY disposition"
        )
        counts = {
            row["disposition"]: row["n"]
            for row in self._safe_execute(sql, [vendor_rule, start, end])
        }
        return build_rule_stats(counts)

    def _entity_reason(self, entity_type: str, display: str) -> tuple[int, str]:
        if entity_type == "host":
            return _HOST_RANK, f"same host {display}"
        if entity_type == "user":
            return _USER_RANK, f"same user {display}"
        return _IOC_TYPES_RANK, f"shared entity {display}"

    def _safe_execute(self, sql: str, params: Sequence[object]) -> list[sqlite3.Row]:
        try:
            return self._conn.execute(sql, tuple(params)).fetchall()
        except sqlite3.DatabaseError as e:
            raise HistoryStoreError(f"history query failed: {e}") from e


def build_rule_stats(counts: dict[str, int]) -> RuleStats:
    """§13.1. Only true_positive/false_positive count toward fp_rate.

    `open`, `benign` and `undetermined` are excluded from the denominator: an analyst
    who has not closed an alert has not said the rule was wrong, and counting those as
    non-FPs would understate a genuinely noisy rule exactly when the queue is backed
    up — the moment the deduction matters most.
    """
    tps = counts.get("true_positive", 0)
    fps = counts.get("false_positive", 0)
    dispositioned = tps + fps
    return RuleStats(
        fired_count=sum(counts.values()),
        true_positives=tps,
        false_positives=fps,
        fp_rate=fps / dispositioned if dispositioned else 0.0,
    )


def fp_rate_or_none(stats: RuleStats) -> float | None:
    """The envelope's `rule_fp_rate` (§13.1).

    `RuleStats.fp_rate` is a plain float in the frozen spec-02 contract, so the
    "no evidence" case is recovered here rather than stored. None, not 0.0: 0.0
    reads as "this rule has never false-positived", a claim unsupported by zero
    evidence, and it would flow into the envelope as a fact.
    """
    if stats.true_positives + stats.false_positives == 0:
        return None
    return stats.fp_rate
