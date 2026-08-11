"""Historical alert correlation. Spec: enrichment-05-spec.md §10-§15 (Architecture §5.4).

Public API: `correlate`, `CorrelationResult`, `get_store`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from soc_agent.config import ConfigError, HistoryConfig, get_config
from soc_agent.models import Entity, RelatedAlertsBlock, RuleStats, StageError
from soc_agent.models.alert import NormalizedAlert
from soc_agent.providers.history.base import (
    CORRELATABLE_TYPES,
    AlertHistoryStore,
    HistoryStoreError,
)
from soc_agent.providers.history.sqlite import (
    SqliteHistoryStore,
    anchor_for,
    fp_rate_or_none,
)

__all__ = [
    "CORRELATABLE_TYPES",
    "AlertHistoryStore",
    "CorrelationResult",
    "HistoryStoreError",
    "correlate",
    "get_store",
]


@dataclass(frozen=True)
class CorrelationResult:
    block: RelatedAlertsBlock
    rule_stats: RuleStats | None = None
    errors: list[StageError] = field(default_factory=list)
    truncated: int = 0
    store_name: str | None = None


def get_store(cfg: HistoryConfig | None = None) -> AlertHistoryStore:
    """Build the configured store. Like the TI registry, an allowlist (§9.3)."""
    cfg = cfg or get_config().history
    if cfg.store == "sqlite":
        return SqliteHistoryStore(cfg.path, value_stoplist=cfg.value_stoplist)
    raise ConfigError(f"unsupported history store: {cfg.store!r}")


def _empty(detail: str) -> CorrelationResult:
    return CorrelationResult(
        block=RelatedAlertsBlock(count=0),
        errors=[StageError(stage="correlate", type="provider_error", detail=detail)],
    )


def correlate(
    alert: NormalizedAlert,
    entities: Sequence[Entity],
    *,
    store: AlertHistoryStore | None = None,
    config: HistoryConfig | None = None,
) -> CorrelationResult:
    """Find related past alerts and rule statistics. Never raises.

    Architecture §11: history store down -> empty correlation -> partial + error.
    An alert with *no* matches is not an error — that is the normal case in a fresh
    deployment, and manufacturing an error there would make every run report partial.
    """
    cfg = config or get_config().history

    owned = store is None
    try:
        active = store if store is not None else get_store(cfg)
    except (HistoryStoreError, ConfigError) as e:
        return _empty(str(e))

    try:
        matches = active.find_related(alert, entities, cfg.window_days)
        stats: RuleStats | None = None
        if alert.vendor_rule:
            stats = active.rule_stats(alert.vendor_rule, cfg.window_days, anchor=anchor_for(alert))
    except HistoryStoreError as e:
        return _empty(str(e))
    except Exception as e:  # noqa: BLE001 — a store bug must not kill the pipeline
        return _empty(f"unexpected {type(e).__name__}: {e}")
    finally:
        if owned:
            try:
                active.close()
            except Exception:  # noqa: BLE001 — close failures are not findings
                pass

    # Counts describe the evidence; the cap describes the rendering (§12.4).
    # Computing dispositions over the capped list would let a display limit change
    # the risk score — fixture 08 is the live proof: its five entity-sharing matches
    # are the five *oldest* of forty, so a recency-ordered cap of 20 would hide every
    # one of them and silently drop 10 points from the history component.
    #
    # Prior TP/FP counts are scoped to entity-sharing matches (§12.5): Architecture
    # §5.6 awards +25 for a related true positive that *shares an entity*, and a
    # rule-only match is "this rule has been right before" — already carried, without
    # double-counting, by rule_fp_rate and rule_fired_count.
    shared = [m for m in matches if m.shared_entities]
    prior_tps = sum(1 for m in shared if m.disposition == "true_positive")
    prior_fps = sum(1 for m in shared if m.disposition == "false_positive")
    shown = matches[: cfg.max_related]

    block = RelatedAlertsBlock(
        count=len(matches),
        prior_true_positives=prior_tps,
        prior_false_positives=prior_fps,
        rule_fp_rate=fp_rate_or_none(stats) if stats else None,
        rule_fired_count=stats.fired_count if stats else None,
        shared_entity_count=len(shared),
        alerts=shown,
    )
    return CorrelationResult(
        block=block,
        rule_stats=stats,
        errors=[],
        truncated=max(0, len(matches) - len(shown)),
        store_name=getattr(active, "name", None),
    )
