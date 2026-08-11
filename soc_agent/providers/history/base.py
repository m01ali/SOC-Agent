"""Alert-history store protocol. Spec: enrichment-05-spec.md §10 (Architecture §5.4).

The dummy -> real seam: a SIEM-API store (Splunk saved search, Elastic DSL) implements
the same two methods and `correlate()` never changes.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol, runtime_checkable

from soc_agent.models import Entity, RelatedAlert, RuleStats
from soc_agent.models.alert import NormalizedAlert

# §12.1 — `process` and `file_path` are excluded. `powershell`, `pskill.exe` and
# `invoice_2207.xlsm` are shared by construction across unrelated alerts; correlating
# on them produces relations with no investigative meaning and inflates the ">= 3
# related" bonus in spec 07's history component.
CORRELATABLE_TYPES: frozenset[str] = frozenset(
    {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "user", "host"}
)


class HistoryStoreError(RuntimeError):
    """The store could not be queried (missing file, bad schema, driver error)."""


@runtime_checkable
class AlertHistoryStore(Protocol):
    name: str

    def find_related(
        self, alert: NormalizedAlert, entities: Sequence[Entity], window_days: int
    ) -> list[RelatedAlert]: ...

    # `anchor` is a deviation from Architecture §5.4's two-argument sketch: the window
    # is anchored on the alert, never on the clock (§4.2), so the anchor has to come
    # in with the query or rule stats would drift daily while find_related did not.
    def rule_stats(self, vendor_rule: str, window_days: int, *, anchor: datetime) -> RuleStats: ...

    def close(self) -> None: ...
