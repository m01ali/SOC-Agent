"""TTL cache for TI verdicts. Spec: enrichment-05-spec.md §8.3.

Process-local for the POC. Architecture §5.3 notes the same call path later fronts a
Redis/SQLite cache; this is a class with two methods precisely so that swap is a
constructor change.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from soc_agent.models import TIVerdict

CacheKey = tuple[str, str, str]  # (provider name, entity type, canonical value)


class TTLCache:
    def __init__(self, ttl_s: int, *, clock: Callable[[], float] = time.monotonic) -> None:
        # time.monotonic, not time.time: a wall-clock jump (NTP step, DST) must not
        # expire or resurrect entries.
        self._ttl_s = ttl_s
        self._clock = clock
        self._entries: dict[CacheKey, tuple[float, TIVerdict]] = {}

    def get(self, key: CacheKey) -> TIVerdict | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        stored_at, verdict = entry
        if self._clock() - stored_at >= self._ttl_s:
            del self._entries[key]
            return None
        return verdict.model_copy(deep=True)

    def put(self, key: CacheKey, verdict: TIVerdict) -> None:
        # Failed lookups are never cached. Caching a timeout for cache_ttl_s (default
        # 3600) turns a one-second network blip into an hour of `unknown` verdicts on
        # a known-bad IOC.
        if verdict.error is not None:
            return
        self._entries[key] = (self._clock(), verdict.model_copy(deep=True))

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
