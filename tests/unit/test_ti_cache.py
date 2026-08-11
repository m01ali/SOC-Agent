"""TTL cache behaviour. Spec: enrichment-05-spec.md §21.4."""

from __future__ import annotations

from soc_agent.models import TIVerdict
from soc_agent.providers.ti import enrich_ti_sync
from soc_agent.providers.ti.cache import TTLCache
from soc_agent.providers.ti.mock import MockTIProvider
from tests.unit.test_ti_mock import SEED_PATH, make_entity


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


KEY = ("mock", "ip", "203.0.113.66")


def test_hit_before_ttl_miss_after():
    """No sleep anywhere — the clock is injected precisely so this test is instant."""
    clock = FakeClock()
    cache = TTLCache(ttl_s=60, clock=clock)
    cache.put(KEY, TIVerdict(verdict="malicious", score=95))

    clock.advance(59)
    assert cache.get(KEY) is not None

    clock.advance(2)
    assert cache.get(KEY) is None
    assert len(cache) == 0  # expiry evicts


def test_failed_lookups_are_never_cached():
    """§8.3: a cached timeout turns a one-second blip into an hour of `unknown`."""
    cache = TTLCache(ttl_s=3600)
    cache.put(KEY, TIVerdict(verdict="unknown", score=0, error="timeout after 5s"))
    assert cache.get(KEY) is None
    assert len(cache) == 0


def test_key_includes_the_provider_name():
    cache = TTLCache(ttl_s=3600)
    cache.put(("a", "ip", "203.0.113.66"), TIVerdict(verdict="malicious", score=95))
    assert cache.get(("b", "ip", "203.0.113.66")) is None


def test_cached_verdicts_are_copies():
    cache = TTLCache(ttl_s=3600)
    cache.put(KEY, TIVerdict(verdict="malicious", score=95, tags=["c2"]))
    first = cache.get(KEY)
    first.tags.append("mutated")
    assert cache.get(KEY).tags == ["c2"]


def test_enrichment_reports_cache_hits(monkeypatch):
    entities = [make_entity("ip", "203.0.113.66"), make_entity("ip", "203.0.113.199")]
    provider = MockTIProvider(SEED_PATH, simulate_latency=False)
    cache = TTLCache(ttl_s=3600)

    first = enrich_ti_sync(entities, providers=[provider], cache=cache)
    assert first.cache_hits == 0

    second = enrich_ti_sync(entities, providers=[provider], cache=cache)
    assert second.cache_hits == 2
    assert second.block.summary.malicious == 2


def test_cache_does_not_change_results_only_timing():
    entities = [make_entity("ip", "203.0.113.66")]
    provider = MockTIProvider(SEED_PATH, simulate_latency=False)
    cache = TTLCache(ttl_s=3600)

    first = enrich_ti_sync(entities, providers=[provider], cache=cache)
    second = enrich_ti_sync(entities, providers=[provider], cache=cache)
    assert first.block.model_dump(mode="json") == second.block.model_dump(mode="json")
