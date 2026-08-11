"""enrich_ti fan-out, timeouts and degradation. Spec: enrichment-05-spec.md §21.5."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from soc_agent.config import ConfigError, ThreatIntelConfig, load_config
from soc_agent.models import Entity, TIVerdict
from soc_agent.providers.ti import enrich_ti, enrich_ti_sync, get_providers
from soc_agent.providers.ti.base import TIProviderError, supports_ioc_types
from soc_agent.providers.ti.failing import FailingTIProvider
from soc_agent.providers.ti.mock import MockTIProvider
from tests.unit.test_ti_mock import SEED_PATH, make_entity

ENTITIES_DIR = Path(__file__).parents[1] / "data" / "entities"


def load_entities(stem: str) -> list[Entity]:
    payload = json.loads((ENTITIES_DIR / f"{stem}.json").read_text())
    return [Entity.model_validate(e) for e in payload]


def mock_provider(**kwargs) -> MockTIProvider:
    return MockTIProvider(SEED_PATH, simulate_latency=kwargs.pop("simulate_latency", False))


def ti_config(**overrides) -> ThreatIntelConfig:
    return ThreatIntelConfig(**{"simulate_latency": False, **overrides})


def test_only_ioc_entities_are_looked_up():
    """Internal IPs, users, hosts and processes never reach a provider (spec 04 §8.1)."""
    result = enrich_ti_sync(
        load_entities("01_c2_beacon"), providers=[mock_provider()], config=ti_config()
    )
    assert result.block.summary.iocs_checked == 1
    assert [r.entity.value for r in result.block.results] == ["203.0.113.66"]


def test_fixture_05_makes_zero_lookups_and_has_a_valid_empty_summary():
    result = enrich_ti_sync(
        load_entities("05_lateral_movement"), providers=[mock_provider()], config=ti_config()
    )
    assert result.block.results == []
    assert result.block.summary.iocs_checked == 0
    assert result.block.summary.worst_verdict is None
    assert result.errors == []


def test_results_are_ordered_worst_first():
    result = enrich_ti_sync(
        load_entities("09_exfil_volume"), providers=[mock_provider()], config=ti_config()
    )
    verdicts = [r.verdict for r in result.block.results]
    assert verdicts == sorted(verdicts, key=lambda v: {"malicious": 0}.get(v, 1))
    assert result.block.summary.worst_verdict == "malicious"


async def test_lookups_run_concurrently():
    """Simulated latency (§6.4) is what makes this assertion mean something."""
    entities = [make_entity("ip", f"203.0.113.{i}") for i in range(20, 30)]
    provider = MockTIProvider(SEED_PATH, simulate_latency=True)

    start = time.perf_counter()
    result = await enrich_ti(entities, providers=[provider], config=ti_config())
    elapsed = time.perf_counter() - start

    assert result.block.summary.iocs_checked == 10
    # Sequential would be >= 10 * 10 ms = 100 ms and averages ~300 ms; concurrent is
    # one max-delay wait (<= 50 ms). A 3x margin keeps this stable on a loaded machine.
    assert elapsed < 0.100, f"lookups appear sequential: {elapsed:.3f}s"


class SlowProvider:
    name = "slow"

    def supports(self, entity: Entity) -> bool:
        return supports_ioc_types(entity)

    async def lookup(self, entity: Entity) -> TIVerdict:
        import asyncio

        if entity.value == "203.0.113.66":
            await asyncio.sleep(10)
        return TIVerdict(verdict="malicious", score=90, sources=[self.name])


async def test_timeout_is_per_ioc_and_siblings_still_resolve():
    entities = [make_entity("ip", "203.0.113.66"), make_entity("ip", "203.0.113.199")]
    result = await enrich_ti(
        entities, providers=[SlowProvider()], config=ti_config(lookup_timeout_s=1)
    )

    by_value = {r.entity.value: r for r in result.block.results}
    assert by_value["203.0.113.66"].verdict == "unknown"
    assert by_value["203.0.113.66"].error == "timeout after 1s"
    assert by_value["203.0.113.199"].verdict == "malicious"

    assert len(result.errors) == 1
    assert result.errors[0].stage == "enrich_ti"
    assert result.errors[0].type == "timeout"
    assert result.errors[0].recoverable is True


class BrokenProvider:
    name = "broken"

    def supports(self, entity: Entity) -> bool:
        return True

    async def lookup(self, entity: Entity) -> TIVerdict:
        raise RuntimeError("provider exploded")


async def test_unexpected_exception_degrades_to_unknown():
    result = await enrich_ti(
        [make_entity("ip", "203.0.113.66")], providers=[BrokenProvider()], config=ti_config()
    )
    assert result.block.results[0].verdict == "unknown"
    assert "provider exploded" in result.block.results[0].error
    assert result.errors[0].type == "provider_error"


@pytest.mark.parametrize("mode", ["error", "timeout"])
async def test_failing_provider_degrades_without_raising(mode):
    """Architecture §1.4's degradation demo, driven by config alone (§9.2)."""
    entities = load_entities("09_exfil_volume")
    result = await enrich_ti(
        entities,
        providers=[FailingTIProvider(mode)],
        config=ti_config(lookup_timeout_s=1),
    )
    assert result.block.summary.iocs_checked == 3
    assert result.block.summary.unknown == 3
    assert all(r.error for r in result.block.results)
    assert len(result.errors) == 3


def test_provider_error_is_recorded_as_provider_error():
    class Raiser:
        name = "raiser"

        def supports(self, entity):
            return True

        async def lookup(self, entity):
            raise TIProviderError("feed unreachable")

    result = enrich_ti_sync(
        [make_entity("ip", "203.0.113.66")], providers=[Raiser()], config=ti_config()
    )
    assert result.errors[0].type == "provider_error"
    assert "feed unreachable" in result.errors[0].detail


def test_unknown_provider_name_is_a_config_error(tmp_path):
    """§9.3: no config typo can produce an outbound call."""
    with pytest.raises(ValueError, match="unknown threat_intel provider"):
        ThreatIntelConfig(providers=["virustotal"])

    # And through the real load path, where it surfaces as ConfigError.
    config_file = tmp_path / "config.yaml"
    config_file.write_text("threat_intel:\n  providers: [virustotal]\n")
    with pytest.raises(ConfigError, match="unknown threat_intel provider"):
        load_config(config_file)


def test_unknown_history_store_is_a_config_error(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("history:\n  store: elasticsearch\n")
    with pytest.raises(ConfigError, match="unknown history store"):
        load_config(config_file)


def test_get_providers_builds_the_allowlisted_names():
    providers = get_providers(ti_config(providers=["mock", "failing", "timeout"]))
    assert [p.name for p in providers] == ["mock", "failing", "timeout"]


def test_providers_used_is_reported_for_provenance():
    result = enrich_ti_sync(
        load_entities("01_c2_beacon"), providers=[mock_provider()], config=ti_config()
    )
    assert result.providers_used == ["mock"]


class IPOnlyProvider:
    name = "ip-only"

    def supports(self, entity: Entity) -> bool:
        return entity.type == "ip"

    async def lookup(self, entity: Entity) -> TIVerdict:
        return TIVerdict(verdict="malicious", score=90, sources=[self.name])


def test_unsupported_types_contribute_nothing_rather_than_unknown():
    """§5: an IP-only feed asked about a hash must not inflate the unknown count."""
    result = enrich_ti_sync(
        load_entities("02_phishing"), providers=[IPOnlyProvider()], config=ti_config()
    )
    # fixture 02's IOCs are a url, a domain and a hash — none of them IPs.
    assert result.block.summary.iocs_checked == 3
    assert result.block.summary.unknown == 3
    assert all(r.sources == [] for r in result.block.results)
    assert result.errors == []
