"""MockTIProvider behaviour. Spec: enrichment-05-spec.md §21.2."""

from __future__ import annotations

from pathlib import Path

import pytest

from soc_agent.models import Entity, EntityProvenance
from soc_agent.providers.ti.mock import MockTIProvider, simulated_delay_s

SEED_PATH = str(Path(__file__).parents[2] / "data" / "ti_seed.yaml")


def make_entity(etype: str, value: str, **kwargs) -> Entity:
    return Entity(
        type=etype,
        value=value,
        confidence=1.0,
        provenance=EntityProvenance(method="field_map"),
        **kwargs,
    )


@pytest.fixture
def provider():
    return MockTIProvider(SEED_PATH, simulate_latency=False)


async def test_seeded_hit_returns_the_full_verdict(provider):
    verdict = await provider.lookup(make_entity("ip", "203.0.113.66"))
    assert verdict.verdict == "malicious"
    assert verdict.score == 95
    assert verdict.tags == ["c2", "cobalt-strike"]
    assert verdict.first_seen is not None and verdict.last_seen is not None
    assert verdict.raw["vt"]["malicious"] == 3
    assert verdict.error is None


async def test_miss_is_a_finding_not_a_failure(provider):
    """`unknown` means checked-and-nothing-known; `error` stays None (§5)."""
    verdict = await provider.lookup(make_entity("ip", "198.51.100.23"))
    assert verdict.verdict == "unknown"
    assert verdict.score == 0
    assert verdict.error is None


@pytest.mark.parametrize(
    ("etype", "value"),
    [
        ("domain", "PAYROLL-UPDATE.EXAMPLE-BILLING.NET"),
        ("hash_sha256", "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"),
    ],
)
async def test_lookup_key_canonicalization(provider, etype, value):
    verdict = await provider.lookup(make_entity(etype, value))
    assert verdict.verdict == "malicious"


async def test_ipv6_canonicalization_shares_the_key():
    """The cache/lookup key uses spec 04's canonical_value, so IPv6 forms unify."""
    seed = {("ip", "2001:db8::1")}
    del seed  # documented intent; the assertion below is the real check
    from soc_agent.providers.ti.base import lookup_key

    assert lookup_key(make_entity("ip", "2001:0db8:0000::0001")) == ("ip", "2001:db8::1")


async def test_url_lookups_are_exact_no_host_inheritance(provider):
    """A URL whose host is seeded but whose URL is not returns unknown (§6.3)."""
    seeded = await provider.lookup(
        make_entity("url", "sftp://transfer.example-cloudshare.net/upload")
    )
    assert seeded.verdict == "malicious"

    other_path = await provider.lookup(
        make_entity("url", "sftp://transfer.example-cloudshare.net/other")
    )
    assert other_path.verdict == "unknown"


async def test_fixture_10_ip_is_capped_at_60(provider):
    """§16.2: at 70 the projected risk reads 71.0 and escalates, contradicting the label."""
    verdict = await provider.lookup(make_entity("ip", "203.0.113.150"))
    assert verdict.verdict == "suspicious"
    assert verdict.score == 60


@pytest.mark.parametrize(
    ("etype", "value"),
    [
        ("user", "l.hassan"),
        ("host", "WS-FIN-0142"),
        ("process", "powershell"),
        ("file_path", "invoice.xlsm"),
        ("email", "user@example-corp.test"),
    ],
)
def test_supports_only_ioc_types(provider, etype, value):
    assert provider.supports(make_entity(etype, value)) is False


@pytest.mark.parametrize("etype", ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"])
def test_supports_ioc_types(provider, etype):
    value = {"ip": "203.0.113.1", "domain": "a.example-x.test", "url": "http://a.example-x.test/"}
    value |= {
        "hash_md5": "0" * 32,
        "hash_sha1": "0" * 40,
        "hash_sha256": "0" * 64,
    }
    assert provider.supports(make_entity(etype, value[etype])) is True


def test_simulated_delay_is_deterministic_and_bounded():
    first = simulated_delay_s("203.0.113.9")
    assert first == simulated_delay_s("203.0.113.9")
    for value in ("a", "b", "203.0.113.9", "example-x.test"):
        assert 0.010 <= simulated_delay_s(value) <= 0.050


def test_verdicts_are_copies_not_shared_state(provider):
    """A caller mutating a verdict must not poison the seed index for the next lookup."""
    import asyncio

    entity = make_entity("ip", "203.0.113.66")
    first = asyncio.run(provider.lookup(entity))
    first.tags.append("mutated")
    second = asyncio.run(provider.lookup(entity))
    assert "mutated" not in second.tags
