"""Threat-intel enrichment. Spec: enrichment-05-spec.md §5-§9 (Architecture §5.3).

Public API: `enrich_ti`, `enrich_ti_sync`, `TIEnrichment`, `get_providers`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field

from soc_agent.config import ConfigError, ThreatIntelConfig, get_config
from soc_agent.extract.config import ioc_entities
from soc_agent.models import Entity, StageError, ThreatIntelBlock, TIResult, TIVerdict
from soc_agent.providers.ti.aggregate import VERDICT_RANK, aggregate_verdicts, summarize
from soc_agent.providers.ti.base import ThreatIntelProvider, TIProviderError, lookup_key
from soc_agent.providers.ti.cache import TTLCache
from soc_agent.providers.ti.failing import FailingTIProvider
from soc_agent.providers.ti.mock import MockTIProvider

__all__ = [
    "TIEnrichment",
    "TIProviderError",
    "ThreatIntelProvider",
    "enrich_ti",
    "enrich_ti_sync",
    "get_providers",
]


@dataclass(frozen=True)
class TIEnrichment:
    block: ThreatIntelBlock
    errors: list[StageError] = field(default_factory=list)
    cache_hits: int = 0
    providers_used: list[str] = field(default_factory=list)


def get_providers(cfg: ThreatIntelConfig | None = None) -> list[ThreatIntelProvider]:
    """Build the configured providers. The registry is an allowlist (§9.3).

    There is no code path by which a config typo, or a half-finished `virustotal`
    entry, causes an outbound call: an unknown name is a ConfigError, never a
    lazily-imported adapter.
    """
    cfg = cfg or get_config().threat_intel
    providers: list[ThreatIntelProvider] = []
    for name in cfg.providers:
        if name == "mock":
            providers.append(MockTIProvider(cfg.seed_path, simulate_latency=cfg.simulate_latency))
        elif name == "failing":
            providers.append(FailingTIProvider("error"))
        elif name == "timeout":
            providers.append(FailingTIProvider("timeout"))
        else:  # pragma: no cover - ThreatIntelConfig validates first
            raise ConfigError(f"unknown threat_intel provider: {name!r}")
    return providers


async def _lookup_one(
    provider: ThreatIntelProvider,
    entity: Entity,
    cfg: ThreatIntelConfig,
    cache: TTLCache,
    sem: asyncio.Semaphore,
    errors: list[StageError],
    stats: dict[str, int],
) -> TIVerdict:
    """Never raises. Every failure becomes an `unknown` verdict + a StageError (§9.1)."""
    key = (provider.name, *lookup_key(entity))
    cached = cache.get(key)
    if cached is not None:
        stats["cache_hits"] += 1
        return cached

    try:
        async with sem:
            verdict = await asyncio.wait_for(provider.lookup(entity), timeout=cfg.lookup_timeout_s)
    except TimeoutError:
        detail = (
            f"{provider.name}: lookup of {entity.type} {entity.value!r} "
            f"timed out after {cfg.lookup_timeout_s}s"
        )
        errors.append(StageError(stage="enrich_ti", type="timeout", detail=detail))
        return TIVerdict(
            verdict="unknown",
            score=0,
            sources=[provider.name],
            error=f"timeout after {cfg.lookup_timeout_s}s",
        )
    except TIProviderError as e:
        detail = f"{provider.name}: {e}"
        errors.append(StageError(stage="enrich_ti", type="provider_error", detail=detail))
        return TIVerdict(verdict="unknown", score=0, sources=[provider.name], error=str(e))
    except Exception as e:  # noqa: BLE001 — a provider bug must not kill the pipeline
        detail = f"{provider.name}: unexpected {type(e).__name__}: {e}"
        errors.append(StageError(stage="enrich_ti", type="provider_error", detail=detail))
        return TIVerdict(verdict="unknown", score=0, sources=[provider.name], error=repr(e))

    cache.put(key, verdict)
    return verdict


async def enrich_ti(
    entities: Sequence[Entity],
    *,
    providers: Sequence[ThreatIntelProvider] | None = None,
    config: ThreatIntelConfig | None = None,
    cache: TTLCache | None = None,
) -> TIEnrichment:
    """Look up every external IOC-typed entity concurrently and aggregate the verdicts.

    Never raises. A provider failure or timeout becomes an `unknown` verdict with
    `error` set plus a StageError (Architecture §5.3: failure is per-IOC).
    """
    cfg = config or get_config().threat_intel
    active = list(providers) if providers is not None else get_providers(cfg)
    cache = cache if cache is not None else TTLCache(cfg.cache_ttl_s)

    # Nothing but ioc_entities() is ever looked up: internal IPs, users, hosts,
    # processes and file paths are excluded at the source (spec 04 §8.1). That is
    # both the privacy control and the reason fixture 05 makes zero lookups.
    targets = ioc_entities(entities)

    errors: list[StageError] = []
    stats = {"cache_hits": 0}
    sem = asyncio.Semaphore(cfg.max_concurrency)

    jobs: list[tuple[int, str]] = []
    coros = []
    for index, entity in enumerate(targets):
        for provider in active:
            # A provider that cannot answer this type contributes nothing, rather than
            # an `unknown` that would drag the summary counts (§5).
            if not provider.supports(entity):
                continue
            jobs.append((index, provider.name))
            coros.append(_lookup_one(provider, entity, cfg, cache, sem, errors, stats))

    verdicts = await asyncio.gather(*coros)

    by_entity: dict[int, list[tuple[str, TIVerdict]]] = {}
    for (index, provider_name), verdict in zip(jobs, verdicts, strict=True):
        by_entity.setdefault(index, []).append((provider_name, verdict))

    results: list[TIResult] = [
        aggregate_verdicts(entity, by_entity.get(index, [])) for index, entity in enumerate(targets)
    ]
    # Most alarming first, then discovery order — the analyst reads the worst news first.
    results.sort(key=lambda r: -VERDICT_RANK[r.verdict])

    return TIEnrichment(
        block=ThreatIntelBlock(summary=summarize(results), results=results),
        errors=errors,
        cache_hits=stats["cache_hits"],
        providers_used=[p.name for p in active],
    )


def enrich_ti_sync(entities: Sequence[Entity], **kwargs) -> TIEnrichment:
    """asyncio.run() wrapper for the CLI and for sync tests."""
    return asyncio.run(enrich_ti(entities, **kwargs))
