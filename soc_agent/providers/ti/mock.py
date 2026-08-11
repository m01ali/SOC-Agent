"""MockTIProvider — the POC threat-intel source. Spec: enrichment-05-spec.md §6.

Backed by `data/ti_seed.yaml`, with response shapes mirroring VirusTotal/OTX so the
real adapters (Architecture §7.3) are drop-in.
"""

from __future__ import annotations

import asyncio
import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from soc_agent.config import ConfigError
from soc_agent.models import Entity, TIVerdict
from soc_agent.providers.ti.base import lookup_key, supports_ioc_types

# §6.2 — validated at load. A seed entry reading `verdict: clean, score: 90` would
# otherwise sail through (TIVerdict only constrains 0-100) and move a fixture across
# a band with no test failing anywhere near the cause.
_SCORE_BANDS: dict[str, tuple[int, int]] = {
    "malicious": (85, 100),
    "suspicious": (40, 70),
    "clean": (0, 10),
    "unknown": (0, 0),
}


def _parse_seed(payload: Any, source: str) -> dict[tuple[str, str], TIVerdict]:
    if not isinstance(payload, dict):
        raise ConfigError(f"{source}: seed root must be a mapping")
    defaults = payload.get("defaults") or {}
    entries = payload.get("entries") or []
    if not isinstance(entries, list):
        raise ConfigError(f"{source}: 'entries' must be a list")

    index: dict[tuple[str, str], TIVerdict] = {}
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise ConfigError(f"{source}: each entry must be a mapping")
        entry = {**defaults, **raw_entry}
        entity_type = entry.pop("type", None)
        value = entry.pop("value", None)
        if not entity_type or not value:
            raise ConfigError(f"{source}: entry missing 'type' or 'value': {raw_entry!r}")

        try:
            verdict = TIVerdict.model_validate(entry)
        except ValidationError as e:
            raise ConfigError(f"{source}: invalid entry for {entity_type} {value!r}: {e}") from e

        low, high = _SCORE_BANDS[verdict.verdict]
        if not low <= verdict.score <= high:
            raise ConfigError(
                f"{source}: {entity_type} {value!r} has verdict {verdict.verdict!r} "
                f"with score {verdict.score}, outside the allowed band {low}-{high} (§6.2)"
            )

        key = (str(entity_type), str(value).lower())
        if key in index:
            raise ConfigError(f"{source}: duplicate seed entry for {entity_type} {value!r}")
        index[key] = verdict
    return index


@lru_cache(maxsize=4)
def load_seed(path: str) -> dict[tuple[str, str], TIVerdict]:
    seed_path = Path(path)
    try:
        raw = yaml.safe_load(seed_path.read_text())
    except FileNotFoundError as e:
        raise ConfigError(f"threat-intel seed not found: {seed_path}") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {seed_path}: {e}") from e
    return _parse_seed(raw, str(seed_path))


def simulated_delay_s(value: str) -> float:
    """Deterministic 10-50 ms, derived from the value — never random (§6.4)."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return (10 + int(digest, 16) % 41) / 1000.0


class MockTIProvider:
    """Architecture §5.3's POC provider. Unknown IOCs return `unknown`, not an error."""

    name = "mock"

    def __init__(self, seed_path: str = "data/ti_seed.yaml", *, simulate_latency: bool = True):
        self._index = load_seed(seed_path)
        self._simulate_latency = simulate_latency

    def supports(self, entity: Entity) -> bool:
        return supports_ioc_types(entity)

    async def lookup(self, entity: Entity) -> TIVerdict:
        key = lookup_key(entity)
        hit = self._index.get(key)
        if hit is not None:
            return hit.model_copy(deep=True)

        # A miss is a finding, not a failure: the IOC was checked and no source knows
        # it. `error` stays None — that is what separates this from §9.1's outages.
        if self._simulate_latency:
            await asyncio.sleep(simulated_delay_s(key[1]))
        return TIVerdict(
            verdict="unknown",
            score=0,
            sources=[self.name],
            summary="No source has an opinion on this indicator (mock data).",
        )


def seed_entries(path: str = "data/ti_seed.yaml") -> dict[tuple[str, str], TIVerdict]:
    """The parsed seed index — used by tests and `soc-agent context` diagnostics."""
    return load_seed(path)


__all__ = ["MockTIProvider", "load_seed", "seed_entries", "simulated_delay_s"]
