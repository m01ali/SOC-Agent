"""FailingTIProvider — the degradation lever. Spec: enrichment-05-spec.md §9.2.

Architecture §1.4 requires a "TI provider down -> partial output" demo. Failure is its
own provider rather than a flag threaded through MockTIProvider, so the mock keeps no
branch it would never take in production:

    threat_intel: {providers: [failing]}     # every lookup raises
    threat_intel: {providers: [timeout]}     # every lookup hangs past lookup_timeout_s
"""

from __future__ import annotations

import asyncio
from typing import Literal

from soc_agent.models import Entity, TIVerdict
from soc_agent.providers.ti.base import TIProviderError, supports_ioc_types


class FailingTIProvider:
    """Always fails, in whichever of the two ways §9.1 has to handle."""

    def __init__(self, mode: Literal["error", "timeout"] = "error") -> None:
        self.mode = mode
        self.name = "failing" if mode == "error" else "timeout"

    def supports(self, entity: Entity) -> bool:
        return supports_ioc_types(entity)

    async def lookup(self, entity: Entity) -> TIVerdict:
        if self.mode == "timeout":
            # Longer than any sane lookup_timeout_s; wait_for cancels it (§8.2).
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")
        raise TIProviderError(f"{self.name} provider is unavailable (simulated)")
