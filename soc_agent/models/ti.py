"""Threat-intel contracts. Spec: data-contracts-02-spec.md §4.5."""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from soc_agent.models.common import ContractModel
from soc_agent.models.entities import EntityRef

TIVerdictLabel = Literal["malicious", "suspicious", "clean", "unknown"]


class TIVerdict(ContractModel):
    verdict: TIVerdictLabel
    score: int = Field(ge=0, le=100)
    sources: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None
    summary: str | None = None
    raw: dict = Field(default_factory=dict)
    error: str | None = None


class TIResult(TIVerdict):
    entity: EntityRef


class TISummary(ContractModel):
    iocs_checked: int = Field(ge=0)
    malicious: int = 0
    suspicious: int = 0
    clean: int = 0
    unknown: int = 0
    worst_verdict: TIVerdictLabel | None = None

    @model_validator(mode="after")
    def _validate_worst_verdict(self) -> TISummary:
        is_zero = self.iocs_checked == 0
        is_none = self.worst_verdict is None
        if is_zero != is_none:
            raise ValueError("worst_verdict must be None iff iocs_checked == 0")
        return self


class ThreatIntelBlock(ContractModel):
    summary: TISummary
    results: list[TIResult] = Field(default_factory=list)
