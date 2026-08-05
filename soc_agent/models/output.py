"""Output envelope contracts. Spec: data-contracts-02-spec.md §4.9."""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from soc_agent.models.alert import NormalizedAlert
from soc_agent.models.attack import AttackMapping
from soc_agent.models.common import SCHEMA_VERSION, ContractModel
from soc_agent.models.entities import Entity
from soc_agent.models.errors import StageError
from soc_agent.models.history import RelatedAlertsBlock
from soc_agent.models.scoring import Briefing, RiskAssessment, TriageRecommendation
from soc_agent.models.ti import ThreatIntelBlock

Status = Literal["success", "partial", "failed"]


class TokenUsage(ContractModel):
    input_tokens: int = 0
    output_tokens: int = 0


class Provenance(ContractModel):
    agent_version: str
    models: dict[str, str] = Field(default_factory=dict)
    ti_providers: list[str] = Field(default_factory=list)
    history_store: str | None = None
    started_at: AwareDatetime
    duration_ms: int = Field(ge=0, default=0)
    stage_timings_ms: dict[str, int] = Field(default_factory=dict)
    token_usage: TokenUsage = Field(default_factory=TokenUsage)


class EnrichmentOutput(ContractModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    status: Status
    alert: NormalizedAlert | None = None
    entities: list[Entity] = Field(default_factory=list)
    threat_intel: ThreatIntelBlock | None = None
    related_alerts: RelatedAlertsBlock | None = None
    mitre_attack: list[AttackMapping] = Field(default_factory=list)
    risk: RiskAssessment | None = None
    recommendation: TriageRecommendation | None = None
    briefing: Briefing | None = None
    errors: list[StageError] = Field(default_factory=list)
    provenance: Provenance

    @model_validator(mode="after")
    def _invariants(self) -> EnrichmentOutput:
        if self.status == "success":
            if self.errors:
                raise ValueError("status='success' requires errors to be empty")
            if self.alert is None:
                raise ValueError("status='success' requires alert to be present")
        elif self.status == "partial":
            if self.alert is None:
                raise ValueError("status='partial' requires alert to be present")
        elif self.status == "failed":
            failed_blocks = (self.risk, self.recommendation, self.briefing)
            if any(block is not None for block in failed_blocks):
                raise ValueError(
                    "status='failed' requires risk, recommendation, and briefing to all be None"
                )
        return self
