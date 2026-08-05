"""Risk, triage, and briefing contracts. Spec: data-contracts-02-spec.md §4.8.

Distinct from `soc_agent/scoring.py` (the scoring math, spec 07) — import explicitly,
never relatively ambiguous.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from soc_agent.models.common import Confidence, ContractModel

RiskBand = Literal["escalate", "investigate", "close"]
TriageAction = RiskBand
Priority = Literal["P1", "P2", "P3", "P4"]


class RiskComponents(ContractModel):
    ti: int = Field(ge=0, le=100)
    severity: int = Field(ge=0, le=100)
    history: int = Field(ge=0, le=100)


class RiskWeights(ContractModel):
    ti: float
    severity: float
    history: float


class RiskAssessment(ContractModel):
    score: int = Field(ge=0, le=100)
    band: RiskBand
    components: RiskComponents
    weights: RiskWeights


class TriageRecommendation(ContractModel):
    """LLM structured output for the triage node (spec 07) — also the final output block."""

    action: TriageAction
    priority: Priority
    confidence: Confidence
    rationale: str = Field(min_length=1)
    override_reason: str | None = None
    suggested_actions: list[str] = Field(default_factory=list)


class Briefing(ContractModel):
    """LLM structured output for the briefing node (spec 07) — also the final output block."""

    markdown: str = Field(min_length=1)
