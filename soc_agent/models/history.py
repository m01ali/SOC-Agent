"""Alert-history correlation contracts. Spec: data-contracts-02-spec.md §4.6.

Addition vs Architecture Appendix C: this module is not enumerated in the original
layout sketch but is required by the ThreatIntelBlock-adjacent RelatedAlertsBlock
referenced throughout §4-§6.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field

from soc_agent.models.common import ContractModel

Disposition = Literal["true_positive", "false_positive", "benign", "open", "undetermined"]


class RelatedAlert(ContractModel):
    alert_id: str
    occurred_at: AwareDatetime
    title: str
    severity: int = Field(ge=0, le=100)
    disposition: Disposition
    shared_entities: list[str] = Field(default_factory=list)
    relation_reason: str


class RuleStats(ContractModel):
    fired_count: int = 0
    true_positives: int = 0
    false_positives: int = 0
    fp_rate: float = Field(ge=0, le=1, default=0.0)


class RelatedAlertsBlock(ContractModel):
    count: int = Field(ge=0)
    prior_true_positives: int = 0
    prior_false_positives: int = 0
    rule_fp_rate: float | None = None
    alerts: list[RelatedAlert] = Field(default_factory=list)
