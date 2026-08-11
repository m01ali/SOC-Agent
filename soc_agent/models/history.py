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
    # enrichment-05-spec.md §13.2: the ">= 10 firings" precondition of scoring's -25
    # history deduction. Without it the envelope shows a rate but not the evidence
    # threshold it was judged against (Architecture §1.3, "every claim is traceable").
    rule_fired_count: int | None = None
    # enrichment-05-spec.md §12.5: how many of `count` matched by a *shared entity*
    # rather than by rule alone. Scoring's "+10 if >= 3 related alerts share entities"
    # reads this; `count` includes rule-only context matches and would over-award it.
    # Computed pre-cap, so a display limit can never change the score.
    shared_entity_count: int = 0
    alerts: list[RelatedAlert] = Field(default_factory=list)
