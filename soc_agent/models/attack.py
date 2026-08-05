"""ATT&CK mapping contracts. Spec: data-contracts-02-spec.md §4.7."""

from __future__ import annotations

from pydantic import Field

from soc_agent.models.common import Confidence, ContractModel

TECHNIQUE_ID_PATTERN = r"^T\d{4}(\.\d{3})?$"
TACTIC_ID_PATTERN = r"^TA\d{4}$"


class AttackMapping(ContractModel):
    """Final, catalog-validated mapping (code fills tactic/name from the catalog, spec 06)."""

    tactic_id: str = Field(pattern=TACTIC_ID_PATTERN)
    tactic: str
    technique_id: str = Field(pattern=TECHNIQUE_ID_PATTERN)
    technique_name: str
    confidence: Confidence
    evidence: list[str] = Field(min_length=1)


class AttackSelectionItem(ContractModel):
    """LLM structured output item (spec 06): IDs only — names come from the catalog."""

    technique_id: str = Field(pattern=TECHNIQUE_ID_PATTERN)
    confidence: Confidence
    evidence: list[str] = Field(min_length=1)


class AttackSelection(ContractModel):
    techniques: list[AttackSelectionItem] = Field(default_factory=list, max_length=5)
