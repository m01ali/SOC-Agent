"""Pydantic data contracts — implemented in data-contracts-02-spec.md (Architecture §4–§6).

Single import surface: `from soc_agent.models import Entity, EnrichmentOutput`.
"""

from __future__ import annotations

from soc_agent.models.alert import (
    AlertCategory,
    NormalizationInfo,
    NormalizationMethod,
    NormalizedAlert,
    NormalizedAlertDraft,
    SourceSystem,
)
from soc_agent.models.attack import (
    TACTIC_ID_PATTERN,
    TECHNIQUE_ID_PATTERN,
    AttackMapping,
    AttackSelection,
    AttackSelectionItem,
)
from soc_agent.models.common import SCHEMA_VERSION, Confidence, ContractModel
from soc_agent.models.entities import (
    IOC_TYPES,
    Entity,
    EntityCandidate,
    EntityProvenance,
    EntityRef,
    EntityRole,
    EntityType,
    ExtractionMethod,
    ExtractionSelection,
)
from soc_agent.models.errors import ErrorType, Stage, StageError
from soc_agent.models.fixtures import ExpectedEntity, ExpectedFixture
from soc_agent.models.history import (
    Disposition,
    RelatedAlert,
    RelatedAlertsBlock,
    RuleStats,
)
from soc_agent.models.output import (
    EnrichmentOutput,
    Provenance,
    Status,
    TokenUsage,
)
from soc_agent.models.scoring import (
    Briefing,
    Priority,
    RiskAssessment,
    RiskBand,
    RiskComponents,
    RiskWeights,
    TriageAction,
    TriageRecommendation,
)
from soc_agent.models.ti import (
    ThreatIntelBlock,
    TIResult,
    TISummary,
    TIVerdict,
    TIVerdictLabel,
)

__all__ = [
    "IOC_TYPES",
    "SCHEMA_VERSION",
    "TACTIC_ID_PATTERN",
    "TECHNIQUE_ID_PATTERN",
    "AlertCategory",
    "AttackMapping",
    "AttackSelection",
    "AttackSelectionItem",
    "Briefing",
    "Confidence",
    "ContractModel",
    "Disposition",
    "EnrichmentOutput",
    "Entity",
    "EntityCandidate",
    "EntityProvenance",
    "EntityRef",
    "EntityRole",
    "EntityType",
    "ErrorType",
    "ExpectedEntity",
    "ExpectedFixture",
    "ExtractionMethod",
    "ExtractionSelection",
    "NormalizationInfo",
    "NormalizationMethod",
    "NormalizedAlert",
    "NormalizedAlertDraft",
    "Priority",
    "Provenance",
    "RelatedAlert",
    "RelatedAlertsBlock",
    "RiskAssessment",
    "RiskBand",
    "RiskComponents",
    "RiskWeights",
    "RuleStats",
    "SourceSystem",
    "Stage",
    "StageError",
    "Status",
    "ThreatIntelBlock",
    "TIResult",
    "TISummary",
    "TIVerdict",
    "TIVerdictLabel",
    "TokenUsage",
    "TriageAction",
    "TriageRecommendation",
]
