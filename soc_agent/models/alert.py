"""Normalized alert contracts. Spec: data-contracts-02-spec.md §4.3."""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, Field

from soc_agent.models.common import ContractModel

SourceSystem = Literal["generic", "splunk", "elastic", "cef", "freetext"]
NormalizationMethod = Literal["parser", "llm"]
AlertCategory = Literal[
    "malware",
    "phishing",
    "command_and_control",
    "lateral_movement",
    "exfiltration",
    "credential_access",
    "initial_access",
    "persistence",
    "reconnaissance",
    "policy_violation",
    "anomaly",
    "other",
]


class NormalizationInfo(ContractModel):
    method: NormalizationMethod
    confidence: float = Field(ge=0, le=1)
    warnings: list[str] = Field(default_factory=list)


class NormalizedAlert(ContractModel):
    alert_id: str = Field(min_length=1)
    dedupe_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_system: SourceSystem
    vendor_rule: str | None = None
    title: str = Field(min_length=1)
    description: str | None = None
    category: AlertCategory | None = None
    severity_original: str | None = None
    severity: int = Field(ge=0, le=100)
    occurred_at: AwareDatetime | None = None
    ingested_at: AwareDatetime
    observed_fields: dict[str, str] = Field(default_factory=dict)
    raw: dict | str
    normalization: NormalizationInfo


class NormalizedAlertDraft(ContractModel):
    """LLM structured output for the free-text normalizer (spec 03).

    Only what the model can read off the text — code adds alert_id, dedupe_key,
    source_system, ingested_at, raw, normalization afterward.
    """

    title: str = Field(min_length=1)
    description: str | None = None
    category: AlertCategory | None = None
    severity_original: str | None = None
    severity: int = Field(ge=0, le=100, default=50)
    occurred_at: AwareDatetime | None = None
    vendor_rule: str | None = None
    observed_fields: dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(ge=0, le=1, default=0.5)
