"""Pipeline stage error contract. Spec: data-contracts-02-spec.md §4.2."""

from __future__ import annotations

from typing import Literal

from soc_agent.models.common import ContractModel

Stage = Literal[
    "ingest",
    "normalize",
    "extract",
    "enrich_ti",
    "correlate",
    "map_attack",
    "triage",
    "brief",
    "assemble",
]
ErrorType = Literal[
    "parse_error",
    "timeout",
    "api_error",
    "provider_error",
    "schema_validation",
    "internal",
]


class StageError(ContractModel):
    stage: Stage
    type: ErrorType
    detail: str
    recoverable: bool = True
