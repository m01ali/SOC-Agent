"""Shared base class, schema version, and confidence type. Spec: data-contracts-02-spec.md §4.1."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

SCHEMA_VERSION = "1.0"

Confidence = Literal["high", "medium", "low"]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
