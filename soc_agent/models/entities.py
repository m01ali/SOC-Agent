"""Entity contracts + value validation. Spec: data-contracts-02-spec.md §4.4."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import Field, model_validator

from soc_agent.models.common import ContractModel

EntityType = Literal[
    "ip",
    "domain",
    "url",
    "hash_md5",
    "hash_sha1",
    "hash_sha256",
    "email",
    "user",
    "host",
    "process",
    "file_path",
]
EntityRole = Literal["source", "destination", "actor", "target", "unknown"]
ExtractionMethod = Literal["field_map", "regex", "llm"]

IOC_TYPES: frozenset[str] = frozenset(
    {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"}
)

_HASH_LENGTHS: dict[str, int] = {"hash_md5": 32, "hash_sha1": 40, "hash_sha256": 64}
_HEX_RE = re.compile(r"^[0-9a-f]+$")


class EntityProvenance(ContractModel):
    field: str | None = None
    method: ExtractionMethod
    original_text: str | None = None


class Entity(ContractModel):
    type: EntityType
    value: str = Field(min_length=1)
    role: EntityRole = "unknown"
    is_internal: bool | None = None
    confidence: float = Field(ge=0, le=1)
    provenance: EntityProvenance

    @model_validator(mode="after")
    def _validate_value(self) -> Entity:
        if self.type == "ip":
            try:
                ipaddress.ip_address(self.value)
            except ValueError as e:
                raise ValueError(f"invalid ip: {self.value!r}") from e
        elif self.type in _HASH_LENGTHS:
            lowered = self.value.lower()
            length = _HASH_LENGTHS[self.type]
            if len(lowered) != length or not _HEX_RE.match(lowered):
                raise ValueError(
                    f"{self.type} must be {length} lowercase hex chars, got {self.value!r}"
                )
            self.value = lowered
        elif self.type == "email":
            if "@" not in self.value:
                raise ValueError(f"invalid email: {self.value!r}")
            self.value = self.value.lower()
        elif self.type == "domain":
            lowered = self.value.lower()
            if "." not in lowered or any(c.isspace() for c in lowered):
                raise ValueError(f"invalid domain: {self.value!r}")
            if lowered.startswith(".") or lowered.endswith("."):
                raise ValueError(f"invalid domain: {self.value!r}")
            self.value = lowered
        return self


class EntityRef(ContractModel):
    """Minimal (type, value) reference — used inside TIResult."""

    type: EntityType
    value: str


class EntityCandidate(ContractModel):
    """LLM structured output for extraction assist (spec 04). No provenance/confidence —
    code stamps method="llm" and assigns confidence on merge."""

    type: EntityType
    value: str = Field(min_length=1)
    role: EntityRole = "unknown"
    context_span: str | None = None


class ExtractionSelection(ContractModel):
    """LLM structured output for the extraction assist (spec 04): the list wrapper
    with_structured_output requires. Additive — does not change SCHEMA_VERSION."""

    entities: list[EntityCandidate] = Field(default_factory=list, max_length=40)
