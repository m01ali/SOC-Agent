"""Fixture-label contract; used by tests + eval. Spec: data-contracts-02-spec.md §4.10.

Label semantics (binding for specs 04/06/09): `entities` is the *complete* ground
truth — precision and recall are both computed over `(type, value)` pairs against
this list. `techniques` = IDs expected within the agent's top-3 (empty list = no
ATT&CK requirement). `action` = expected recommendation; `forbidden_actions` are
hard failures if produced.
"""

from __future__ import annotations

import re

from pydantic import Field, field_validator

from soc_agent.models.alert import AlertCategory, SourceSystem
from soc_agent.models.attack import TECHNIQUE_ID_PATTERN
from soc_agent.models.common import ContractModel
from soc_agent.models.entities import EntityRole, EntityType
from soc_agent.models.scoring import RiskBand

_TECHNIQUE_RE = re.compile(TECHNIQUE_ID_PATTERN)


class ExpectedEntity(ContractModel):
    type: EntityType
    value: str
    role: EntityRole | None = None


class ExpectedFixture(ContractModel):
    format: SourceSystem
    category: AlertCategory | None = None
    action: RiskBand
    forbidden_actions: list[RiskBand] = Field(default_factory=list)
    entities: list[ExpectedEntity]
    techniques: list[str] = Field(default_factory=list)
    notes: str | None = None

    @field_validator("techniques")
    @classmethod
    def _validate_technique_ids(cls, value: list[str]) -> list[str]:
        for technique_id in value:
            if not _TECHNIQUE_RE.match(technique_id):
                raise ValueError(f"invalid technique id: {technique_id!r}")
        return value
