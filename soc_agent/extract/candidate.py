"""Internal candidate representation shared across extraction passes.

Spec: extraction-04-spec.md §5. Passes emit Candidate objects rather than Entity
objects directly, because an Entity validates its value on construction — a
validation failure inside a pass would abort the whole sweep. merge() is the only
place that constructs Entity, wrapping each construction defensively.
"""

from __future__ import annotations

from dataclasses import dataclass

from soc_agent.models import EntityRole, EntityType, ExtractionMethod


@dataclass(frozen=True)
class Candidate:
    type: EntityType
    value: str
    role: EntityRole = "unknown"
    method: ExtractionMethod = "regex"
    field: str | None = None
    original_text: str | None = None  # the defanged / as-written form
    order: int = 0  # discovery index, for stable sorting
