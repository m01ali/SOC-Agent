"""Extraction scoring: precision/recall/F1 against fixture labels.

Spec: extraction-04-spec.md §11.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from soc_agent.extract.merge import canonical_value
from soc_agent.models import Entity, EntityType, ExpectedEntity


def _canonical_key(entity_type: EntityType, value: str) -> tuple[str, str]:
    """(type, canonical(value)) — identical to merge()'s dedupe key (§10.1)."""
    return entity_type, canonical_value(entity_type, value)


@dataclass(frozen=True)
class ExtractionScore:
    precision: float
    recall: float
    f1: float
    true_positives: list[tuple[str, str]]
    false_positives: list[tuple[str, str]]
    false_negatives: list[tuple[str, str]]


def extraction_f1(
    predicted: Sequence[Entity], expected: Sequence[ExpectedEntity]
) -> ExtractionScore:
    """Precision/recall/F1 over (type, value) pairs. Roles are never scored (spec 02 §4.10)."""
    predicted_keys = {_canonical_key(e.type, e.value) for e in predicted}
    expected_keys = {_canonical_key(e.type, e.value) for e in expected}

    true_positives = sorted(predicted_keys & expected_keys)
    false_positives = sorted(predicted_keys - expected_keys)
    false_negatives = sorted(expected_keys - predicted_keys)

    if not predicted_keys and not expected_keys:
        return ExtractionScore(1.0, 1.0, 1.0, [], [], [])

    precision = len(true_positives) / len(predicted_keys) if predicted_keys else 0.0
    recall = len(true_positives) / len(expected_keys) if expected_keys else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return ExtractionScore(
        precision=precision,
        recall=recall,
        f1=f1,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )
