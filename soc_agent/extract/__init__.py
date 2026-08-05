"""Entity/IOC extraction. Spec: extraction-04-spec.md (Architecture §5.2).

Public API: `extract_entities`, `ioc_entities`, `ExtractionResult`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from soc_agent.config import get_config
from soc_agent.extract.config import ioc_entities
from soc_agent.extract.field_map import field_map_pass
from soc_agent.extract.llm_assist import llm_assist as _run_llm_assist
from soc_agent.extract.llm_assist import should_run
from soc_agent.extract.merge import derive, merge
from soc_agent.extract.regex_pass import regex_pass
from soc_agent.models import Entity, StageError
from soc_agent.models.alert import NormalizedAlert

__all__ = ["ExtractionResult", "LLMAssistMode", "extract_entities", "ioc_entities"]

LLMAssistMode = Literal["freetext", "always", "never"]


@dataclass(frozen=True)
class ExtractionResult:
    entities: list[Entity]
    errors: list[StageError] = field(default_factory=list)
    dropped: dict[str, int] = field(default_factory=dict)  # reason -> count (§10.5)
    llm_used: bool = False


def _merge_dropped(*dicts: dict[str, int]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for d in dicts:
        for key, count in d.items():
            merged[key] = merged.get(key, 0) + count
    return merged


def extract_entities(
    alert: NormalizedAlert,
    *,
    llm_assist_mode: LLMAssistMode | None = None,
) -> ExtractionResult:
    """Run the field-map, regex, derivation and (optionally) LLM passes, then merge.

    Never raises for a well-formed alert. LLM failures degrade to the deterministic
    result with a StageError recorded (Architecture §5.2: "never blocks").
    """
    cfg = get_config().extraction
    if llm_assist_mode is not None:
        cfg = cfg.model_copy(update={"llm_assist": llm_assist_mode})

    field_candidates, field_dropped = field_map_pass(alert)
    regex_candidates, regex_dropped = regex_pass(
        alert, aggressive_refang=cfg.aggressive_refang, order_start=len(field_candidates)
    )
    deterministic = field_candidates + regex_candidates

    derived = derive(deterministic, cfg, order_start=len(deterministic))
    deterministic = deterministic + derived

    llm_candidates, llm_errors, llm_dropped = _run_llm_assist(
        alert, deterministic, cfg, order_start=len(deterministic)
    )

    entities, merge_dropped = merge(deterministic + llm_candidates, alert, cfg)
    dropped = _merge_dropped(field_dropped, regex_dropped, llm_dropped, merge_dropped)

    return ExtractionResult(
        entities=entities,
        errors=llm_errors,
        dropped=dropped,
        llm_used=should_run(alert, cfg),
    )
