"""MITRE ATT&CK mapping. Spec: attack-mapping-06-spec.md (Architecture §5.5).

Public API: `map_attack`, `AttackResult`.

Two-step grounded mapping: deterministic code shortlists candidates, the LLM selects
from that list only, and code validates the result back against the catalog. A
hallucinated technique ID cannot reach the output.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from soc_agent.attack.catalog import AttackCatalog, load_catalog
from soc_agent.attack.hints import hints_for_rule
from soc_agent.attack.select import select_techniques, validate_selection
from soc_agent.attack.shortlist import Candidate, shortlist
from soc_agent.config import AttackConfig, get_config
from soc_agent.models import (
    AttackMapping,
    Entity,
    RelatedAlertsBlock,
    StageError,
    ThreatIntelBlock,
)
from soc_agent.models.alert import NormalizedAlert

__all__ = ["AttackResult", "Candidate", "map_attack"]


@dataclass(frozen=True)
class AttackResult:
    mappings: list[AttackMapping]
    candidates: list[Candidate] = field(default_factory=list)
    errors: list[StageError] = field(default_factory=list)
    dropped: dict[str, int] = field(default_factory=dict)
    llm_used: bool = False


def _ti_tags(threat_intel: ThreatIntelBlock | None) -> list[str]:
    if threat_intel is None:
        return []
    tags: list[str] = []
    for result in threat_intel.results:
        tags.extend(result.tags)
    return tags


def rule_hint_mappings(
    alert: NormalizedAlert, cfg: AttackConfig, catalog: AttackCatalog
) -> list[AttackMapping]:
    """The degraded path (§13). Honest about its own provenance: `confidence: low` and
    evidence that names the hint rather than borrowing the LLM's voice."""
    mappings: list[AttackMapping] = []
    for technique_id in hints_for_rule(alert.vendor_rule, cfg.rule_hints, catalog):
        technique = catalog.get(technique_id)
        if technique is None:  # pragma: no cover - hints are validated at load
            continue
        tactic_id, tactic_name = catalog.resolve_tactic(technique_id, alert.category)
        if tactic_id is None or tactic_name is None:  # pragma: no cover
            continue
        mappings.append(
            AttackMapping(
                tactic_id=tactic_id,
                tactic=tactic_name,
                technique_id=technique_id,
                technique_name=technique.name,
                confidence="low",
                evidence=[f"matched rule hint for '{alert.vendor_rule}'"],
            )
        )
    return mappings[: cfg.max_techniques]


def map_attack(
    alert: NormalizedAlert,
    entities: Sequence[Entity] = (),
    threat_intel: ThreatIntelBlock | None = None,
    related: RelatedAlertsBlock | None = None,
    *,
    use_llm: bool | None = None,
    catalog: AttackCatalog | None = None,
    config: AttackConfig | None = None,
) -> AttackResult:
    """Shortlist, select, validate. Never raises.

    Architecture §11: an LLM failure degrades to rule-hint mappings only, with the
    error recorded and the pipeline continuing.
    """
    cfg = config or get_config().attack
    active_catalog = catalog if catalog is not None else load_catalog(cfg.catalog)
    wants_llm = cfg.use_llm if use_llm is None else use_llm

    candidates = shortlist(alert, _ti_tags(threat_intel), catalog=active_catalog, cfg=cfg)

    # An alert with no ATT&CK signal is a legitimate outcome (fixture 04's label is
    # `techniques: []`); manufacturing an error would make every benign alert partial.
    if not candidates:
        return AttackResult(mappings=[], candidates=[], llm_used=False)

    if not wants_llm:
        return AttackResult(
            mappings=rule_hint_mappings(alert, cfg, active_catalog),
            candidates=candidates,
            llm_used=False,
        )

    selection, errors = select_techniques(
        alert, entities, candidates, threat_intel, related, cfg, active_catalog
    )
    if selection is None:
        return AttackResult(
            mappings=rule_hint_mappings(alert, cfg, active_catalog),
            candidates=candidates,
            errors=errors,
            llm_used=False,
        )

    mappings, dropped = validate_selection(
        selection, candidates, active_catalog, cfg, alert.category
    )

    # Every returned item was rejected: report it, but keep whatever the rule hints
    # can still say rather than emitting nothing.
    if selection.techniques and not mappings:
        errors.append(
            StageError(
                stage="map_attack",
                type="schema_validation",
                detail=(
                    f"all {len(selection.techniques)} returned technique(s) failed "
                    f"validation: {dropped}"
                ),
            )
        )
        mappings = rule_hint_mappings(alert, cfg, active_catalog)

    return AttackResult(
        mappings=mappings,
        candidates=candidates,
        errors=errors,
        dropped=dropped,
        llm_used=True,
    )
