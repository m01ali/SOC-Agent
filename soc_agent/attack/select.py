"""Evidence bundle, LLM selection and validation. Spec: attack-mapping-06-spec.md §10-§11."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from pydantic import ValidationError

from soc_agent.attack.catalog import AttackCatalog
from soc_agent.attack.shortlist import Candidate
from soc_agent.llm.client import get_llm
from soc_agent.llm.prompt import render_messages
from soc_agent.models import (
    AttackMapping,
    AttackSelection,
    Entity,
    RelatedAlertsBlock,
    StageError,
    ThreatIntelBlock,
)
from soc_agent.models.alert import NormalizedAlert

if TYPE_CHECKING:
    from soc_agent.config import AttackConfig

EVIDENCE_MAX_CHARS = 200
MAX_RELATED_IN_BUNDLE = 3


def _bump(dropped: dict[str, int], reason: str) -> None:
    dropped[reason] = dropped.get(reason, 0) + 1


def build_evidence_bundle(
    alert: NormalizedAlert,
    entities: Sequence[Entity],
    threat_intel: ThreatIntelBlock | None,
    related: RelatedAlertsBlock | None,
    *,
    max_chars: int = 4000,
) -> str:
    """A fixed-order rendering of what specs 03-05 established (§10.3).

    Fixed order matters twice: the cache key hashes the rendered messages, and the
    briefing (spec 07) cites the same facts. Everything here is already in the output
    envelope — the bundle introduces nothing the analyst cannot see.
    """
    lines: list[str] = [f"title: {alert.title}"]
    if alert.category:
        lines.append(f"category: {alert.category}")
    lines.append(f"severity: {alert.severity}")
    if alert.vendor_rule:
        lines.append(f"rule: {alert.vendor_rule}")
    if alert.description:
        lines.append(f"description: {alert.description}")

    if entities:
        lines.append("entities:")
        for entity in entities:
            marker = " (internal)" if entity.is_internal else ""
            lines.append(f"  - {entity.type} {entity.value} [{entity.role}]{marker}")

    if threat_intel and threat_intel.results:
        lines.append("threat_intel:")
        for result in threat_intel.results:
            tags = f" tags={','.join(result.tags)}" if result.tags else ""
            lines.append(
                f"  - {result.entity.value}: {result.verdict} (score {result.score}){tags}"
            )

    if related and related.count:
        lines.append(
            f"related_alerts: {related.count} in window, "
            f"{related.prior_true_positives} prior true positive(s), "
            f"{related.prior_false_positives} prior false positive(s)"
        )
        if related.rule_fp_rate is not None:
            lines.append(
                f"  rule false-positive rate: {related.rule_fp_rate:.2f} "
                f"over {related.rule_fired_count} firings"
            )
        for item in related.alerts[:MAX_RELATED_IN_BUNDLE]:
            lines.append(f"  - {item.title} [{item.disposition}] ({item.relation_reason})")

    return "\n".join(lines)[:max_chars]


def render_candidates(candidates: Sequence[Candidate], catalog: AttackCatalog) -> str:
    """`N. <ID> — <name>` plus the summary. The ID must be visible and copyable, which
    is why this is not a bare numbered list."""
    lines: list[str] = []
    for index, candidate in enumerate(candidates, start=1):
        technique = catalog.get(candidate.technique_id)
        if technique is None:  # pragma: no cover - shortlist only emits catalog ids
            continue
        lines.append(f"{index}. {technique.technique_id} — {technique.name}")
        if technique.summary:
            lines.append(f"   {technique.summary}")
    return "\n".join(lines)


def select_techniques(
    alert: NormalizedAlert,
    entities: Sequence[Entity],
    candidates: Sequence[Candidate],
    threat_intel: ThreatIntelBlock | None,
    related: RelatedAlertsBlock | None,
    cfg: AttackConfig,
    catalog: AttackCatalog,
) -> tuple[AttackSelection | None, list[StageError]]:
    """One LLM call. Returns (selection, errors); never raises (§13)."""
    bundle = build_evidence_bundle(
        alert, entities, threat_intel, related, max_chars=cfg.max_bundle_chars
    )
    try:
        messages = render_messages(
            "map_attack",
            evidence_bundle=bundle,
            candidates=render_candidates(candidates, catalog),
        )
        llm = get_llm("map_attack", structured=AttackSelection)
        return llm.invoke(messages), []
    except Exception as e:  # noqa: BLE001 — any LLM-layer failure degrades (§13)
        return None, [StageError(stage="map_attack", type="api_error", detail=str(e))]


def validate_selection(
    selection: AttackSelection,
    candidates: Sequence[Candidate],
    catalog: AttackCatalog,
    cfg: AttackConfig,
    category: str | None,
) -> tuple[list[AttackMapping], dict[str, int]]:
    """§11: in-candidates -> in-catalog -> dedupe/cap, then build from the catalog.

    The model cannot invent a technique. It can only mis-argue for a real one that
    deterministic code already shortlisted.
    """
    dropped: dict[str, int] = {}
    candidate_ids = {c.technique_id for c in candidates}
    mappings: list[AttackMapping] = []
    seen: set[str] = set()

    for item in selection.techniques:
        technique_id = item.technique_id

        if technique_id not in candidate_ids:
            _bump(dropped, "not_in_candidates")
            continue
        if technique_id not in catalog:
            _bump(dropped, "not_in_catalog")
            continue
        if technique_id in seen:
            _bump(dropped, "duplicate")
            continue

        evidence = [e.strip()[:EVIDENCE_MAX_CHARS] for e in item.evidence if e and e.strip()]
        if not evidence:
            _bump(dropped, "empty_evidence")
            continue

        if len(mappings) >= cfg.max_techniques:
            _bump(dropped, "over_cap")
            continue

        tactic_id, tactic_name = catalog.resolve_tactic(technique_id, category)
        if tactic_id is None or tactic_name is None:
            # No catalog technique lacks a tactic (verified: 0 of 697), so this is
            # unreachable today. Dropping beats inventing a placeholder tactic id that
            # would then be indistinguishable from a real one in the envelope.
            _bump(dropped, "no_tactic")
            continue

        technique = catalog.techniques[technique_id]
        try:
            mappings.append(
                AttackMapping(
                    tactic_id=tactic_id,
                    tactic=tactic_name,
                    technique_id=technique_id,
                    technique_name=technique.name,
                    confidence=item.confidence,
                    evidence=evidence,
                )
            )
        except ValidationError:
            _bump(dropped, "invalid_mapping")
            continue
        seen.add(technique_id)

    return mappings, dropped
