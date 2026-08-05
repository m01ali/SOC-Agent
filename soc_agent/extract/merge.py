"""Merge, arbitration, derivation and finalization. Spec: extraction-04-spec.md §10."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import replace
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from pydantic import ValidationError

from soc_agent.extract.candidate import Candidate
from soc_agent.extract.config import is_internal_ip
from soc_agent.extract.patterns import validate_domain, validate_ip
from soc_agent.models import Entity, EntityProvenance, EntityType, ExtractionMethod
from soc_agent.models.alert import NormalizedAlert

if TYPE_CHECKING:
    from soc_agent.config import ExtractionConfig

# field_map beats regex beats llm (§10.1).
_PRECEDENCE: dict[ExtractionMethod, int] = {"field_map": 0, "regex": 1, "llm": 2}

# Tie-break for cross-type arbitration at the same precedence level (§10.2).
_TYPE_PRIORITY: dict[EntityType, int] = {
    "url": 0,
    "email": 1,
    "ip": 2,
    "hash_sha256": 3,
    "hash_sha1": 4,
    "hash_md5": 5,
    "domain": 6,
    "file_path": 7,
    "process": 8,
    "host": 9,
    "user": 10,
}

# In a brute-force, impossible-travel or phishing alert the account is the victim,
# not the actor (spec 03 §8 note 1, resolved here per §8.2).
_VICTIM_CATEGORIES = frozenset({"credential_access", "initial_access", "phishing"})


def _bump(dropped: dict[str, int], reason: str, n: int = 1) -> None:
    dropped[reason] = dropped.get(reason, 0) + n


def canonical_value(entity_type: EntityType, value: str) -> str:
    """The dedupe-key value half: .compressed for ip, case-fold otherwise (§10.1).
    Shared with score.py (extraction_f1) and llm_assist.py (the budget check)."""
    if entity_type == "ip":
        canon = validate_ip(value)
        return canon if canon is not None else value
    return value.lower()


def derive(
    candidates: Sequence[Candidate], cfg: ExtractionConfig, *, order_start: int
) -> list[Candidate]:
    """URL -> ip/domain, and (opt-in) email -> domain. §10.3."""
    derived: list[Candidate] = []
    order = order_start

    for c in candidates:
        if c.type == "url":
            host = urlsplit(c.value).hostname
            if not host:
                continue
            ip_canonical = validate_ip(host)
            if ip_canonical is not None:
                derived.append(
                    Candidate(
                        type="ip",
                        value=ip_canonical,
                        role=c.role,
                        method=c.method,
                        field=c.field,
                        original_text=c.value,
                        order=order,
                    )
                )
                order += 1
                continue
            domain_canonical = validate_domain(host)
            if domain_canonical is not None:
                derived.append(
                    Candidate(
                        type="domain",
                        value=domain_canonical,
                        role=c.role,
                        method=c.method,
                        field=c.field,
                        original_text=c.value,
                        order=order,
                    )
                )
                order += 1
        elif c.type == "email" and cfg.derive_email_domain:
            _local, _, domain_part = c.value.partition("@")
            domain_canonical = validate_domain(domain_part)
            if domain_canonical is not None:
                derived.append(
                    Candidate(
                        type="domain",
                        value=domain_canonical,
                        role=c.role,
                        method=c.method,
                        field=c.field,
                        original_text=c.value,
                        order=order,
                    )
                )
                order += 1

    return derived


def _resolve_duplicates(
    candidates: Sequence[Candidate], dropped: dict[str, int]
) -> dict[tuple[EntityType, str], Candidate]:
    groups: dict[tuple[EntityType, str], list[Candidate]] = defaultdict(list)
    for c in candidates:
        groups[(c.type, canonical_value(c.type, c.value))].append(c)

    winners: dict[tuple[EntityType, str], Candidate] = {}
    for key, group in groups.items():
        ordered = sorted(group, key=lambda c: (_PRECEDENCE[c.method], c.order))
        winner = ordered[0]
        if len(ordered) > 1:
            _bump(dropped, "duplicate", len(ordered) - 1)
        if winner.role == "unknown":
            for other in ordered[1:]:
                if other.role != "unknown":
                    winner = replace(winner, role=other.role)
                    break
        winners[key] = winner
    return winners


def _resolve_type_conflicts(
    winners: dict[tuple[EntityType, str], Candidate], dropped: dict[str, int]
) -> list[Candidate]:
    by_value: dict[str, list[Candidate]] = defaultdict(list)
    for (_type, value), candidate in winners.items():
        by_value[value].append(candidate)

    finalists: list[Candidate] = []
    for entries in by_value.values():
        if len(entries) == 1:
            finalists.append(entries[0])
            continue
        best = min(
            entries,
            key=lambda c: (_PRECEDENCE[c.method], _TYPE_PRIORITY.get(c.type, 99), c.order),
        )
        _bump(dropped, "type_conflict", len(entries) - 1)
        finalists.append(best)
    return finalists


def _refine_roles(candidates: list[Candidate], alert: NormalizedAlert) -> list[Candidate]:
    if alert.category not in _VICTIM_CATEGORIES:
        return candidates
    return [
        replace(c, role="target") if c.type == "user" and c.role == "actor" else c
        for c in candidates
    ]


def _confidence_for(candidate: Candidate, cfg: ExtractionConfig) -> float:
    return cfg.llm_confidence if candidate.method == "llm" else 1.0


def merge(
    candidates: Sequence[Candidate], alert: NormalizedAlert, cfg: ExtractionConfig
) -> tuple[list[Entity], dict[str, int]]:
    """Dedupe -> cross-type arbitration -> role refinement -> cap -> validate. §10.4."""
    dropped: dict[str, int] = {}

    winners = _resolve_duplicates(candidates, dropped)
    finalists = _resolve_type_conflicts(winners, dropped)
    finalists = _refine_roles(finalists, alert)

    finalists.sort(key=lambda c: (_PRECEDENCE[c.method], c.order))
    if len(finalists) > cfg.max_entities:
        overflow = len(finalists) - cfg.max_entities
        _bump(dropped, "entity_cap", overflow)
        finalists = finalists[: cfg.max_entities]

    # Output order is discovery order, not precedence order (§10.4).
    finalists.sort(key=lambda c: c.order)

    entities: list[Entity] = []
    for c in finalists:
        is_internal = is_internal_ip(c.value) if c.type == "ip" else None
        try:
            entity = Entity(
                type=c.type,
                value=c.value,
                role=c.role,
                is_internal=is_internal,
                confidence=_confidence_for(c, cfg),
                provenance=EntityProvenance(
                    field=c.field, method=c.method, original_text=c.original_text
                ),
            )
        except ValidationError:
            _bump(dropped, "invalid_value")
            continue
        entities.append(entity)

    return entities, dropped
