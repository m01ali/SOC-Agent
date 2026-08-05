"""LLM extraction assist: a bounded recall backstop. Spec: extraction-04-spec.md §9.

Architecture §5.2: the assist "never blocks". Every failure — API error, timeout,
a structured-output ValidationError, a CacheMissError in replay mode — degrades to
the deterministic result plus a recorded StageError. There is no repair retry beyond
the one get_llm already performs (§9.6).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from soc_agent.extract.candidate import Candidate
from soc_agent.extract.merge import canonical_value
from soc_agent.extract.patterns import (
    validate_domain,
    validate_email,
    validate_hash,
    validate_ip,
    validate_url,
)
from soc_agent.extract.refang import refang
from soc_agent.llm.client import get_llm
from soc_agent.llm.prompt import render_messages
from soc_agent.models import EntityType, ExtractionSelection, StageError
from soc_agent.models.alert import NormalizedAlert

if TYPE_CHECKING:
    from soc_agent.config import ExtractionConfig


def should_run(alert: NormalizedAlert, cfg: ExtractionConfig) -> bool:
    """§9.1: freetext (default) runs only for the free-text normalization path."""
    if cfg.llm_assist == "never":
        return False
    if cfg.llm_assist == "always":
        return True
    return alert.normalization.method == "llm"


def _alert_text(alert: NormalizedAlert) -> str:
    """Title, description, and raw-as-string only — never the known entities (§9.2),
    so the cache key stays independent of the field map and regex table."""
    parts = [alert.title]
    if alert.description:
        parts.append(alert.description)
    if isinstance(alert.raw, str):
        parts.append(alert.raw)
    return "\n".join(parts)


def _is_grounded(value: str, haystacks: tuple[str, str]) -> bool:
    lowered = value.lower()
    return any(lowered in haystack for haystack in haystacks)


def _validate_type(entity_type: EntityType, value: str) -> str | None:
    """The same §7.4 validators the regex pass uses — Entity's own validator alone is
    looser (it has no TLD allowlist), so a bad-TLD "domain" would otherwise slip through."""
    if entity_type == "ip":
        return validate_ip(value)
    if entity_type == "domain":
        return validate_domain(value)
    if entity_type == "url":
        return validate_url(value)
    if entity_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        resolved = validate_hash(value)
        if resolved is None or resolved[0] != entity_type:
            return None
        return resolved[1]
    if entity_type == "email":
        return validate_email(value)
    stripped = value.strip()
    return stripped or None


def llm_assist(
    alert: NormalizedAlert,
    known: Sequence[Candidate],
    cfg: ExtractionConfig,
    *,
    order_start: int = 0,
) -> tuple[list[Candidate], list[StageError], dict[str, int]]:
    """Returns (candidates, errors, dropped). Never raises."""
    dropped: dict[str, int] = {}
    if not should_run(alert, cfg):
        return [], [], dropped

    text = _alert_text(alert)
    refanged_text = refang(text, aggressive=cfg.aggressive_refang).text
    haystacks = (text.lower(), refanged_text.lower())

    try:
        messages = render_messages("extract_entities", alert_text=text)
        llm = get_llm("extract", structured=ExtractionSelection)
        selection: ExtractionSelection = llm.invoke(messages)
    except Exception as e:  # noqa: BLE001 — any LLM-layer failure degrades, never blocks
        return [], [StageError(stage="extract", type="api_error", detail=str(e))], dropped

    known_keys = {(c.type, canonical_value(c.type, c.value)) for c in known}

    accepted: list[Candidate] = []
    order = order_start
    net_new = 0

    for item in selection.entities:
        if not _is_grounded(item.value, haystacks):
            dropped["llm_ungrounded"] = dropped.get("llm_ungrounded", 0) + 1
            continue

        # The prompt tells the model to copy indicators exactly as written, defanged
        # form included — refang before type validation, exactly like the regex pass.
        refanged_value = refang(item.value, aggressive=cfg.aggressive_refang).text
        canonical = _validate_type(item.type, refanged_value)
        if canonical is None:
            dropped["llm_ungrounded"] = dropped.get("llm_ungrounded", 0) + 1
            continue

        key = (item.type, canonical_value(item.type, canonical))
        if key not in known_keys:
            if net_new >= cfg.max_llm_additions:
                dropped["llm_budget"] = dropped.get("llm_budget", 0) + 1
                continue
            net_new += 1

        original_text = item.value if refanged_value != item.value else None
        accepted.append(
            Candidate(
                type=item.type,
                value=canonical,
                role=item.role,
                method="llm",
                field=None,
                original_text=original_text,
                order=order,
            )
        )
        order += 1

    return accepted, [], dropped
