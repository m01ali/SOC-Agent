"""Regex sweep pass: refang -> pattern match -> validate -> mask.

Spec: extraction-04-spec.md §7.5.
"""

from __future__ import annotations

import re

from soc_agent.extract.candidate import Candidate
from soc_agent.extract.patterns import (
    DOMAIN,
    EMAIL,
    FILENAME,
    HASH,
    IPV4,
    IPV6,
    URL,
    preceded_by_version_prefix,
    validate_domain,
    validate_email,
    validate_file_path,
    validate_hash,
    validate_ip,
    validate_url,
)
from soc_agent.extract.refang import Refanged, original_span, refang
from soc_agent.models.alert import NormalizedAlert

# Fixed masking order: each pattern blanks the spans it consumed before the next runs
# (§7.5) — a URL's host is not separately matched as a domain, an email's domain is not
# separately matched as a domain either.
_PATTERN_ORDER: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url", URL),
    ("email", EMAIL),
    ("ipv6", IPV6),
    ("ipv4", IPV4),
    ("hash", HASH),
    ("domain", DOMAIN),
    ("filename", FILENAME),
)

_MASK_CHAR = "\0"


def surfaces(alert: NormalizedAlert) -> list[tuple[str, str]]:
    """(field_name, text) pairs to sweep, in a fixed order. §7.5."""
    result: list[tuple[str, str]] = [("title", alert.title)]
    if alert.description:
        result.append(("description", alert.description))
    if alert.source_system in ("cef", "freetext") and isinstance(alert.raw, str):
        result.append(("raw", alert.raw))
    return result


def _mask(text: str, start: int, end: int) -> str:
    return text[:start] + (_MASK_CHAR * (end - start)) + text[end:]


def _original_text_for(
    original: str, refanged: Refanged, start: int, end: int, matched_value: str
) -> str | None:
    recovered = original_span(original, refanged, start, end)
    return recovered if recovered != matched_value else None


def _build(
    kind: str,
    field: str,
    matched_value: str,
    original: str,
    refanged: Refanged,
    start: int,
    end: int,
    dropped: dict[str, int],
) -> Candidate | None:
    original_text = _original_text_for(original, refanged, start, end, matched_value)

    if kind == "url":
        canonical = validate_url(matched_value)
        if canonical is None:
            return None
        return Candidate(
            type="url",
            value=canonical,
            role="unknown",
            method="regex",
            field=field,
            original_text=original_text,
        )
    if kind == "email":
        canonical = validate_email(matched_value)
        if canonical is None:
            return None
        return Candidate(
            type="email",
            value=canonical,
            role="unknown",
            method="regex",
            field=field,
            original_text=original_text,
        )
    if kind == "ipv6":
        canonical = validate_ip(matched_value)
        if canonical is None or ":" not in matched_value:
            return None
        return Candidate(
            type="ip",
            value=canonical,
            role="unknown",
            method="regex",
            field=field,
            original_text=original_text,
        )
    if kind == "ipv4":
        if preceded_by_version_prefix(refanged.text, start):
            return None
        canonical = validate_ip(matched_value)
        if canonical is None:
            return None
        return Candidate(
            type="ip",
            value=canonical,
            role="unknown",
            method="regex",
            field=field,
            original_text=original_text,
        )
    if kind == "hash":
        resolved = validate_hash(matched_value)
        if resolved is None:
            return None
        hash_type, canonical_hash = resolved
        return Candidate(
            type=hash_type,
            value=canonical_hash,
            role="unknown",
            method="regex",
            field=field,
            original_text=original_text,
        )
    if kind == "domain":
        canonical = validate_domain(matched_value)
        if canonical is None:
            dropped["tld_not_allowed"] = dropped.get("tld_not_allowed", 0) + 1
            return None
        return Candidate(
            type="domain",
            value=canonical,
            role="unknown",
            method="regex",
            field=field,
            original_text=original_text,
        )
    if kind == "filename":
        canonical = validate_file_path(matched_value)
        if canonical is None:
            return None
        return Candidate(
            type="file_path",
            value=canonical,
            role="unknown",
            method="regex",
            field=field,
            original_text=original_text,
        )
    raise AssertionError(f"unhandled pattern kind: {kind}")


def _sweep_surface(
    field: str, text: str, *, aggressive_refang: bool, order_start: int, dropped: dict[str, int]
) -> tuple[list[Candidate], int]:
    refanged = refang(text, aggressive=aggressive_refang)
    working = refanged.text
    candidates: list[Candidate] = []
    order = order_start

    for kind, pattern in _PATTERN_ORDER:
        matches = list(pattern.finditer(working))
        mask_spans: list[tuple[int, int]] = []
        for match in matches:
            start, end = match.start(1), match.end(1)
            matched_value = working[start:end]
            candidate = _build(kind, field, matched_value, text, refanged, start, end, dropped)
            if candidate is not None:
                candidates.append(
                    Candidate(
                        type=candidate.type,
                        value=candidate.value,
                        role=candidate.role,
                        method=candidate.method,
                        field=candidate.field,
                        original_text=candidate.original_text,
                        order=order,
                    )
                )
                order += 1
                mask_spans.append((start, end))
        for start, end in mask_spans:
            working = _mask(working, start, end)

    return candidates, order


def regex_pass(
    alert: NormalizedAlert, *, aggressive_refang: bool = False, order_start: int = 0
) -> tuple[list[Candidate], dict[str, int]]:
    """Deterministic candidates from the regex sweep over title/description/raw. §7.5."""
    all_candidates: list[Candidate] = []
    dropped: dict[str, int] = {}
    order = order_start
    for field, text in surfaces(alert):
        found, order = _sweep_surface(
            field, text, aggressive_refang=aggressive_refang, order_start=order, dropped=dropped
        )
        all_candidates.extend(found)
    return all_candidates, dropped
