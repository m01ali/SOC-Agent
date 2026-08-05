"""Field-map pass: `observed_fields` (spec 03 §8 vocabulary) -> typed candidates.

Spec: extraction-04-spec.md §6.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from soc_agent.extract.candidate import Candidate
from soc_agent.extract.patterns import validate_domain, validate_hash
from soc_agent.extract.refang import refang
from soc_agent.models import EntityRole, EntityType
from soc_agent.models.alert import NormalizedAlert

_PLACEHOLDER_VALUES: frozenset[str] = frozenset({"", "-", "unknown", "n/a", "null", "none"})

FieldType = EntityType | Literal["host_or_domain", "hash_auto"]


@dataclass(frozen=True)
class FieldRule:
    key: str
    type: FieldType
    role: EntityRole


# Discovery order for field-map candidates follows this table, not observed_fields'
# dict insertion order (§6 rule 3 / §16.4).
FIELD_MAP: tuple[FieldRule, ...] = (
    FieldRule("src_ip", "ip", "source"),
    FieldRule("dest_ip", "ip", "destination"),
    FieldRule("src_host", "host_or_domain", "source"),
    FieldRule("dest_host", "host_or_domain", "destination"),
    FieldRule("host", "host_or_domain", "unknown"),
    FieldRule("user", "user", "actor"),
    FieldRule("src_user", "user", "actor"),
    FieldRule("dest_user", "user", "target"),
    FieldRule("process", "process", "unknown"),
    FieldRule("process_hash_sha256", "hash_sha256", "unknown"),
    FieldRule("process_hash_sha1", "hash_sha1", "unknown"),
    FieldRule("process_hash_md5", "hash_md5", "unknown"),
    FieldRule("file_hash", "hash_auto", "unknown"),
    FieldRule("file_path", "file_path", "unknown"),
    FieldRule("url", "url", "destination"),
    FieldRule("domain", "domain", "unknown"),
    FieldRule("query", "domain", "unknown"),
    FieldRule("email", "email", "unknown"),
)

# Vocabulary keys spec 03 §8 documents as "context only": they never produce entities.
CONTEXT_ONLY_KEYS: frozenset[str] = frozenset(
    {
        "src_port",
        "dest_port",
        "protocol",
        "app",
        "count",
        "bytes_in",
        "bytes_out",
        "action",
        "device_vendor",
        "device_product",
        "device_event_class_id",
    }
)


def _is_placeholder(value: str) -> bool:
    return value.strip().lower() in _PLACEHOLDER_VALUES


def _resolve_host_or_domain(value: str) -> EntityType:
    return "domain" if validate_domain(value) is not None else "host"


def field_map_pass(alert: NormalizedAlert) -> tuple[list[Candidate], dict[str, int]]:
    """Deterministic candidates from observed_fields, in FIELD_MAP table order.

    Returns (candidates, dropped) so merge() can fold drop counts into ExtractionResult.
    """
    candidates: list[Candidate] = []
    dropped: dict[str, int] = {}
    order = 0

    for rule in FIELD_MAP:
        raw_value = alert.observed_fields.get(rule.key)
        if raw_value is None:
            continue
        stripped = raw_value.strip()
        if _is_placeholder(stripped):
            dropped["placeholder_value"] = dropped.get("placeholder_value", 0) + 1
            continue

        refanged = refang(stripped)
        value = refanged.text
        original_text = stripped if value != stripped else None

        if rule.type == "host_or_domain":
            resolved_type: EntityType = _resolve_host_or_domain(value)
            candidates.append(
                Candidate(
                    type=resolved_type,
                    value=value,
                    role=rule.role,
                    method="field_map",
                    field=rule.key,
                    original_text=original_text,
                    order=order,
                )
            )
            order += 1
        elif rule.type == "hash_auto":
            resolved = validate_hash(value)
            if resolved is None:
                dropped["hash_bad_length"] = dropped.get("hash_bad_length", 0) + 1
                continue
            resolved_hash_type, canonical_value = resolved
            candidates.append(
                Candidate(
                    type=resolved_hash_type,
                    value=canonical_value,
                    role=rule.role,
                    method="field_map",
                    field=rule.key,
                    original_text=original_text,
                    order=order,
                )
            )
            order += 1
        else:
            candidates.append(
                Candidate(
                    type=rule.type,
                    value=value,
                    role=rule.role,
                    method="field_map",
                    field=rule.key,
                    original_text=original_text,
                    order=order,
                )
            )
            order += 1

    return candidates, dropped
