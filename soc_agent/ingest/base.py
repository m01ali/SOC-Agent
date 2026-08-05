"""Shared ingestion plumbing: context, dedupe key, alert id, warning codes.

Spec: ingestion-03-spec.md §5.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

# Warning vocabulary (§5.4) — tests assert on these codes; normalizers must not invent new strings.
WARN_UNRECOGNIZED_JSON_STRUCTURE = "unrecognized_json_structure"
WARN_NO_TIMESTAMP = "no_timestamp"
WARN_YEAR_INFERRED = "year_inferred"
WARN_SEVERITY_DEFAULTED = "severity_defaulted"
WARN_CATEGORY_NOT_INFERRED = "category_not_inferred"
WARN_LLM_NORMALIZATION = "llm_normalization"
WARN_LLM_REPAIR_RETRY = "llm_repair_retry"


@dataclass
class IngestContext:
    raw: str
    now: datetime
    parsed: dict | None = None
    warnings: list[str] = field(default_factory=list)

    def warn(self, code: str) -> None:
        if code not in self.warnings:
            self.warnings.append(code)


def dedupe_key(raw: str) -> str:
    """Deterministic sha256 over a canonicalized form of the raw input.

    Hashes the raw payload (not the normalized alert) so the key stays stable
    when normalization logic changes.
    """
    canonical = raw.replace("\r\n", "\n").replace("\r", "\n").strip()
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def generated_alert_id(dedupe: str) -> str:
    """Deterministic fallback alert id — same input always yields the same id."""
    return f"soc-agent-{dedupe[:12]}"
