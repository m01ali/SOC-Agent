"""Per-source severity normalization. Spec: ingestion-03-spec.md §6."""

from __future__ import annotations

from soc_agent.ingest.base import WARN_SEVERITY_DEFAULTED, IngestContext
from soc_agent.models import SourceSystem

DEFAULT_SEVERITY = 50

_LABELS: dict[str, int] = {
    "informational": 10,
    "info": 10,
    "none": 10,
    "low": 25,
    "medium": 50,
    "moderate": 50,
    "high": 75,
    "critical": 95,
    "severe": 95,
    "very-high": 95,
}


def _clamp(n: float) -> int:
    return max(0, min(100, round(n)))


def normalize_severity(
    source: SourceSystem, value: str | int | float | None, ctx: IngestContext
) -> tuple[int, str | None]:
    """Return (severity 0-100, severity_original). Emits `severity_defaulted` on None/unknown."""
    if value is None or (isinstance(value, str) and not value.strip()):
        ctx.warn(WARN_SEVERITY_DEFAULTED)
        return DEFAULT_SEVERITY, None

    original = str(value)

    if isinstance(value, (int, float)):
        if source == "cef":
            return _clamp(float(value) * 10), original
        return _clamp(float(value)), original

    label = value.strip().lower()
    if label in _LABELS:
        return _LABELS[label], original

    # Numeric string?
    try:
        num = float(label)
    except ValueError:
        pass
    else:
        if source == "cef":
            return _clamp(num * 10), original
        return _clamp(num), original

    ctx.warn(WARN_SEVERITY_DEFAULTED)
    return DEFAULT_SEVERITY, original
