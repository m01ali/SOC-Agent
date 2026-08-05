"""Canonical/generic JSON normalizer. Spec: ingestion-03-spec.md §9.1."""

from __future__ import annotations

from typing import get_args

from soc_agent.ingest.base import (
    WARN_NO_TIMESTAMP,
    IngestContext,
    dedupe_key,
    generated_alert_id,
)
from soc_agent.ingest.category import infer_category
from soc_agent.ingest.errors import NormalizationError
from soc_agent.ingest.severity import normalize_severity
from soc_agent.models import AlertCategory, NormalizationInfo, NormalizedAlert

_VALID_CATEGORIES = set(get_args(AlertCategory))


def normalize(ctx: IngestContext) -> NormalizedAlert:
    doc = ctx.parsed
    if doc is None or "title" not in doc:
        raise NormalizationError("generic payload missing required field 'title'")

    key = dedupe_key(ctx.raw)
    title = doc["title"]
    description = doc.get("description")

    raw_category = doc.get("category")
    category: AlertCategory | None
    if isinstance(raw_category, str) and raw_category in _VALID_CATEGORIES:
        category = raw_category  # type: ignore[assignment]
    else:
        category = infer_category(title, description)

    severity, severity_original = normalize_severity("generic", doc.get("severity"), ctx)

    occurred_at = doc.get("occurred_at")
    if occurred_at is None:
        ctx.warn(WARN_NO_TIMESTAMP)

    observed_fields = {k: str(v) for k, v in (doc.get("observed_fields") or {}).items()}

    return NormalizedAlert(
        alert_id=doc.get("alert_id") or generated_alert_id(key),
        dedupe_key=key,
        source_system="generic",
        vendor_rule=doc.get("vendor_rule") or doc.get("rule"),
        title=title,
        description=description,
        category=category,
        severity_original=severity_original,
        severity=severity,
        occurred_at=occurred_at,
        ingested_at=ctx.now,
        observed_fields=observed_fields,
        raw=doc,
        normalization=NormalizationInfo(method="parser", confidence=1.0, warnings=ctx.warnings),
    )
