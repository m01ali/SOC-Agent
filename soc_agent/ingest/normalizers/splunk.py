"""Splunk ES notable event normalizer. Spec: ingestion-03-spec.md §9.2."""

from __future__ import annotations

from soc_agent.ingest.base import (
    WARN_NO_TIMESTAMP,
    IngestContext,
    dedupe_key,
    generated_alert_id,
)
from soc_agent.ingest.category import infer_category
from soc_agent.ingest.errors import NormalizationError
from soc_agent.ingest.severity import normalize_severity
from soc_agent.models import NormalizationInfo, NormalizedAlert

_FIELD_MAP = {
    "src": "src_ip",
    "dest": "dest_ip",
    "src_host": "src_host",
    "dest_host": "dest_host",
    "user": "user",
    "app": "app",
    "transport": "protocol",
    "count": "count",
    "dest_port": "dest_port",
}


def normalize(ctx: IngestContext) -> NormalizedAlert:
    doc = ctx.parsed
    if doc is None or "search_name" not in doc:
        raise NormalizationError("splunk payload missing required field 'search_name'")

    key = dedupe_key(ctx.raw)
    search_name = doc["search_name"]
    result = doc.get("result") or {}

    description = result.get("_raw")
    category = infer_category(search_name, description)

    urgency = doc.get("urgency") or result.get("urgency")
    severity, severity_original = normalize_severity("splunk", urgency, ctx)

    occurred_at = result.get("_time") or doc.get("_time")
    if occurred_at is None:
        ctx.warn(WARN_NO_TIMESTAMP)

    observed_fields: dict[str, str] = {}
    for src_key, dest_key in _FIELD_MAP.items():
        if src_key in result:
            observed_fields[dest_key] = str(result[src_key])
    for src_key, value in result.items():
        if src_key in _FIELD_MAP or src_key in ("_raw", "_time"):
            continue
        observed_fields[src_key] = str(value)

    return NormalizedAlert(
        alert_id=doc.get("sid") or generated_alert_id(key),
        dedupe_key=key,
        source_system="splunk",
        vendor_rule=search_name,
        title=search_name,
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
