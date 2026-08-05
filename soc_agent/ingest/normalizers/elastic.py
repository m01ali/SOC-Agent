"""Elastic Security / ECS normalizer. Spec: ingestion-03-spec.md §9.3."""

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
    "source.ip": "src_ip",
    "destination.ip": "dest_ip",
    "host.name": "host",
    "user.name": "user",
    "process.name": "process",
    "process.hash.sha256": "process_hash_sha256",
    "process.hash.sha1": "process_hash_sha1",
    "process.hash.md5": "process_hash_md5",
    "file.path": "file_path",
    "url.full": "url",
    "destination.port": "dest_port",
    "network.protocol": "protocol",
}


def dotted_get(doc: dict, path: str, default: object = None) -> object:
    """Flat literal key first, then a nested walk. `kibana.alert.rule.name` resolves either way."""
    if path in doc:
        return doc[path]
    cur: object = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def normalize(ctx: IngestContext) -> NormalizedAlert:
    doc = ctx.parsed
    if doc is None or "@timestamp" not in doc:
        raise NormalizationError("elastic payload missing required field '@timestamp'")

    key = dedupe_key(ctx.raw)

    rule_name = (
        dotted_get(doc, "kibana.alert.rule.name")
        or dotted_get(doc, "signal.rule.name")
        or dotted_get(doc, "rule.name")
    )
    reason = dotted_get(doc, "kibana.alert.reason") or doc.get("message")

    ecs_categories = dotted_get(doc, "event.category")
    if not isinstance(ecs_categories, list):
        ecs_categories = None
    category = infer_category(rule_name, reason, ecs_categories=ecs_categories)

    severity_value = (
        dotted_get(doc, "kibana.alert.severity")
        or dotted_get(doc, "kibana.alert.risk_score")
        or dotted_get(doc, "event.severity")
    )
    severity, severity_original = normalize_severity("elastic", severity_value, ctx)

    occurred_at = doc.get("@timestamp")
    if occurred_at is None:
        ctx.warn(WARN_NO_TIMESTAMP)

    observed_fields: dict[str, str] = {}
    for path, dest_key in _FIELD_MAP.items():
        value = dotted_get(doc, path)
        if value is not None:
            observed_fields[dest_key] = str(value)

    title = rule_name or "Elastic alert"

    return NormalizedAlert(
        alert_id=dotted_get(doc, "kibana.alert.uuid") or doc.get("_id") or generated_alert_id(key),
        dedupe_key=key,
        source_system="elastic",
        vendor_rule=rule_name,
        title=title,
        description=reason,
        category=category,
        severity_original=severity_original,
        severity=severity,
        occurred_at=occurred_at,
        ingested_at=ctx.now,
        observed_fields=observed_fields,
        raw=doc,
        normalization=NormalizationInfo(method="parser", confidence=1.0, warnings=ctx.warnings),
    )
