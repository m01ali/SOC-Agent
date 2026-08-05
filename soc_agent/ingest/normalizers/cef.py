"""CEF (syslog) normalizer. Spec: ingestion-03-spec.md §9.4."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from soc_agent.ingest.base import (
    WARN_YEAR_INFERRED,
    IngestContext,
    dedupe_key,
    generated_alert_id,
)
from soc_agent.ingest.category import infer_category
from soc_agent.ingest.errors import NormalizationError
from soc_agent.ingest.severity import normalize_severity
from soc_agent.models import NormalizationInfo, NormalizedAlert

_CEF_HEADER = re.compile(r"CEF:\d+\|")
_EXT_KEY = re.compile(r"(?<!\\)\b([A-Za-z][A-Za-z0-9_.\[\]-]*)=")
_SYSLOG_DATE = re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

_FIELD_MAP = {
    "src": "src_ip",
    "dst": "dest_ip",
    "shost": "src_host",
    "dhost": "dest_host",
    "suser": "user",
    "duser": "dest_user",
    "spt": "src_port",
    "dpt": "dest_port",
    "proto": "protocol",
    "request": "url",
    "fname": "file_path",
    "fileHash": "file_hash",
    "in": "bytes_in",
    "out": "bytes_out",
    "act": "action",
    "app": "app",
}

_NON_PASSTHROUGH = frozenset(_FIELD_MAP) | {
    "cs1Label",
    "cs2Label",
    "cs3Label",
    "cs4Label",
    "cs5Label",
    "cs6Label",
}


def _split_unescaped(s: str, sep: str, maxsplit: int) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            buf.append(s[i + 1])
            i += 2
            continue
        if c == sep and len(out) < maxsplit:
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    out.append("".join(buf))
    return out


def _unescape(s: str) -> str:
    return s.replace("\\=", "=").replace("\\n", "\n").replace("\\r", "\r").replace("\\\\", "\\")


def _parse_extension(ext: str) -> dict[str, str]:
    keys = list(_EXT_KEY.finditer(ext))
    out: dict[str, str] = {}
    for i, m in enumerate(keys):
        end = keys[i + 1].start() if i + 1 < len(keys) else len(ext)
        out[m.group(1)] = _unescape(ext[m.end() : end].strip())
    return out


def _resolve_custom_labels(ext: dict[str, str]) -> dict[str, str]:
    resolved = dict(ext)
    for key in list(resolved):
        if not key.endswith("Label"):
            continue
        base = key[: -len("Label")]
        label_name = resolved.pop(key)
        if base in resolved:
            value = resolved.pop(base)
            resolved[label_name] = value
    return resolved


def _infer_year(month_day_time: str, now: object) -> tuple[datetime, bool]:
    assert isinstance(now, datetime)
    candidate = datetime.strptime(f"{now.year} {month_day_time}", "%Y %b %d %H:%M:%S").replace(
        tzinfo=UTC
    )
    if candidate - now > timedelta(hours=24):
        candidate = candidate.replace(year=now.year - 1)
    return candidate, True


def normalize(ctx: IngestContext) -> NormalizedAlert:
    m = _CEF_HEADER.search(ctx.raw)
    if m is None:
        raise NormalizationError("no CEF header found")

    syslog_prefix = ctx.raw[: m.start()]
    header_and_ext = ctx.raw[m.end() :].rstrip("\n")
    parts = _split_unescaped(header_and_ext, "|", 6)
    if len(parts) < 7:
        raise NormalizationError(f"CEF header has {len(parts)} fields, need 7")

    (
        device_vendor,
        device_product,
        _device_version,
        device_event_class_id,
        name,
        cef_severity,
        ext_raw,
    ) = parts
    ext = _resolve_custom_labels(_parse_extension(ext_raw))

    key = dedupe_key(ctx.raw)

    description = ext.get("msg") or name
    category = infer_category(name, description, device_product)

    severity, severity_original = normalize_severity("cef", cef_severity, ctx)

    occurred_at = None
    rt = ext.get("rt") or ext.get("end") or ext.get("start")
    if rt is not None:
        try:
            occurred_at = datetime.fromtimestamp(int(rt) / 1000, tz=UTC)
        except (ValueError, OverflowError):
            occurred_at = None
    if occurred_at is None:
        date_match = _SYSLOG_DATE.search(syslog_prefix)
        if date_match:
            occurred_at, inferred = _infer_year(date_match.group(1), ctx.now)
            if inferred:
                ctx.warn(WARN_YEAR_INFERRED)
    if occurred_at is None:
        ctx.warn("no_timestamp")

    observed_fields: dict[str, str] = {}
    for src_key, dest_key in _FIELD_MAP.items():
        if src_key in ext:
            observed_fields[dest_key] = ext[src_key]
    for src_key, value in ext.items():
        if src_key in _NON_PASSTHROUGH:
            continue
        observed_fields[src_key] = value
    observed_fields["device_vendor"] = device_vendor
    observed_fields["device_product"] = device_product
    observed_fields["device_event_class_id"] = device_event_class_id

    return NormalizedAlert(
        alert_id=ext.get("externalId") or generated_alert_id(key),
        dedupe_key=key,
        source_system="cef",
        vendor_rule=name,
        title=name,
        description=description,
        category=category,
        severity_original=severity_original,
        severity=severity,
        occurred_at=occurred_at,
        ingested_at=ctx.now,
        observed_fields=observed_fields,
        raw=ctx.raw,
        normalization=NormalizationInfo(method="parser", confidence=1.0, warnings=ctx.warnings),
    )
