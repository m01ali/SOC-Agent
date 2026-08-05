"""Input-format detection. Spec: ingestion-03-spec.md §4 (Architecture §4.1)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from soc_agent.ingest.base import WARN_UNRECOGNIZED_JSON_STRUCTURE
from soc_agent.ingest.errors import UnparseableInputError
from soc_agent.models import SourceSystem

_CEF_SIGNATURE = re.compile(r"CEF:\d+\|")


@dataclass(frozen=True)
class DetectionResult:
    format: SourceSystem
    warnings: list[str]
    parsed: dict | None


def _is_splunk(doc: dict) -> bool:
    result = doc.get("result")
    return (
        "search_name" in doc
        or "sid" in doc
        or (isinstance(result, dict) and bool({"_raw", "_time"} & result.keys()))
    )


def _is_elastic(doc: dict) -> bool:
    if "@timestamp" not in doc:
        return False
    event = doc.get("event")
    return (
        any(k.startswith("kibana.alert.") for k in doc)
        or "kibana" in doc
        or (isinstance(event, dict) and event.get("kind") == "signal")
        or "signal" in doc
    )


def _is_generic(doc: dict) -> bool:
    return doc.get("schema") == "soc-agent/alert@v1" or ("alert_id" in doc and "title" in doc)


def detect_format(raw: str, hint: SourceSystem | None = None) -> DetectionResult:
    """Classify raw input. Never raises for non-empty input — unknown falls back to freetext."""
    if not raw.strip():
        raise UnparseableInputError("input is empty")

    if hint is not None:
        parsed: dict | None = None
        if hint != "cef":
            try:
                doc = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                doc = None
            if isinstance(doc, dict):
                parsed = doc
        return DetectionResult(format=hint, warnings=[], parsed=parsed)

    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        doc = None

    if isinstance(doc, dict):
        if _is_splunk(doc):
            return DetectionResult(format="splunk", warnings=[], parsed=doc)
        if _is_elastic(doc):
            return DetectionResult(format="elastic", warnings=[], parsed=doc)
        if _is_generic(doc):
            return DetectionResult(format="generic", warnings=[], parsed=doc)
        return DetectionResult(
            format="freetext", warnings=[WARN_UNRECOGNIZED_JSON_STRUCTURE], parsed=doc
        )

    first_line = raw.splitlines()[0] if raw.splitlines() else ""
    if _CEF_SIGNATURE.search(first_line):
        return DetectionResult(format="cef", warnings=[], parsed=None)

    return DetectionResult(format="freetext", warnings=[], parsed=None)
