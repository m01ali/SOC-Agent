"""Input detection and normalization. Spec: ingestion-03-spec.md (Architecture §4).

Public API: `load_input`, `detect_format`, `normalize` — the one entry point specs
04-08 call. Nothing else in soc_agent should construct an IngestContext directly.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from soc_agent.ingest.base import IngestContext
from soc_agent.ingest.detector import DetectionResult, detect_format
from soc_agent.ingest.errors import IngestError, NormalizationError, UnparseableInputError
from soc_agent.ingest.normalizers import NORMALIZERS
from soc_agent.models import NormalizedAlert, SourceSystem

__all__ = [
    "DetectionResult",
    "IngestError",
    "NormalizationError",
    "UnparseableInputError",
    "detect_format",
    "load_input",
    "normalize",
]


def load_input(path: Path) -> str:
    """Read an alert file as UTF-8 text. Raises UnparseableInputError on empty/undecodable input."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise UnparseableInputError(f"{path}: not valid UTF-8") from e
    except OSError as e:
        raise UnparseableInputError(f"{path}: {e}") from e
    if not text.strip():
        raise UnparseableInputError(f"{path}: empty input")
    return text


def normalize(
    raw: str, *, hint: SourceSystem | None = None, now: datetime | None = None
) -> NormalizedAlert:
    """detect_format() + dispatch to the matching normalizer. The entry point specs 04-08 call."""
    result = detect_format(raw, hint=hint)
    ctx = IngestContext(
        raw=raw,
        now=now if now is not None else datetime.now(UTC),
        parsed=result.parsed,
        warnings=list(result.warnings),
    )
    return NORMALIZERS[result.format](ctx)
