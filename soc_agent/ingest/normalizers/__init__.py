"""Per-format normalizer registry. Spec: ingestion-03-spec.md §9."""

from __future__ import annotations

from collections.abc import Callable

from soc_agent.ingest.base import IngestContext
from soc_agent.ingest.normalizers import cef, elastic, freetext, generic, splunk
from soc_agent.models import NormalizedAlert, SourceSystem

NORMALIZERS: dict[SourceSystem, Callable[[IngestContext], NormalizedAlert]] = {
    "generic": generic.normalize,
    "splunk": splunk.normalize,
    "elastic": elastic.normalize,
    "cef": cef.normalize,
    "freetext": freetext.normalize,
}
