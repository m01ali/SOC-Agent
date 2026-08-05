"""Ingestion failure types. Spec: ingestion-03-spec.md §3.2."""

from __future__ import annotations


class IngestError(RuntimeError):
    """Base for all ingestion failures."""


class UnparseableInputError(IngestError):
    """Input could not be read or is empty. -> status "failed", exit 2 (Architecture §5.1)."""


class NormalizationError(IngestError):
    """A normalizer ran but could not produce a valid alert. -> status "failed", exit 2."""
