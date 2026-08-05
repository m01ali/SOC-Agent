"""Free-text LLM normalizer. Spec: ingestion-03-spec.md §10.

The one LLM call in this phase whose failure is terminal (Architecture §5.1):
without an alert there is nothing downstream to enrich.
"""

from __future__ import annotations

from pydantic import ValidationError

from soc_agent.ingest.base import (
    WARN_LLM_NORMALIZATION,
    WARN_LLM_REPAIR_RETRY,
    WARN_UNRECOGNIZED_JSON_STRUCTURE,
    IngestContext,
    dedupe_key,
    generated_alert_id,
)
from soc_agent.ingest.errors import NormalizationError
from soc_agent.llm.client import get_llm
from soc_agent.llm.prompt import render_messages
from soc_agent.models import NormalizationInfo, NormalizedAlert, NormalizedAlertDraft


def _invoke(ctx: IngestContext) -> NormalizedAlertDraft:
    messages = render_messages("normalize_freetext", alert_text=ctx.raw)
    llm = get_llm("normalize", structured=NormalizedAlertDraft)
    try:
        return llm.invoke(messages)
    except ValidationError as e:
        ctx.warn(WARN_LLM_REPAIR_RETRY)
        repair_messages = [
            *messages,
            ("user", f"Your previous output failed validation with this error: {e}\n"
                     "Return corrected structured output."),
        ]
        return llm.invoke(repair_messages)


def normalize(ctx: IngestContext) -> NormalizedAlert:
    try:
        draft = _invoke(ctx)
    except ValidationError as e:
        raise NormalizationError(f"free-text normalization failed validation twice: {e}") from e
    except Exception as e:  # noqa: BLE001 — any LLM-layer failure is terminal here
        raise NormalizationError(f"free-text normalization failed: {e}") from e

    unrecognized_json = WARN_UNRECOGNIZED_JSON_STRUCTURE in ctx.warnings
    ctx.warn(WARN_LLM_NORMALIZATION)
    key = dedupe_key(ctx.raw)
    confidence = min(draft.confidence, 0.6) if unrecognized_json else draft.confidence

    return NormalizedAlert(
        alert_id=generated_alert_id(key),
        dedupe_key=key,
        source_system="freetext",
        vendor_rule=draft.vendor_rule,
        title=draft.title,
        description=draft.description or ctx.raw,
        category=draft.category,
        severity_original=draft.severity_original,
        severity=draft.severity,
        occurred_at=draft.occurred_at,
        ingested_at=ctx.now,
        observed_fields={k: str(v) for k, v in draft.observed_fields.items()},
        raw=ctx.raw,
        normalization=NormalizationInfo(
            method="llm", confidence=confidence, warnings=ctx.warnings
        ),
    )
