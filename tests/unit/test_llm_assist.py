"""LLM assist grounding + failure-degradation tests (API-free, stubbed).

Spec: extraction-04-spec.md §16.8 — the two bullets explicitly called out as
API-free live here rather than in tests/llm/test_extract_llm.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

import soc_agent.extract.llm_assist as llm_assist_module
from soc_agent.config import get_config
from soc_agent.extract import extract_entities
from soc_agent.models import EntityCandidate, ExtractionSelection
from soc_agent.models.alert import NormalizationInfo, NormalizedAlert


def _alert(**overrides) -> NormalizedAlert:
    defaults = dict(
        alert_id="soc-agent-test",
        dedupe_key="a" * 64,
        source_system="freetext",
        title="Alert on WS-HR-0009",
        description="user t.baros ran powershell. Also saw 999.999.999.999 in the logs.",
        severity=50,
        ingested_at=datetime(2026, 7, 20, 12, tzinfo=UTC),
        observed_fields={"host": "WS-HR-0009", "user": "t.baros"},
        raw={},
        normalization=NormalizationInfo(method="llm", confidence=0.9),
    )
    defaults.update(overrides)
    return NormalizedAlert(**defaults)


class _StubLLM:
    def __init__(self, *, selection=None, exc=None):
        self._selection = selection
        self._exc = exc

    def invoke(self, messages):
        if self._exc is not None:
            raise self._exc
        return self._selection


def test_ungrounded_and_invalid_candidates_are_all_rejected(monkeypatch) -> None:
    """An invented hash, an out-of-range IP (grounded but type-invalid), and a value
    that never appears in the text — all three rejected, zero additions."""
    selection = ExtractionSelection(
        entities=[
            EntityCandidate(type="hash_sha256", value="a" * 64),  # not in text at all
            EntityCandidate(type="ip", value="999.999.999.999"),  # verbatim, but invalid
            EntityCandidate(type="user", value="ghost.user"),  # not in text at all
        ]
    )
    monkeypatch.setattr(llm_assist_module, "get_llm", lambda *a, **k: _StubLLM(selection=selection))

    alert = _alert()
    cfg = get_config().extraction
    accepted, errors, dropped = llm_assist_module.llm_assist(alert, known=[], cfg=cfg)

    assert accepted == []
    assert errors == []
    assert dropped.get("llm_ungrounded") == 3


def test_assist_failure_degrades_to_deterministic_set(monkeypatch) -> None:
    """Architecture §11: assist failure -> deterministic extraction only, `partial`
    (a recorded StageError), never a crash."""
    monkeypatch.setattr(
        llm_assist_module, "get_llm", lambda *a, **k: _StubLLM(exc=RuntimeError("boom"))
    )

    alert = _alert()
    deterministic_only = extract_entities(alert, llm_assist_mode="never")
    with_failing_assist = extract_entities(alert, llm_assist_mode="always")

    assert with_failing_assist.entities == deterministic_only.entities
    assert len(with_failing_assist.errors) == 1
    error = with_failing_assist.errors[0]
    assert error.stage == "extract"
    assert error.type == "api_error"
    assert with_failing_assist.llm_used is True
