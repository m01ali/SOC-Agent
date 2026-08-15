"""Briefing word cap, grounding and fallback. Spec: §17.4. API-free (stubbed LLM)."""

from __future__ import annotations

import pytest

from soc_agent.brief import (
    brief,
    deterministic_briefing,
    normalize_markdown,
    truncate_to_words,
    word_count,
)
from soc_agent.config import AppConfig, BriefingConfig
from soc_agent.models import Briefing, EntityRef, RelatedAlertsBlock, TIResult
from soc_agent.models.ti import ThreatIntelBlock, TISummary
from tests.unit.test_scoring import make_alert
from tests.unit.test_triage_rules import entity, recommendation, risk_at


def ti_block() -> ThreatIntelBlock:
    return ThreatIntelBlock(
        summary=TISummary(iocs_checked=1, malicious=1, worst_verdict="malicious"),
        results=[
            TIResult(
                entity=EntityRef(type="ip", value="203.0.113.66"),
                verdict="malicious",
                score=95,
                tags=["c2"],
            )
        ],
    )


def stub_briefing(monkeypatch, markdown: str):
    import soc_agent.brief as brief_module

    class Stub:
        def invoke(self, messages):
            return Briefing(markdown=markdown)

    monkeypatch.setattr(brief_module, "get_llm", lambda *a, **k: Stub())


# -- word counting and truncation (§10.2) ------------------------------------


def test_word_count_is_whitespace_split():
    assert word_count("one two three") == 3
    assert word_count("**bold** text\n\n- bullet") == 4


def test_short_briefing_passes_untouched(monkeypatch):
    text = " ".join(["word"] * 199) + "."
    stub_briefing(monkeypatch, text)
    result = brief(
        make_alert(),
        risk=risk_at(84),
        recommendation=recommendation("escalate"),
        config=AppConfig(),
    )
    assert result.truncated is False
    assert result.briefing.markdown == text
    assert result.errors == []


def test_over_length_briefing_is_truncated_at_a_sentence_boundary(monkeypatch):
    text = ("This is a sentence. " * 150).strip()
    stub_briefing(monkeypatch, text)
    result = brief(
        make_alert(),
        risk=risk_at(84),
        recommendation=recommendation("escalate"),
        config=AppConfig(),
    )

    assert result.truncated is True
    assert result.word_count <= 200
    assert result.briefing.markdown.endswith(".")
    assert len(result.errors) == 1
    assert result.errors[0].stage == "brief"
    assert result.errors[0].type == "schema_validation"
    assert "truncated" in result.errors[0].detail


def test_truncation_never_cuts_mid_word():
    text = "Alpha beta gamma. Delta epsilon zeta. Eta theta iota."
    out = truncate_to_words(text, 7)
    assert out == "Alpha beta gamma. Delta epsilon zeta."
    assert not out.endswith("Delta epsilo")


def test_truncation_without_a_sentence_boundary_keeps_words():
    """Better a clipped phrase than an empty briefing."""
    out = truncate_to_words("alpha beta gamma delta", 2)
    assert out == "alpha beta"


def test_custom_word_cap_is_honoured(monkeypatch):
    stub_briefing(monkeypatch, "One. Two. Three. Four. Five. Six.")
    cfg = AppConfig(briefing=BriefingConfig(max_words=4))
    result = brief(
        make_alert(), risk=risk_at(84), recommendation=recommendation("escalate"), config=cfg
    )
    assert result.word_count <= 4
    assert result.truncated is True


# -- grounding (§10.2) -------------------------------------------------------


def test_ungrounded_ioc_is_recorded_but_the_text_is_kept(monkeypatch):
    """Deliberately asymmetric with §9: excising a sentence mid-paragraph does more
    damage to readability than the claim does to trust."""
    text = "**Verdict.** The host contacted 8.8.8.8 repeatedly."
    stub_briefing(monkeypatch, text)
    result = brief(
        make_alert(),
        entities=[entity("ip", "203.0.113.66")],
        risk=risk_at(84),
        recommendation=recommendation("escalate"),
        config=AppConfig(),
    )
    # Kept — the claim survives verbatim. (The markdown itself gains a line break from
    # normalize_markdown; what matters is that no text was excised.)
    assert "The host contacted 8.8.8.8 repeatedly." in result.briefing.markdown
    assert result.briefing.markdown.split() == text.split()
    assert any("absent from the alert evidence" in e.detail for e in result.errors)


def test_grounded_briefing_records_no_error(monkeypatch):
    text = "**Verdict.** The host contacted 203.0.113.66 repeatedly."
    stub_briefing(monkeypatch, text)
    result = brief(
        make_alert(),
        entities=[entity("ip", "203.0.113.66")],
        risk=risk_at(84),
        recommendation=recommendation("escalate"),
        config=AppConfig(),
    )
    assert result.errors == []


# -- the deterministic fallback (§11.1) --------------------------------------


def test_llm_failure_yields_a_usable_briefing(monkeypatch):
    import soc_agent.brief as brief_module

    def boom(*args, **kwargs):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(brief_module, "get_llm", boom)

    result = brief(
        make_alert(severity=75),
        threat_intel=ti_block(),
        risk=risk_at(84),
        recommendation=recommendation("escalate"),
        config=AppConfig(),
    )
    markdown = result.briefing.markdown
    assert markdown  # not None, not empty
    assert "84/100" in markdown
    assert "escalate" in markdown
    assert result.llm_used is False
    assert result.errors[0].type == "api_error"


def test_deterministic_briefing_reports_the_no_ioc_case():
    markdown = deterministic_briefing(
        make_alert(), None, None, (), risk_at(42), recommendation("investigate", "P3")
    )
    assert "no external IOCs" in markdown
    assert "no related alerts" in markdown


def test_deterministic_briefing_introduces_no_new_indicator():
    markdown = deterministic_briefing(
        make_alert(),
        ti_block(),
        RelatedAlertsBlock(count=0),
        (),
        risk_at(84),
        recommendation("escalate"),
    )
    # It reports counts and verdicts, never an address the state does not contain.
    assert "8.8.8.8" not in markdown
    assert "1 IOC(s) checked" in markdown


def test_use_llm_false_uses_the_deterministic_path(monkeypatch):
    import soc_agent.brief as brief_module

    monkeypatch.setattr(
        brief_module, "get_llm", lambda *a, **k: pytest.fail("should not be called")
    )
    result = brief(
        make_alert(),
        risk=risk_at(42),
        recommendation=recommendation("investigate"),
        use_llm=False,
        config=AppConfig(),
    )
    assert result.llm_used is False
    assert result.errors == []
    assert result.briefing.markdown


def test_empty_llm_briefing_falls_back(monkeypatch):
    stub_briefing(monkeypatch, "   ")
    result = brief(
        make_alert(),
        risk=risk_at(84),
        recommendation=recommendation("escalate"),
        config=AppConfig(),
    )
    assert result.briefing.markdown.strip()
    assert result.llm_used is False


# -- markdown normalization (§10.2) ------------------------------------------


def test_run_on_markdown_is_split_into_lines():
    """Measured across the corpus: the model emits the whole briefing on ONE line, so
    `**verdict**Host…` and `*   **Threat Intel:**…` never render as markdown."""
    text = (
        "**Escalate: C2 beaconing**Host WS-FIN-0142 beaconed for 7 hours."
        "*   **Threat Intel:** score 95.*   **History:** one prior true positive."
    )
    out = normalize_markdown(text)
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) >= 3
    assert lines[0] == "**Escalate: C2 beaconing**"
    assert any(line.startswith("- **Threat Intel:**") for line in lines)


def test_normalization_never_changes_the_words():
    """It is the same class of intervention as the word cap.

    It inserts line breaks and rewrites a `*` bullet marker to `-`, so token boundaries
    move by design — what must not change is the prose itself.
    """
    import re as _re

    text = "**Verdict**Body text here.*   **Threat Intel:** score 95."
    words = _re.findall(r"[A-Za-z0-9]+", text)
    assert _re.findall(r"[A-Za-z0-9]+", normalize_markdown(text)) == words


def test_already_formatted_markdown_is_left_alone():
    text = "**Verdict**\n\nBody text.\n\n- **Threat Intel:** score 95."
    assert normalize_markdown(text) == text


def test_a_headline_only_briefing_is_not_a_briefing(monkeypatch):
    """The regression an over-prescriptive prompt caused: 8 of 10 briefings collapsed
    to a bare headline, and an upper-bound-only word check did not notice."""
    stub_briefing(monkeypatch, "**Escalate immediately: C2 beaconing detected.**")
    result = brief(
        make_alert(), risk=risk_at(84), recommendation=recommendation("escalate"),
        config=AppConfig(),
    )
    assert result.word_count < 20  # documents the shape; the LLM suite gates on >= 80
