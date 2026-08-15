"""The analyst briefing. Spec: triage-briefing-07-spec.md §10 (Architecture §5.7).

<= 200 words of markdown for a Tier-1 analyst who has not seen this alert, restating
only facts already in the state.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from soc_agent.evidence import build_evidence_bundle, render_risk_block
from soc_agent.llm.client import get_llm
from soc_agent.llm.prompt import render_messages
from soc_agent.models import (
    AttackMapping,
    Briefing,
    Entity,
    RelatedAlertsBlock,
    RiskAssessment,
    StageError,
    ThreatIntelBlock,
    TriageRecommendation,
)
from soc_agent.models.alert import NormalizedAlert
from soc_agent.triage import _grounding_set, _is_grounded

if TYPE_CHECKING:
    from soc_agent.config import AppConfig

__all__ = [
    "BriefResult",
    "brief",
    "deterministic_briefing",
    "normalize_markdown",
    "truncate_to_words",
    "word_count",
]

_SENTENCE_END = re.compile(r"[.!?](?:\s|$)")


@dataclass(frozen=True)
class BriefResult:
    briefing: Briefing
    errors: list[StageError] = field(default_factory=list)
    word_count: int = 0
    truncated: bool = False
    llm_used: bool = False


def word_count(markdown: str) -> int:
    """Crude, stable, and the same number the prompt asks for."""
    return len(markdown.split())


# Structural markers that must begin a line for the markdown to render as intended.
_BULLET_RUN_ON = re.compile(r"(?<=[.!?:\w])\s*(?=[-*]\s{1,3}\*\*)")
# Only after a CLOSING `**` — i.e. one preceded by text. A bare `(?<=\*\*)` also matches
# after the opening marker and splits `**Verdict**` down the middle. The optional space
# matters: the model writes both `**Verdict.**Host …` and `**Verdict.** Host …`.
_BOLD_RUN_ON = re.compile(r"(?<=[\w.!?:)]\*\*)[ \t]*(?=[A-Z])")


def normalize_markdown(markdown: str) -> str:
    """Insert the line breaks the model omits. Formatting only — never changes words.

    Measured across the corpus: the model emits the full briefing as a SINGLE line with
    no newlines anywhere, so `**verdict**Host WS-FIN-0142 initiated…` and
    `*   **Threat Intel:**…` run together and the bullets do not render as a list. The
    briefing is the pipeline's primary human-facing artifact, so this is a real defect
    rather than a cosmetic one.

    Prompting for line breaks was tried first and made it worse (8 of 10 briefings
    collapsed to a bare headline), so the fix lives here: deterministic, free, and
    robust to the model's JSON-string formatting habits. It is the same class of
    intervention as the word-cap truncation in §10.2 — it moves whitespace, never text.
    """
    text = markdown.strip()
    if "\n" in text:
        return text  # the model already formatted it

    # A bullet marker mid-line starts a new line.
    text = _BULLET_RUN_ON.sub("\n", text)
    # The first paragraph break goes after the leading bold verdict.
    text = _BOLD_RUN_ON.sub("\n\n", text, count=1)
    # Normalize bullet markers to "- " and collapse the runs of spaces after them.
    text = re.sub(r"^[*]\s{1,3}(?=\*\*)", "- ", text, flags=re.MULTILINE)
    return text.strip()


def truncate_to_words(markdown: str, max_words: int) -> str:
    """Cut at the last complete sentence within the cap, never mid-word (§10.2)."""
    words = markdown.split()
    if len(words) <= max_words:
        return markdown

    clipped = " ".join(words[:max_words])
    ends = list(_SENTENCE_END.finditer(clipped))
    if ends:
        return clipped[: ends[-1].end()].rstrip()
    # No sentence boundary survived the cut — keep the words rather than emit nothing.
    return clipped.rstrip()


def deterministic_briefing(
    alert: NormalizedAlert,
    threat_intel: ThreatIntelBlock | None,
    related: RelatedAlertsBlock | None,
    attack: Sequence[AttackMapping],
    risk: RiskAssessment,
    recommendation: TriageRecommendation,
) -> str:
    """The fallback (§11.1). Not None.

    The envelope permits a null briefing, but an operator running with no API key should
    still get something readable, and spec 09's degraded-mode demo is more convincing
    when the output stays usable. Every value here is already in the state, so this
    introduces no claim the LLM path could not also make.
    """
    lines = [
        f"**{alert.title}** — risk {risk.score}/100 (`{risk.band}`).",
        "",
        (
            f"Deterministic assessment from threat intel {risk.components.ti}, "
            f"severity {risk.components.severity} and history {risk.components.history}."
        ),
        "",
    ]

    if threat_intel and threat_intel.results:
        summary = threat_intel.summary
        lines.append(
            f"- Threat intel: {summary.iocs_checked} IOC(s) checked, "
            f"worst verdict **{summary.worst_verdict}**"
        )
    else:
        lines.append("- Threat intel: no external IOCs to check")

    if related and related.count:
        lines.append(
            f"- History: {related.count} related alert(s), "
            f"{related.prior_true_positives} prior true positive(s)"
        )
    else:
        lines.append("- History: no related alerts in the window")

    if attack:
        techniques = ", ".join(f"{m.technique_id} ({m.technique_name})" for m in attack[:2])
        lines.append(f"- ATT&CK: {techniques}")

    lines.append("")
    lines.append(
        f"**Recommendation: {recommendation.action} ({recommendation.priority}).** "
        "Generated without the summary model; see `errors` for details."
    )
    return "\n".join(lines)


def brief(
    alert: NormalizedAlert,
    entities: Sequence[Entity] = (),
    threat_intel: ThreatIntelBlock | None = None,
    related: RelatedAlertsBlock | None = None,
    attack: Sequence[AttackMapping] = (),
    risk: RiskAssessment | None = None,
    recommendation: TriageRecommendation | None = None,
    *,
    use_llm: bool | None = None,
    config: AppConfig | None = None,
) -> BriefResult:
    """Never raises. An LLM failure degrades to the deterministic briefing (§11)."""
    if config is None:
        from soc_agent.config import get_config

        config = get_config()
    if risk is None:
        from soc_agent.scoring import score_risk

        risk = score_risk(alert, threat_intel, related, config=config.scoring)
    if recommendation is None:
        from soc_agent.triage import deterministic_recommendation

        recommendation = deterministic_recommendation(risk)

    max_words = config.briefing.max_words
    wants_llm = config.briefing.use_llm if use_llm is None else use_llm

    def fallback(errors: list[StageError]) -> BriefResult:
        markdown = deterministic_briefing(
            alert, threat_intel, related, attack, risk, recommendation
        )
        return BriefResult(
            briefing=Briefing(markdown=markdown),
            errors=errors,
            word_count=word_count(markdown),
            llm_used=False,
        )

    if not wants_llm:
        return fallback([])

    bundle = build_evidence_bundle(
        alert, entities, threat_intel, related, attack, max_chars=config.attack.max_bundle_chars
    )
    recommendation_block = (
        f"action {recommendation.action} ({recommendation.priority}, "
        f"confidence {recommendation.confidence})\n"
        f"rationale: {recommendation.rationale}"
    )
    try:
        messages = render_messages(
            "brief",
            evidence_bundle=bundle,
            risk_block=render_risk_block(risk),
            recommendation_block=recommendation_block,
            max_words=str(max_words),
        )
        llm = get_llm("brief", structured=Briefing)
        raw: Briefing = llm.invoke(messages)
    except Exception as e:  # noqa: BLE001 — any LLM-layer failure degrades (§11)
        return fallback([StageError(stage="brief", type="api_error", detail=str(e))])

    markdown = normalize_markdown(raw.markdown)
    errors: list[StageError] = []
    truncated = False

    count = word_count(markdown)
    if count > max_words:
        markdown = truncate_to_words(markdown, max_words)
        truncated = True
        errors.append(
            StageError(
                stage="brief",
                type="schema_validation",
                detail=f"briefing was {count} words, truncated to the {max_words}-word cap",
            )
        )
        count = word_count(markdown)

    if not markdown:
        return fallback(errors)

    # Ungrounded IOCs are recorded but the text is KEPT (§10.2). Unlike a suggested
    # action, briefing prose is not actionable in itself, and excising a sentence from
    # the middle of a paragraph does more damage to readability than the claim does to
    # trust — the error record is the right remedy. Deliberately asymmetric with §9.
    if not _is_grounded(markdown, _grounding_set(entities, attack)):
        errors.append(
            StageError(
                stage="brief",
                type="schema_validation",
                detail="briefing cites an indicator absent from the alert evidence",
            )
        )

    return BriefResult(
        briefing=Briefing(markdown=markdown),
        errors=errors,
        word_count=count,
        truncated=truncated,
        llm_used=True,
    )
