"""Band-constrained triage. Spec: triage-briefing-07-spec.md §7-§9, §12 (Architecture §5.6).

This is the node an attacker wants. Extraction and ATT&CK influence *description*;
triage influences the *decision*, and fixture 10's alert body asks to be closed. Three
independent controls, in order of strength:

  1. the action is anchored to a deterministic score the LLM cannot compute or alter;
  2. overrides are bounded to +/-1 band and must be justified in a field that survives
     into the envelope;
  3. `forbidden_actions` in the fixture labels is a hard test failure, not a metric.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from soc_agent.evidence import build_evidence_bundle, render_risk_block
from soc_agent.extract.merge import canonical_value
from soc_agent.extract.patterns import (
    DOMAIN,
    HASH,
    IPV4,
    IPV6,
    URL,
    validate_domain,
    validate_hash,
    validate_ip,
    validate_url,
)
from soc_agent.llm.client import get_llm
from soc_agent.llm.prompt import render_messages
from soc_agent.models import (
    AttackMapping,
    Entity,
    ExpectedFixture,
    Priority,
    RelatedAlertsBlock,
    RiskAssessment,
    RiskBand,
    StageError,
    ThreatIntelBlock,
    TriageRecommendation,
)
from soc_agent.models.alert import NormalizedAlert

if TYPE_CHECKING:
    from soc_agent.config import AppConfig

__all__ = [
    "AgreementScore",
    "TriageResult",
    "priority_for",
    "recommendation_agreement",
    "triage",
]

BAND_ORDER: dict[str, int] = {"close": 0, "investigate": 1, "escalate": 2}

# §6 — allowed priorities per band. The model chooses within these; code clamps.
_ALLOWED_PRIORITIES: dict[str, tuple[Priority, ...]] = {
    "escalate": ("P1", "P2"),
    "investigate": ("P2", "P3"),
    "close": ("P4",),
}

_P1_MIN_SCORE = 90
_P2_MIN_INVESTIGATE_SCORE = 60


def _validate_hash_value(value: str) -> str | None:
    resolved = validate_hash(value)
    return resolved[1] if resolved is not None else None


# (pattern, validator) — spec 04 §7.2's discipline: generate, then arbitrate.
_IOC_PATTERNS: tuple[tuple[object, object], ...] = (
    (URL, validate_url),
    (IPV4, validate_ip),
    (IPV6, validate_ip),
    (HASH, _validate_hash_value),
    (DOMAIN, validate_domain),
)


@dataclass(frozen=True)
class TriageResult:
    recommendation: TriageRecommendation
    errors: list[StageError] = field(default_factory=list)
    dropped: dict[str, int] = field(default_factory=dict)
    overridden: bool = False
    clamped: bool = False
    llm_used: bool = False


def _bump(dropped: dict[str, int], reason: str) -> None:
    dropped[reason] = dropped.get(reason, 0) + 1


def priority_for(band: RiskBand, score: int) -> Priority:
    """§6. Verified against Architecture Appendix B: fixture 01 scores 84 -> escalate/P2."""
    if band == "escalate":
        return "P1" if score >= _P1_MIN_SCORE else "P2"
    if band == "investigate":
        return "P2" if score >= _P2_MIN_INVESTIGATE_SCORE else "P3"
    return "P4"


def allowed_priorities(band: RiskBand) -> tuple[Priority, ...]:
    return _ALLOWED_PRIORITIES[band]


# -- grounding (§9) ----------------------------------------------------------


def _ioc_tokens(text: str) -> set[str]:
    """Validated IOC tokens in prose, using spec 04's patterns AND its validators.

    Spec 04 §7.2: "the regexes are candidate generators; the validators are the
    arbiter." Matching without validating produces false positives that would drop a
    perfectly good suggested action — a model running two sentences together
    ("...indicator set.Escalation is required...") yields `set.Escalation`, which is
    domain-SHAPED but fails the TLD allowlist. Caught on fixture 09 during recording.
    """
    tokens: set[str] = set()
    for pattern, validate in _IOC_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(0).rstrip(".,;:!?)\"'")
            validated = validate(raw)
            if validated is not None:
                tokens.add(validated if isinstance(validated, str) else raw)
    return tokens


def _domain_suffixes(value: str) -> set[str]:
    """Every registrable parent of a domain: a.b.example.net -> b.example.net, example.net.

    Referring to the parent of an observed FQDN is describing what the pipeline saw, not
    inventing infrastructure — "the example-analytics.net domain" is how an analyst
    names the thing they would sinkhole. Without this, fixture 07's briefing was flagged
    for citing the parent of its own observed domain.
    """
    labels = value.lower().split(".")
    return {".".join(labels[i:]) for i in range(1, len(labels) - 1)}


def _grounding_set(entities: Sequence[Entity], attack: Sequence[AttackMapping]) -> set[str]:
    known = {canonical_value(e.type, e.value) for e in entities}
    known |= {e.value.lower() for e in entities}
    known |= {m.technique_id.lower() for m in attack}
    for entity in entities:
        if entity.type == "domain":
            known |= _domain_suffixes(entity.value)
        elif entity.type == "url":
            host = urlsplit(entity.value.lower()).hostname
            if host:
                known.add(host)
                known |= _domain_suffixes(host)
    return known


def _is_grounded(text: str, known: set[str]) -> bool:
    """True when every IOC-shaped token in `text` is one the pipeline actually saw.

    Host and user names are deliberately NOT checked: they appear in prose in forms the
    extractor never emits ("the WS-FIN-0142 workstation", "l.hassan's account"), and
    dropping actions over that would remove the most useful advice. IOCs are checked
    because they are exactly the tokens with a machine-actionable, high-consequence
    form — an analyst may block an address straight out of this list.
    """
    for token in _ioc_tokens(text):
        lowered = token.lower()
        if lowered in known:
            continue
        # An IP may be written canonically in the entity set but not in prose.
        if lowered.rstrip("/") in known:
            continue
        return False
    return True


def ground_actions(
    actions: Sequence[str],
    entities: Sequence[Entity],
    attack: Sequence[AttackMapping],
    dropped: dict[str, int],
) -> list[str]:
    known = _grounding_set(entities, attack)
    kept: list[str] = []
    for action in actions:
        text = action.strip()
        if not text:
            continue
        if not _is_grounded(text, known):
            _bump(dropped, "ungrounded_action")
            continue
        kept.append(text)
    return kept


# -- band constraint (§8) ----------------------------------------------------


def constrain_to_band(
    recommendation: TriageRecommendation,
    risk: RiskAssessment,
    *,
    allow_downgrade: bool = True,
) -> tuple[TriageRecommendation, dict[str, int], list[StageError], bool, bool]:
    """Architecture §5.6: match the band unless justified, +/-1 at most.

    Clamping rather than rejecting the whole response keeps the rationale and suggested
    actions — usually still useful — while the action returns to the number the
    deterministic scorer stands behind.
    """
    dropped: dict[str, int] = {}
    errors: list[StageError] = []
    band = risk.band
    action = recommendation.action
    distance = BAND_ORDER[action] - BAND_ORDER[band]

    overridden = False
    clamped = False
    override_reason = (recommendation.override_reason or "").strip() or None

    if distance == 0:
        # A non-override cannot carry a reason.
        override_reason = None
    elif abs(distance) >= 2:
        _bump(dropped, "override_out_of_bounds")
        errors.append(
            StageError(
                stage="triage",
                type="schema_validation",
                detail=(
                    f"action {action!r} is {abs(distance)} bands from the deterministic "
                    f"band {band!r}; overrides are limited to +/-1 (clamped)"
                ),
            )
        )
        action, override_reason, clamped = band, None, True
    elif override_reason is None:
        _bump(dropped, "override_unjustified")
        errors.append(
            StageError(
                stage="triage",
                type="schema_validation",
                detail=(
                    f"action {action!r} differs from band {band!r} with no "
                    f"override_reason (clamped)"
                ),
            )
        )
        action, clamped = band, True
    elif distance < 0 and not allow_downgrade:
        _bump(dropped, "downgrade_blocked")
        errors.append(
            StageError(
                stage="triage",
                type="schema_validation",
                detail=(
                    f"downgrade from band {band!r} to {action!r} blocked by "
                    f"scoring.allow_downgrade_override (clamped)"
                ),
            )
        )
        action, override_reason, clamped = band, None, True
    else:
        overridden = True

    # §8.3 — priority is DERIVED, not chosen. It is a deterministic function of the
    # final action and the score, so the model has no judgment to add. Measured during
    # recording: letting the model pick freely within the band collapsed the P3 tier to
    # zero and tripled P1 (3 of 10 alerts at top priority instead of 1), which defeats
    # the point of having tiers. The model still returns the field — the spec-02
    # contract requires it — and divergence is counted so it stays visible.
    priority = priority_for(action, risk.score)
    if priority != recommendation.priority:
        _bump(dropped, "priority_normalized")

    constrained = recommendation.model_copy(
        update={"action": action, "priority": priority, "override_reason": override_reason}
    )
    return constrained, dropped, errors, overridden, clamped


# -- the deterministic fallback (§11) ----------------------------------------

_BAND_ACTIONS: dict[str, list[str]] = {
    "escalate": [
        "Escalate to Tier 2 with the evidence below",
        "Isolate or restrict the affected host pending review",
        "Preserve host and network telemetry for the last 7 days",
    ],
    "investigate": [
        "Review the affected host and account activity around the alert time",
        "Confirm whether the observed activity was expected or authorized",
        "Pull supporting telemetry before making a disposition",
    ],
    "close": [
        "Review the supporting evidence and confirm the disposition",
        "If closing, record the rationale against the detection rule",
    ],
}


def deterministic_recommendation(risk: RiskAssessment) -> TriageRecommendation:
    """Band-derived, low confidence, honest about being a fallback (§11).

    Close-band never auto-closes: this is a recommendation, and disposition authority
    stays with the analyst (Architecture §1.3, §5.6).
    """
    components = risk.components
    return TriageRecommendation(
        action=risk.band,
        priority=priority_for(risk.band, risk.score),
        confidence="low",
        rationale=(
            f"Automated recommendation derived from the deterministic risk score of "
            f"{risk.score}/100 (band '{risk.band}'), computed from threat intel "
            f"{components.ti}, alert severity {components.severity} and historical "
            f"correlation {components.history}. The analyst summary model was "
            f"unavailable, so this rationale is templated rather than reasoned."
        ),
        override_reason=None,
        suggested_actions=list(_BAND_ACTIONS[risk.band]),
    )


# -- the node ----------------------------------------------------------------


def triage(
    alert: NormalizedAlert,
    entities: Sequence[Entity] = (),
    threat_intel: ThreatIntelBlock | None = None,
    related: RelatedAlertsBlock | None = None,
    attack: Sequence[AttackMapping] = (),
    risk: RiskAssessment | None = None,
    *,
    use_llm: bool | None = None,
    config: AppConfig | None = None,
) -> TriageResult:
    """Band-constrained recommendation. Never raises (§11)."""
    if config is None:
        from soc_agent.config import get_config

        config = get_config()
    if risk is None:
        from soc_agent.scoring import score_risk

        risk = score_risk(alert, threat_intel, related, config=config.scoring)

    wants_llm = config.scoring.use_llm if use_llm is None else use_llm
    if not wants_llm:
        return TriageResult(recommendation=deterministic_recommendation(risk), llm_used=False)

    bundle = build_evidence_bundle(
        alert, entities, threat_intel, related, attack, max_chars=config.attack.max_bundle_chars
    )
    try:
        messages = render_messages(
            "triage",
            evidence_bundle=bundle,
            risk_block=render_risk_block(risk),
            band=risk.band,
            allowed_priorities=", ".join(allowed_priorities(risk.band)),
        )
        llm = get_llm("triage", structured=TriageRecommendation)
        raw: TriageRecommendation = llm.invoke(messages)
    except Exception as e:  # noqa: BLE001 — any LLM-layer failure degrades (§11)
        return TriageResult(
            recommendation=deterministic_recommendation(risk),
            errors=[StageError(stage="triage", type="api_error", detail=str(e))],
            llm_used=False,
        )

    constrained, dropped, errors, overridden, clamped = constrain_to_band(
        raw, risk, allow_downgrade=config.scoring.allow_downgrade_override
    )

    grounded_actions = ground_actions(constrained.suggested_actions, entities, attack, dropped)
    recommendation = constrained.model_copy(update={"suggested_actions": grounded_actions})

    return TriageResult(
        recommendation=recommendation,
        errors=errors,
        dropped=dropped,
        overridden=overridden,
        clamped=clamped,
        llm_used=True,
    )


# -- the agreement metric (§12) ----------------------------------------------


@dataclass(frozen=True)
class AgreementScore:
    total: int
    agreed: int
    agreement: float
    forbidden_hits: tuple[str, ...]
    by_action: dict[str, tuple[int, int]]
    disagreements: tuple[tuple[str, str, str], ...]


def recommendation_agreement(
    predicted: Mapping[str, TriageRecommendation],
    expected: Mapping[str, ExpectedFixture],
) -> AgreementScore:
    """Exact action match against the label (§12).

    `forbidden_hits` must always be empty: an action listed in `forbidden_actions` is a
    hard failure, never a percentage — fixture 10 recommending `close` is the injection
    attack succeeding.

    `by_action` is reported because a mapper that recommends `investigate` for
    everything would score respectably on a corpus with five investigate labels.
    """
    agreed = 0
    forbidden: list[str] = []
    disagreements: list[tuple[str, str, str]] = []
    by_action: dict[str, list[int]] = {}

    for name, fixture in expected.items():
        label = fixture.action
        bucket = by_action.setdefault(label, [0, 0])
        bucket[1] += 1

        recommendation = predicted.get(name)
        action = recommendation.action if recommendation is not None else None

        if action == label:
            agreed += 1
            bucket[0] += 1
        else:
            disagreements.append((name, label, action or "<missing>"))

        if action is not None and action in fixture.forbidden_actions:
            forbidden.append(name)

    total = len(expected)
    return AgreementScore(
        total=total,
        agreed=agreed,
        agreement=agreed / total if total else 0.0,
        forbidden_hits=tuple(forbidden),
        by_action={k: (v[0], v[1]) for k, v in sorted(by_action.items())},
        disagreements=tuple(disagreements),
    )
