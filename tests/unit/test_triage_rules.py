"""Band constraint, overrides, priority, grounding. Spec: §17.3.

All API-free: the LLM response is stubbed, so these run in the default pytest suite.
"""

from __future__ import annotations

import pytest

from soc_agent.config import AppConfig, ScoringConfig
from soc_agent.models import (
    AttackMapping,
    Entity,
    EntityProvenance,
    RiskAssessment,
    RiskComponents,
    RiskWeights,
    TriageRecommendation,
)
from soc_agent.scoring import band_for
from soc_agent.triage import (
    allowed_priorities,
    constrain_to_band,
    deterministic_recommendation,
    ground_actions,
    priority_for,
    triage,
)
from tests.unit.test_scoring import make_alert

CFG = ScoringConfig()


def risk_at(score: int) -> RiskAssessment:
    return RiskAssessment(
        score=score,
        band=band_for(score, CFG),
        components=RiskComponents(ti=score, severity=score, history=50),
        weights=RiskWeights(ti=0.45, severity=0.30, history=0.25),
    )


def recommendation(action, priority="P2", reason=None, actions=()) -> TriageRecommendation:
    return TriageRecommendation(
        action=action,
        priority=priority,
        confidence="medium",
        rationale="Because of the evidence.",
        override_reason=reason,
        suggested_actions=list(actions),
    )


def entity(etype: str, value: str) -> Entity:
    return Entity(
        type=etype, value=value, confidence=1.0, provenance=EntityProvenance(method="field_map")
    )


# -- priority (§6) -----------------------------------------------------------


@pytest.mark.parametrize(
    ("band", "score", "expected"),
    [
        ("escalate", 90, "P1"),
        ("escalate", 89, "P2"),
        ("escalate", 84, "P2"),  # Architecture Appendix B: fixture 01
        ("investigate", 60, "P2"),
        ("investigate", 59, "P3"),
        ("investigate", 36, "P3"),
        ("close", 21, "P4"),
        ("close", 0, "P4"),
    ],
)
def test_priority_table(band, score, expected):
    assert priority_for(band, score) == expected


def test_appendix_b_priority_parity():
    """Fixture 01 scores 84 -> escalate -> P2, exactly as the worked example shows."""
    assert priority_for("escalate", 84) == "P2"


def test_allowed_priorities_per_band():
    assert allowed_priorities("escalate") == ("P1", "P2")
    assert allowed_priorities("investigate") == ("P2", "P3")
    assert allowed_priorities("close") == ("P4",)


# -- band constraint (§8.1) --------------------------------------------------


def test_action_matching_the_band_is_accepted():
    risk = risk_at(84)  # escalate
    out, dropped, errors, overridden, clamped = constrain_to_band(
        recommendation("escalate", "P2"), risk
    )
    assert out.action == "escalate"
    assert dropped == {} and errors == []
    assert not overridden and not clamped


def test_a_non_override_cannot_carry_a_reason():
    risk = risk_at(84)
    out, *_ = constrain_to_band(recommendation("escalate", "P2", reason="just because"), risk)
    assert out.override_reason is None


def test_justified_single_band_override_is_accepted_and_flagged():
    risk = risk_at(62)  # investigate
    out, dropped, errors, overridden, clamped = constrain_to_band(
        recommendation("escalate", "P2", reason="beacon cadence plus prior TPs on this host"),
        risk,
    )
    assert out.action == "escalate"
    assert out.override_reason == "beacon cadence plus prior TPs on this host"
    assert overridden and not clamped
    assert dropped == {} and errors == []


def test_unjustified_override_is_clamped_to_the_band():
    risk = risk_at(62)
    out, dropped, errors, overridden, clamped = constrain_to_band(
        recommendation("escalate", "P2"), risk
    )
    assert out.action == "investigate"
    assert clamped and not overridden
    assert dropped["override_unjustified"] == 1
    assert errors[0].stage == "triage" and errors[0].type == "schema_validation"


def test_whitespace_only_reason_does_not_justify():
    risk = risk_at(62)
    out, dropped, *_ = constrain_to_band(recommendation("escalate", reason="   "), risk)
    assert out.action == "investigate"
    assert dropped["override_unjustified"] == 1


def test_two_band_jump_is_clamped_even_with_a_reason():
    """close from escalate: the most consequential move available, and out of bounds."""
    risk = risk_at(84)
    out, dropped, errors, overridden, clamped = constrain_to_band(
        recommendation("close", "P4", reason="looks benign to me"), risk
    )
    assert out.action == "escalate"
    assert out.override_reason is None
    assert clamped and not overridden
    assert dropped["override_out_of_bounds"] == 1
    assert "limited to +/-1" in errors[0].detail


def test_clamping_preserves_the_rationale_and_actions():
    """Clamping keeps what is still useful; only the action returns to the band."""
    risk = risk_at(62)
    original = recommendation("escalate", "P2", actions=["Do the thing"])
    out, *_ = constrain_to_band(original, risk)
    assert out.rationale == original.rationale
    assert out.suggested_actions == ["Do the thing"]


# -- downgrade policy (§8.2) -------------------------------------------------


def test_downgrade_allowed_by_default():
    risk = risk_at(62)  # investigate
    out, dropped, _errors, overridden, clamped = constrain_to_band(
        recommendation("close", "P4", reason="confirmed benign by the asset owner"),
        risk,
        allow_downgrade=True,
    )
    assert out.action == "close"
    assert overridden and not clamped
    assert dropped == {}


def test_downgrade_blocked_when_configured():
    risk = risk_at(62)
    out, dropped, errors, overridden, clamped = constrain_to_band(
        recommendation("close", "P4", reason="confirmed benign by the asset owner"),
        risk,
        allow_downgrade=False,
    )
    assert out.action == "investigate"
    assert clamped and not overridden
    assert dropped["downgrade_blocked"] == 1
    assert "allow_downgrade_override" in errors[0].detail


def test_upgrade_still_allowed_when_downgrades_are_blocked():
    risk = risk_at(62)
    out, _dropped, _errors, overridden, _clamped = constrain_to_band(
        recommendation("escalate", "P2", reason="TI now malicious"), risk, allow_downgrade=False
    )
    assert out.action == "escalate"
    assert overridden


# -- priority clamping (§8.3) ------------------------------------------------


def test_priority_is_derived_not_chosen():
    """§8.3 — the model's value is replaced by the §6 table, always.

    Measured during recording: free choice within the band collapsed the P3 tier to
    zero and tripled P1, which defeats the point of having tiers.
    """
    risk = risk_at(84)  # escalate at 84 -> P2 by the table
    out, dropped, errors, *_ = constrain_to_band(recommendation("escalate", "P1"), risk)
    assert out.priority == "P2"
    assert dropped["priority_normalized"] == 1
    assert errors == []  # a derivable disagreement is not a reasoning failure


def test_matching_priority_is_not_counted_as_divergence():
    risk = risk_at(84)
    out, dropped, *_ = constrain_to_band(recommendation("escalate", "P2"), risk)
    assert out.priority == "P2"
    assert "priority_normalized" not in dropped


def test_priority_is_derived_from_the_final_action():
    """After a clamp, the priority follows the band the action was reset to."""
    risk = risk_at(21)  # close
    out, dropped, *_ = constrain_to_band(recommendation("investigate", "P2"), risk)
    assert out.action == "close"
    assert out.priority == "P4"
    assert dropped["priority_normalized"] == 1


# -- suggested-action grounding (§9) -----------------------------------------


def test_ungrounded_indicator_drops_the_action():
    """An analyst may act on 'block X at egress'. A fabricated address there is a
    firewall change against an innocent host."""
    entities = [entity("ip", "203.0.113.66")]
    dropped: dict[str, int] = {}
    kept = ground_actions(
        ["Block 203.0.113.66 at egress", "Block 8.8.8.8 at egress"], entities, [], dropped
    )
    assert kept == ["Block 203.0.113.66 at egress"]
    assert dropped["ungrounded_action"] == 1


def test_host_and_user_names_in_prose_are_not_dropped():
    """§9 — they appear in forms the extractor never emits; dropping over that would
    remove the most useful advice."""
    entities = [entity("host", "WS-FIN-0142"), entity("user", "l.hassan")]
    dropped: dict[str, int] = {}
    kept = ground_actions(
        ["Isolate the WS-FIN-0142 workstation", "Review l.hassan's account activity"],
        entities,
        [],
        dropped,
    )
    assert len(kept) == 2
    assert dropped == {}


def test_technique_ids_count_as_grounded():
    dropped: dict[str, int] = {}
    mapping = AttackMapping(
        tactic_id="TA0011",
        tactic="Command and Control",
        technique_id="T1071.001",
        technique_name="X",
        confidence="high",
        evidence=["e"],
    )
    kept = ground_actions(["Hunt for T1071.001 activity"], [], [mapping], dropped)
    assert kept == ["Hunt for T1071.001 activity"]


def test_domains_and_hashes_are_grounded_too():
    entities = [entity("domain", "payroll-update.example-billing.net")]
    dropped: dict[str, int] = {}
    kept = ground_actions(
        [
            "Sinkhole payroll-update.example-billing.net",
            "Sinkhole evil-unknown.example-other.net",
        ],
        entities,
        [],
        dropped,
    )
    assert kept == ["Sinkhole payroll-update.example-billing.net"]
    assert dropped["ungrounded_action"] == 1


def test_empty_actions_are_dropped_silently():
    dropped: dict[str, int] = {}
    assert ground_actions(["", "   "], [], [], dropped) == []
    assert dropped == {}


# -- the deterministic path (§11) --------------------------------------------


def test_deterministic_recommendation_follows_the_band():
    rec = deterministic_recommendation(risk_at(84))
    assert rec.action == "escalate"
    assert rec.priority == "P2"
    assert rec.confidence == "low"
    assert "84/100" in rec.rationale
    assert len(rec.suggested_actions) >= 2


def test_deterministic_close_band_still_only_recommends():
    """Architecture §5.6: the close band never auto-closes."""
    rec = deterministic_recommendation(risk_at(16))
    assert rec.action == "close"
    assert "confirm the disposition" in " ".join(rec.suggested_actions).lower()


def test_llm_failure_degrades(monkeypatch):
    import soc_agent.triage as triage_module

    def boom(*args, **kwargs):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(triage_module, "get_llm", boom)

    result = triage(make_alert(severity=75), risk=risk_at(84), config=AppConfig())
    assert result.recommendation.action == "escalate"
    assert result.recommendation.confidence == "low"
    assert result.llm_used is False
    assert len(result.errors) == 1
    assert result.errors[0].type == "api_error"
    assert "model unavailable" in result.errors[0].detail


def test_use_llm_false_skips_the_call(monkeypatch):
    import soc_agent.triage as triage_module

    monkeypatch.setattr(
        triage_module, "get_llm", lambda *a, **k: pytest.fail("should not be called")
    )
    result = triage(make_alert(), risk=risk_at(62), use_llm=False, config=AppConfig())
    assert result.llm_used is False
    assert result.errors == []


def test_triage_end_to_end_with_a_stub(monkeypatch):
    import soc_agent.triage as triage_module

    class Stub:
        def invoke(self, messages):
            return recommendation(
                "escalate",
                "P1",
                reason="TI is malicious and the host has a prior true positive",
                actions=["Block 203.0.113.66 at egress", "Block 1.2.3.4 at egress"],
            )

    monkeypatch.setattr(triage_module, "get_llm", lambda *a, **k: Stub())

    result = triage(
        make_alert(severity=75),
        entities=[entity("ip", "203.0.113.66")],
        risk=risk_at(62),
        config=AppConfig(),
    )
    assert result.recommendation.action == "escalate"
    assert result.overridden is True
    assert result.recommendation.suggested_actions == ["Block 203.0.113.66 at egress"]
    assert result.dropped["ungrounded_action"] == 1
    assert result.llm_used is True
