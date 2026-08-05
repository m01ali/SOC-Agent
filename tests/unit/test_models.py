"""Data contract tests — no API calls. Spec: data-contracts-02-spec.md §8."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from soc_agent.models import (
    AttackMapping,
    AttackSelectionItem,
    Briefing,
    EnrichmentOutput,
    Entity,
    EntityProvenance,
    EntityRef,
    NormalizationInfo,
    NormalizedAlert,
    Provenance,
    RelatedAlert,
    RelatedAlertsBlock,
    RiskAssessment,
    RiskComponents,
    RiskWeights,
    StageError,
    ThreatIntelBlock,
    TIResult,
    TISummary,
    TriageRecommendation,
)

AWARE_NOW = datetime(2026, 7, 20, 9, 0, 0, tzinfo=UTC)
NAIVE_NOW = datetime(2026, 7, 20, 9, 0, 0)


def _alert(**overrides) -> NormalizedAlert:
    fields = dict(
        alert_id="SIEM-2026-000001",
        dedupe_key="a" * 64,
        source_system="generic",
        title="Test alert",
        severity=50,
        ingested_at=AWARE_NOW,
        raw={"k": "v"},
        normalization=NormalizationInfo(method="parser", confidence=1.0),
    )
    fields.update(overrides)
    return NormalizedAlert(**fields)


def _provenance() -> Provenance:
    return Provenance(agent_version="0.1.0", started_at=AWARE_NOW)


def _entity(**overrides) -> Entity:
    fields = dict(
        type="ip",
        value="10.0.0.1",
        confidence=1.0,
        provenance=EntityProvenance(method="field_map"),
    )
    fields.update(overrides)
    return Entity(**fields)


class TestEnvelopeInvariants:
    def test_success_with_errors_rejected(self):
        with pytest.raises(ValidationError):
            EnrichmentOutput(
                status="success",
                alert=_alert(),
                errors=[StageError(stage="normalize", type="parse_error", detail="x")],
                provenance=_provenance(),
            )

    def test_failed_with_recommendation_rejected(self):
        with pytest.raises(ValidationError):
            EnrichmentOutput(
                status="failed",
                recommendation=TriageRecommendation(
                    action="escalate", priority="P2", confidence="high", rationale="x"
                ),
                provenance=_provenance(),
            )

    def test_success_without_alert_rejected(self):
        with pytest.raises(ValidationError):
            EnrichmentOutput(status="success", provenance=_provenance())

    def test_partial_requires_alert(self):
        with pytest.raises(ValidationError):
            EnrichmentOutput(status="partial", provenance=_provenance())

    def test_minimal_valid_failed_output(self):
        out = EnrichmentOutput(status="failed", provenance=_provenance())
        assert out.status == "failed"


class TestEntityValueRules:
    def test_invalid_ip_rejected(self):
        with pytest.raises(ValidationError):
            _entity(type="ip", value="999.999.999.999")

    def test_hash_sha256_wrong_length_rejected(self):
        with pytest.raises(ValidationError):
            _entity(type="hash_sha256", value="deadbeef")

    def test_hash_uppercase_lowercased(self):
        e = _entity(type="hash_sha256", value="A" * 64)
        assert e.value == "a" * 64

    def test_domain_uppercase_lowercased(self):
        e = _entity(type="domain", value="Example.COM")
        assert e.value == "example.com"

    def test_naive_datetime_rejected(self):
        with pytest.raises(ValidationError):
            _alert(occurred_at=NAIVE_NOW)

    def test_naive_ingested_at_rejected(self):
        with pytest.raises(ValidationError):
            _alert(ingested_at=NAIVE_NOW)


def test_entity_unknown_key_rejected():
    with pytest.raises(ValidationError):
        Entity.model_validate(
            {
                "type": "ip",
                "value": "10.0.0.1",
                "confidence": 1.0,
                "provenance": {"method": "field_map"},
                "bogus": "nope",
            }
        )


class TestAttackPatterns:
    def test_bad_technique_id_rejected(self):
        with pytest.raises(ValidationError):
            AttackSelectionItem(technique_id="T9999.99", confidence="high", evidence=["x"])

    def test_bad_tactic_id_rejected(self):
        with pytest.raises(ValidationError):
            AttackMapping(
                tactic_id="TA999",
                tactic="Command and Control",
                technique_id="T1071.001",
                technique_name="Web Protocols",
                confidence="high",
                evidence=["x"],
            )

    def test_valid_technique_id_accepted(self):
        item = AttackSelectionItem(technique_id="T1071.001", confidence="high", evidence=["x"])
        assert item.technique_id == "T1071.001"

    def test_empty_evidence_rejected(self):
        with pytest.raises(ValidationError):
            AttackSelectionItem(technique_id="T1071.001", confidence="high", evidence=[])


class TestTISummary:
    def test_worst_verdict_must_be_none_when_zero_checked(self):
        with pytest.raises(ValidationError):
            TISummary(iocs_checked=0, worst_verdict="malicious")

    def test_worst_verdict_required_when_checked_nonzero(self):
        with pytest.raises(ValidationError):
            TISummary(iocs_checked=1, malicious=1)

    def test_zero_checked_none_verdict_ok(self):
        summary = TISummary(iocs_checked=0)
        assert summary.worst_verdict is None


def test_full_output_round_trips():
    out = EnrichmentOutput(
        status="success",
        alert=_alert(),
        entities=[_entity()],
        threat_intel=ThreatIntelBlock(
            summary=TISummary(iocs_checked=1, malicious=1, worst_verdict="malicious"),
            results=[
                TIResult(
                    entity=EntityRef(type="ip", value="10.0.0.1"),
                    verdict="malicious",
                    score=90,
                )
            ],
        ),
        related_alerts=RelatedAlertsBlock(
            count=1,
            prior_true_positives=1,
            alerts=[
                RelatedAlert(
                    alert_id="SIEM-2026-000002",
                    occurred_at=AWARE_NOW,
                    title="prior alert",
                    severity=50,
                    disposition="true_positive",
                    relation_reason="same host",
                )
            ],
        ),
        mitre_attack=[
            AttackMapping(
                tactic_id="TA0011",
                tactic="Command and Control",
                technique_id="T1071.001",
                technique_name="Web Protocols",
                confidence="high",
                evidence=["x"],
            )
        ],
        risk=RiskAssessment(
            score=80,
            band="escalate",
            components=RiskComponents(ti=90, severity=70, history=60),
            weights=RiskWeights(ti=0.45, severity=0.30, history=0.25),
        ),
        recommendation=TriageRecommendation(
            action="escalate", priority="P2", confidence="high", rationale="x"
        ),
        briefing=Briefing(markdown="**summary**"),
        provenance=_provenance(),
    )

    round_tripped = EnrichmentOutput.model_validate_json(out.model_dump_json())
    assert round_tripped == out
