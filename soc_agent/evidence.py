"""The shared evidence bundle. Spec: triage-briefing-07-spec.md §14.1.

Moved here from `attack/select.py` (spec 06 §10.3): triage and briefing need the same
rendering, and importing it from the ATT&CK package would point the dependency the
wrong way — they do not depend on ATT&CK mapping, they depend on the evidence all three
share.

CACHE CONTRACT: the rendered text is hashed into the LLM cache key (spec 03 §11.2). The
`attack` and `risk` sections are appended ONLY when non-empty, so the bundle
`map_attack` renders is byte-identical to what spec 06 recorded and its ten committed
cache entries keep replaying. tests/unit/test_evidence.py pins that.
"""

from __future__ import annotations

from collections.abc import Sequence

from soc_agent.models import (
    AttackMapping,
    Entity,
    RelatedAlertsBlock,
    RiskAssessment,
    ThreatIntelBlock,
)
from soc_agent.models.alert import NormalizedAlert

MAX_RELATED_IN_BUNDLE = 3
MAX_ATTACK_IN_BUNDLE = 5


def build_evidence_bundle(
    alert: NormalizedAlert,
    entities: Sequence[Entity],
    threat_intel: ThreatIntelBlock | None,
    related: RelatedAlertsBlock | None,
    attack: Sequence[AttackMapping] = (),
    *,
    max_chars: int = 4000,
) -> str:
    """A fixed-order rendering of what specs 03-06 established (spec 06 §10.3).

    Fixed order matters twice: the cache key hashes the rendered messages, and the
    briefing cites the same facts the triage node saw. Everything here is already in
    the output envelope — the bundle introduces nothing the analyst cannot see.
    """
    lines: list[str] = [f"title: {alert.title}"]
    if alert.category:
        lines.append(f"category: {alert.category}")
    lines.append(f"severity: {alert.severity}")
    if alert.vendor_rule:
        lines.append(f"rule: {alert.vendor_rule}")
    if alert.description:
        lines.append(f"description: {alert.description}")

    if entities:
        lines.append("entities:")
        for entity in entities:
            marker = " (internal)" if entity.is_internal else ""
            lines.append(f"  - {entity.type} {entity.value} [{entity.role}]{marker}")

    if threat_intel and threat_intel.results:
        lines.append("threat_intel:")
        for result in threat_intel.results:
            tags = f" tags={','.join(result.tags)}" if result.tags else ""
            lines.append(
                f"  - {result.entity.value}: {result.verdict} (score {result.score}){tags}"
            )

    if related and related.count:
        lines.append(
            f"related_alerts: {related.count} in window, "
            f"{related.prior_true_positives} prior true positive(s), "
            f"{related.prior_false_positives} prior false positive(s)"
        )
        if related.rule_fp_rate is not None:
            lines.append(
                f"  rule false-positive rate: {related.rule_fp_rate:.2f} "
                f"over {related.rule_fired_count} firings"
            )
        for item in related.alerts[:MAX_RELATED_IN_BUNDLE]:
            lines.append(f"  - {item.title} [{item.disposition}] ({item.relation_reason})")

    # Appended only when non-empty — see the cache contract in the module docstring.
    if attack:
        lines.append("mitre_attack:")
        for mapping in list(attack)[:MAX_ATTACK_IN_BUNDLE]:
            lines.append(
                f"  - {mapping.technique_id} {mapping.technique_name} "
                f"[{mapping.tactic}] ({mapping.confidence})"
            )
            for citation in mapping.evidence:
                lines.append(f"      evidence: {citation}")

    return "\n".join(lines)[:max_chars]


def render_risk_block(risk: RiskAssessment) -> str:
    """The pipeline's own computation, rendered OUTSIDE <alert_data> (§7.2).

    The model must be able to tell a pipeline-computed fact from attacker-influenced
    text to reason about an override at all — so "the risk assessment says escalate"
    cannot be forged by the alert body.
    """
    components = risk.components
    weights = risk.weights
    return (
        f'score {risk.score} -> band "{risk.band}"\n'
        f"components: ti {components.ti}, severity {components.severity}, "
        f"history {components.history}\n"
        f"weights:    ti {weights.ti}, severity {weights.severity}, "
        f"history {weights.history}"
    )
