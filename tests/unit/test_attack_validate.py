"""Selection validation — the anti-hallucination bound. Spec: §19.3.

All API-free: the LLM response is stubbed, so these run in the default pytest suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from soc_agent.attack.catalog import load_catalog
from soc_agent.attack.select import (
    EVIDENCE_MAX_CHARS,
    build_evidence_bundle,
    render_candidates,
    validate_selection,
)
from soc_agent.attack.shortlist import Candidate
from soc_agent.config import AttackConfig
from soc_agent.models import AttackSelection, AttackSelectionItem, EntityRef, TIResult
from soc_agent.models.history import RelatedAlert, RelatedAlertsBlock
from soc_agent.models.ti import ThreatIntelBlock, TISummary
from tests.unit.test_attack_shortlist import load_alert, make_alert

CATALOG_PATH = str(Path(__file__).parents[2] / "data" / "attack_catalog.json")

CANDIDATES = [
    Candidate("T1071.001", 30.0, ("keyword:beacon",)),
    Candidate("T1573", 20.0, ("keyword:ja3",)),
    Candidate("T1090", 10.0, ("name",)),
]


@pytest.fixture(scope="module")
def catalog():
    return load_catalog(CATALOG_PATH)


@pytest.fixture(scope="module")
def cfg():
    return AttackConfig()


def selection(*items: tuple[str, str, list[str]]) -> AttackSelection:
    return AttackSelection(
        techniques=[
            AttackSelectionItem(technique_id=tid, confidence=conf, evidence=ev)
            for tid, conf, ev in items
        ]
    )


def test_valid_selection_is_built_from_the_catalog(catalog, cfg):
    mappings, dropped = validate_selection(
        selection(("T1071.001", "high", ["412 HTTPS connections at 60s intervals"])),
        CANDIDATES,
        catalog,
        cfg,
        "command_and_control",
    )
    assert dropped == {}
    assert len(mappings) == 1
    mapping = mappings[0]
    # Name and tactic come from the catalog, never from the model.
    assert mapping.technique_name == "Application Layer Protocol: Web Protocols"
    assert mapping.tactic_id == "TA0011"
    assert mapping.tactic == "Command and Control"
    assert mapping.confidence == "high"


def test_id_outside_the_candidate_list_is_dropped(catalog, cfg):
    """The structural control: deterministic code chose the candidates (§11.1)."""
    mappings, dropped = validate_selection(
        selection(("T1059.001", "high", ["powershell"])), CANDIDATES, catalog, cfg, "malware"
    )
    assert mappings == []
    assert dropped == {"not_in_candidates": 1}


def test_nonexistent_id_is_dropped(catalog, cfg):
    candidates = [*CANDIDATES, Candidate("T9999.999", 5.0, ("name",))]
    mappings, dropped = validate_selection(
        selection(("T9999.999", "high", ["invented"])), candidates, catalog, cfg, None
    )
    assert mappings == []
    assert dropped == {"not_in_catalog": 1}


def test_revoked_id_is_dropped(catalog, cfg):
    """T1015 exists in the STIX bundle but is revoked, so it is not in the catalog —
    the §4.1 exclusion is what makes this validation meaningful."""
    candidates = [*CANDIDATES, Candidate("T1015", 5.0, ("name",))]
    mappings, dropped = validate_selection(
        selection(("T1015", "high", ["accessibility features"])), candidates, catalog, cfg, None
    )
    assert mappings == []
    assert dropped == {"not_in_catalog": 1}


def test_duplicates_collapse(catalog, cfg):
    mappings, dropped = validate_selection(
        selection(
            ("T1071.001", "high", ["beacon"]),
            ("T1071.001", "low", ["again"]),
        ),
        CANDIDATES,
        catalog,
        cfg,
        "command_and_control",
    )
    assert len(mappings) == 1
    assert dropped == {"duplicate": 1}


def test_cap_truncates_keeping_model_order(catalog, cfg):
    capped = cfg.model_copy(update={"max_techniques": 2})
    mappings, dropped = validate_selection(
        selection(
            ("T1573", "medium", ["tls"]),
            ("T1071.001", "high", ["beacon"]),
            ("T1090", "low", ["proxy"]),
        ),
        CANDIDATES,
        catalog,
        capped,
        "command_and_control",
    )
    assert [m.technique_id for m in mappings] == ["T1573", "T1071.001"]
    assert dropped == {"over_cap": 1}


def test_empty_evidence_is_dropped(catalog, cfg):
    mappings, dropped = validate_selection(
        selection(("T1071.001", "high", ["   "])), CANDIDATES, catalog, cfg, None
    )
    assert mappings == []
    assert dropped == {"empty_evidence": 1}


def test_long_evidence_is_truncated(catalog, cfg):
    mappings, _ = validate_selection(
        selection(("T1071.001", "high", ["x" * 500])), CANDIDATES, catalog, cfg, None
    )
    assert len(mappings[0].evidence[0]) == EVIDENCE_MAX_CHARS


def test_tactic_follows_the_alert_category(catalog, cfg):
    """T1078 has four tactics; the category is what disambiguates (§5)."""
    candidates = [Candidate("T1078", 50.0, ("keyword:sign-in",))]
    mappings, _ = validate_selection(
        selection(("T1078", "medium", ["sign-ins from distant locations"])),
        candidates,
        catalog,
        cfg,
        "initial_access",
    )
    assert mappings[0].tactic_id == "TA0001"


# -- evidence bundle ---------------------------------------------------------


def ti_block() -> ThreatIntelBlock:
    return ThreatIntelBlock(
        summary=TISummary(iocs_checked=1, malicious=1, worst_verdict="malicious"),
        results=[
            TIResult(
                entity=EntityRef(type="ip", value="203.0.113.66"),
                verdict="malicious",
                score=95,
                tags=["c2", "cobalt-strike"],
            )
        ],
    )


def related_block() -> RelatedAlertsBlock:
    return RelatedAlertsBlock(
        count=2,
        prior_true_positives=1,
        shared_entity_count=2,
        rule_fp_rate=0.9,
        rule_fired_count=12,
        alerts=[
            RelatedAlert(
                alert_id="SIEM-1",
                occurred_at="2026-07-15T03:22:00Z",
                title="EDR: suspicious rundll32 network activity",
                severity=80,
                disposition="true_positive",
                shared_entities=["WS-FIN-0142"],
                relation_reason="same host WS-FIN-0142",
            )
        ],
    )


def test_evidence_bundle_contains_the_pipeline_evidence():
    alert = load_alert("01_c2_beacon")
    bundle = build_evidence_bundle(alert, [], ti_block(), related_block())
    assert alert.title in bundle
    assert "malicious" in bundle and "c2,cobalt-strike" in bundle
    assert "1 prior true positive" in bundle
    assert "rule false-positive rate: 0.90 over 12 firings" in bundle
    assert "EDR: suspicious rundll32 network activity" in bundle


def test_evidence_bundle_is_deterministic_and_capped():
    alert = load_alert("01_c2_beacon")
    first = build_evidence_bundle(alert, [], ti_block(), related_block(), max_chars=200)
    second = build_evidence_bundle(alert, [], ti_block(), related_block(), max_chars=200)
    assert first == second
    assert len(first) <= 200


def test_evidence_bundle_omits_absent_sections():
    bundle = build_evidence_bundle(make_alert(title="bare"), [], None, None)
    assert "threat_intel" not in bundle
    assert "related_alerts" not in bundle


def test_rendered_candidates_expose_ids(catalog):
    rendered = render_candidates(CANDIDATES, catalog)
    assert "1. T1071.001 — Application Layer Protocol: Web Protocols" in rendered
    assert "3. T1090" in rendered
