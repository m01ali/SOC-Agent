"""The §5 band table — closing spec 05 §16.3. Spec: triage-briefing-07-spec.md §17.2.

Printed by `make bands`. Every number here was measured against the real TI seed and
the real history store before the threshold change was made.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from soc_agent.config import HistoryConfig, ScoringBands, ScoringConfig, ThreatIntelConfig
from soc_agent.models import Entity, ExpectedFixture
from soc_agent.providers.history import correlate
from soc_agent.providers.ti import enrich_ti_sync
from soc_agent.scoring import band_for, score_risk
from tests.unit.test_attack_shortlist import FIXTURES_DIR, STEMS, load_alert

ENTITIES_DIR = Path(__file__).parents[1] / "data" / "entities"

# §5 — the measured table. score, then the band under each threshold.
EXPECTED_SCORES = {
    "01_c2_beacon": (84, "escalate"),
    "02_phishing": (90, "escalate"),
    "03_brute_force": (36, "investigate"),
    "04_malware_hash_fp": (21, "close"),
    "05_lateral_movement": (42, "investigate"),
    "06_impossible_travel": (62, "investigate"),
    "07_dns_newdomain": (55, "investigate"),
    "08_portscan_noisy": (16, "close"),
    "09_exfil_volume": (77, "escalate"),
    "10_injection": (67, "investigate"),
}

CURRENT = ScoringConfig()
OLD_THRESHOLD = ScoringConfig(bands=ScoringBands(escalate=70, investigate=40))


def load_entities(stem: str) -> list[Entity]:
    return [
        Entity.model_validate(e) for e in json.loads((ENTITIES_DIR / f"{stem}.json").read_text())
    ]


def load_expected(stem: str) -> ExpectedFixture:
    return ExpectedFixture.model_validate(
        yaml.safe_load((FIXTURES_DIR / f"{stem}.expected.yaml").read_text())
    )


@pytest.fixture(scope="module")
def assessments(request):
    """One RiskAssessment per fixture, from the real TI seed and history store."""
    from soc_agent.providers.history.seed import build_seeded_db
    from soc_agent.providers.history.sqlite import SqliteHistoryStore

    tmp = request.config._tmp_path_factory.mktemp("bands")
    db = tmp / "history.db"
    build_seeded_db(str(db))
    store = SqliteHistoryStore(str(db))
    ti_cfg = ThreatIntelConfig(simulate_latency=False)
    try:
        out = {}
        for stem in STEMS:
            alert, entities = load_alert(stem), load_entities(stem)
            ti = enrich_ti_sync(entities, config=ti_cfg)
            related = correlate(alert, entities, store=store, config=HistoryConfig()).block
            out[stem] = score_risk(alert, ti.block, related, config=CURRENT)
        return out
    finally:
        store.close()


@pytest.mark.parametrize("stem", STEMS)
def test_scores_match_the_measured_table(stem, assessments):
    score, band = EXPECTED_SCORES[stem]
    assert assessments[stem].score == score
    assert assessments[stem].band == band


def test_band_agreement_is_total(assessments, capsys):
    """§5: 10/10 at investigate=35. The phase's central claim."""
    rows, agreed = [], 0
    for stem in STEMS:
        assessment = assessments[stem]
        label = load_expected(stem).action
        hit = assessment.band == label
        agreed += hit
        rows.append((stem, assessment, label, hit))

    with capsys.disabled():
        header = f"{'fixture':<22}{'sev':>4}{'ti':>4}{'hist':>5}{'score':>7}"
        print(f"\n{header}  {'band':<12}{'label':<12}")
        for stem, a, label, hit in rows:
            c = a.components
            print(
                f"{stem:<22}{c.severity:>4}{c.ti:>4}{c.history:>5}{a.score:>7}  "
                f"{a.band:<12}{label:<12}{'OK' if hit else 'MISS'}"
            )
        print(f"{'BAND AGREEMENT':<22}{agreed}/{len(STEMS)} = {agreed / len(STEMS):.0%}\n")

    assert agreed == len(STEMS) == 10


def test_old_threshold_misses_exactly_fixture_03(assessments):
    """The regression that documents why the threshold is 35 (§5).

    At investigate=40 agreement is 9/10 and the single miss is fixture 03 — labeled
    `investigate`, scoring 36, with its TI component 0 by label, its history component
    already at the structural maximum of 85, and its severity frozen by spec 03's
    Splunk mapping. 36 is the ceiling, which is why the fix had to be the threshold.
    """
    misses = [
        stem
        for stem in STEMS
        if band_for(assessments[stem].score, OLD_THRESHOLD) != load_expected(stem).action
    ]
    assert misses == ["03_brute_force"]


def test_fixture_03_is_the_only_alert_in_the_changed_range(assessments):
    """The check that makes the change side-effect-free: nothing else lives in [35, 40)."""
    in_range = [stem for stem in STEMS if 35 <= assessments[stem].score < 40]
    assert in_range == ["03_brute_force"]


def test_fixture_03_margin_is_the_thinnest_in_the_corpus(assessments):
    """§5.1 — it moved from 3.75 below the old line to 1.25 above the new one.

    Still the corpus's most fragile band assignment. Spec 09 should treat it as a known
    weak point when it adds unseen alerts, not as a solved problem.
    """

    def margin(stem: str) -> float:
        score = assessments[stem].score
        return min(abs(score - CURRENT.bands.investigate), abs(score - CURRENT.bands.escalate))

    margins = {stem: margin(stem) for stem in STEMS}
    assert min(margins, key=margins.get) == "03_brute_force"
    assert margins["03_brute_force"] == 1


def test_fixture_05_components_are_structurally_maxed(assessments):
    """§5.1 / spec 05 §16.2 — the re-weighting tripwire.

    Fixture 05 has no external IOCs (ti is structurally 0) and its history component is
    already at the 85 maximum, so it has no headroom anywhere. If spec 09 or a later
    tuning pass lowers the history weight, this is what breaks first.
    """
    components = assessments["05_lateral_movement"].components
    assert components.ti == 0
    assert components.history == 85
    assert assessments["05_lateral_movement"].band == "investigate"


def test_close_band_fixtures_have_exculpatory_evidence(assessments):
    """§5.1's justification for a 35-point floor: closing needs positive evidence of
    benignity, not merely absent threat intel. Both close-band fixtures have some."""
    # 04: a TI-clean hash. 08: a 95%-FP rule.
    assert assessments["04_malware_hash_fp"].components.history == 25
    assert assessments["08_portscan_noisy"].components.history == 35
    assert assessments["04_malware_hash_fp"].score < 35
    assert assessments["08_portscan_noisy"].score < 35
