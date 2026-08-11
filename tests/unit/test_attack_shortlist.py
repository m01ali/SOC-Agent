"""The shortlister — the ceiling on the phase. Spec: attack-mapping-06-spec.md §19.2.

The LLM selects from the candidate list only, so a technique that does not rank here
cannot appear in the output. Shortlist recall is therefore a hard upper bound on
Architecture §1.4's ">= 70% in top 3", and it is deterministic: measurable for zero
tokens, before a prompt exists.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from soc_agent.attack.catalog import load_catalog
from soc_agent.attack.hints import keyword_table, rule_hints
from soc_agent.attack.shortlist import (
    W_KEYWORD,
    W_NAME,
    W_RULE_HINT,
    W_SUMMARY,
    Candidate,
    shortlist,
)
from soc_agent.config import AttackConfig, ConfigError
from soc_agent.models.alert import NormalizationInfo, NormalizedAlert

REPO = Path(__file__).parents[2]
FIXTURES_DIR = REPO / "fixtures" / "alerts"
NORMALIZED_DIR = REPO / "tests" / "data" / "normalized"
CATALOG_PATH = str(REPO / "data" / "attack_catalog.json")

STEMS = [
    "01_c2_beacon",
    "02_phishing",
    "03_brute_force",
    "04_malware_hash_fp",
    "05_lateral_movement",
    "06_impossible_travel",
    "07_dns_newdomain",
    "08_portscan_noisy",
    "09_exfil_volume",
    "10_injection",
]

# The TI tags spec 05's seed returns for each fixture's IOCs (§6.1 match surface).
FIXTURE_TI_TAGS = {
    "01_c2_beacon": ["c2", "cobalt-strike"],
    "02_phishing": [
        "phishing",
        "credential-harvesting",
        "newly-registered",
        "maldoc",
        "xlsm-macro",
    ],
    "03_brute_force": [],
    "04_malware_hash_fp": ["sysinternals", "admin-tool"],
    "05_lateral_movement": [],
    "06_impossible_travel": ["vpn", "anonymizer"],
    "07_dns_newdomain": ["newly-registered", "dga-like"],
    "08_portscan_noisy": [],
    "09_exfil_volume": ["exfil", "file-sharing-abuse"],
    "10_injection": ["suspicious-tls", "recent-c2-adjacent"],
}


@pytest.fixture(scope="module")
def catalog():
    return load_catalog(CATALOG_PATH)


@pytest.fixture(scope="module")
def cfg():
    return AttackConfig()


def load_alert(stem: str) -> NormalizedAlert:
    return NormalizedAlert.model_validate(json.loads((NORMALIZED_DIR / f"{stem}.json").read_text()))


def load_labels(stem: str) -> list[str]:
    payload = yaml.safe_load((FIXTURES_DIR / f"{stem}.expected.yaml").read_text())
    return payload.get("techniques") or []


def ids_for(stem: str, catalog, cfg) -> list[str]:
    candidates = shortlist(load_alert(stem), FIXTURE_TI_TAGS[stem], catalog=catalog, cfg=cfg)
    return [c.technique_id for c in candidates]


def make_alert(**overrides) -> NormalizedAlert:
    defaults = dict(
        alert_id="TEST-1",
        dedupe_key="a" * 64,
        source_system="generic",
        title="test alert",
        severity=50,
        ingested_at="2026-07-20T12:00:00Z",
        raw={},
        normalization=NormalizationInfo(method="parser", confidence=1.0),
    )
    return NormalizedAlert(**{**defaults, **overrides})


# -- the ceiling -------------------------------------------------------------


def test_shortlist_recall_is_total(catalog, cfg, capsys):
    """11/11 at K=12. Printed as a table by `make attack-recall`."""
    rows, hits, total, missing = [], 0, 0, []
    for stem in STEMS:
        labels = load_labels(stem)
        if not labels:
            continue
        ids = ids_for(stem, catalog, cfg)
        ranks = [ids.index(t) + 1 if t in ids else None for t in labels]
        for technique_id in labels:
            if technique_id in ids:
                hits += 1
            else:
                missing.append(f"{stem}/{technique_id}")
        total += len(labels)
        rows.append((stem, labels, ranks))

    with capsys.disabled():
        print(f"\n{'fixture':<22}{'labeled':<28}ranks in shortlist")
        for stem, labels, ranks in rows:
            print(f"{stem:<22}{','.join(labels):<28}{ranks}")
        print(f"{'SHORTLIST RECALL':<22}{hits}/{total} = {hits / total:.0%}\n")

    assert missing == []
    assert hits == total == 11


def test_every_label_ranks_first_or_second(catalog, cfg):
    """The deterministic ranker nearly solves the task; the LLM's job is to choose
    among 12 plausible candidates and justify the choice (§9)."""
    for stem in STEMS:
        for technique_id in load_labels(stem):
            ids = ids_for(stem, catalog, cfg)
            assert ids.index(technique_id) < 2, (
                f"{stem}/{technique_id} ranked {ids.index(technique_id) + 1}"
            )


def test_ablation_lexical_signal_alone_is_insufficient(catalog, cfg, tmp_path):
    """§9: names+summaries+category reach only 64% — below the 70% gate.

    Pinned so a refactor that makes the lexical signal look sufficient is caught: the
    keyword table would then be quietly deletable, and the phase would fail on unseen
    alerts instead of here.
    """
    empty_hints = tmp_path / "hints.yaml"
    empty_hints.write_text("version: 1\nrules: {}\n")
    empty_keywords = tmp_path / "keywords.yaml"
    empty_keywords.write_text("version: 1\nkeywords: {}\n")
    lexical_only = cfg.model_copy(
        update={"rule_hints": str(empty_hints), "keywords": str(empty_keywords)}
    )

    hits = total = 0
    for stem in STEMS:
        labels = load_labels(stem)
        ids = ids_for(stem, catalog, lexical_only)
        hits += sum(1 for t in labels if t in ids)
        total += len(labels)

    assert total == 11
    assert hits <= 7, f"lexical signal now finds {hits}/11 — re-verify §9 before relaxing this"


def test_ablation_keywords_alone_reach_total_recall(catalog, cfg, tmp_path):
    """§9: keywords without rule hints = 100%. The table is the load-bearing signal."""
    empty_hints = tmp_path / "hints.yaml"
    empty_hints.write_text("version: 1\nrules: {}\n")
    no_hints = cfg.model_copy(update={"rule_hints": str(empty_hints)})

    hits = total = 0
    for stem in STEMS:
        labels = load_labels(stem)
        ids = ids_for(stem, catalog, no_hints)
        hits += sum(1 for t in labels if t in ids)
        total += len(labels)

    assert hits == total == 11


def _recall_without(catalog, cfg, tmp_path, corpus_texts) -> tuple[int, int, list[str], list[str]]:
    """Shortlist recall with every phrase occurring in `corpus_texts` removed."""
    surviving: dict[str, list[str]] = {}
    removed: list[str] = []
    for technique_id, phrases in keyword_table(cfg.keywords, catalog):
        kept = []
        for phrase in phrases:
            if any(phrase in text for text in corpus_texts):
                removed.append(f"{technique_id}:{phrase}")
            else:
                kept.append(phrase)
        if kept:
            surviving[technique_id] = kept

    thinned = tmp_path / "keywords.yaml"
    thinned.write_text(yaml.safe_dump({"version": 1, "keywords": surviving}))
    thinned_cfg = cfg.model_copy(update={"keywords": str(thinned)})

    hits = total = 0
    misses: list[str] = []
    for stem in STEMS:
        labels = load_labels(stem)
        ids = ids_for(stem, catalog, thinned_cfg)
        for technique_id in labels:
            if technique_id in ids:
                hits += 1
            else:
                misses.append(f"{stem}/{technique_id}")
        total += len(labels)
    return hits, total, removed, misses


def test_recall_does_not_depend_on_fixture_headline_phrasing(catalog, cfg, tmp_path):
    """§8's authoring rule, as much of it as a test can actually enforce.

    The obvious test — "no keyword phrase may appear in the corpus" — is wrong. "port
    scan", "powershell" and "failed login" occur in the fixtures precisely BECAUSE the
    fixtures are realistic SOC alerts, and a table forbidden from using the terms a real
    SIEM emits would be useless.

    What *is* checkable: recall must not lean on a fixture's headline wording, which is
    the part most specific to how this corpus was written. Drop every phrase appearing
    in any fixture TITLE and require the rest to still find all 11 labels. Adding
    "impossible travel" (fixture 06's title) to the table fails here.
    """
    titles = [load_alert(stem).title.lower() for stem in STEMS]
    hits, total, _removed, misses = _recall_without(catalog, cfg, tmp_path, titles)
    assert hits == total == 11, (
        f"shortlist recall drops to {hits}/{total} once title-echoing phrases are "
        f"removed — the table is tuned to these ten alerts. Missing: {misses}"
    )


def test_documented_sensitivity_to_description_vocabulary(catalog, cfg, tmp_path, capsys):
    """A measurement, not a bar — and the caveat §9 attaches to its own 100%.

    Removing every phrase that appears anywhere in a fixture body (not just titles)
    drops recall to 9/11: fixture 01's two labels rest entirely on "https connection"
    and "ja3". Both are standard industry vocabulary — JA3 is *the* TLS fingerprint
    every NDR emits — so this is not evidence of overfitting. It is evidence that no
    mechanical test can separate "generic term that happens to appear" from "phrase
    tuned to this corpus", which is why spec 09's ten unseen alerts are the only real
    measurement of whether this table generalizes.

    Pinned so the number moves visibly rather than silently.
    """
    bodies = []
    for stem in STEMS:
        alert = load_alert(stem)
        bodies.append(alert.title.lower())
        if alert.description:
            bodies.append(alert.description.lower())

    hits, total, removed, misses = _recall_without(catalog, cfg, tmp_path, bodies)
    with capsys.disabled():
        print(
            f"\n[sensitivity] removing {len(removed)} body-echoing phrases: "
            f"recall {hits}/{total}, losing {misses}\n"
        )
    assert (hits, total) == (9, 11)
    assert misses == ["01_c2_beacon/T1071.001", "01_c2_beacon/T1573"]


# -- mechanics ---------------------------------------------------------------


def test_shortlist_is_deterministic(catalog, cfg):
    first = shortlist(load_alert("01_c2_beacon"), ["c2"], catalog=catalog, cfg=cfg)
    second = shortlist(load_alert("01_c2_beacon"), ["c2"], catalog=catalog, cfg=cfg)
    assert first == second


def test_respects_candidate_top_k(catalog, cfg):
    narrowed = cfg.model_copy(update={"candidate_top_k": 3})
    assert len(ids_for("01_c2_beacon", catalog, narrowed)) == 3


def test_ties_break_by_technique_id(catalog, cfg):
    candidates = shortlist(load_alert("04_malware_hash_fp"), [], catalog=catalog, cfg=cfg)
    for earlier, later in zip(candidates, candidates[1:], strict=False):
        if earlier.score == later.score:
            assert earlier.technique_id < later.technique_id


def test_rule_hint_outranks_everything(catalog, cfg):
    """A hinted technique is rank 1 even when the alert text argues elsewhere."""
    alert = make_alert(
        title="powershell encoded command spawned from a document",
        vendor_rule="Network - Port Scan Detected - Rule",
        category="malware",
    )
    candidates = shortlist(alert, [], catalog=catalog, cfg=cfg)
    assert candidates[0].technique_id == "T1046"
    assert "rule_hint" in candidates[0].reasons
    assert candidates[0].score >= W_RULE_HINT


def test_reasons_name_the_signals_that_fired(catalog, cfg):
    candidates = {
        c.technique_id: c
        for c in shortlist(
            load_alert("01_c2_beacon"), ["c2", "cobalt-strike"], catalog=catalog, cfg=cfg
        )
    }
    beacon = candidates["T1071.001"]
    assert any(r.startswith("keyword:") for r in beacon.reasons)
    assert "tactic" in beacon.reasons  # command_and_control -> TA0011


def test_rule_hints_fire_for_exactly_the_hinted_rules(catalog, cfg):
    hinted = set(rule_hints(cfg.rule_hints, catalog))
    for stem in STEMS:
        alert = load_alert(stem)
        candidates = shortlist(alert, FIXTURE_TI_TAGS[stem], catalog=catalog, cfg=cfg)
        fired = any("rule_hint" in c.reasons for c in candidates)
        assert fired == ((alert.vendor_rule or "").strip().lower() in hinted), stem


def test_rule_matching_is_case_insensitive(catalog, cfg):
    alert = make_alert(
        vendor_rule="ACCESS - EXCESSIVE FAILED LOGINS - RULE", category="credential_access"
    )
    candidates = shortlist(alert, [], catalog=catalog, cfg=cfg)
    assert candidates[0].technique_id == "T1110"


def test_tactic_bonus_never_admits_a_zero_scoring_technique(catalog, cfg):
    """The bonus biases the ranking; it does not make all 697 techniques candidates."""
    alert = make_alert(title="zzzz", description=None, category="command_and_control")
    for candidate in shortlist(alert, [], catalog=catalog, cfg=cfg):
        assert candidate.reasons != ("tactic",)


def test_entity_values_are_not_in_the_match_surface(catalog, cfg):
    """§6.1 — an IP carries no technique signal, and attacker-controlled strings in a
    keyword matcher buy only noise."""
    plain = make_alert(title="unusual activity", category="malware")
    with_ioc = make_alert(title="unusual activity", category="malware")
    assert shortlist(plain, [], catalog=catalog, cfg=cfg) == shortlist(
        with_ioc, [], catalog=catalog, cfg=cfg
    )


def test_ti_tags_contribute_signal(catalog, cfg):
    alert = make_alert(title="outbound connections", category="command_and_control")
    without = {c.technique_id for c in shortlist(alert, [], catalog=catalog, cfg=cfg)}
    with_tags = {c.technique_id for c in shortlist(alert, ["beacon"], catalog=catalog, cfg=cfg)}
    assert "T1071.001" in with_tags - without


def test_weights_are_ordered_as_specified():
    assert W_RULE_HINT > W_KEYWORD > W_NAME > W_SUMMARY


def test_candidate_is_hashable_and_frozen():
    candidate = Candidate(technique_id="T1071", score=1.0, reasons=("name",))
    with pytest.raises(Exception):  # noqa: B017 - dataclasses raise FrozenInstanceError
        candidate.score = 2.0  # type: ignore[misc]


# -- loader validation -------------------------------------------------------


def test_unknown_technique_in_rule_hints_is_rejected(catalog, tmp_path):
    path = tmp_path / "hints.yaml"
    path.write_text('version: 1\nrules:\n  "Some Rule": [T9999]\n')
    with pytest.raises(ConfigError, match="not in the ATT&CK catalog"):
        rule_hints(str(path), catalog)


def test_unknown_technique_in_keywords_is_rejected(catalog, tmp_path):
    path = tmp_path / "kw.yaml"
    path.write_text("version: 1\nkeywords:\n  T9999: [thing]\n")
    with pytest.raises(ConfigError, match="not in the ATT&CK catalog"):
        keyword_table(str(path), catalog)


def test_committed_tables_load_against_the_committed_catalog(catalog, cfg):
    assert rule_hints(cfg.rule_hints, catalog)
    assert keyword_table(cfg.keywords, catalog)
