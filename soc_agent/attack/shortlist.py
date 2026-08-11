"""The deterministic candidate shortlister. Spec: attack-mapping-06-spec.md §6.

This module is the ceiling on the phase's success metric. The LLM selects from the
candidate list only (§10), so a technique that does not rank here cannot appear in the
output, whatever the model thinks. §9's ablation is why the keyword table exists:
matching against technique names and summaries alone reaches 64% shortlist recall on
the corpus, below Architecture §1.4's 70% target, before the LLM has lost anything.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from soc_agent.attack.catalog import CATEGORY_TACTICS, AttackCatalog
from soc_agent.attack.hints import hints_for_rule, keyword_table
from soc_agent.models.alert import NormalizedAlert

if TYPE_CHECKING:
    from soc_agent.config import AttackConfig

# §6.2 weights.
W_RULE_HINT = 100.0  # an operator's explicit statement; a guarantee, not a weight
W_KEYWORD = 8.0
W_NAME = 3.0
W_SUMMARY = 0.5
W_TACTIC = 4.0

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    """the a an and or of to in on for with by is are be as at from that this it its into
    over under not no using use used via can may other than when where which who""".split()
)


@dataclass(frozen=True)
class Candidate:
    technique_id: str
    score: float
    reasons: tuple[str, ...]


def tokens(text: str) -> set[str]:
    return {w for w in _TOKEN_RE.findall(text.lower()) if len(w) > 2 and w not in _STOPWORDS}


def match_surface(alert: NormalizedAlert, ti_tags: Sequence[str] = ()) -> str:
    """Title, description, vendor rule and TI tags — never entity values (§6.1).

    Tags are deliberately high-signal: a TI vendor's vocabulary for what an indicator
    *does* is far closer to ATT&CK's than a SIEM rule name is. Entity values carry no
    technique signal, and feeding attacker-controlled strings to a keyword matcher buys
    nothing but noise.
    """
    parts = [alert.title, alert.description or "", alert.vendor_rule or "", *ti_tags]
    return " ".join(parts).lower()


def shortlist(
    alert: NormalizedAlert,
    ti_tags: Sequence[str] = (),
    *,
    catalog: AttackCatalog,
    cfg: AttackConfig,
) -> list[Candidate]:
    surface = match_surface(alert, ti_tags)
    query = tokens(surface)
    wanted_tactic = CATEGORY_TACTICS.get(alert.category or "")

    scores: dict[str, float] = {}
    reasons: dict[str, list[str]] = {}

    def add(technique_id: str, points: float, reason: str) -> None:
        if technique_id not in catalog:
            return
        scores[technique_id] = scores.get(technique_id, 0.0) + points
        reasons.setdefault(technique_id, []).append(reason)

    for technique_id in hints_for_rule(alert.vendor_rule, cfg.rule_hints, catalog):
        add(technique_id, W_RULE_HINT, "rule_hint")

    for technique_id, phrases in keyword_table(cfg.keywords, catalog):
        for phrase in phrases:
            if phrase in surface:
                add(technique_id, W_KEYWORD, f"keyword:{phrase}")

    for technique_id, technique in catalog.techniques.items():
        name_hits = len(query & tokens(technique.name))
        if name_hits:
            add(technique_id, W_NAME * name_hits, "name")
        summary_hits = len(query & tokens(technique.summary))
        if summary_hits:
            add(technique_id, W_SUMMARY * summary_hits, "summary")

    # The tactic bonus biases the ranking; it never admits a technique that scored
    # nothing on another signal, or all 697 would become candidates.
    if wanted_tactic:
        for technique_id in list(scores):
            if wanted_tactic in catalog.techniques[technique_id].tactics:
                add(technique_id, W_TACTIC, "tactic")

    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return [
        Candidate(technique_id=tid, score=round(score, 3), reasons=tuple(reasons[tid]))
        for tid, score in ranked[: cfg.candidate_top_k]
    ]
