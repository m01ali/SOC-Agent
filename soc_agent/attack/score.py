"""ATT&CK mapping metric. Spec: attack-mapping-06-spec.md §14.

Architecture §1.4 sets "correct ATT&CK technique in agent's top 3" at >= 70%.
Spec 09's eval harness imports this rather than reimplementing it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from soc_agent.attack.catalog import AttackCatalog
from soc_agent.models import AttackMapping, ExpectedFixture

TOP_N = 3


@dataclass(frozen=True)
class AttackScore:
    fixtures_scored: int
    top3_hits: int
    top3_recall: float
    label_hits: int
    label_total: int
    label_recall: float
    family_hits: int
    hallucinated: int
    misses: tuple[str, ...] = ()


def _family(technique_id: str) -> str:
    return technique_id.split(".")[0]


def attack_top3_recall(
    predicted: Mapping[str, Sequence[AttackMapping]],
    expected: Mapping[str, ExpectedFixture],
    *,
    catalog: AttackCatalog | None = None,
) -> AttackScore:
    """Per-fixture top-3 recall, with per-label and family numbers alongside.

    Decisions, pinned because spec 09 reuses this:

    - A fixture counts as a hit if AT LEAST ONE labeled technique appears in the agent's
      first three mappings — Architecture §1.4's wording ("correct technique in the
      agent's top 3"). `label_recall` over individual IDs is stricter and reported too,
      because fixtures 01 and 02 carry two labels each.
    - Fixtures with `techniques: []` are EXCLUDED from the denominator. Fixture 04's
      empty list means "no ATT&CK requirement", not "must output nothing".
    - Exact ID match only. T1071 when T1071.001 is labeled is not a hit; it is counted
      in `family_hits` and reported. Family credit is real tuning information, but
      folding it into the headline would let a systematically vague mapper pass.
    - `hallucinated` must be 0 on every run. It is not a quality metric; it is the
      assertion that §11's validation works.
    """
    fixtures_scored = top3_hits = label_hits = label_total = family_hits = hallucinated = 0
    misses: list[str] = []

    for name, fixture in expected.items():
        mappings = list(predicted.get(name, []))

        if catalog is not None:
            hallucinated += sum(1 for m in mappings if m.technique_id not in catalog)

        if not fixture.techniques:
            continue

        fixtures_scored += 1
        label_total += len(fixture.techniques)

        all_ids = [m.technique_id for m in mappings]
        top_ids = all_ids[:TOP_N]

        if any(t in top_ids for t in fixture.techniques):
            top3_hits += 1
        else:
            misses.append(name)

        for technique_id in fixture.techniques:
            if technique_id in all_ids:
                label_hits += 1
            elif _family(technique_id) in {_family(i) for i in all_ids}:
                family_hits += 1

    return AttackScore(
        fixtures_scored=fixtures_scored,
        top3_hits=top3_hits,
        top3_recall=top3_hits / fixtures_scored if fixtures_scored else 0.0,
        label_hits=label_hits,
        label_total=label_total,
        label_recall=label_hits / label_total if label_total else 0.0,
        family_hits=family_hits,
        hallucinated=hallucinated,
        misses=tuple(misses),
    )
