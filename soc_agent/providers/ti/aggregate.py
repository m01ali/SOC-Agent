"""Multi-provider aggregation and the TI summary. Spec: enrichment-05-spec.md §7."""

from __future__ import annotations

from collections.abc import Sequence

from soc_agent.models import Entity, EntityRef, TIResult, TISummary, TIVerdict, TIVerdictLabel

# §7.2 — also drives TISummary.worst_verdict. `unknown` outranks `clean` deliberately:
# "no source has an opinion" is more concerning to an analyst than "checked and benign",
# and worst_verdict answers "what is the most alarming thing here".
VERDICT_RANK: dict[str, int] = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}


def _dedupe(values: Sequence[str]) -> list[str]:
    """Union preserving first-seen order."""
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return list(seen)


def aggregate_verdicts(entity: Entity, per_provider: Sequence[tuple[str, TIVerdict]]) -> TIResult:
    """Architecture §5.3: max score wins, verdicts unioned, all sources listed (§7.1).

    The aggregate verdict is the *max-score entry's* verdict, not the worst label
    across providers. Worst-label-wins lets a provider returning `malicious` at
    score 20 overrule one returning `clean` at 95, and produces output where a
    "malicious" verdict carries a score below the investigate band. `score` is what
    spec 07 scores on and `verdict` is what the briefing quotes; they must agree.
    """
    ref = EntityRef(type=entity.type, value=entity.value)
    if not per_provider:
        return TIResult(entity=ref, verdict="unknown", score=0)

    # Max score; ties broken by severity rank so a 0-score tie still prefers the
    # more alarming label.
    winner_name, winner = max(
        per_provider, key=lambda pair: (pair[1].score, VERDICT_RANK[pair[1].verdict])
    )

    sources: list[str] = []
    tags: list[str] = []
    firsts: list = []
    lasts: list = []
    raw: dict = {}
    for name, verdict in per_provider:
        sources.extend(verdict.sources or [name])
        tags.extend(verdict.tags)
        if verdict.first_seen is not None:
            firsts.append(verdict.first_seen)
        if verdict.last_seen is not None:
            lasts.append(verdict.last_seen)
        if verdict.raw:
            raw[name] = verdict.raw

    # An error only survives aggregation if *every* supporting provider failed —
    # one working provider means the IOC was genuinely checked.
    errors = [v.error for _, v in per_provider if v.error]
    error = "; ".join(errors) if len(errors) == len(per_provider) and errors else None

    return TIResult(
        entity=ref,
        verdict=winner.verdict,
        score=winner.score,
        sources=_dedupe(sources),
        tags=_dedupe(tags),
        first_seen=min(firsts) if firsts else None,
        last_seen=max(lasts) if lasts else None,
        summary=winner.summary,
        raw=raw,
        error=error,
    )


def summarize(results: Sequence[TIResult]) -> TISummary:
    """Counts by verdict + the worst verdict seen (§7.3).

    `worst_verdict` is None iff `iocs_checked == 0` — the spec-02 model validator
    enforces it, and fixture 05 (no external IOCs at all) is the case it exists for.
    """
    counts: dict[TIVerdictLabel, int] = {
        "malicious": 0,
        "suspicious": 0,
        "clean": 0,
        "unknown": 0,
    }
    for result in results:
        counts[result.verdict] += 1

    worst: TIVerdictLabel | None = None
    if results:
        worst = max((r.verdict for r in results), key=lambda v: VERDICT_RANK[v])

    return TISummary(iocs_checked=len(results), worst_verdict=worst, **counts)
