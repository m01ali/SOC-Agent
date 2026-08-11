# enrichment-05-spec — Threat Intel & Historical Correlation

**Series:** spec 05 of the SOC alert-enrichment agent POC
**Parent:** [Architecture.md](Architecture.md) — implements §13 **Phase 4** (threat intel) and **Phase 5** (historical correlation), covering §5.3 and §5.4
**Requires:** [extraction-04-spec.md](extraction-04-spec.md) complete (`ioc_entities()`, the entity goldens, F1 = 1.0)
**Date:** 2026-08-11
**Status:** Ready to implement
**Token budget:** **0.** Both stages are fully deterministic — no LLM node, no prompt, no cache entry. The first phase since 01 that spends nothing.

---

## 1. Objective

Turn `list[Entity]` into the two evidence blocks that ATT&CK mapping, scoring, triage and the briefing all read:

1. **The TI provider seam** (§5) — the `ThreatIntelProvider` protocol, the aggregation policy, and the concurrency/timeout/cache machinery that a real VirusTotal or OTX adapter drops into unchanged.
2. **`MockTIProvider`** (§6) — `data/ti_seed.yaml`, response shapes mirroring VirusTotal/OTX, engineered so every fixture's labeled verdict falls out of the seed rather than out of luck.
3. **The history store seam** (§10) — the `AlertHistoryStore` protocol and a SQLite implementation with real indexes and parameterized queries.
4. **The history seed** (§14) — ~75 past alerts, generated deterministically, engineered so each fixture surfaces exactly the relations its label requires.
5. **The arithmetic** (§16) — the projected risk score for all 10 fixtures under Architecture §5.6's formula, from this phase's TI and history outputs. Nine land on their labeled band. One does not, and §16.3 hands spec 07 the exact gap.

At the end of this phase `soc-agent context <fixture>` prints a complete `ThreatIntelBlock` and `RelatedAlertsBlock` for all 10 fixtures, byte-identical on every run, with zero network calls and zero tokens.

**Out of scope:** ATT&CK mapping (spec 06), the risk score itself (spec 07 — this phase produces its inputs and projects its outputs, but implements no scorer), graph wiring (spec 08), the eval harness (spec 09). `soc_agent/nodes/enrich.py` and `nodes/correlate.py` are spec 08's thin wrappers; this phase ships the libraries they call. The `enrich` CLI stays a stub.

---

## 2. What This Phase Consumes and Produces

| From specs 02–04 (read-only) | Used for |
|---|---|
| `ioc_entities(result.entities)` | the TI lookup set — external, IOC-typed only (spec 04 §8.1) |
| `Entity.type` / `.value` / `.is_internal` | lookup dispatch and correlation keys |
| `canonical_value()` in `soc_agent/extract/merge.py` | the TI cache key and the history match key — one canonicalization, three call sites |
| `NormalizedAlert.occurred_at` / `.ingested_at` / `.vendor_rule` | the correlation window anchor and rule stats |
| `TIVerdict`, `TIResult`, `TISummary`, `ThreatIntelBlock` | the TI output contract (spec 02 §4.5) |
| `RelatedAlert`, `RuleStats`, `RelatedAlertsBlock` | the correlation output contract (spec 02 §4.6) |
| `StageError` with stages `enrich_ti` / `correlate` | degraded-mode error records |
| `tests/data/entities/*.json` | correlation input in the golden tests — no re-extraction |

| Produced here | Consumed by |
|---|---|
| `enrich_ti(entities) -> TIEnrichment` | spec 08 graph node |
| `correlate(alert, entities) -> CorrelationResult` | spec 08 graph node |
| `ThreatIntelBlock` (verdicts, scores, **tags**) | spec 06 candidate shortlisting, spec 07 `ti` component, spec 07 briefing |
| `RelatedAlertsBlock` + `RuleStats` | spec 07 `history` component (**needs `fired_count`, not just `fp_rate`** — §13.2) |
| `data/ti_seed.yaml` (committed) | specs 06–09 and every demo |
| `seed_history()` + `scripts/seed_history.py` | `make seed`, spec 09's eval harness |
| `tests/data/context/*.json` goldens | regression anchor for specs 06–09 |

**Freeze policy:** `TIEnrichment`, `CorrelationResult`, the `ThreatIntelProvider` and `AlertHistoryStore` protocols, the `relation_reason` vocabulary (§12.2) and the corpus epoch (§4) are cross-spec API. Adding a field is fine. Changing the aggregation policy (§7), the correlatable-type set (§12.1), the `fp_rate` denominator (§13.1) or the epoch requires a dated changelog entry here **and** a note in spec 07, whose band arithmetic depends on all four.

---

## 3. Module Layout & Public API

```
soc_agent/providers/
├── ti/
│   ├── __init__.py     # public: enrich_ti, enrich_ti_sync, TIEnrichment, get_providers
│   ├── base.py         # ThreatIntelProvider protocol, lookup_key(), TIProviderError
│   ├── mock.py         # MockTIProvider  (data/ti_seed.yaml)
│   ├── failing.py      # FailingTIProvider — the degraded-mode lever (§9.2)
│   ├── aggregate.py    # multi-provider merge + TISummary (§7)
│   └── cache.py        # TTL cache with an injectable clock (§8.3)
└── history/
    ├── __init__.py     # public: correlate, CorrelationResult, get_store
    ├── base.py         # AlertHistoryStore protocol, HistoryStoreError
    ├── sqlite.py       # SqliteHistoryStore — schema, indexes, queries (§11)
    └── seed.py         # seed_history() — the deterministic generator (§14)

data/ti_seed.yaml       # committed
scripts/seed_history.py # thin CLI over seed.py
```

> **Addition vs Architecture Appendix C** — Appendix C puts the seed generator in `scripts/seed_history.py` only. The generator is also test infrastructure (§21.6 builds a temp DB from it), and importing from `scripts/` is not a thing this package does, so the generator lands in `providers/history/seed.py` and the script becomes a ~30-line CLI over it. Same precedent as spec 04 promoting `nodes/extract.py` to a package.

### 3.1 Public API

```python
# soc_agent/providers/ti/__init__.py

async def enrich_ti(
    entities: Sequence[Entity],
    *,
    providers: Sequence[ThreatIntelProvider] | None = None,   # None -> config
    config: ThreatIntelConfig | None = None,
) -> TIEnrichment:
    """Look up every external IOC-typed entity concurrently and aggregate the verdicts.

    Never raises. A provider failure or timeout becomes an `unknown` verdict with
    `error` set plus a StageError (Architecture §5.3: failure is per-IOC)."""


def enrich_ti_sync(entities, **kwargs) -> TIEnrichment:
    """asyncio.run() wrapper for the CLI and for sync tests."""


@dataclass(frozen=True)
class TIEnrichment:
    block: ThreatIntelBlock
    errors: list[StageError] = field(default_factory=list)
    cache_hits: int = 0
    providers_used: list[str] = field(default_factory=list)   # -> Provenance.ti_providers
```

```python
# soc_agent/providers/history/__init__.py

def correlate(
    alert: NormalizedAlert,
    entities: Sequence[Entity],
    *,
    store: AlertHistoryStore | None = None,    # None -> config
    config: HistoryConfig | None = None,
) -> CorrelationResult:
    """Find related past alerts and rule statistics. Never raises."""


@dataclass(frozen=True)
class CorrelationResult:
    block: RelatedAlertsBlock
    rule_stats: RuleStats | None = None    # full stats for spec 07; only fp_rate + fired_count
                                           # reach the envelope (§13.2)
    errors: list[StageError] = field(default_factory=list)
    truncated: int = 0                     # matches found beyond max_related (§12.4)
    store_name: str | None = None          # -> Provenance.history_store
```

Both are frozen dataclasses, not Pydantic contracts — same precedent as spec 03's `DetectionResult` and spec 04's `ExtractionResult`. `assemble` (spec 08) lifts `.block` into the envelope and extends `errors`.

**Purity.** Neither function reads the clock for anything that reaches its output. `enrich_ti` reads a monotonic clock for cache TTL only; `correlate` reads no clock at all — its window is anchored on the alert (§4.2). Two invocations against the same seed produce byte-identical `model_dump(mode="json")`. That is what makes §21.9's goldens possible.

---

## 4. Time, Determinism and the Corpus Epoch

This is the section to read twice. Correlation is the first stage whose output depends on *when* it runs, and there are two independent ways to get it wrong.

### 4.1 The corpus epoch

```python
CORPUS_EPOCH = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)   # providers/history/seed.py
```

Every seeded alert's `occurred_at` is `CORPUS_EPOCH − offset`, never `now() − offset`.

The naive alternative — generate history relative to run time so the demo always looks fresh — is **wrong here and silently so**. The fixture corpus has fixed `occurred_at` values in 2026-07-19/20. A history seeded at today's date sits in the *future* relative to every fixture, the window filter excludes all of it, and every fixture correlates to nothing. The failure looks exactly like a working pipeline on an alert with no history.

The reverse mistake is equally available: anchoring the seed at a fixed epoch while filtering the window against `now()` makes the whole seed age out of a 30-day window on 2026-08-19 and the demo quietly stops finding relations. §4.2 is what prevents that.

`scripts/seed_history.py --epoch <iso8601>` re-anchors everything for a future corpus refresh. The epoch is written into the `meta` table (§11.1) so a DB can always report what it was built against.

### 4.2 The window anchor is the alert, never the clock

```python
anchor = alert.occurred_at or alert.ingested_at
window_start = anchor - timedelta(days=config.window_days)
# matches satisfy: window_start <= occurred_at <= anchor
```

Anchoring on the alert (not `now()`) is what keeps a fixture's correlation output constant forever. The upper bound matters as much as the lower one: an alert that happened *after* the one being triaged is not prior history, and including it would let the seed leak future TPs into a fixture's score.

### 4.3 Fixture 10 and the one unavoidable clock dependency

Fixture 10 is the only alert in the corpus with `occurred_at: null` (the free-text normalizer found no timestamp in the text). Its anchor is therefore `ingested_at`, which is wall-clock `now()` outside of tests — so its window slides forward daily and the July seed will fall out of it on 2026-08-19.

Rather than special-case the anchor, **fixture 10 is deliberately given zero seeded relations** (§14, group H). Its `related_alerts` block is empty, its history component is the neutral 50, and both are therefore time-invariant by construction. §21.8 asserts the emptiness, and the seed generator carries a comment naming fixture 10's entities (`WS-HR-0009`, `t.baros`, `203.0.113.150`, `powershell`) as reserved — a future seed addition that uses one of them re-introduces the drift.

### 4.4 Timestamp storage format

`occurred_at` is stored as `YYYY-MM-DDTHH:MM:SSZ` — fixed width, UTC, `Z` suffix. Fixed-width ISO-8601 sorts lexicographically in the same order as chronologically, so SQLite's `BETWEEN` and `ORDER BY` work on the text column with no date functions and no locale surprises. Parsing back is `datetime.fromisoformat` with `Z` → `+00:00`. Any seeded value with sub-second precision or a non-UTC offset is a bug; the seed generator truncates to whole seconds and §21.6 asserts the format with a regex.

---

## 5. The TI Provider Interface (`providers/ti/base.py`)

```python
class ThreatIntelProvider(Protocol):
    name: str

    async def lookup(self, entity: Entity) -> TIVerdict:
        """Dispatch on entity.type: ip | domain | url | hash_md5 | hash_sha1 | hash_sha256.

        Raises TIProviderError for a provider-level failure. Returning an `unknown`
        verdict means 'looked it up, nothing known' — a different thing entirely."""

    def supports(self, entity: Entity) -> bool:
        """False for types this provider cannot answer (e.g. an IP-only reputation feed)."""
```

The distinction in that docstring is the whole contract. `unknown` is a *finding* — the IOC was checked and no source knows it, which is real information for an analyst. An exception is an *outage*. Collapsing the two would make a dead provider indistinguishable from a clean environment, which is precisely the failure Architecture §1.3 ("degrade, don't die") is guarding against. §9.1 keeps them apart in the output.

`supports()` exists so a multi-provider setup does not fabricate `unknown` results from providers that were never going to have an opinion: an IP-only feed asked about a hash contributes nothing to the aggregate rather than an `unknown` that drags the summary counts.

### 5.1 Lookup keys

```python
def lookup_key(entity: Entity) -> tuple[str, str]:
    return entity.type, canonical_value(entity.type, entity.value)
```

`canonical_value` is imported from `soc_agent.extract.merge` — the same function spec 04 §10.1 dedupes with (`.compressed` for IPs, case-fold otherwise). Re-implementing it here would let the extraction dedupe key and the TI cache key drift apart, and the first symptom would be a cache that never hits on IPv6.

Only validated entity values reach this function — spec 04 §7.4 validated every deterministic candidate and §9.5 grounded every LLM one. Architecture §10.1's requirement that "arbitrary injected strings never reach a provider query" is satisfied upstream; §20 records why that is load-bearing here.

---

## 6. `MockTIProvider` and `data/ti_seed.yaml`

### 6.1 Seed file shape

```yaml
version: 1
defaults:
  sources: [mock]
entries:
  - type: ip
    value: 203.0.113.66
    verdict: malicious
    score: 95
    tags: [c2, cobalt-strike]
    first_seen: 2026-06-30T00:00:00Z
    last_seen: 2026-07-18T00:00:00Z
    summary: Flagged as Cobalt Strike C2 by 3 vendors (mock data).
    raw:
      vt:  { malicious: 3, suspicious: 1, harmless: 62, undetected: 12 }
      otx: { pulse_count: 7, adversary: "TA-EXAMPLE-04" }
```

`raw` mirrors the response shapes of VirusTotal's `last_analysis_stats` and OTX's pulse summary, so the post-POC adapters in Architecture §7.3 populate the same field with genuinely similar data and nothing downstream needs to change.

### 6.2 Verdict/score consistency — validated at load

| Verdict | Score band |
|---|---|
| `malicious` | 85–100 |
| `suspicious` | 40–70 |
| `clean` | 0–10 |
| `unknown` | 0 |

`MockTIProvider` validates every entry against this table when the seed loads, and raises `ConfigError` on a violation. A seed entry reading `verdict: clean, score: 90` would otherwise sail through — `TIVerdict` constrains the score to 0–100 and nothing more — and it would move a fixture across a band with no test failing anywhere near the cause. The bands are also what let §16 project scores from verdicts.

Entries are indexed by `lookup_key()` at load time; lookup is a dict hit, `unknown` on a miss.

### 6.3 The seeded corpus

Every entry is derived from the `notes:` line of a fixture's `*.expected.yaml`, which is the ground truth for what TI is supposed to say.

| Fixture | IOC | Type | Verdict | Score | Tags |
|---|---|---|---|---|---|
| 01 | `203.0.113.66` | ip | malicious | 95 | `c2`, `cobalt-strike` |
| 02 | `https://payroll-update.example-billing.net/login` | url | malicious | 90 | `phishing`, `credential-harvesting` |
| 02 | `payroll-update.example-billing.net` | domain | malicious | 90 | `phishing`, `newly-registered` |
| 02 | `9f86d081…0a08` | hash_sha256 | malicious | 95 | `maldoc`, `xlsm-macro` |
| 03 | `198.51.100.23` | — | *not seeded* | — | → `unknown` (0) by design |
| 04 | `4c2fa1e0…3d4e` | hash_sha256 | clean | 0 | `sysinternals`, `admin-tool` |
| 05 | — | — | *no external IOCs* | — | `iocs_checked == 0` (§7.3) |
| 06 | `198.51.100.77` | ip | suspicious | 60 | `vpn`, `anonymizer` |
| 07 | `cdn-metrics-sync.example-analytics.net` | domain | suspicious | 60 | `newly-registered`, `dga-like` |
| 08 | `198.51.100.201` | — | *not seeded* | — | → `unknown` (0) by design |
| 09 | `203.0.113.199` | ip | malicious | 90 | `exfil`, `file-sharing-abuse` |
| 09 | `transfer.example-cloudshare.net` | domain | malicious | 85 | `exfil`, `file-sharing-abuse` |
| 09 | `sftp://transfer.example-cloudshare.net/upload` | url | malicious | 85 | `exfil`, `file-sharing-abuse` |
| 10 | `203.0.113.150` | ip | suspicious | 60 | `suspicious-tls`, `recent-c2-adjacent` |

Plus ~15 decoy entries (other documentation-range IPs, `.example`/`.test` domains, random hashes) across all four verdicts, so the seed is not a lookup table with exactly one row per fixture and a "matches everything" bug would be visible.

Three numbers in that table are load-bearing and §16 explains each:

- **Fixture 09's URL is seeded explicitly.** There is no URL→host verdict inheritance. Deriving a URL's verdict from its domain is inference dressed as intelligence, and it would make provenance a lie (`sources: [mock]` for a lookup that never happened). Real feeds score URLs and domains separately; so does this one.
- **Fixture 10's IP is capped at 60.** At 70 the projected score crosses into `escalate` (§16.2) and contradicts the fixture's label. The cap is a decision, not a coincidence, and §21.2 pins it.
- **Fixtures 03 and 08 are deliberately absent from the seed.** Their labels say "unknown to mock TI", and the `unknown` path needs corpus coverage — it is the single most common verdict in a real deployment.

### 6.4 Simulated latency

Architecture §5.3 asks for a deterministic pseudo-latency on unknown IOCs so demos look realistic. It is derived from the value, never random:

```python
delay_ms = 10 + (int(sha256(value.encode()).hexdigest()[:8], 16) % 41)   # 10-50 ms
```

Gated by `threat_intel.simulate_latency` (default `true`; §21 sets it `false` except where it is the subject). It costs nothing in determinism — the output never contains a timing — and it earns its keep in §21.5, where it makes the concurrency assertion meaningful: ten IOCs at ~30 ms each take ~300 ms sequentially and ~30 ms through `asyncio.gather`.

---

## 7. Aggregation, Summary and the Two Rankings (`providers/ti/aggregate.py`)

### 7.1 Per-entity aggregation across providers

Architecture §5.3: "max score wins, verdicts unioned, all sources listed." `verdict` is a single `Literal`, so "unioned" needs a precise reading:

| Field | Policy |
|---|---|
| `score` | `max` across providers |
| `verdict` | the verdict **of the max-score entry**; ties broken by severity rank (§7.2) |
| `sources` | union, in configured provider order, deduplicated |
| `tags` | union, first-seen order preserved, deduplicated |
| `first_seen` | `min` of the non-null values |
| `last_seen` | `max` of the non-null values |
| `summary` | the max-score entry's summary |
| `raw` | `{provider_name: provider_raw}` — every provider's response preserved |
| `error` | set only if **every** provider that supports the type failed |

Binding the verdict to the max-score entry keeps the two consistent, which matters because spec 07 scores on `score` while the briefing quotes `verdict`. The alternative — worst label across providers regardless of score — lets a provider that returns `malicious` with score 20 overrule one returning `clean` with score 95, and produces output where a "malicious" verdict carries a score below the investigate band. Rejected for that reason.

### 7.2 The severity rank

```python
_VERDICT_RANK = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}
```

Used for tie-breaking in §7.1 and for `TISummary.worst_verdict`. `unknown` outranks `clean` deliberately: "no source has an opinion" is a more concerning state for an analyst than "checked and benign", and `worst_verdict` exists to answer "what is the most alarming thing here".

### 7.3 The summary and its two invariants

`TISummary` counts every looked-up entity by verdict. Two properties, both asserted (§21.3):

1. `malicious + suspicious + clean + unknown == iocs_checked`.
2. `worst_verdict is None` **iff** `iocs_checked == 0` — enforced by the spec-02 model validator, and reached in practice by exactly one fixture: **05**, which has no external IOCs at all. It is the reason that validator exists, and the reason `enrich_ti` must construct the empty-summary case explicitly instead of letting a default slip through.

---

## 8. Concurrency, Timeouts and the Cache

### 8.1 Fan-out

```python
sem = asyncio.Semaphore(config.max_concurrency)      # default 10
results = await asyncio.gather(
    *(self._lookup_one(provider, entity, sem) for entity in targets for provider in providers),
    return_exceptions=False,   # _lookup_one never raises; see §9.1
)
```

`targets = ioc_entities(entities)` — nothing else is ever looked up. Internal IPs, users, hosts, processes and file paths are excluded at the source (spec 04 §8.1), which is both the privacy control and the reason fixture 05 makes zero lookups.

The semaphore is not needed for the mock, and is present because the post-POC adapters are rate-limited; putting it in now means the real adapter is a `lookup()` implementation and nothing else.

### 8.2 Per-lookup timeout

`asyncio.wait_for(provider.lookup(entity), timeout=config.lookup_timeout_s)` — 5 s per Architecture §5.3. A timeout is per-IOC and never cancels its siblings: `gather` is over already-wrapped coroutines that resolve to a verdict either way.

### 8.3 The TTL cache (`providers/ti/cache.py`)

```python
class TTLCache:
    def __init__(self, ttl_s: int, *, clock: Callable[[], float] = time.monotonic) -> None: ...
    def get(self, key: tuple[str, str, str]) -> TIVerdict | None: ...
    def put(self, key: tuple[str, str, str], verdict: TIVerdict) -> None: ...
```

- Key is `(provider.name, *lookup_key(entity))`.
- The clock is injected so §21.4 can expire an entry without sleeping. `time.monotonic`, not `time.time` — a wall-clock jump must not expire or resurrect entries.
- **Failed lookups are never cached.** Caching a timeout for `cache_ttl_s` (default 3600) turns a one-second network blip into an hour of `unknown` verdicts on a known-bad IOC. Only a verdict with `error is None` is stored, and §21.4 pins it.
- Process-local for the POC. Architecture §5.3 notes the same call path later fronts Redis/SQLite; `TTLCache` is a class with two methods precisely so that swap is a constructor change.

---

## 9. TI Failure Policy

### 9.1 Per-IOC degradation

| Failure | Result for that IOC | Recorded |
|---|---|---|
| `asyncio.TimeoutError` | `TIVerdict(verdict="unknown", score=0, error="timeout after 5s")` | `StageError(stage="enrich_ti", type="timeout")` |
| `TIProviderError` | `unknown`, `error=<message>` | `StageError(stage="enrich_ti", type="provider_error")` |
| Any other exception | `unknown`, `error=<repr>` | `StageError(stage="enrich_ti", type="provider_error")` |
| Provider `supports()` is False | *no result from that provider* | nothing |

`_lookup_one` catches everything; `enrich_ti` cannot raise. The pipeline continues and spec 08 turns the non-empty `errors` list into `status: "partial"` — Architecture §11's "TI lookup timeout/error (per IOC) → verdict unknown for that IOC → partial + error".

The `error` field on the verdict is what keeps §5's distinction visible in the output: an analyst reading `verdict: unknown, error: null` knows the IOC was checked, and `verdict: unknown, error: "timeout after 5s"` knows it was not.

### 9.2 `FailingTIProvider` — the degradation demo

Architecture §1.4 requires a "TI provider down → partial output" demo, and §13's Phase 4 gate requires a timeout test. Rather than a failure flag threaded through `MockTIProvider`, failure is its own provider:

```python
class FailingTIProvider:
    """Always fails. Registered as 'failing' / 'timeout' for the §1.4 degradation demo."""
    name = "failing"
    def __init__(self, mode: Literal["error", "timeout"] = "error") -> None: ...
```

`threat_intel.providers: [failing]` (or `SOC_AGENT_THREAT_INTEL__PROVIDERS='["timeout"]'`) reproduces the demo with no code change and no branch inside the mock. Spec 09 drives its degraded-mode test from here.

### 9.3 The provider registry is an allowlist

```python
_PROVIDERS = {"mock": MockTIProvider, "failing": ..., "timeout": ...}
```

An unrecognized name in `threat_intel.providers` raises `ConfigError` at construction. This is the POC's `--live` guard from Architecture §7.3: there is no code path by which a config typo, or a half-finished `virustotal` entry, causes an outbound call. When real adapters land they register here behind an `enabled: false` default.

---

## 10. The History Store Interface (`providers/history/base.py`)

```python
class AlertHistoryStore(Protocol):
    name: str

    def find_related(
        self, alert: NormalizedAlert, entities: Sequence[Entity], window_days: int
    ) -> list[RelatedAlert]: ...

    # `anchor` deviates from Architecture §5.4's two-argument sketch: the window is
    # anchored on the alert, never on the clock (§4.2), so the anchor has to come in
    # with the query or rule stats would drift daily while find_related did not.
    def rule_stats(
        self, vendor_rule: str, window_days: int, *, anchor: datetime
    ) -> RuleStats: ...

    def close(self) -> None: ...
```

Synchronous, per Architecture §5.4 — the SQLite queries are sub-millisecond and `correlate` runs on the graph's parallel branch alongside `enrich_ti`, so the concurrency that matters is already there. A future SIEM-API store that needs async gets an async sibling method; forcing async on a local SQLite read now would buy nothing and complicate spec 08's node.

`find_related` raises `HistoryStoreError` for store-level problems (missing file, corrupt schema). `correlate` catches it (§15).

---

## 11. SQLite Schema and Queries (`providers/history/sqlite.py`)

### 11.1 Schema

```sql
CREATE TABLE alerts (
    alert_id     TEXT PRIMARY KEY,
    occurred_at  TEXT NOT NULL,          -- YYYY-MM-DDTHH:MM:SSZ (§4.4)
    title        TEXT NOT NULL,
    severity     INTEGER NOT NULL,
    vendor_rule  TEXT,
    category     TEXT,
    disposition  TEXT NOT NULL           -- Disposition literal (spec 02 §4.6)
);

CREATE TABLE alert_entities (
    alert_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    type     TEXT NOT NULL,
    value    TEXT NOT NULL,              -- canonical_value() form (§5.1)
    PRIMARY KEY (alert_id, type, value)
);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
-- schema_version, epoch, seed_version, generated_alerts

CREATE INDEX idx_entities_value      ON alert_entities(value);
CREATE INDEX idx_entities_type_value ON alert_entities(type, value);
CREATE INDEX idx_alerts_rule_time    ON alerts(vendor_rule, occurred_at);
CREATE INDEX idx_alerts_time         ON alerts(occurred_at);
```

Values are stored **already canonicalized** by `canonical_value()`, so the query side never needs `LOWER()` and the `idx_entities_value` index is actually usable. A query-time `LOWER(value) = ?` would degrade every correlation to a full scan — invisible at 75 rows, fatal at the SIEM-scale store this interface is meant to grow into.

### 11.2 Read-only at query time

`SqliteHistoryStore` opens the DB through a URI with `mode=ro`:

```python
sqlite3.connect(f"file:{path}?mode=ro", uri=True)
```

Correlation is a read. Opening read-write would let a bug in a query path mutate the analyst's evidence base, and `mode=ro` also turns "the file is missing" into a clean, immediate `sqlite3.OperationalError` instead of SQLite helpfully creating an empty database — which would otherwise present as "this alert has no history" for every alert, forever. That silent-empty-DB failure is the single most likely way this stage goes wrong in a real deployment, and one connection flag prevents it.

Missing file → `HistoryStoreError` → §15.

### 11.3 Queries — parameterized, always

```sql
-- shared entities
SELECT a.alert_id, a.occurred_at, a.title, a.severity, a.disposition, e.type, e.value
FROM alerts a JOIN alert_entities e ON e.alert_id = a.alert_id
WHERE e.value IN (?, ?, …)              -- one placeholder per correlatable entity
  AND a.occurred_at BETWEEN ? AND ?
ORDER BY a.occurred_at DESC, a.alert_id ASC;

-- same rule
SELECT … FROM alerts
WHERE vendor_rule = ? AND occurred_at BETWEEN ? AND ?
ORDER BY occurred_at DESC, alert_id ASC;

-- rule stats
SELECT disposition, COUNT(*) FROM alerts
WHERE vendor_rule = ? AND occurred_at BETWEEN ? AND ? GROUP BY disposition;
```

The `IN` list is built as `",".join("?" * len(values))` with the values passed as parameters — **never** interpolated. Entity values are attacker-influenced text (a phishing subject line, a process command line), and this is the one place in the pipeline where they reach a query engine. §20 and §21.7 treat it as a security control, not a style preference.

Architecture §5.4 lists "same user/host within window" as a third matching mode. It is subsumed by the shared-entity query — spec 04's field map emits `user` and `host` entities for every alert that has them — so it is implemented as the same query with a different `relation_reason` (§12.2) rather than a third round trip.

---

## 12. Matching, Reasons, Ordering and Caps

### 12.1 Correlatable types

```python
_CORRELATABLE = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "user", "host"}
```

`process` and `file_path` are excluded. `powershell` (fixture 10), `pskill.exe` (04) and `invoice_2207.xlsm` (02) are shared by construction across unrelated alerts; correlating on them produces relations with no investigative meaning and inflates the `≥3 related` bonus in spec 07's history component. Hashes stay in — a shared hash is a strong link.

Internal IPs **are** correlatable, unlike in TI. `10.20.14.88` linking fixture 01 to fixture 05's cluster is exactly the kind of link an analyst wants; the exclusion in §8.1 is about not sending internal addresses to an external service, which does not apply to a local history query.

`history.value_stoplist` (default `[]`) drops specific values from entity matching for deployments where a shared service account or a NAT egress IP dominates. It ships empty because the right list is deployment-specific, and shipping opinions about which account names are "too common" would silently change every correlation result.

Measured rather than assumed (§21.8): stopping `admin` alone does **not** change fixture 03, whose user is literally `admin` — every alert reached through that value is also reached through `BASTION-01` or `10.20.7.5`. The corpus is redundantly linked, so correlation degrades gradually under a stoplist instead of falling off a cliff. Only stopping `admin` **and** `BASTION-01` together drops it to a single entity-sharing match.

### 12.2 `relation_reason` — a fixed vocabulary

| Form | When |
|---|---|
| `shared entity <value>` | the shared entity is an IOC type (ip/domain/url/hash/email) |
| `same user <value>` | the shared entity is a `user` |
| `same host <value>` | the shared entity is a `host` |
| `same rule "<vendor_rule>"` | matched only by `vendor_rule`, no shared entity |

An alert matched several ways appears **once**. Its `relation_reason` is the highest-precedence match (IOC entity > host > user > rule) and `shared_entities` lists every shared value, sorted by the alert's own entity order so the output is stable. Merging before construction — rather than emitting one `RelatedAlert` per match — is what keeps `count` meaningful; without it, fixture 03's four related alerts would report as nine.

Reasons are asserted verbatim by §21.8: they are analyst-facing strings that appear in the briefing, and spec 07's prompt quotes them.

### 12.3 Ordering

Entity-linked matches first, then `occurred_at DESC`, then `alert_id ASC`.

Relevance outranks recency because the cap (§12.4) truncates the tail, and this is not hypothetical: fixture 08's five entity-sharing matches are the five **oldest** of the rule's forty firings. Under pure recency ordering with the default `max_related: 20`, every one of them falls off the end and the rendered list is twenty rows of "the noisy rule fired again" — the least useful twenty rows available. Determinism here is not cosmetic either; it is what makes the §21.9 goldens byte-stable.

### 12.4 The cap, and why counts are computed before it

`history.max_related` (default 20) bounds `block.alerts`. But:

```python
block.count                 = len(all_matches)          # pre-cap
block.shared_entity_count   = len(entity_matches)       # pre-cap  (§12.5)
block.prior_true_positives  = tp_count(entity_matches)  # pre-cap  (§12.5)
block.prior_false_positives = fp_count(entity_matches)  # pre-cap  (§12.5)
block.alerts                = all_matches[:max_related]
result.truncated            = max(0, len(all_matches) - max_related)
```

Computing any of these over the capped list would let a display limit change the risk score. Fixture 08 is the live proof rather than a hypothetical: its five entity-sharing matches are its five oldest, so a recency-ordered cap of 20 would hide all of them and silently drop 10 points from the history component. Counts describe the evidence; the cap describes the rendering. `count > len(alerts)` is therefore a legitimate output state, consistent with Architecture Appendix B, and `truncated` records the difference for spec 08's provenance.

### 12.5 Entity matches and rule matches are counted separately

A rule-only match is *context* — "this rule has fired before" — not evidence about this alert's entities. The two are counted apart:

| Field | Counts |
|---|---|
| `count` | every match, entity-linked or rule-only |
| `shared_entity_count` | matches sharing at least one entity |
| `prior_true_positives` / `prior_false_positives` | **entity-sharing matches only** |

Two things force this, both found by running the corpus:

- **Architecture §5.6 awards +25 for a related true positive that *shares an entity*.** Fixture 04 matches its noisy rule 12 times, one of which is a true positive on an unrelated host. Counting rule-only matches in `prior_true_positives` would award +25 on the strength of "this rule was right once, about something else", pushing fixture 04 from history 25 to 50.
- **Double-counting.** A noisy rule's false positives would otherwise land in `prior_false_positives` *and* drive the −25 deduction through `rule_fp_rate` — the same evidence, priced twice.

`shared_entity_count` is what spec 07's "+10 if ≥3 related alerts share entities" reads. `count` would over-award it: fixture 08 has 40 matches but only 5 entity-sharing ones, and fixture 04 has 12 but only 1.

---

## 13. Rule Statistics

### 13.1 The `fp_rate` denominator

```python
dispositioned = true_positives + false_positives
fp_rate = false_positives / dispositioned if dispositioned else None
```

Only `true_positive` and `false_positive` count. `open`, `benign` and `undetermined` are excluded from the denominator: an analyst who has not closed an alert has not said the rule was wrong, and counting those as non-FPs would understate a genuinely noisy rule exactly when the queue is backed up — the moment the deduction matters most.

**`fp_rate` is `None`, not `0.0`, when nothing is dispositioned.** `0.0` reads as "this rule has never false-positived", a claim unsupported by zero evidence, and it would flow into the envelope as a fact. `RelatedAlertsBlock.rule_fp_rate` is already `float | None` in the spec-02 contract; this is the case it was typed for. Six of ten fixtures land here (§16.1), because four have no `vendor_rule` at all and two carry rules with no seeded history.

### 13.2 Spec 07 needs `fired_count`, so the envelope carries it

Architecture §5.6's history rule is: `−25 if rule_fp_rate ≥ 0.8 with ≥10 firings`. The firing count is a *precondition of a 25-point deduction*, and the envelope currently exposes only `rule_fp_rate` — so an analyst reading the output would see a score dragged down with no visible justification for the threshold being met. That contradicts Architecture §1.3 ("every claim is traceable").

`CorrelationResult.rule_stats` carries the full `RuleStats` for spec 07, and §18.1 adds `rule_fired_count: int | None` to `RelatedAlertsBlock` so the number reaches the output alongside the rate.

`RuleStats.fp_rate` is a plain `float` in the frozen spec-02 contract, so the "no evidence" state cannot be stored on it. `fp_rate_or_none(stats)` in `sqlite.py` recovers it for the envelope; `RuleStats` itself always carries a number.

---

## 14. The History Seed (`providers/history/seed.py`)

### 14.1 Generation

```python
def seed_history(conn: sqlite3.Connection, *, epoch: datetime = CORPUS_EPOCH) -> SeedSummary:
    """Create the schema and insert the corpus. Deterministic: same epoch -> same rows."""
```

`random.Random(20260720)` for the filler group only; every fixture-serving alert is a literal in a table, not a generated one. No `datetime.now()`, no `uuid4()`, no dict iteration order dependence. Re-running against a fresh connection produces identical rows in identical order — §21.6 asserts it by comparing full table dumps from two independent builds.

`data/history.db` stays gitignored (it already is). Tests never touch it; they build a temp DB from `seed_history()` directly, so the demo DB and the test DB can never diverge.

### 14.2 The groups

Each group exists to produce one fixture's labeled history component. The counts are not decorative — §16 shows the arithmetic that fixes each one.

| Group | Alerts | Serves | Composition | Resulting history component |
|---|---|---|---|---|
| **A** | 3 | 01, 05 | A1 `SIEM-2026-017901` TP (`WS-FIN-0142`) · A2 benign (`l.hassan`, `10.20.14.88`) · A3 undetermined (`FS-CORP-03`, `10.20.30.12`) | 01 → **75**, 05 → **85** |
| **B** | 4 | 02 | 3 × TP + 1 × FP, all sharing `j.okafor` | **85** |
| **C** | 4 | 03 | 2 × TP + 1 × FP + 1 × undetermined across `BASTION-01` / `admin` | **85** |
| **D** | 12 | 04 | rule *Hash matched local blocklist*: 11 FP + 1 TP; exactly one (FP) shares `WS-ENG-0231` | **25** (50 − 25) |
| **E** | 2 | 06 | benign + undetermined on `sso-gateway` / `m.silva`, **no TP, ≤ 2 by design** | **50** |
| **F** | 40 | 08 | rule *Network - Port Scan Detected - Rule*: 38 FP + 2 TP; 5 FPs share `10.20.0.15` | **35** (50 + 10 − 25) |
| **G** | 1 | 09 | benign on `SRV-DB-02` / `svc_backup` | **50** |
| **H** | 0 | 10 | **none, deliberately** (§4.3) | **50** |
| **J** | 1 | 07 | undetermined on `WS-MKT-0077` / `s.novak` | **50** |
| **I** | 8 | — | unrelated filler: other hosts, users and rules, mixed dispositions | — |
| | **75** | | | |

**Group A is the subtle one.** Fixture 01 and fixture 05 share `WS-FIN-0142`, `l.hassan` and `10.20.14.88`, so any alert touching those relates to both. But fixture 01 needs exactly **2** relations (→ 75, reproducing Architecture Appendix B's worked example, which shows `count: 2` and a single prior TP) while fixture 05 needs **3** (→ 85, the only value that puts it over the `investigate` line — §16.2). The split is achieved by giving A3 only fixture 05's *unshared* entities, `FS-CORP-03` and `10.20.30.12`. A1 is seeded with Appendix B's exact `alert_id`, timestamp, title, severity and disposition, so fixture 01's output reproduces the Architecture document verbatim.

**Group F is why the store holds ~75 rows, not the ~50 Architecture §7.2 estimates.** Fixture 08's label requires a rule with "40+ firings" at 95% FP, and `rule_stats` computes from rows rather than a summary table — a fudged aggregate would make the rule-stats query untested on the one fixture that exercises it. 40 rows of one noisy rule is also exactly what a noisy rule looks like in a real SIEM, and it gives §21.8 a genuine truncation case against the default `max_related: 20`.

**Group D's single TP must share nothing with fixture 04.** If it did, fixture 04 would gain the +25 "related TP shares an entity" bonus, land at 50 − 25 + 25 = 50, and drift toward the wrong band. §21.6 asserts the entity-disjointness directly rather than trusting the table.

### 14.3 Hygiene

Architecture §7.1 and §10.3 are binding on the seed as much as on the fixtures: external IPs from `203.0.113.0/24` / `198.51.100.0/24` only, internal from `10.0.0.0/8`, domains under `.example`-style invented names or `.test`, hashes random hex. No real IOCs, no real hostnames, no credentials. §21.6 asserts it mechanically over every seeded value.

---

## 15. Correlation Failure Policy

| Failure | Behavior | Recorded |
|---|---|---|
| DB file missing / unreadable | empty `RelatedAlertsBlock(count=0)`, `rule_stats=None` | `StageError(stage="correlate", type="provider_error")` |
| Schema mismatch (`meta.schema_version`) | as above, detail names expected vs found | same |
| `sqlite3.OperationalError` mid-query | as above | same |
| Alert has no `vendor_rule` | correlation proceeds; `rule_fp_rate=None` | nothing — not an error |
| No matches within window | `count=0`, empty `alerts` | nothing — a legitimate finding |

`correlate` never raises. Architecture §11: "History store down → empty correlation → `partial` + error". The last two rows matter as much as the first three: an alert with no history is the normal case for a new environment and must not manufacture an error, or every run in a fresh deployment reports `partial`.

---

## 16. The Enrichment Projection — What This Phase Hands Spec 07

Spec 07 implements Architecture §5.6's scorer. This phase produces both of its non-severity inputs, so the seed is only correct if the resulting score lands on each fixture's labeled band. The arithmetic is here, in the phase that controls the numbers, rather than discovered in spec 07 when changing them is expensive.

```
ti      = max TI score across looked-up IOCs (0 if none)
history = 50  +25 if any related TP shares an entity
              +10 if ≥3 related alerts share an entity      (rule-only matches excluded)
              −25 if rule_fp_rate ≥ 0.8 and fired_count ≥ 10
              clamped 0-100  →  max attainable is 85
risk    = 0.45·ti + 0.30·severity + 0.25·history
band:   ≥70 escalate · 40-69 investigate · <40 close
```

One semantic decision this phase makes on spec 07's behalf, because the seed depends on it: **the `+10` counts related alerts that share an *entity*; rule-only matches do not count** — the `shared_entity_count` column below, not `count`. Otherwise fixture 04's 12 same-rule matches would grant +10 on evidence that says only "this noisy rule fired again", double-counting the very thing the −25 penalizes (§12.5).

### 16.1 The table

Every row is asserted by `tests/unit/test_enrichment_inputs.py` (§21.10), so the table and the code cannot drift apart.

| # | sev | TI verdict (score) | count | shared | prior TP | rule fp_rate (fired) | history | **risk** | **band** | label | ✓ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 01 | 75 | malicious (95) | 2 | 2 | 1 | — (—) | 75 | **84.00** | escalate | escalate | ✅ |
| 02 | 85 | malicious (95) | 4 | 4 | 3 | — (—) | 85 | **89.50** | escalate | escalate | ✅ |
| 03 | 50 | unknown (0) | 4 | 4 | 2 | 0.50 (3) | 85 | **36.25** | close | investigate | ❌ |
| 04 | 50 | clean (0) | 12 | 1 | 0 | 0.92 (12) | 25 | **21.25** | close | close | ✅ |
| 05 | 70 | — (no IOCs) | 3 | 3 | 1 | — (0) | 85 | **42.25** | investigate | investigate | ✅ |
| 06 | 75 | suspicious (60) | 2 | 2 | 0 | — (0) | 50 | **62.00** | investigate | investigate | ✅ |
| 07 | 50 | suspicious (60) | 1 | 1 | 0 | — (—) | 50 | **54.50** | investigate | investigate | ✅ |
| 08 | 25 | unknown (0) | 40 | 5 | 0 | 0.95 (40) | 35 | **16.25** | close | close | ✅ |
| 09 | 80 | malicious (90) | 1 | 1 | 0 | — (0) | 50 | **77.00** | escalate | escalate | ✅ |
| 10 | 90 | suspicious (60) | 0 | 0 | 0 | — (—) | 50 | **66.50** | investigate | investigate | ✅ |

`rule fp_rate` of `—` means `None`: `(—)` in the fired column is an alert with no `vendor_rule` at all (01, 02, 07, 10), `(0)` is a rule with no seeded firings in the window (05, 06, 09). Both are honest "no evidence" states, and §13.1 is why neither reports `0.0`.

### 16.2 Three margins that are thinner than they look

- **Fixture 05 clears `investigate` by 2.25 points**, and only because group A3 supplies its third shared-entity relation. Its history component is already at the structural maximum of 85 and its TI component is structurally 0 (no external IOCs), so there is no headroom anywhere: if spec 07 lowers the history weight or drops the `+10`, fixture 05 is the first thing that breaks. It is the corpus tripwire and §21.10 pins its relation count at exactly 3.
- **Fixture 10 sits 3.5 points below `escalate`**, which is why §6.3 caps `203.0.113.150` at score 60. At 70 it reads 71.0 and escalates, contradicting its label. The fixture's severity is 90 — the free-text normalizer's reading of genuinely alarming prose — so almost all of its budget is already spent.
- **Fixture 01 lands on exactly 84.00**, matching Architecture Appendix B's stated components (ti 95 / severity 75 / history 75). Appendix B prints `"score": 86` for those same components, which is a two-point arithmetic slip in the document; 84 is what the stated formula yields. Flagged rather than reverse-engineered — no seed value should be bent to reproduce a typo.

### 16.3 The one gap: fixture 03

Fixture 03 is labeled `investigate` and projects to **36.25**, short of the 40 threshold by **3.75 points**. This is not fixable from inside spec 05:

- Its TI component is 0 by label ("Source IP unknown to mock TI — lands mid-band by design"), and seeding it a verdict would contradict the fixture and delete the corpus's only `unknown`-with-history case.
- Its history component is already **85, the structural maximum** (group C supplies 4 relations and 2 prior TPs).
- Its severity is 50, fixed by spec 03's frozen Splunk `urgency: medium` mapping.

`0.45·0 + 0.30·50 + 0.25·85 = 36.25` is the ceiling. Spec 07's options, with the corpus consequence of each:

| Option | Effect | Side effects on the corpus |
|---|---|---|
| **Lower `bands.investigate` 40 → 35** *(recommended)* | 03 → `investigate` | **None.** No other fixture projects into `[35, 40)` — the nearest are 04 at 21.25 and 05 at 42.25. A one-line config change in `scoring.bands`. |
| Let the triage LLM's ±1 band override carry it | 03 → `investigate` with an `override_reason` | Makes a labeled acceptance gate depend on model judgment; the override is designed for evidence the scorer cannot see, not for a systematic band-edge deficit. |
| Re-weight `ti`/`severity`/`history` | 03 → `investigate` | Rebalances all ten; fixture 05's 2.25-point margin (§16.2) is the constraint any re-weighting must respect. |

Recommended: the band change, with spec 07's table-driven scorer test asserting the full §16.1 column so the next tuning attempt fails loudly instead of drifting.

---

## 17. Configuration

```yaml
threat_intel:
  providers: [mock]           # allowlist: mock | failing | timeout  (§9.3)
  lookup_timeout_s: 5
  cache_ttl_s: 3600
  max_concurrency: 10         # new — bounds the asyncio fan-out (§8.1)
  simulate_latency: true      # new — deterministic 10-50 ms demo latency (§6.4)
  seed_path: data/ti_seed.yaml  # new

history:
  store: sqlite               # allowlist: sqlite | memory
  path: data/history.db
  window_days: 30
  max_related: 20             # new — caps block.alerts, never the counts (§12.4)
  value_stoplist: []          # new — values excluded from entity matching (§12.1)
```

`ThreatIntelConfig` and `HistoryConfig` already exist in `soc_agent/config.py`; this adds fields to both. `providers` and `store` are validated against their allowlists at load time and raise `ConfigError` on an unknown name — the §9.3 guard. `SOC_AGENT_HISTORY__WINDOW_DAYS=7` works through the existing env-override machinery.

`window_days: 30` is left at Architecture's default even though group B's oldest phishing TP sits 22 days before the epoch. §21.8 includes a 7-day-window case that drops it, so the boundary is tested rather than assumed.

---

## 18. Amendments to Earlier Phases

### 18.1 Two `RelatedAlertsBlock` additions

```python
class RelatedAlertsBlock(ContractModel):
    ...
    rule_fp_rate: float | None = None
    rule_fired_count: int | None = None   # §13.2 — the ≥10 precondition, made visible
    shared_entity_count: int = 0          # §12.5 — what the +10 actually reads
```

Both exist for the same reason: Architecture §5.6 moves the risk score on evidence the envelope could not otherwise show. `rule_fired_count` is the `≥ 10 firings` precondition of the −25. `shared_entity_count` is the `≥ 3 related alerts share entities` precondition of the +10, which `count` over-reports whenever a rule is noisy — 40 vs 5 on fixture 08, 12 vs 1 on fixture 04.

Both are additive and defaulted, no existing shape changes, output envelope otherwise untouched → `SCHEMA_VERSION` does **not** bump, exactly as spec 04 §13.1 handled `ExtractionSelection`. Both require a dated changelog entry in `data-contracts-02-spec.md` per that spec's freeze policy, and `make schema` to regenerate `schemas/output.schema.json`.

### 18.2 No changes needed to `errors.py`

`Stage` already includes `enrich_ti` and `correlate`; `ErrorType` already includes `timeout` and `provider_error`. Checked rather than assumed — this phase adds no error vocabulary.

### 18.3 `soc-agent seed` un-stubbed, `make seed` split

`cli.py`'s `seed` command currently calls `_stub("enrichment-05-spec.md")`. It becomes real (§19.1). The Makefile's combined `seed eval:` stub rule splits so `seed` runs the real command and `eval` keeps its stub until spec 09.

---

## 19. CLI & Makefile

### 19.1 `soc-agent seed` (implemented)

```python
@app.command()
def seed(
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing history.db.")] = False,
    epoch: Annotated[str | None, typer.Option("--epoch", help="ISO-8601 corpus epoch.")] = None,
) -> None:
    """Build local seed data: data/history.db (spec 05)."""
```

Writes `history.path`, refuses to overwrite without `--force` (exit 3), prints a summary to stderr: alert count, distinct rules, disposition breakdown, epoch. Exit 0.

### 19.2 `soc-agent context` (new)

The phase's debugging surface, following `soc-agent normalize` (spec 03) and `soc-agent extract` (spec 04):

```python
@app.command()
def context(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT")],
    fmt: Annotated[str | None, typer.Option("--format")] = None,
    no_ti: Annotated[bool, typer.Option("--no-ti", help="Skip threat-intel lookups.")] = False,
    no_history: Annotated[bool, typer.Option("--no-history", help="Skip correlation.")] = False,
    pretty: Annotated[bool, typer.Option("--pretty")] = False,
) -> None:
    """Normalize, extract, then print the TI and history context as JSON (spec 05 surface)."""
```

```jsonc
{
  "alert_id": "SIEM-2026-018233",
  "iocs": ["203.0.113.66"],
  "threat_intel": { "summary": {…}, "results": [ /* TIResult[] */ ] },
  "related_alerts": { "count": 2, "prior_true_positives": 1, "prior_false_positives": 0,
                      "rule_fp_rate": null, "rule_fired_count": null, "alerts": [ /* … */ ] },
  "errors": [],
  "providers": { "ti": ["mock"], "history": "sqlite" }
}
```

`--no-ti` / `--no-history` exist so the degraded paths are demonstrable by hand, not only through a test. Exit codes unchanged: `0` success, `2` `IngestError`, `3` config/auth.

### 19.3 Makefile

```make
seed:               ## build data/history.db from the deterministic seed
	.venv/bin/soc-agent seed --force

context:            ## print the TI + history context for one fixture (ALERT=path)
	.venv/bin/soc-agent context $(or $(ALERT),fixtures/alerts/01_c2_beacon.json) --pretty

eval:               ## stub until spec 09
	.venv/bin/soc-agent eval
```

Add `context` to `.PHONY`; remove `seed` from the combined stub rule.

---

## 20. Security Considerations

1. **SQL injection is the live risk in this phase.** Entity values originate in attacker-influenced alert text and reach a query engine for the first time here. Every value is bound as a parameter (§11.3); the `IN` list is built from placeholders, never from values. §21.7 fires a `' OR 1=1 --` entity value through `find_related` and asserts zero rows and no error.
2. **Lookup keys are pre-validated.** Only `ioc_entities()` output reaches a provider — type-validated by spec 04 §7.4 and, for LLM-contributed entities, grounded verbatim in the alert text by §9.5. Architecture §10.1's "arbitrary injected strings never reach a provider query" is enforced upstream and depended on here; a future provider that accepts free-form search terms would break that chain.
3. **No outbound calls exist.** The provider registry is an allowlist of local implementations (§9.3); an unknown name is a `ConfigError`, not a lazily-imported adapter. The POC cannot make a network call from this stage even if misconfigured.
4. **Seed hygiene.** `ti_seed.yaml` and the history seed contain only documentation-range IPs, invented `.example`/`.test` domains and random hex hashes (§14.3), asserted mechanically. `data/history.db` is gitignored; `data/ti_seed.yaml` is committed and contains nothing sensitive by construction.
5. **The store is opened read-only** (§11.2). Correlation cannot mutate the evidence base it reads.
6. **PII.** The history store holds usernames and hostnames. It is local SQLite in the POC, and no part of this phase transmits anything anywhere. The field-level redaction flagged in Architecture §10.2 stays post-POC.

---

## 21. Tests

All API-free — the default `pytest` run covers this phase completely. No `llm`-marked tests are added.

### 21.1 `tests/unit/test_ti_seed.py`

- Every `data/ti_seed.yaml` entry parses, and its score falls in its verdict's §6.2 band.
- A hand-built entry violating the band raises `ConfigError` with the value in the message.
- Every IOC in the §6.3 table is present with the stated verdict and score; the three deliberate absences (`198.51.100.23`, `198.51.100.201`, and any fixture-05 IOC) are asserted **absent**.
- Hygiene (§14.3): every seeded IP is in a documentation range, every domain ends `.example`/`.test`/`.invalid` or contains `example-`, every hash matches `^[0-9a-f]{32,64}$`.

### 21.2 `tests/unit/test_ti_mock.py`

- Seeded hit returns the full verdict incl. `tags`, `first_seen`, `last_seen`, `raw`.
- Miss returns `unknown`, score 0, `error is None` — the §5 distinction.
- Key canonicalization: uppercase domain, mixed-case hash and `2001:0db8::0001` all hit their seeded entries.
- URL lookups are exact — fixture 09's URL hits its own entry, and a URL whose host is seeded but whose full URL is not returns `unknown` (no host inheritance, §6.3).
- **Fixture 10's IP scores exactly 60** with a comment pointing at §16.2.
- `supports()` is False for `user`/`host`/`process`/`file_path`.

### 21.3 `tests/unit/test_ti_aggregate.py`

- Max score wins; the winning entry's verdict is the aggregate verdict.
- The rejected policy: `malicious`/20 + `clean`/95 aggregates to score 95 **and** verdict `clean` — pinned so a future "worst label wins" rewrite fails here (§7.1).
- Tags/sources unioned, order preserved, deduplicated; `first_seen` min, `last_seen` max; `raw` keyed by provider.
- `error` set only when every supporting provider failed.
- `worst_verdict` follows the §7.2 rank, including `unknown` > `clean`.
- Summary counts sum to `iocs_checked`; the `iocs_checked == 0 ⇒ worst_verdict is None` invariant round-trips through the model validator.

### 21.4 `tests/unit/test_ti_cache.py`

- Hit before TTL, miss after, using an injected clock — **no `sleep`**.
- A verdict with `error` set is never stored (§8.3), asserted by a second lookup reaching the provider.
- Key includes the provider name: two providers cache the same entity independently.
- `TIEnrichment.cache_hits` counts correctly across a repeated entity set.

### 21.5 `tests/unit/test_ti_enrich.py`

- Only `ioc_entities()` are looked up: a fixture-01 entity list produces exactly one lookup; internal IPs, `user`, `host`, `process` produce none.
- **Fixture 05 produces zero lookups** and a valid empty summary (`iocs_checked: 0`, `worst_verdict: None`).
- **Concurrency**: 10 IOCs with `simulate_latency=True` complete in well under the sequential sum (bounded assertion, ~3× margin), proving the `gather` is real.
- Per-IOC timeout → `unknown` + `error` + one `StageError(type="timeout")`; sibling lookups still return their verdicts.
- `TIProviderError` → `unknown` + one `StageError(type="provider_error")`; `enrich_ti` returns normally.
- `FailingTIProvider` in both modes → every IOC `unknown`, one `StageError` each, `enrich_ti` never raises.
- An unknown provider name in config raises `ConfigError` (§9.3).

### 21.6 `tests/unit/test_history_seed.py`

- **Determinism**: two independent `seed_history()` builds into separate temp DBs produce identical full-table dumps.
- Row count matches §14.2; every group's composition is asserted (dispositions, rule names, entity sets).
- Every `occurred_at` matches `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$` and is `<= epoch` (§4.4).
- **Group D's TP shares no entity with fixture 04** (§14.2) — asserted directly.
- **Group H is empty**: no seeded alert carries `WS-HR-0009`, `t.baros`, `203.0.113.150` or `powershell` (§4.3).
- Hygiene over every seeded entity value, as §21.1.
- `--epoch` shifts every timestamp by exactly the delta and changes nothing else.

### 21.7 `tests/unit/test_history_store.py`

- Schema and all four indexes exist; `meta.schema_version` and `meta.epoch` are populated.
- Window filtering is inclusive at both bounds; an alert one second past `anchor` is excluded (§4.2).
- `rule_stats` math: fired/TP/FP counts, the §13.1 denominator, and **`fp_rate is None` when nothing is dispositioned** — not `0.0`.
- **Injection**: an entity value of `' OR 1=1 --` returns zero rows and raises nothing (§20.1).
- Read-only: an attempted write through the store's connection raises; a missing DB file raises `HistoryStoreError` rather than creating an empty database (§11.2).
- Canonicalized storage: a stored `ws-fin-0142` is found by an entity valued `WS-FIN-0142`.

### 21.8 `tests/unit/test_correlate.py`

Parametrized over all 10 fixtures, reading entities from `tests/data/entities/*.json` and alerts from `tests/data/normalized/*.json` — no re-extraction, no LLM:

- `count`, `shared_entity_count`, `prior_true_positives`, `prior_false_positives`, `rule_fp_rate` and `rule_fired_count` match §16.1 column for column.
- **Fixture 10 correlates to zero alerts** and its block is byte-identical when the anchor moves a year forward (§4.3).
- `relation_reason` strings match the §12.2 vocabulary verbatim; an alert matching several ways appears once with merged `shared_entities`.
- Ordering is `occurred_at DESC, alert_id ASC`.
- **Truncation**: fixture 08 against `max_related=2` yields `len(alerts) == 2`, `count == 40`, and **unchanged** `shared_entity_count == 5` and `prior_false_positives == 5`, with `truncated == 38` (§12.4). Against `max_related=5`, every rendered alert still carries shared entities — the §12.3 ordering guarantee.
- `window_days=7` drops **all three** of group B's phishing TPs (they sit 22, 15 and 8 days out), leaving only the false positive: fixture 02's history component would fall 85 → 50. The window is a scoring input, not a display preference.
- `process` and `file_path` entities never produce a relation (§12.1). A `value_stoplist` of `["admin"]` leaves fixture 03 unchanged (redundant linkage, §12.1); `["admin", "BASTION-01"]` reduces it to one entity-sharing match.
- Rule-only matches carry `same rule "<name>"` and an empty `shared_entities`, and are excluded from `prior_true_positives` / `prior_false_positives` (§12.5).
- Missing DB → empty block + one `StageError(stage="correlate", type="provider_error")`, no exception.
- An alert with `vendor_rule=None` yields `rule_fp_rate=None` and **no** error record (§15).

### 21.9 `tests/unit/test_context_goldens.py`

Parametrized over all 10 fixtures against a temp seeded DB, `simulate_latency=False`:

- `{"threat_intel": …, "related_alerts": …}` equals `tests/data/context/NN_name.json` after canonical JSON dumping.
- Running twice in one process produces identical output (cache must not change results, only timing).
- `--update-goldens` rewrites them; `make goldens` covers this file alongside the spec 03/04 golden tests.

### 21.10 `tests/unit/test_enrichment_inputs.py`

The guard on §16, asserting this phase's *inputs to* the scorer without implementing the scorer:

- For each fixture: severity, max TI score, `count`, `shared_entity_count`, prior TP count, `rule_fp_rate` and `rule_fired_count` equal §16.1, and the reconstructed history component and projected risk match the table's last two columns.
- The projected band equals the fixture's label for nine of ten, and fixture 03 is asserted to be **exactly** the documented exception — a test that fails if the gap silently closes or silently widens.
- **Fixture 05 has exactly 3 shared-entity relations** including ≥1 TP — the 2.25-point margin from §16.2, pinned with a comment pointing there.
- **Fixture 01 has exactly 2** relations and one prior TP (Appendix B parity).
- Fixture 03's inputs are the structural maximum, documenting §16.3's gap in code so spec 07 meets it as an assertion rather than a surprise.

---

## 22. Token Budget

| Activity | Est. tokens |
|---|---|
| Everything in this phase | **0** |

No LLM node, no prompt file, no cache entry, no `llm`-marked test. Both stages are deterministic by design (Architecture §3.2 lists `enrich_ti` and `correlate` as deterministic), and the entire phase runs inside the default API-free `pytest`. The 1 M free quota is untouched; the running total after Phase 5 is whatever specs 03 and 04 spent.

---

## 23. Implementation Order

1. [ ] `threat_intel:` / `history:` config additions + allowlist validation (§17) — and `make test` still green
2. [ ] §18.1 `rule_fired_count` + spec-02 changelog entry + `make schema`
3. [ ] `providers/ti/base.py`: protocol, `lookup_key`, `TIProviderError`
4. [ ] `data/ti_seed.yaml` + `mock.py` + `tests/unit/test_ti_seed.py`, `test_ti_mock.py` — **write the verdict/score band validator first** (§6.2)
5. [ ] `aggregate.py` + `tests/unit/test_ti_aggregate.py`, incl. the rejected-policy pin (§21.3)
6. [ ] `cache.py` with the injected clock + `tests/unit/test_ti_cache.py`
7. [ ] `enrich_ti` fan-out, timeouts, failure policy + `failing.py` + `tests/unit/test_ti_enrich.py`
8. [ ] `providers/history/base.py` + `sqlite.py` (schema, indexes, read-only URI, parameterized queries)
9. [ ] `tests/unit/test_history_store.py` — **write the injection and read-only tests first** (§20.1, §11.2)
10. [ ] `seed.py` with `CORPUS_EPOCH` + the §14.2 groups + `tests/unit/test_history_seed.py`
11. [ ] `correlate()`: matching, reason vocabulary, merge, ordering, cap + `tests/unit/test_correlate.py`
12. [ ] `tests/unit/test_enrichment_inputs.py` → confirm §16.1 empirically; **if a row disagrees with the table, fix the seed and amend the table in the same commit**
13. [ ] `soc-agent seed` + `soc-agent context` + Makefile targets
14. [ ] `make goldens` → commit `tests/data/context/*.json`
15. [ ] `make test` + `make lint` green
16. [ ] Commit: `feat: threat-intel enrichment + historical correlation (enrichment-05-spec)`

Estimated effort: ~1.5–2 days (Architecture Phases 4 and 5 combined).

---

## 24. Acceptance Gate

| # | Check | Expected |
|---|---|---|
| 1 | `make test` | green, incl. all ten new unit modules; **zero network calls, zero tokens** |
| 2 | `make lint` | clean |
| 3 | `make seed` | builds `data/history.db`, prints 75 alerts + the epoch; `--force` required to overwrite |
| 4 | `soc-agent context fixtures/alerts/01_c2_beacon.json --pretty` | exit 0; `iocs_checked: 1`, `malicious: 1`, `worst_verdict: "malicious"`; `related_alerts.count == 2` with one `true_positive` — Architecture Appendix B parity |
| 5 | Known-bad IOCs | fixtures 01, 02, 09 return `malicious`; 06, 07, 10 `suspicious`; 04 `clean`; 03, 08 `unknown` (Phase 4 gate) |
| 6 | Fixture 05 | zero TI lookups; `iocs_checked: 0`, `worst_verdict: null`; **3** related alerts (Phase 4 no-TI path + §16.2 tripwire) |
| 7 | Fixture 02 | surfaces `j.okafor`'s 3 prior true positives (Phase 5 gate) |
| 8 | Fixture 08 | `rule_fp_rate == 0.95` with `rule_fired_count == 40`, `shared_entity_count == 5` (Phase 5 gate: fp_rate ≥ 0.9) |
| 9 | Timeout path | a per-IOC timeout yields `unknown` + `error` + one `StageError`; siblings still resolve; `enrich_ti` returns (Phase 4 gate) |
| 10 | Store-down path | a missing `history.db` yields an empty block + one `StageError`, no exception |
| 11 | Injection | `' OR 1=1 --` as an entity value returns zero rows and raises nothing |
| 12 | Determinism | two `seed_history()` builds are identical; `make goldens` produces no diff on a clean tree |
| 13 | Time-invariance | fixture 10 correlates to zero alerts with the anchor moved a year forward (§4.3) |
| 14 | §16.1 | every projected row reproduced by `test_enrichment_inputs.py`; the fixture-03 gap documented, not silently patched |
| 15 | `git status` after commit | clean; `data/ti_seed.yaml` and `tests/data/context/` **are** committed; `data/history.db` is **not** |

Phase 05 is **done** when all fifteen pass and the commit exists. Next: `attack-mapping-06-spec.md` (ATT&CK catalog, candidate shortlisting, grounded LLM selection), whose evidence bundle is this phase's `ThreatIntelBlock.results[].tags` plus `RelatedAlertsBlock`.

---

*Changelog: (add dated entries here when the aggregation policy, the verdict ranking, the correlatable-type set, the fp_rate denominator, the corpus epoch, the seed composition, `TIEnrichment` or `CorrelationResult` change)*

- **2026-08-11** — `AlertHistoryStore.rule_stats` gained a keyword-only `anchor: datetime`. §4.2 anchors the correlation window on the alert rather than the clock, but §10's protocol sketch (copied from Architecture §5.4) passed only `window_days`, which would have left rule stats drifting daily while `find_related` stayed fixed. Caught wiring `correlate()`.
- **2026-08-11** — **`prior_true_positives` / `prior_false_positives` are scoped to entity-sharing matches**, and `shared_entity_count` was added to `RelatedAlertsBlock` (§12.5, §18.1). Found by running the corpus: fixture 04 matches its noisy rule 12 times including one true positive on an unrelated host, so rule-scoped counting awarded the +25 "related TP shares an entity" bonus on evidence that says only "this rule was right once, about something else", moving its history component 25 → 50. It also double-counted a noisy rule's false positives — once in `prior_false_positives` and again through the −25. The §16.1 `count` column was corrected accordingly (04: 1 → 12, 08: 5 → 40) with the entity-sharing count split into its own column.
- **2026-08-11** — **Related alerts are ordered entity-matches-first, then recency** (§12.3), rather than pure recency. Fixture 08's five entity-sharing matches turned out to be the five *oldest* of its rule's forty firings, so the default `max_related: 20` hid every one of them behind twenty rows of rule-only noise. The scoring inputs were already safe (§12.4 computes them pre-cap), but the rendered list was the least useful twenty rows available.
- **2026-08-11** — §12.1's justification for the empty `value_stoplist` default was wrong and is corrected. It claimed fixture 03's labeled band depends on `admin` matching; measured, stopping `admin` alone changes nothing, because every alert it reaches is also reached via `BASTION-01` or `10.20.7.5`. The real reason the default ships empty is that the right list is deployment-specific. The redundancy is a property worth keeping and is now asserted.
- **2026-08-11** — A decoy `hash_sha256` in `data/ti_seed.yaml` was 65 characters. Caught by §21.1's hygiene test before it could become a permanently unreachable seed entry — no valid `Entity` could ever have matched it.
