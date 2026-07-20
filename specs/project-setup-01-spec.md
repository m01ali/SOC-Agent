# project-setup-01-spec — Project Setup & Scaffolding

**Series:** spec 01 of the SOC alert-enrichment agent POC
**Parent:** [Architecture.md](Architecture.md) — implements §13 **Phase 0 (Scaffold)**, expanded to cover *everything* needed before feature work starts
**Date:** 2026-07-20
**Status:** Ready to implement

> **Spec-doc convention.** Implementation specs live in `specs/` and follow `[name]-NN-spec.md`, numbered in build order. Planned series (mapping to Architecture §13):
>
> | Spec | Covers | Architecture phase |
> |---|---|---|
> | `project-setup-01-spec.md` | this document | Phase 0 |
> | `data-contracts-02-spec.md` | Pydantic models, output schema, fixtures | Phase 1 |
> | `ingestion-03-spec.md` | format detection + normalizers | Phase 2 |
> | `extraction-04-spec.md` | entity/IOC extraction | Phase 3 |
> | `enrichment-05-spec.md` | TI provider + history correlation | Phases 4–5 |
> | `attack-mapping-06-spec.md` | ATT&CK mapping | Phase 6 |
> | `triage-briefing-07-spec.md` | scoring, triage, briefing | Phase 7 |
> | `graph-cli-08-spec.md` | LangGraph wiring + CLI completion | Phase 8 |
> | `hardening-eval-09-spec.md` | injection tests, degraded modes, eval | Phase 9 |

---

## 1. Objective

At the end of this phase the repository is a fully working, empty shell: installable package, working CLI with stub commands, configuration + secrets handling, a verified connection to Qwen3.7 Max, test/lint tooling, and git hygiene. **No pipeline logic** — every later spec drops code into slots created here.

**Out of scope:** anything from spec 02 onward (models, normalizers, nodes, providers, fixtures with content).

---

## 2. Prerequisites

| Item | Requirement | Check |
|---|---|---|
| Python | ≥ 3.11 (project venv already exists at `.venv/`, Python 3.14.6) | `.venv/bin/python --version` |
| DashScope account | Model Studio account with the 1M-token free quota active (note the **expiry date** in the console) | console login |
| API key | `DASHSCOPE_API_KEY` value available | — |
| git | installed | `git --version` |

No other cloud resources are needed — TI and history data are local mocks per Architecture §7.

---

## 3. Repository Layout (created in this phase)

Everything below is created now. Python packages get an `__init__.py` with a one-line docstring referencing the Architecture section they implement; module files are importable stubs (docstring only) unless specified otherwise in §5–§9.

```
Agent-1/
├── .env                        # local secrets — NEVER committed (from .env.example)
├── .env.example                # committed template, §6
├── .gitignore                  # §10
├── Makefile                    # §9
├── README.md                   # stub: name, one-paragraph purpose, quickstart (install/check/test)
├── config.yaml                 # §7 — content from Architecture §9
├── pyproject.toml              # §4
├── specs/
│   ├── Architecture.md
│   └── project-setup-01-spec.md
├── soc_agent/
│   ├── __init__.py             # __version__ = "0.1.0"
│   ├── __main__.py             # python -m soc_agent → cli.main()
│   ├── cli.py                  # §8 — typer app, implemented skeleton + stubs
│   ├── config.py               # §7 — implemented in this phase
│   ├── graph.py                # stub (spec 08)
│   ├── state.py                # stub (spec 08)
│   ├── scoring.py              # stub (spec 07)
│   ├── models/__init__.py      # stubs (spec 02)
│   ├── ingest/
│   │   ├── __init__.py
│   │   ├── detector.py         # stub (spec 03)
│   │   └── normalizers/__init__.py
│   ├── nodes/__init__.py       # stubs (specs 04–07)
│   ├── providers/
│   │   ├── __init__.py
│   │   ├── ti/__init__.py      # stubs (spec 05)
│   │   └── history/__init__.py
│   └── llm/
│       ├── __init__.py
│       ├── client.py           # §5 — implemented in this phase
│       └── prompts/            # .gitkeep; versioned prompt files land in specs 03+
├── data/                       # .gitkeep — seeds/catalogs land in specs 05–06
├── fixtures/alerts/            # .gitkeep — fixtures land in spec 02
├── schemas/                    # .gitkeep — generated JSON Schema lands in spec 02
├── scripts/                    # .gitkeep — seed/build scripts land in specs 05–06
└── tests/
    ├── conftest.py             # §11 — implemented in this phase
    ├── unit/test_scaffold.py   # §11 — implemented in this phase
    ├── llm/test_connectivity.py# §11 — implemented in this phase (llm-marked)
    ├── e2e/.gitkeep
    └── llm_cache/.gitkeep      # record/replay cache dir (mechanism in spec 03); CACHE IS COMMITTED
```

---

## 4. Python Project — `pyproject.toml`

Exact content (version floors, not hard pins — see resolution policy below):

```toml
[project]
name = "soc-agent"
version = "0.1.0"
description = "SOC alert-enrichment agent (POC): SIEM alert in, analyst-ready JSON out"
requires-python = ">=3.11"
dependencies = [
    "langgraph>=0.3",
    "langchain-openai>=0.3",
    "langchain-core>=0.3",
    "pydantic>=2.7",
    "pydantic-settings>=2.2",
    "typer>=0.12",
    "rich>=13",
    "pyyaml>=6.0",
    "python-dotenv>=1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "ruff>=0.4",
]
api = [                          # spec 08 stretch — not installed by default
    "fastapi>=0.111",
    "uvicorn>=0.30",
]

[project.scripts]
soc-agent = "soc_agent.cli:main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["soc_agent*"]

[tool.pytest.ini_options]
addopts = "-q -m 'not llm'"      # default run NEVER touches the API (token budget, §14 of Architecture)
markers = [
    "llm: calls the DashScope API — run explicitly with `pytest -m llm`",
]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B"]
```

**Dependency resolution policy:** floors above resolve to latest at install time. At the end of this phase, freeze the actual resolution into `requirements.lock` (`pip freeze > requirements.lock`, committed) so the team and any CI install identical versions. If `langgraph`/`langchain-openai` latest turn out incompatible with Python 3.14, resolve there first (worst case: recreate `.venv` on 3.12 — record the decision in this spec's changelog).

**Install command** (existing venv, editable so the `soc-agent` entry point tracks source):

```bash
.venv/bin/pip install -e ".[dev]"
```

---

## 5. LLM Client Factory — `soc_agent/llm/client.py` (implemented now)

The single place the app touches the LLM (Architecture §2.2: provider-swappable). Later specs call `get_llm(...)`; nothing else may construct a chat model.

```python
"""LLM client factory — the only module that constructs chat models (Architecture §2.2)."""
import os
from langchain_openai import ChatOpenAI
from pydantic import BaseModel
from soc_agent.config import get_config

class MissingAPIKeyError(RuntimeError): ...

def get_llm(node: str, *, structured: type[BaseModel] | None = None):
    """Return the chat model for a pipeline node, per config.

    - model = models.overrides[node] if present, else models.default
    - always passes enable_thinking explicitly (never rely on server default)
    - structured=SomeModel -> .with_structured_output(SomeModel) (function-calling)
    """
    api_key = os.environ.get("DASHSCOPE_API_KEY")
    if not api_key:
        raise MissingAPIKeyError(
            "DASHSCOPE_API_KEY is not set. Copy .env.example to .env and add your key."
        )
    cfg = get_config()
    llm = ChatOpenAI(
        model=cfg.models.overrides.get(node, cfg.models.default),
        api_key=api_key,
        base_url=cfg.llm.base_url,
        temperature=cfg.llm.temperature,
        max_tokens=cfg.llm.max_tokens,
        timeout=cfg.llm.timeout_s,
        max_retries=cfg.llm.max_retries,
        extra_body={"enable_thinking": cfg.llm.enable_thinking},
    )
    return llm.with_structured_output(structured) if structured else llm
```

Notes:
- OpenAI-compatible DashScope endpoint (intl) comes from config — never hardcoded at call sites.
- `enable_thinking` is passed explicitly on every call so behavior never depends on a server-side default (thinking tokens bill as output — Architecture §14).
- Per-node `structured` schemas arrive in specs 03+; this phase only needs the factory + connectivity check.

---

## 6. Environment & Secrets

### 6.1 `.env.example` (committed)

```bash
# --- Required -----------------------------------------------------------
# Alibaba Cloud Model Studio (DashScope) API key — international endpoint
DASHSCOPE_API_KEY=sk-your-key-here

# --- Optional: config overrides (defaults live in config.yaml) ----------
# Prefix SOC_AGENT_, nested keys joined with __ (double underscore)
# SOC_AGENT_MODELS__DEFAULT=qwen3.7-max
# SOC_AGENT_LLM__ENABLE_THINKING=false
# SOC_AGENT_LLM__MAX_TOKENS=4096

# --- Optional: LangSmith tracing (off by default) ------------------------
# LANGSMITH_TRACING=true
# LANGSMITH_API_KEY=
# LANGSMITH_PROJECT=soc-agent-poc
```

### 6.2 Rules

- `.env` is created by copying `.env.example` and filling the key. It is **gitignored**; a pre-commit sanity habit: `git status` must never show `.env`.
- Loading: `cli.main()` calls `load_dotenv()` (python-dotenv) **before** anything reads config, so CLI runs pick up `.env` automatically. Tests do **not** auto-load `.env` — LLM tests read the real environment only (explicit is safer for CI later).
- Precedence (highest wins): **process env → `.env` → `config.yaml` defaults**. (python-dotenv does not override already-set process vars; pydantic-settings prefers env over init values — this yields exactly that ordering.)
- `DASHSCOPE_API_KEY` is deliberately *not* under the `SOC_AGENT_` prefix — it keeps the vendor's conventional name so the same env var works for any DashScope tooling.

---

## 7. Configuration System

### 7.1 `config.yaml` (committed — POC defaults, verbatim from Architecture §9)

```yaml
models:
  default: qwen3.7-max
  overrides: {}            # e.g. extract: qwen-flash  (cost lever, off by default)
llm:
  base_url: https://dashscope-intl.aliyuncs.com/compatible-mode/v1
  max_tokens: 4096
  temperature: 0.0
  enable_thinking: false   # per-node override possible; thinking tokens bill as output
  timeout_s: 120
  max_retries: 2           # client-level; plus 1 schema-repair retry at node level
threat_intel:
  providers: [mock]
  lookup_timeout_s: 5
  cache_ttl_s: 3600
history:
  store: sqlite
  path: data/history.db
  window_days: 30
attack:
  catalog: data/attack_catalog.json
  candidate_top_k: 12
  max_techniques: 5
scoring:
  weights: { ti: 0.45, severity: 0.30, history: 0.25 }
  bands:   { escalate: 70, investigate: 40 }
briefing:
  max_words: 200
```

### 7.2 `soc_agent/config.py` (implemented now)

- One Pydantic model per section: `ModelsConfig`, `LLMConfig`, `ThreatIntelConfig`, `HistoryConfig`, `AttackConfig`, `ScoringConfig`, `BriefingConfig` — field names/defaults exactly as in the YAML, so an **empty file still yields a fully valid default config**.
- Root `AppConfig(BaseSettings)` with `SettingsConfigDict(env_prefix="SOC_AGENT_", env_nested_delimiter="__")` → `SOC_AGENT_LLM__MAX_TOKENS=1024` overrides `llm.max_tokens`.
- `load_config(path: Path | None = None) -> AppConfig`: path resolution `--config` CLI flag → `SOC_AGENT_CONFIG` env → `./config.yaml` → built-in defaults. YAML content is passed as init values so env vars still win.
- `get_config() -> AppConfig`: cached accessor (`functools.lru_cache`); `reset_config()` for tests.
- Validation on load: weights sum to 1.0 (±0.001), `bands.escalate > bands.investigate`, `max_tokens > 0`. Violations raise `ConfigError` with the offending key — the CLI prints it and exits 3.

---

## 8. CLI Skeleton — `soc_agent/cli.py` (implemented now)

Typer app. `main()` = entry point (loads `.env`, configures logging, invokes app).

**Global options:** `--config PATH` (config file), `--log-level [debug|info|warning|error]` (default `info`).

**Logging:** stdlib `logging` to **stderr** (stdout is reserved for output JSON — Architecture §8.1), format `%(asctime)s %(levelname)s %(name)s: %(message)s`.

| Command | This phase | Behavior |
|---|---|---|
| `check` | **implemented** | Startup diagnostics, §8.1 |
| `enrich INPUT` | stub | prints `not implemented — see graph-cli-08-spec.md`, exit 1 |
| `enrich-dir DIR` | stub | same |
| `seed` | stub | `enrichment-05-spec.md`, exit 1 |
| `eval` | stub | `hardening-eval-09-spec.md`, exit 1 |
| `schema` | stub | `data-contracts-02-spec.md`, exit 1 |

Exit-code contract (reserved now, enforced from spec 08): `0` success/partial · `1` stub/not-implemented · `2` failed input · `3` config/auth/unexpected.

### 8.1 `soc-agent check` — the setup-phase deliverable

Verifies the whole chain end to end, in order, with ✓/✗ per step:

1. Config loads and validates (prints resolved config path, default model).
2. `DASHSCOPE_API_KEY` present (prints key masked: `sk-…last4`).
3. **One live call** through `get_llm("check")` — plain invoke, prompt `"Reply with the single word OK."` — prints model id, round-trip latency, and `usage_metadata` token counts.
4. Warns (non-fatal) if `LANGSMITH_TRACING` is set without `LANGSMITH_API_KEY`.

Cost: ~30–60 tokens per run — the only API-touching step in this entire phase. Any step failing → exit 3 with a one-line fix hint.

---

## 9. `Makefile`

Targets run via `.venv/bin/` so no shell activation is required:

```make
PY := .venv/bin/python

.PHONY: install test test-llm lint format check lock seed eval schema

install:            ## editable install + dev tools into existing .venv
	.venv/bin/pip install -e ".[dev]"

test:               ## unit tests only — never calls the API
	$(PY) -m pytest

test-llm:           ## opt-in API tests (needs DASHSCOPE_API_KEY)
	$(PY) -m pytest -m llm

lint:
	$(PY) -m ruff check soc_agent tests

format:
	$(PY) -m ruff format soc_agent tests

check:              ## config + key + live endpoint diagnostic (~50 tokens)
	.venv/bin/soc-agent check

lock:               ## freeze resolved deps for reproducible installs
	.venv/bin/pip freeze > requirements.lock

seed eval schema:   ## stubs until specs 02/05/09
	.venv/bin/soc-agent $@
```

---

## 10. Git & Hygiene

1. `git init -b main` (repo is not yet under version control).
2. `.gitignore`:

```
# secrets & local env
.env

# python
.venv/
__pycache__/
*.pyc
*.egg-info/
dist/
.pytest_cache/
.ruff_cache/

# generated / local artifacts
data/history.db
results/
eval_results.json

# os
.DS_Store
```

3. **Deliberately committed** (do not ignore): `tests/llm_cache/` — the record/replay cache (mechanism in spec 03) is shared via git so teammates/CI replay LLM tests **without keys or token spend**; `requirements.lock`; `.env.example`; `config.yaml`.
4. Initial commit after the acceptance checklist passes: `chore: project scaffold (project-setup-01-spec)`.

---

## 11. Test Scaffold (implemented now)

**`tests/conftest.py`:**
- Auto-skip `llm`-marked tests when `DASHSCOPE_API_KEY` is absent (skip reason says so) — `pytest -m llm` on a keyless machine skips cleanly rather than erroring.
- `reset_config()` autouse fixture so config-cache state never leaks between tests.

**`tests/unit/test_scaffold.py`** (runs in the default, API-free suite):
- `soc_agent` imports; `__version__ == "0.1.0"`.
- `load_config()` on the repo's `config.yaml` → `models.default == "qwen3.7-max"`, weights sum to 1.0.
- Env override works: with `SOC_AGENT_LLM__MAX_TOKENS=1024` set (monkeypatch), config reports 1024.
- Invalid config (weights sum ≠ 1.0, via tmp yaml) raises `ConfigError`.
- CLI: `--help` exits 0 and lists all six commands (typer `CliRunner`); each stub command exits 1 with its spec pointer; `check` without an API key exits 3 with the `.env` hint.
- `get_llm` without `DASHSCOPE_API_KEY` raises `MissingAPIKeyError` (no network involved).

**`tests/llm/test_connectivity.py`** (`@pytest.mark.llm`):
- `get_llm("check").invoke("Reply with the single word OK.")` returns non-empty content and `usage_metadata` with nonzero token counts. (~50 tokens; the llm-cache mechanism in spec 03 will make even this free on re-runs.)

---

## 12. Implementation Order (checklist)

1. [ ] `git init -b main`; write `.gitignore`
2. [ ] Write `pyproject.toml`; create the full directory tree + `__init__.py`/stub files + `.gitkeep`s (§3)
3. [ ] `make install` (creates `soc-agent` entry point in `.venv/bin/`)
4. [ ] Write `config.yaml`, implement `soc_agent/config.py` (§7)
5. [ ] Implement `soc_agent/llm/client.py` (§5)
6. [ ] Implement `soc_agent/cli.py` + `__main__.py` (§8), including `check`
7. [ ] Write `.env.example`; copy to `.env`; paste real key
8. [ ] Write `Makefile` (§9), `README.md` stub
9. [ ] Implement tests (§11)
10. [ ] `make lock` → commit `requirements.lock`
11. [ ] Run the acceptance checklist (§13); fix until green
12. [ ] Initial commit

---

## 13. Acceptance Checklist (phase gate)

All must pass, in order:

| # | Command | Expected |
|---|---|---|
| 1 | `make install` | exits 0; `soc-agent` on `.venv/bin/` |
| 2 | `soc-agent --help` | exits 0; shows `check enrich enrich-dir seed eval schema` |
| 3 | `make test` | green; **zero network calls**; llm tests deselected |
| 4 | `make lint` | clean |
| 5 | `.venv/bin/python -c "from soc_agent.config import get_config; print(get_config().models.default)"` | `qwen3.7-max` |
| 6 | `SOC_AGENT_LLM__MAX_TOKENS=1024 .venv/bin/python -c "...print(get_config().llm.max_tokens)"` | `1024` |
| 7 | `make check` | all ✓ incl. live Qwen round-trip with token counts (~50 tokens) |
| 8 | `make test-llm` | connectivity test passes (or skips cleanly if key unset) |
| 9 | `git status` | clean tree; `.env` absent from tracking |
| 10 | `soc-agent enrich x.json` | exit 1 + pointer to `graph-cli-08-spec.md` (stub behaving as specified) |

Phase 01 is **done** when all ten pass and the initial commit exists. Next: `data-contracts-02-spec.md`.
