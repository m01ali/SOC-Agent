PY := .venv/bin/python

.PHONY: install test test-llm lint format check lock seed eval schema goldens test-llm-refresh f1 context attack attack-recall catalog triage bands

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
	.venv/bin/pip freeze --exclude-editable > requirements.lock

schema:             ## export schemas/output.schema.json
	.venv/bin/soc-agent schema

goldens:            ## regenerate tests/data/{normalized,entities,context}/*.json
	SOC_AGENT_LLM_CACHE=replay $(PY) -m pytest \
	    tests/unit/test_ingest_goldens.py tests/unit/test_extract_goldens.py \
	    tests/unit/test_context_goldens.py tests/unit/test_attack_goldens.py \
	    tests/unit/test_risk_goldens.py --update-goldens

f1:                 ## print the extraction F1 table across all fixtures
	$(PY) -m pytest tests/unit/test_extract_f1.py -q -s

test-llm-refresh:   ## re-record the LLM cache (SPENDS TOKENS)
	$(PY) -m pytest -m llm --refresh-llm-cache

seed:               ## build data/history.db from the deterministic seed
	.venv/bin/soc-agent seed --force

context:            ## print the TI + history context for one fixture (ALERT=path)
	.venv/bin/soc-agent context $(or $(ALERT),fixtures/alerts/01_c2_beacon.json) --pretty

attack:             ## print the ATT&CK mapping for one fixture (ALERT=path)
	.venv/bin/soc-agent attack $(or $(ALERT),fixtures/alerts/01_c2_beacon.json) --pretty --candidates

triage:             ## score + recommend + brief one fixture (ALERT=path)
	.venv/bin/soc-agent triage $(or $(ALERT),fixtures/alerts/01_c2_beacon.json) --pretty

bands:              ## print the risk/band table across the corpus
	$(PY) -m pytest tests/unit/test_scoring_bands.py -q -s

attack-recall:      ## print the shortlist-recall and top-3 tables
	$(PY) -m pytest tests/unit/test_attack_shortlist.py tests/unit/test_attack_score.py -q -s

catalog:            ## rebuild data/attack_catalog.json from the official STIX bundle (NETWORK)
	$(PY) scripts/build_attack_catalog.py --out data/attack_catalog.json

eval:               ## stub until spec 09
	.venv/bin/soc-agent eval
