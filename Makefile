PY := .venv/bin/python

.PHONY: install test test-llm lint format check lock seed eval schema goldens test-llm-refresh f1

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

goldens:            ## regenerate tests/data/normalized/*.json and tests/data/entities/*.json
	SOC_AGENT_LLM_CACHE=replay $(PY) -m pytest \
	    tests/unit/test_ingest_goldens.py tests/unit/test_extract_goldens.py --update-goldens

f1:                 ## print the extraction F1 table across all fixtures
	$(PY) -m pytest tests/unit/test_extract_f1.py -q -s

test-llm-refresh:   ## re-record the LLM cache (SPENDS TOKENS)
	$(PY) -m pytest -m llm --refresh-llm-cache

seed eval:          ## stubs until specs 05/09
	.venv/bin/soc-agent $@
