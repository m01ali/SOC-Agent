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
	.venv/bin/pip freeze --exclude-editable > requirements.lock

seed eval schema:   ## stubs until specs 02/05/09
	.venv/bin/soc-agent $@
