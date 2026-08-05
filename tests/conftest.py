"""Shared test fixtures. Spec: project-setup-01-spec.md §11."""

from __future__ import annotations

import os

import pytest

from soc_agent import config as config_module
from soc_agent.llm import cache as cache_module


def pytest_addoption(parser):
    parser.addoption(
        "--update-goldens", action="store_true", default=False, help="Rewrite golden files."
    )
    parser.addoption(
        "--refresh-llm-cache",
        action="store_true",
        default=False,
        help="Force LLM cache record mode, overwriting existing cache entries (spends tokens).",
    )


def pytest_collection_modifyitems(config, items):
    """Skip llm-marked tests cleanly when no API key is available; select the LLM cache mode.

    A real DASHSCOPE_API_KEY -> record (call through on a miss, persist the result).
    No key -> replay (serve only from the committed cache; a miss is a hard failure,
    never a silent spend). `--refresh-llm-cache` forces record and overwrites hits too.
    """
    if config.getoption("--refresh-llm-cache"):
        os.environ["SOC_AGENT_LLM_CACHE"] = "record"
        os.environ["SOC_AGENT_LLM_CACHE_FORCE"] = "1"
    elif os.environ.get("DASHSCOPE_API_KEY"):
        os.environ.setdefault("SOC_AGENT_LLM_CACHE", "record")
    else:
        os.environ.setdefault("SOC_AGENT_LLM_CACHE", "replay")

    if os.environ.get("DASHSCOPE_API_KEY"):
        return
    skip = pytest.mark.skip(reason="DASHSCOPE_API_KEY not set")
    for item in items:
        if "llm" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def llm_call_counter():
    """Exposes hit/miss/live-call counts for cached LLM calls made during the test."""
    counter = cache_module.LLMCallCounter()
    cache_module.set_active_counter(counter)
    yield counter
    cache_module.set_active_counter(None)


@pytest.fixture(autouse=True)
def _clean_config_state():
    """Config cache/path must never leak between tests."""
    config_module.set_config_path(None)
    yield
    config_module.set_config_path(None)
