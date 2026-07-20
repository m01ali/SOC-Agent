"""Shared test fixtures. Spec: project-setup-01-spec.md §11."""

from __future__ import annotations

import os

import pytest

from soc_agent import config as config_module


def pytest_collection_modifyitems(config, items):
    """Skip llm-marked tests cleanly when no API key is available."""
    if os.environ.get("DASHSCOPE_API_KEY"):
        return
    skip = pytest.mark.skip(reason="DASHSCOPE_API_KEY not set")
    for item in items:
        if "llm" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _clean_config_state():
    """Config cache/path must never leak between tests."""
    config_module.set_config_path(None)
    yield
    config_module.set_config_path(None)
