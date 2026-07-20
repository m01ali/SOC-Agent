"""Live DashScope connectivity (~50 tokens). Spec: project-setup-01-spec.md §11.

Run with: pytest -m llm  (auto-skipped when DASHSCOPE_API_KEY is unset).
"""

from __future__ import annotations

import pytest

from soc_agent.llm.client import get_llm

pytestmark = pytest.mark.llm


def test_qwen_roundtrip():
    resp = get_llm("check").invoke("Reply with the single word OK.")
    assert isinstance(resp.content, str) and resp.content.strip()
    usage = resp.usage_metadata
    assert usage is not None
    assert usage["input_tokens"] > 0
    assert usage["output_tokens"] > 0
