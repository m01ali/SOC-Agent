"""LLM client factory — the only module that constructs chat models.

Spec: project-setup-01-spec.md §5 (Architecture §2.2). Every pipeline node obtains its
model via get_llm(node); nothing else may instantiate one. This is the seam that keeps
the provider swappable.
"""

from __future__ import annotations

import os

from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from soc_agent.config import get_config
from soc_agent.llm.cache import cache_mode, maybe_cache


class MissingAPIKeyError(RuntimeError):
    """DASHSCOPE_API_KEY is not set in the environment."""


def get_llm(node: str, *, structured: type[BaseModel] | None = None):
    """Return the chat model for a pipeline node, per config.

    - model = models.overrides[node] if present, else models.default
    - enable_thinking is always passed explicitly (never rely on a server default;
      thinking tokens bill as output — Architecture §14)
    - structured=SomeModel -> .with_structured_output(SomeModel) (function-calling)
    """
    api_key = os.environ.get("DASHSCOPE_API_KEY")
    if not api_key:
        if cache_mode() == "replay":
            # Never actually used: a cache hit returns before any HTTP call, and a
            # miss raises CacheMissError. This lets a keyless machine replay the
            # committed cache (spec 03 §16 gate 8) instead of failing before the
            # cache is ever consulted.
            api_key = "replay-placeholder"
        else:
            raise MissingAPIKeyError(
                "DASHSCOPE_API_KEY is not set. Copy .env.example to .env and add your key."
            )
    cfg = get_config()
    model = cfg.models.overrides.get(node, cfg.models.default)
    llm = ChatOpenAI(
        model=model,
        api_key=api_key,
        base_url=cfg.llm.base_url,
        temperature=cfg.llm.temperature,
        max_tokens=cfg.llm.max_tokens,
        timeout=cfg.llm.timeout_s,
        max_retries=cfg.llm.max_retries,
        extra_body={"enable_thinking": cfg.llm.enable_thinking},
    )
    runnable = llm.with_structured_output(structured) if structured else llm
    params = {
        "temperature": cfg.llm.temperature,
        "max_tokens": cfg.llm.max_tokens,
        "enable_thinking": cfg.llm.enable_thinking,
    }
    return maybe_cache(runnable, node=node, model=model, structured=structured, params=params)
