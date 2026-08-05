"""LLM record/replay cache. Spec: ingestion-03-spec.md §11.

Wired transparently into `get_llm()` — every pipeline node gets caching for free
with no awareness of it. This is what keeps the POC inside the free token quota
(Architecture §14): once a prompt is recorded, every later run replays at zero cost.

Modes, selected by SOC_AGENT_LLM_CACHE:
  off (default) - no caching, direct call through.
  record        - cache hit -> replay; miss -> call, then persist.
  replay        - cache hit -> replay; miss -> raise CacheMissError (never spends silently).

Cache directory: SOC_AGENT_LLM_CACHE_DIR, default tests/llm_cache/ (committed to git).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

DEFAULT_CACHE_DIR = Path("tests/llm_cache")


class CacheMissError(RuntimeError):
    """No cache entry found in replay mode. Never spends silently."""


def _message_pairs(messages: Any) -> list[list[str]]:
    if isinstance(messages, str):
        return [["human", messages]]
    pairs: list[list[str]] = []
    for m in messages:
        if isinstance(m, tuple):
            role, content = m[0], m[1]
        elif hasattr(m, "type") and hasattr(m, "content"):
            role, content = m.type, m.content
        else:
            role, content = "unknown", str(m)
        pairs.append([str(role), str(content)])
    return pairs


def cache_key(
    model: str,
    messages: Any,
    *,
    structured: type[BaseModel] | None,
    params: dict[str, Any],
) -> str:
    """Deterministic key over everything that affects the response.

    Including the structured model's JSON Schema means a contract edit busts exactly
    the affected entries instead of replaying a response that no longer validates.
    """
    payload = json.dumps(
        {
            "model": model,
            "params": params,
            "structured": structured.__name__ if structured is not None else None,
            "schema": structured.model_json_schema() if structured is not None else None,
            "messages": _message_pairs(messages),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _entry_path(directory: Path, node: str, key: str) -> Path:
    return directory / f"{node}-{key[:16]}.json"


def _dump_result(
    result: Any, structured: type[BaseModel] | None
) -> tuple[str, str | None, dict[str, Any], dict[str, Any]]:
    """Return (kind, schema_name, data, usage_metadata)."""
    if structured is not None:
        return "pydantic", structured.__name__, result.model_dump(mode="json"), {}
    usage = dict(getattr(result, "usage_metadata", None) or {})
    return "ai_message", None, {"content": result.content}, usage


def _load_result(entry: dict[str, Any], structured: type[BaseModel] | None) -> Any:
    if entry["kind"] == "pydantic":
        if structured is None:
            node = entry.get("node")
            raise CacheMissError(f"cached entry {node!r} is 'pydantic' but no schema requested")
        return structured.model_validate(entry["data"])

    from langchain_core.messages import AIMessage

    usage = entry.get("usage_metadata") or None
    if usage and "total_tokens" not in usage:
        total = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        usage = {**usage, "total_tokens": total}

    return AIMessage(content=entry["data"]["content"], usage_metadata=usage)


class CachedRunnable:
    """Wraps a runnable's invoke/ainvoke with record/replay caching."""

    def __init__(
        self,
        runnable: Any,
        *,
        mode: str,
        directory: Path,
        node: str,
        model: str,
        structured: type[BaseModel] | None,
        params: dict[str, Any],
        force: bool = False,
        counter: LLMCallCounter | None = None,
    ) -> None:
        self._runnable = runnable
        self._mode = mode
        self._directory = directory
        self._node = node
        self._model = model
        self._structured = structured
        self._params = params
        self._force = force
        self._counter = counter

    def _lookup(self, key: str) -> Any | None:
        path = _entry_path(self._directory, self._node, key)
        if not path.exists():
            return None
        entry = json.loads(path.read_text())
        if entry.get("key") != key:
            # Truncated-key collision — treat as a miss rather than serve the wrong response.
            return None
        return entry

    def _persist(self, key: str, result: Any) -> None:
        self._directory.mkdir(parents=True, exist_ok=True)
        kind, schema_name, data, usage = _dump_result(result, self._structured)
        entry = {
            "key": key,
            "node": self._node,
            "model": self._model,
            "recorded_at": datetime.now(UTC).isoformat(),
            "kind": kind,
            "schema_name": schema_name,
            "data": data,
            "usage_metadata": usage,
        }
        path = _entry_path(self._directory, self._node, key)
        path.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n")

    def invoke(self, messages: Any, *args: Any, **kwargs: Any) -> Any:
        if self._mode not in ("record", "replay"):
            return self._runnable.invoke(messages, *args, **kwargs)

        key = cache_key(self._model, messages, structured=self._structured, params=self._params)

        if not self._force:
            entry = self._lookup(key)
            if entry is not None:
                if self._counter is not None:
                    self._counter.hits += 1
                return _load_result(entry, self._structured)

        if self._mode == "replay":
            if self._counter is not None:
                self._counter.misses += 1
            raise CacheMissError(f"no cached response for node={self._node!r} key={key}")

        if self._counter is not None:
            self._counter.live_calls += 1
        result = self._runnable.invoke(messages, *args, **kwargs)
        self._persist(key, result)
        return result

    async def ainvoke(self, messages: Any, *args: Any, **kwargs: Any) -> Any:
        if self._mode not in ("record", "replay"):
            return await self._runnable.ainvoke(messages, *args, **kwargs)

        key = cache_key(self._model, messages, structured=self._structured, params=self._params)

        if not self._force:
            entry = self._lookup(key)
            if entry is not None:
                if self._counter is not None:
                    self._counter.hits += 1
                return _load_result(entry, self._structured)

        if self._mode == "replay":
            if self._counter is not None:
                self._counter.misses += 1
            raise CacheMissError(f"no cached response for node={self._node!r} key={key}")

        if self._counter is not None:
            self._counter.live_calls += 1
        result = await self._runnable.ainvoke(messages, *args, **kwargs)
        self._persist(key, result)
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self._runnable, name)


class LLMCallCounter:
    """Test-only instrumentation: hit/miss/live counts across cached calls."""

    def __init__(self) -> None:
        self.hits = 0
        self.misses = 0
        self.live_calls = 0

    def reset(self) -> None:
        self.hits = self.misses = self.live_calls = 0


_active_counter: LLMCallCounter | None = None


def set_active_counter(counter: LLMCallCounter | None) -> None:
    """Test hook: route cache hit/miss/live-call counts to `counter` (or disable)."""
    global _active_counter
    _active_counter = counter


def maybe_cache(
    runnable: Any,
    *,
    node: str,
    model: str,
    structured: type[BaseModel] | None,
    params: dict[str, Any],
) -> Any:
    mode = os.environ.get("SOC_AGENT_LLM_CACHE", "off")
    if mode not in ("record", "replay"):
        return runnable
    directory = Path(os.environ.get("SOC_AGENT_LLM_CACHE_DIR", str(DEFAULT_CACHE_DIR)))
    force = mode == "record" and os.environ.get("SOC_AGENT_LLM_CACHE_FORCE") == "1"
    return CachedRunnable(
        runnable,
        mode=mode,
        directory=directory,
        node=node,
        model=model,
        structured=structured,
        params=params,
        force=force,
        counter=_active_counter,
    )
