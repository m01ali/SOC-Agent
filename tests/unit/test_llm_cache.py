"""LLM record/replay cache tests — a fake runnable, no API involved.

Spec: ingestion-03-spec.md §13.4.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel

from soc_agent.llm.cache import (
    CachedRunnable,
    CacheMissError,
    LLMCallCounter,
    cache_key,
)


class _Draft(BaseModel):
    title: str
    confidence: float = 0.5


class _FakeStructuredRunnable:
    """Stands in for llm.with_structured_output(Model) — no network."""

    def __init__(self, result: BaseModel):
        self.result = result
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        return self.result

    async def ainvoke(self, messages):
        self.calls += 1
        return self.result


class _FakeChatMessage:
    def __init__(self, content: str, usage: dict):
        self.content = content
        self.usage_metadata = usage


class _FakeChatRunnable:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        return self.result


def _runnable(
    fake,
    *,
    mode,
    tmp_path,
    node="test_node",
    model="qwen3.7-max",
    structured=None,
    force=False,
    counter=None,
):
    return CachedRunnable(
        fake,
        mode=mode,
        directory=Path(tmp_path),
        node=node,
        model=model,
        structured=structured,
        params={"temperature": 0.0},
        force=force,
        counter=counter,
    )


# --- mode behavior -----------------------------------------------------------


def test_record_mode_writes_once_then_replays_without_calling_through(tmp_path):
    fake = _FakeStructuredRunnable(_Draft(title="hello"))
    cached = _runnable(fake, mode="record", tmp_path=tmp_path, structured=_Draft)

    first = cached.invoke([("user", "hi")])
    assert first == _Draft(title="hello")
    assert fake.calls == 1

    second = cached.invoke([("user", "hi")])
    assert second == _Draft(title="hello")
    assert fake.calls == 1  # no further call — served from cache


def test_replay_mode_hit_returns_cached_value(tmp_path):
    fake = _FakeStructuredRunnable(_Draft(title="hello"))
    recorder = _runnable(fake, mode="record", tmp_path=tmp_path, structured=_Draft)
    recorder.invoke([("user", "hi")])

    fake2 = _FakeStructuredRunnable(_Draft(title="should not be used"))
    replayer = _runnable(fake2, mode="replay", tmp_path=tmp_path, structured=_Draft)
    result = replayer.invoke([("user", "hi")])
    assert result == _Draft(title="hello")
    assert fake2.calls == 0


def test_replay_mode_miss_raises_cache_miss_error(tmp_path):
    fake = _FakeStructuredRunnable(_Draft(title="hello"))
    replayer = _runnable(fake, mode="replay", tmp_path=tmp_path, structured=_Draft)
    with pytest.raises(CacheMissError):
        replayer.invoke([("user", "never recorded")])
    assert fake.calls == 0


def test_off_mode_never_writes_always_calls_through(tmp_path):
    fake = _FakeStructuredRunnable(_Draft(title="hello"))
    cached = _runnable(fake, mode="off", tmp_path=tmp_path, structured=_Draft)
    cached.invoke([("user", "hi")])
    cached.invoke([("user", "hi")])
    assert fake.calls == 2
    assert list(Path(tmp_path).glob("*.json")) == []


def test_force_overwrites_existing_entry(tmp_path):
    fake1 = _FakeStructuredRunnable(_Draft(title="first"))
    r1 = _runnable(fake1, mode="record", tmp_path=tmp_path, structured=_Draft)
    r1.invoke([("user", "hi")])

    fake2 = _FakeStructuredRunnable(_Draft(title="second"))
    r2 = _runnable(fake2, mode="record", tmp_path=tmp_path, structured=_Draft, force=True)
    result = r2.invoke([("user", "hi")])
    assert result == _Draft(title="second")
    assert fake2.calls == 1

    r3 = _runnable(fake2, mode="replay", tmp_path=tmp_path, structured=_Draft)
    assert r3.invoke([("user", "hi")]) == _Draft(title="second")


# --- key sensitivity -----------------------------------------------------


def test_key_changes_with_model():
    a = cache_key("model-a", [("user", "hi")], structured=None, params={})
    b = cache_key("model-b", [("user", "hi")], structured=None, params={})
    assert a != b


def test_key_changes_with_params():
    a = cache_key("m", [("user", "hi")], structured=None, params={"temperature": 0.0})
    b = cache_key("m", [("user", "hi")], structured=None, params={"temperature": 0.5})
    assert a != b


def test_key_changes_with_prompt_text():
    a = cache_key("m", [("user", "hi")], structured=None, params={})
    b = cache_key("m", [("user", "bye")], structured=None, params={})
    assert a != b


def test_key_changes_with_structured_schema():
    class Other(BaseModel):
        note: str

    a = cache_key("m", [("user", "hi")], structured=_Draft, params={})
    b = cache_key("m", [("user", "hi")], structured=Other, params={})
    assert a != b


# --- collision safety ---------------------------------------------------------


def test_stale_key_in_file_treated_as_miss(tmp_path):
    fake = _FakeStructuredRunnable(_Draft(title="hello"))
    recorder = _runnable(fake, mode="record", tmp_path=tmp_path, structured=_Draft)
    recorder.invoke([("user", "hi")])

    # Corrupt the stored key to simulate a truncated-prefix collision.
    written = next(Path(tmp_path).glob("*.json"))
    import json

    entry = json.loads(written.read_text())
    entry["key"] = "not-the-real-key"
    written.write_text(json.dumps(entry))

    fake2 = _FakeStructuredRunnable(_Draft(title="recomputed"))
    cached = _runnable(fake2, mode="record", tmp_path=tmp_path, structured=_Draft, node="test_node")
    # Same cache_key as before -> same filename -> stale "key" field forces a fresh call.
    result = cached.invoke([("user", "hi")])
    assert result == _Draft(title="recomputed")
    assert fake2.calls == 1


# --- round-trip ----------------------------------------------------------------


def test_pydantic_entry_round_trips(tmp_path):
    fake = _FakeStructuredRunnable(_Draft(title="round trip", confidence=0.9))
    recorder = _runnable(fake, mode="record", tmp_path=tmp_path, structured=_Draft)
    original = recorder.invoke([("user", "hi")])

    replayer = _runnable(
        _FakeStructuredRunnable(_Draft(title="unused")),
        mode="replay",
        tmp_path=tmp_path,
        structured=_Draft,
    )
    replayed = replayer.invoke([("user", "hi")])
    assert replayed == original


def test_ai_message_entry_round_trips(tmp_path):
    msg = _FakeChatMessage("hello there", {"input_tokens": 10, "output_tokens": 5})
    fake = _FakeChatRunnable(msg)
    recorder = _runnable(fake, mode="record", tmp_path=tmp_path, structured=None)
    recorder.invoke([("user", "hi")])

    replayer = _runnable(_FakeChatRunnable(None), mode="replay", tmp_path=tmp_path, structured=None)
    replayed = replayer.invoke([("user", "hi")])
    assert replayed.content == "hello there"
    assert replayed.usage_metadata["input_tokens"] == 10
    assert replayed.usage_metadata["output_tokens"] == 5


# --- counter instrumentation --------------------------------------------------


def test_counter_tracks_hits_misses_and_live_calls(tmp_path):
    counter = LLMCallCounter()
    fake = _FakeStructuredRunnable(_Draft(title="hello"))
    cached = _runnable(fake, mode="record", tmp_path=tmp_path, structured=_Draft, counter=counter)

    cached.invoke([("user", "hi")])  # miss -> live call
    assert counter.live_calls == 1
    assert counter.hits == 0

    cached.invoke([("user", "hi")])  # hit
    assert counter.hits == 1
    assert counter.live_calls == 1
