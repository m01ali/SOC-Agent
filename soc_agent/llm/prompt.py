"""Versioned prompt loader. Spec: ingestion-03-spec.md §10.2."""

from __future__ import annotations

from functools import cache
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent / "prompts"


@cache
def load_prompt(name: str) -> str:
    return (_PROMPTS_DIR / f"{name}.md").read_text(encoding="utf-8")


def render_messages(name: str, **fmt: str) -> list[tuple[str, str]]:
    """Split a prompt file on `## system` / `## user` headings and interpolate `fmt`.

    Returns a list of (role, content) pairs suitable for ChatOpenAI's message format.
    """
    text = load_prompt(name)
    messages: list[tuple[str, str]] = []
    role: str | None = None
    buf: list[str] = []
    for line in text.splitlines():
        stripped = line.strip().lower()
        if stripped in ("## system", "## user"):
            if role is not None:
                messages.append((role, "\n".join(buf).strip()))
            role = stripped[3:]
            buf = []
            continue
        if line.startswith("<!--"):
            continue
        buf.append(line)
    if role is not None:
        messages.append((role, "\n".join(buf).strip()))

    def _interpolate(content: str) -> str:
        for key, value in fmt.items():
            content = content.replace("{" + key + "}", value)
        return content

    return [(role, _interpolate(content)) for role, content in messages]
