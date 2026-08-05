"""Defang/refang with an original-text index map. Spec: extraction-04-spec.md §7.1."""

from __future__ import annotations

from dataclasses import dataclass

_BASE_TOKENS: tuple[tuple[str, str], ...] = (
    ("hxxp", "http"),
    ("[://]", "://"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("[@]", "@"),
    ("(@)", "@"),
    ("{@}", "@"),
    ("[dot]", "."),
    ("[at]", "@"),
)

_AGGRESSIVE_TOKENS: tuple[tuple[str, str], ...] = (
    (" dot ", "."),
    (" at ", "@"),
    ("\\.", "."),
)


def _tokens(aggressive: bool) -> list[tuple[str, str]]:
    table = list(_BASE_TOKENS) + (list(_AGGRESSIVE_TOKENS) if aggressive else [])
    return sorted(table, key=lambda pair: len(pair[0]), reverse=True)


@dataclass(frozen=True)
class Refanged:
    text: str
    index_map: list[int]  # index_map[i] = index in the ORIGINAL text of refanged char i


def original_span(original: str, refanged: Refanged, start: int, end: int) -> str:
    """Recover the original substring underlying refanged.text[start:end]."""
    if start >= end:
        return ""
    return original[refanged.index_map[start] : refanged.index_map[end - 1] + 1]


def refang(text: str, *, aggressive: bool = False) -> Refanged:
    """Single left-to-right pass. At each position, try each token (longest first);
    on a hit append the replacement and record an original index for every emitted
    character, else copy one character through."""
    tokens = _tokens(aggressive)
    out: list[str] = []
    index_map: list[int] = []
    i = 0
    n = len(text)
    lowered = text.lower()
    while i < n:
        match: tuple[str, str] | None = None
        for token, replacement in tokens:
            token_len = len(token)
            if lowered[i : i + token_len] == token:
                match = (token, replacement)
                break
        if match is not None:
            token, replacement = match
            start, length = i, len(token)
            r = len(replacement)
            for k in range(r):
                if r == 1:
                    orig_idx = start + length - 1
                else:
                    orig_idx = start + round(k * (length - 1) / (r - 1))
                out.append(replacement[k])
                index_map.append(orig_idx)
            i += length
        else:
            out.append(text[i])
            index_map.append(i)
            i += 1
    return Refanged(text="".join(out), index_map=index_map)
