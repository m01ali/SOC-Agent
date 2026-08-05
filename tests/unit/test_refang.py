"""Refang matrix + index-map correctness. Spec: extraction-04-spec.md §16.1."""

from __future__ import annotations

import pytest

from soc_agent.extract.refang import original_span, refang

DEFANG_MATRIX = [
    ("hxxp://evil.com", "http://evil.com"),
    ("hXXps://evil.com", "https://evil.com"),
    ("1.2.3[.]4", "1.2.3.4"),
    ("evil[.]com", "evil.com"),
    ("evil(.)com", "evil.com"),
    ("evil{.}com", "evil.com"),
    ("user[@]corp[.]com", "user@corp.com"),
    ("evil[dot]com", "evil.com"),
    ("hxxps[://]host", "https://host"),
]


@pytest.mark.parametrize("original,expected", DEFANG_MATRIX)
def test_defang_matrix(original: str, expected: str) -> None:
    assert refang(original).text == expected


@pytest.mark.parametrize("original,expected", DEFANG_MATRIX)
def test_index_map_recovers_full_span(original: str, expected: str) -> None:
    r = refang(original)
    recovered = original_span(original, r, 0, len(r.text))
    assert recovered == original


@pytest.mark.parametrize("original,expected", DEFANG_MATRIX)
def test_idempotent(original: str, expected: str) -> None:
    once = refang(original).text
    twice = refang(once).text
    assert once == twice


def test_prose_safe_by_default() -> None:
    text = "the alert fired at 03:00 and the dot matched"
    assert refang(text).text == text


def test_aggressive_refang_changes_prose() -> None:
    text = "the alert fired at 03:00 and the dot matched"
    result = refang(text, aggressive=True).text
    assert result != text
    assert "@03:00" in result
    assert "the.matched" in result


def test_aggressive_backslash_dot() -> None:
    assert refang("evil\\.com", aggressive=True).text == "evil.com"
    assert refang("evil\\.com", aggressive=False).text == "evil\\.com"


def test_empty_string() -> None:
    r = refang("")
    assert r.text == ""
    assert r.index_map == []
