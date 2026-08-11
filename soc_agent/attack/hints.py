"""Rule-hint and keyword table loaders. Spec: attack-mapping-06-spec.md §7-§8."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from soc_agent.attack.catalog import AttackCatalog
from soc_agent.config import ConfigError


def _load_yaml(path: str) -> Any:
    try:
        return yaml.safe_load(Path(path).read_text())
    except FileNotFoundError as e:
        raise ConfigError(f"file not found: {path}") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {path}: {e}") from e


def _check_ids(ids: list[str], catalog: AttackCatalog, source: str, context: str) -> None:
    for technique_id in ids:
        if technique_id not in catalog:
            raise ConfigError(
                f"{source}: {context} references {technique_id!r}, "
                "which is not in the ATT&CK catalog"
            )


# The parse is cached by path; catalog validation runs on every call. AttackCatalog
# holds dicts and is therefore unhashable, and validation is a handful of set lookups —
# cheap enough that trading it for a cache key would be a false economy.
@lru_cache(maxsize=4)
def _parse_rule_hints(path: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    payload = _load_yaml(path)
    rules = (payload or {}).get("rules") or {}
    if not isinstance(rules, dict):
        raise ConfigError(f"{path}: 'rules' must be a mapping")
    parsed: list[tuple[str, tuple[str, ...]]] = []
    for rule, ids in rules.items():
        if not isinstance(ids, list):
            raise ConfigError(f"{path}: rule {rule!r} must map to a list of technique ids")
        # Rules are matched case-insensitively; SIEMs are inconsistent about casing.
        parsed.append((str(rule).strip().lower(), tuple(ids)))
    return tuple(parsed)


@lru_cache(maxsize=4)
def _parse_keywords(path: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    payload = _load_yaml(path)
    keywords = (payload or {}).get("keywords") or {}
    if not isinstance(keywords, dict):
        raise ConfigError(f"{path}: 'keywords' must be a mapping")
    table: list[tuple[str, tuple[str, ...]]] = []
    for technique_id, phrases in keywords.items():
        if not isinstance(phrases, list):
            raise ConfigError(f"{path}: {technique_id!r} must map to a list of phrases")
        table.append((str(technique_id), tuple(p.lower() for p in phrases)))
    # Sorted so shortlist scoring is order-independent and reproducible.
    return tuple(sorted(table))


def rule_hints(path: str, catalog: AttackCatalog) -> dict[str, tuple[str, ...]]:
    parsed = _parse_rule_hints(path)
    for rule, ids in parsed:
        _check_ids(list(ids), catalog, path, f"rule {rule!r}")
    return dict(parsed)


def keyword_table(path: str, catalog: AttackCatalog) -> tuple[tuple[str, tuple[str, ...]], ...]:
    table = _parse_keywords(path)
    for technique_id, _phrases in table:
        _check_ids([technique_id], catalog, path, "keyword entry")
    return table


def hints_for_rule(vendor_rule: str | None, path: str, catalog: AttackCatalog) -> tuple[str, ...]:
    if not vendor_rule:
        return ()
    return rule_hints(path, catalog).get(vendor_rule.strip().lower(), ())
