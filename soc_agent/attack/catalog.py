"""ATT&CK catalog loading, validation and tactic resolution.

Spec: attack-mapping-06-spec.md §4-§5 (Architecture §5.5).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from soc_agent.config import ConfigError, get_config
from soc_agent.models.alert import AlertCategory
from soc_agent.models.attack import TACTIC_ID_PATTERN, TECHNIQUE_ID_PATTERN

CATALOG_SCHEMA = "soc-agent/attack-catalog@v1"

_TECHNIQUE_RE = re.compile(TECHNIQUE_ID_PATTERN)
_TACTIC_RE = re.compile(TACTIC_ID_PATTERN)

# §5 — the tactic an alert's category implies. A *preference*, not an override: when the
# technique does not carry this tactic, resolve_tactic falls back to the technique's own
# first kill-chain phase. That is what makes T1046 + reconnaissance resolve to TA0007
# Discovery (scanning from inside a network you already reached) rather than TA0043.
CATEGORY_TACTICS: dict[str, str] = {
    "command_and_control": "TA0011",
    "phishing": "TA0001",
    "lateral_movement": "TA0008",
    "exfiltration": "TA0010",
    "credential_access": "TA0006",
    "initial_access": "TA0001",
    "persistence": "TA0003",
    "reconnaissance": "TA0043",
    "malware": "TA0002",
    # policy_violation / anomaly / other imply no tactic.
}


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    parent_id: str | None
    summary: str


@dataclass(frozen=True)
class AttackCatalog:
    tactics: dict[str, str]
    techniques: dict[str, Technique]
    bundle_version: str = "unknown"
    built_at: str = "unknown"

    def __contains__(self, technique_id: object) -> bool:
        return technique_id in self.techniques

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id)

    def resolve_tactic(
        self, technique_id: str, category: AlertCategory | str | None = None
    ) -> tuple[str | None, str | None]:
        """(tactic_id, tactic_name) — the alert category's tactic when the technique has
        it, else the technique's first kill-chain phase (§5).

        145 of 697 techniques carry more than one tactic while AttackMapping carries one;
        T1078 alone belongs to four, and picking arbitrarily would label an
        impossible-travel sign-in as a persistence technique.
        """
        technique = self.techniques.get(technique_id)
        if technique is None or not technique.tactics:
            return None, None
        preferred = CATEGORY_TACTICS.get(category or "")
        tactic_id = preferred if preferred in technique.tactics else technique.tactics[0]
        return tactic_id, self.tactics.get(tactic_id)


def _validate(payload: Any, source: str) -> AttackCatalog:
    if not isinstance(payload, dict):
        raise ConfigError(f"{source}: catalog root must be a mapping")
    if payload.get("schema") != CATALOG_SCHEMA:
        raise ConfigError(
            f"{source}: expected schema {CATALOG_SCHEMA!r}, got {payload.get('schema')!r}"
        )

    tactics = payload.get("tactics")
    if not isinstance(tactics, dict) or not tactics:
        raise ConfigError(f"{source}: 'tactics' must be a non-empty mapping")
    for tactic_id in tactics:
        if not _TACTIC_RE.match(tactic_id):
            raise ConfigError(f"{source}: invalid tactic id {tactic_id!r}")

    raw_techniques = payload.get("techniques")
    if not isinstance(raw_techniques, dict) or not raw_techniques:
        raise ConfigError(f"{source}: 'techniques' must be a non-empty mapping")

    techniques: dict[str, Technique] = {}
    for technique_id, entry in raw_techniques.items():
        if not _TECHNIQUE_RE.match(technique_id):
            raise ConfigError(f"{source}: invalid technique id {technique_id!r}")
        entry_tactics = tuple(entry.get("tactics") or ())
        for tactic_id in entry_tactics:
            if tactic_id not in tactics:
                raise ConfigError(
                    f"{source}: {technique_id} references unknown tactic {tactic_id!r}"
                )
        techniques[technique_id] = Technique(
            technique_id=technique_id,
            name=entry["name"],
            tactics=entry_tactics,
            parent_id=entry.get("parent_id"),
            summary=entry.get("summary", ""),
        )

    for technique in techniques.values():
        if technique.parent_id is not None and technique.parent_id not in techniques:
            raise ConfigError(
                f"{source}: {technique.technique_id} has dangling parent {technique.parent_id!r}"
            )

    return AttackCatalog(
        tactics=dict(tactics),
        techniques=techniques,
        bundle_version=str(payload.get("bundle_version", "unknown")),
        built_at=str(payload.get("built_at", "unknown")),
    )


@lru_cache(maxsize=4)
def load_catalog(path: str | None = None) -> AttackCatalog:
    resolved = path or get_config().attack.catalog
    try:
        payload = json.loads(Path(resolved).read_text())
    except FileNotFoundError as e:
        raise ConfigError(
            f"ATT&CK catalog not found: {resolved}. Run `make catalog` to build it."
        ) from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"invalid JSON in {resolved}: {e}") from e
    return _validate(payload, str(resolved))


def catalog_from_dict(payload: Any, source: str = "<memory>") -> AttackCatalog:
    """Validation entry point for tests and for hand-built catalogs."""
    return _validate(payload, source)
