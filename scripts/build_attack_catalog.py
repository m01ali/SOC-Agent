#!/usr/bin/env python
"""Build data/attack_catalog.json from the official ATT&CK Enterprise STIX bundle.

Spec: attack-mapping-06-spec.md §4 (Architecture §7.2).

The only thing in the POC that touches the network. It runs once, its 328 KB output is
committed, and `make test` never invokes it — so the POC itself needs no network.

    python scripts/build_attack_catalog.py --out data/attack_catalog.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_STIX = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
CATALOG_SCHEMA = "soc-agent/attack-catalog@v1"
SUMMARY_LIMIT = 400

_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_HTML = re.compile(r"<[^>]+>")


def external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def clean_text(text: str) -> str:
    text = _CITATION.sub("", text)
    text = _MD_LINK.sub(r"\1", text)
    text = _HTML.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def summarize(description: str, limit: int = SUMMARY_LIMIT) -> str:
    """Cleaned, capped at `limit`, cut at the last sentence boundary (§4.3).

    Full descriptions run median ~1300 chars; at 12 candidates that is ~3.9k tokens of
    prompt per alert, against Architecture §14's ~10.5k budget for all four LLM calls.
    """
    text = clean_text(description)
    if len(text) <= limit:
        return text
    cut = text[:limit]
    boundary = cut.rfind(". ")
    return cut[: boundary + 1] if boundary > limit // 2 else cut.rstrip() + "…"


def load_bundle(source: str) -> dict[str, Any]:
    if source.startswith(("http://", "https://")):
        print(f"fetching {source} …", file=sys.stderr)
        with urllib.request.urlopen(source, timeout=300) as response:  # noqa: S310 - pinned URL
            return json.loads(response.read())
    return json.loads(Path(source).read_text())


def build_catalog(bundle: dict[str, Any]) -> dict[str, Any]:
    objects = bundle["objects"]

    # shortname -> (id, name); kill_chain_phases[].phase_name joins on the shortname.
    tactics_by_shortname: dict[str, tuple[str, str]] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            tactic_id = external_id(obj)
            if tactic_id:
                tactics_by_shortname[obj["x_mitre_shortname"]] = (tactic_id, obj["name"])

    # Revoked and deprecated techniques are excluded deliberately (§4.1): a revoked ID
    # still matches TECHNIQUE_ID_PATTERN and still appears in old detection rules, so it
    # would pass spec 06 §11 validation as a technique that no longer exists.
    live = [
        obj
        for obj in objects
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked")
        and not obj.get("x_mitre_deprecated")
    ]
    by_id = {tid: obj for obj in live if (tid := external_id(obj))}

    techniques: dict[str, Any] = {}
    for technique_id, obj in sorted(by_id.items()):
        name = obj["name"]
        parent_id = None
        if obj.get("x_mitre_is_subtechnique"):
            parent_id = technique_id.split(".")[0]
            parent = by_id.get(parent_id)
            if parent is not None:
                # STIX stores the short form ("Web Protocols"); Architecture Appendix B
                # and every Navigator view use "Application Layer Protocol: Web Protocols".
                name = f"{parent['name']}: {name}"
        techniques[technique_id] = {
            "name": name,
            "tactics": [
                tactics_by_shortname[phase["phase_name"]][0]
                for phase in obj.get("kill_chain_phases", [])
                if phase["phase_name"] in tactics_by_shortname
            ],
            "parent_id": parent_id,
            "summary": summarize(obj.get("description", "")),
        }

    versions = {obj.get("x_mitre_attack_spec_version") for obj in live}
    versions.discard(None)

    return {
        "schema": CATALOG_SCHEMA,
        "source": "mitre-attack enterprise",
        "bundle_version": sorted(versions)[-1] if versions else "unknown",
        "built_at": datetime.now(UTC).date().isoformat(),
        "tactics": {tid: name for tid, name in sorted(tactics_by_shortname.values())},
        "techniques": techniques,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix", default=DEFAULT_STIX, help="STIX bundle URL or local path.")
    parser.add_argument("--out", default="data/attack_catalog.json", help="Catalog output path.")
    args = parser.parse_args()

    catalog = build_catalog(load_bundle(args.stix))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(catalog, indent=1, sort_keys=True) + "\n")

    size_kb = out.stat().st_size / 1024
    print(
        f"✓ {out}: {len(catalog['techniques'])} techniques, "
        f"{len(catalog['tactics'])} tactics, {size_kb:.0f} KB "
        f"(bundle spec {catalog['bundle_version']})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
