"""`soc-agent schema` export tests. Spec: data-contracts-02-spec.md §8."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from soc_agent.cli import app

REPO_ROOT = Path(__file__).parents[2]
COMMITTED_SCHEMA = REPO_ROOT / "schemas" / "output.schema.json"

runner = CliRunner()


def test_schema_export_exits_zero_and_writes_valid_json(tmp_path):
    out = tmp_path / "x.json"
    result = runner.invoke(app, ["schema", "--out", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    payload = json.loads(out.read_text())
    assert "schema_version" in payload["properties"]


def test_schema_export_is_deterministic(tmp_path):
    out1 = tmp_path / "a.json"
    out2 = tmp_path / "b.json"
    runner.invoke(app, ["schema", "--out", str(out1)])
    runner.invoke(app, ["schema", "--out", str(out2)])
    assert out1.read_bytes() == out2.read_bytes()


def test_committed_schema_is_current(tmp_path):
    out = tmp_path / "committed_check.json"
    runner.invoke(app, ["schema", "--out", str(out)])
    assert out.read_bytes() == COMMITTED_SCHEMA.read_bytes()
