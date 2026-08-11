"""Phase-01 scaffold tests — no API calls. Spec: project-setup-01-spec.md §11."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import soc_agent
from soc_agent.cli import app
from soc_agent.config import ConfigError, load_config
from soc_agent.llm.client import MissingAPIKeyError, get_llm

REPO_ROOT = Path(__file__).parents[2]
CONFIG_YAML = REPO_ROOT / "config.yaml"

runner = CliRunner()


def test_version():
    assert soc_agent.__version__ == "0.1.0"


def test_repo_config_loads():
    cfg = load_config(CONFIG_YAML)
    assert cfg.models.default == "qwen3.7-max"
    assert "dashscope-intl" in cfg.llm.base_url
    weights = cfg.scoring.weights
    assert abs((weights.ti + weights.severity + weights.history) - 1.0) <= 0.001


def test_defaults_without_config_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no config.yaml here -> built-in defaults
    cfg = load_config()
    assert cfg.models.default == "qwen3.7-max"
    assert cfg.llm.max_tokens == 4096
    assert cfg.llm.enable_thinking is False


def test_env_overrides_yaml(monkeypatch):
    monkeypatch.setenv("SOC_AGENT_LLM__MAX_TOKENS", "1024")
    cfg = load_config(CONFIG_YAML)
    assert cfg.llm.max_tokens == 1024
    assert cfg.llm.temperature == 0.0  # untouched keys still come from YAML


def test_invalid_weights_raise_config_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("scoring:\n  weights: { ti: 0.5, severity: 0.3, history: 0.1 }\n")
    with pytest.raises(ConfigError, match="sum to 1.0"):
        load_config(bad)


def test_cli_help_lists_all_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("check", "enrich", "enrich-dir", "seed", "eval", "schema"):
        assert command in result.output


@pytest.mark.parametrize(
    ("args", "spec"),
    [
        (["enrich", "x.json"], "graph-cli-08-spec.md"),
        (["enrich-dir", "alerts/"], "graph-cli-08-spec.md"),
        (["eval"], "hardening-eval-09-spec.md"),
    ],
)
def test_stub_commands_exit_1_with_spec_pointer(args, spec):
    """`seed` left this list in spec 05; `normalize`/`extract`/`context` were never stubs."""
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    assert spec in result.output


def test_check_without_key_exits_3(monkeypatch):
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    monkeypatch.chdir(REPO_ROOT)
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 3
    assert ".env" in result.output


def test_get_llm_without_key_raises(monkeypatch):
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    monkeypatch.setenv("SOC_AGENT_LLM_CACHE", "off")
    with pytest.raises(MissingAPIKeyError):
        get_llm("check")


def test_get_llm_without_key_in_replay_mode_does_not_raise(monkeypatch):
    """extraction-04-spec.md §13.2: a keyless machine can replay the committed LLM
    cache. The placeholder key is never used — a cache hit returns before any HTTP
    call, and a miss raises CacheMissError, not MissingAPIKeyError."""
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    monkeypatch.setenv("SOC_AGENT_LLM_CACHE", "replay")
    get_llm("check")
