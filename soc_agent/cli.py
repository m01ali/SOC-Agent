"""Typer CLI. Spec: project-setup-01-spec.md §8.

Exit codes: 0 success/partial · 1 stub/not-implemented · 2 failed input · 3 config/auth/unexpected.
stdout is reserved for output JSON (enrich); diagnostics and logs go to stderr.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv

from soc_agent.config import ConfigError, current_config_path, get_config, set_config_path

app = typer.Typer(
    help="SOC alert-enrichment agent (POC).",
    no_args_is_help=True,
    add_completion=False,
)

_LOG_LEVELS = ("debug", "info", "warning", "error")


@app.callback()
def _global_options(
    config: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
    log_level: Annotated[
        str, typer.Option("--log-level", help="debug|info|warning|error")
    ] = "info",
) -> None:
    level = log_level.lower()
    if level not in _LOG_LEVELS:
        raise typer.BadParameter(f"--log-level must be one of {list(_LOG_LEVELS)}")
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    set_config_path(config)


def _fail(msg: str) -> None:
    typer.secho(f"✗ {msg}", fg=typer.colors.RED)
    raise typer.Exit(3)


def _stub(spec: str) -> None:
    typer.echo(f"not implemented — see specs/{spec}")
    raise typer.Exit(1)


@app.command()
def check() -> None:
    """Verify config, API key, and live Qwen connectivity (~50 tokens)."""
    # 1. Config loads and validates
    try:
        cfg = get_config()
    except ConfigError as e:
        _fail(f"config: {e}")
    source = current_config_path() or "built-in defaults"
    typer.secho(
        f"✓ config loaded ({source}); default model: {cfg.models.default}",
        fg=typer.colors.GREEN,
    )

    # 2. API key present
    key = os.environ.get("DASHSCOPE_API_KEY")
    if not key:
        _fail("DASHSCOPE_API_KEY is not set. Copy .env.example to .env and add your key.")
    masked = f"{key[:3]}…{key[-4:]}" if len(key) >= 8 else "…"
    typer.secho(f"✓ DASHSCOPE_API_KEY present ({masked})", fg=typer.colors.GREEN)

    # 3. One live round-trip through the factory
    from soc_agent.llm.client import get_llm  # local import keeps CLI startup light

    try:
        t0 = time.perf_counter()
        resp = get_llm("check").invoke("Reply with the single word OK.")
        dt_ms = (time.perf_counter() - t0) * 1000
    except Exception as e:  # noqa: BLE001 — any failure here is a setup problem
        _fail(f"endpoint call failed: {e}")
    usage = getattr(resp, "usage_metadata", None) or {}
    model = cfg.models.overrides.get("check", cfg.models.default)
    typer.secho(
        f"✓ endpoint reachable — model {model}, {dt_ms:.0f} ms, "
        f"tokens in/out: {usage.get('input_tokens', '?')}/{usage.get('output_tokens', '?')}",
        fg=typer.colors.GREEN,
    )

    # 4. LangSmith sanity (non-fatal)
    if os.environ.get("LANGSMITH_TRACING") and not os.environ.get("LANGSMITH_API_KEY"):
        typer.secho(
            "⚠ LANGSMITH_TRACING is set but LANGSMITH_API_KEY is missing — tracing will fail",
            fg=typer.colors.YELLOW,
        )

    typer.secho("All checks passed.", fg=typer.colors.GREEN, bold=True)


@app.command()
def normalize(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="Alert file to normalize.")],
    fmt: Annotated[
        str | None, typer.Option("--format", help="generic|splunk|elastic|cef|freetext")
    ] = None,
    pretty: Annotated[bool, typer.Option("--pretty")] = False,
) -> None:
    """Detect the format and print the canonical alert as JSON (spec 03 debugging surface)."""
    import json

    from soc_agent.ingest import IngestError, load_input
    from soc_agent.ingest import normalize as normalize_alert
    from soc_agent.llm.client import MissingAPIKeyError

    try:
        raw = load_input(input_path)
        alert = normalize_alert(raw, hint=fmt)  # type: ignore[arg-type]
    except MissingAPIKeyError as e:
        _fail(str(e))
    except IngestError as e:
        typer.secho(f"✗ {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from e

    payload = alert.model_dump(mode="json")
    indent = 2 if pretty else None
    typer.echo(json.dumps(payload, indent=indent, sort_keys=pretty))


@app.command()
def enrich(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="Alert file to enrich.")],
) -> None:
    """Enrich a single SIEM alert (spec 08)."""
    _stub("graph-cli-08-spec.md")


@app.command(name="enrich-dir")
def enrich_dir(
    directory: Annotated[Path, typer.Argument(help="Directory of alert files.")],
    out: Annotated[Path | None, typer.Option("--out", help="Output directory.")] = None,
) -> None:
    """Batch-enrich a directory of alerts (spec 08)."""
    _stub("graph-cli-08-spec.md")


@app.command()
def seed() -> None:
    """Build local seed data: history.db and caches (spec 05)."""
    _stub("enrichment-05-spec.md")


@app.command(name="eval")
def eval_cmd() -> None:
    """Run the labeled eval set and print metrics (spec 09)."""
    _stub("hardening-eval-09-spec.md")


@app.command()
def schema(
    out: Annotated[Path, typer.Option("--out", help="Output path.")] = Path(
        "schemas/output.schema.json"
    ),
) -> None:
    """Export the output JSON Schema."""
    import json

    from soc_agent.models import EnrichmentOutput

    out.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(EnrichmentOutput.model_json_schema(), indent=2, sort_keys=True) + "\n"
    out.write_text(payload)
    typer.echo(str(out))


def main() -> None:
    load_dotenv()
    app()
