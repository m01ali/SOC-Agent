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
def extract(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="Alert file to extract.")],
    fmt: Annotated[
        str | None, typer.Option("--format", help="generic|splunk|elastic|cef|freetext")
    ] = None,
    no_llm: Annotated[
        bool, typer.Option("--no-llm", help="Force extraction.llm_assist=never.")
    ] = False,
    pretty: Annotated[bool, typer.Option("--pretty")] = False,
) -> None:
    """Normalize an alert and print its extracted entities as JSON (spec 04 debugging surface)."""
    import json

    from soc_agent.extract import extract_entities, ioc_entities
    from soc_agent.ingest import IngestError, load_input
    from soc_agent.ingest import normalize as normalize_alert
    from soc_agent.llm.client import MissingAPIKeyError

    try:
        raw = load_input(input_path)
        alert = normalize_alert(raw, hint=fmt)  # type: ignore[arg-type]
        result = extract_entities(alert, llm_assist_mode="never" if no_llm else None)
    except MissingAPIKeyError as e:
        _fail(str(e))
    except IngestError as e:
        typer.secho(f"✗ {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from e

    payload = {
        "alert_id": alert.alert_id,
        "entities": [e.model_dump(mode="json") for e in result.entities],
        "iocs": [e.value for e in ioc_entities(result.entities)],
        "errors": [e.model_dump(mode="json") for e in result.errors],
        "dropped": result.dropped,
        "llm_used": result.llm_used,
    }
    indent = 2 if pretty else None
    typer.echo(json.dumps(payload, indent=indent, sort_keys=pretty))


@app.command()
def context(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="Alert file to enrich.")],
    fmt: Annotated[
        str | None, typer.Option("--format", help="generic|splunk|elastic|cef|freetext")
    ] = None,
    no_ti: Annotated[bool, typer.Option("--no-ti", help="Skip threat-intel lookups.")] = False,
    no_history: Annotated[
        bool, typer.Option("--no-history", help="Skip historical correlation.")
    ] = False,
    pretty: Annotated[bool, typer.Option("--pretty")] = False,
) -> None:
    """Normalize, extract, then print the TI and history context as JSON (spec 05 surface)."""
    import json

    from soc_agent.extract import extract_entities, ioc_entities
    from soc_agent.ingest import IngestError, load_input
    from soc_agent.ingest import normalize as normalize_alert
    from soc_agent.llm.client import MissingAPIKeyError
    from soc_agent.providers.history import correlate
    from soc_agent.providers.ti import enrich_ti_sync

    cfg = get_config()
    try:
        raw = load_input(input_path)
        alert = normalize_alert(raw, hint=fmt)  # type: ignore[arg-type]
        extraction = extract_entities(alert)
    except MissingAPIKeyError as e:
        _fail(str(e))
    except IngestError as e:
        typer.secho(f"✗ {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from e

    errors = [e.model_dump(mode="json") for e in extraction.errors]

    threat_intel = None
    ti_providers: list[str] = []
    if not no_ti:
        ti = enrich_ti_sync(extraction.entities, config=cfg.threat_intel)
        threat_intel = ti.block.model_dump(mode="json")
        ti_providers = ti.providers_used
        errors += [e.model_dump(mode="json") for e in ti.errors]

    related = None
    history_store = None
    if not no_history:
        correlation = correlate(alert, extraction.entities, config=cfg.history)
        related = correlation.block.model_dump(mode="json")
        history_store = correlation.store_name
        errors += [e.model_dump(mode="json") for e in correlation.errors]

    payload = {
        "alert_id": alert.alert_id,
        "iocs": [e.value for e in ioc_entities(extraction.entities)],
        "threat_intel": threat_intel,
        "related_alerts": related,
        "errors": errors,
        "providers": {"ti": ti_providers, "history": history_store},
    }
    indent = 2 if pretty else None
    typer.echo(json.dumps(payload, indent=indent, sort_keys=pretty))


@app.command()
def attack(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="Alert file to map.")],
    fmt: Annotated[
        str | None, typer.Option("--format", help="generic|splunk|elastic|cef|freetext")
    ] = None,
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Shortlist + rule hints only.")] = False,
    show_candidates: Annotated[
        bool, typer.Option("--candidates", help="Print the full shortlist with scores.")
    ] = False,
    pretty: Annotated[bool, typer.Option("--pretty")] = False,
) -> None:
    """Normalize, extract, enrich, then print the ATT&CK mapping as JSON (spec 06 surface)."""
    import json

    from soc_agent.attack import map_attack
    from soc_agent.extract import extract_entities
    from soc_agent.ingest import IngestError, load_input
    from soc_agent.ingest import normalize as normalize_alert
    from soc_agent.llm.client import MissingAPIKeyError
    from soc_agent.providers.history import correlate
    from soc_agent.providers.ti import enrich_ti_sync

    cfg = get_config()
    try:
        raw = load_input(input_path)
        alert = normalize_alert(raw, hint=fmt)  # type: ignore[arg-type]
        extraction = extract_entities(alert)
    except MissingAPIKeyError as e:
        _fail(str(e))
    except IngestError as e:
        typer.secho(f"✗ {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from e

    ti = enrich_ti_sync(extraction.entities, config=cfg.threat_intel)
    correlation = correlate(alert, extraction.entities, config=cfg.history)
    result = map_attack(
        alert,
        extraction.entities,
        ti.block,
        correlation.block,
        use_llm=False if no_llm else None,
        config=cfg.attack,
    )

    payload = {
        "alert_id": alert.alert_id,
        "mitre_attack": [m.model_dump(mode="json") for m in result.mappings],
        "errors": [e.model_dump(mode="json") for e in result.errors],
        "dropped": result.dropped,
        "llm_used": result.llm_used,
    }
    if show_candidates:
        payload["candidates"] = [
            {"technique_id": c.technique_id, "score": c.score, "reasons": list(c.reasons)}
            for c in result.candidates
        ]
    indent = 2 if pretty else None
    typer.echo(json.dumps(payload, indent=indent, sort_keys=pretty))


@app.command()
def triage(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="Alert file to triage.")],
    fmt: Annotated[
        str | None, typer.Option("--format", help="generic|splunk|elastic|cef|freetext")
    ] = None,
    no_llm: Annotated[
        bool, typer.Option("--no-llm", help="Deterministic scoring, triage and briefing only.")
    ] = False,
    pretty: Annotated[bool, typer.Option("--pretty")] = False,
) -> None:
    """Score, recommend and brief a single alert as JSON (spec 07 surface)."""
    import json

    from soc_agent.attack import map_attack
    from soc_agent.brief import brief as brief_alert
    from soc_agent.extract import extract_entities
    from soc_agent.ingest import IngestError, load_input
    from soc_agent.ingest import normalize as normalize_alert
    from soc_agent.llm.client import MissingAPIKeyError
    from soc_agent.providers.history import correlate
    from soc_agent.providers.ti import enrich_ti_sync
    from soc_agent.scoring import score_risk
    from soc_agent.triage import triage as triage_alert

    cfg = get_config()
    try:
        raw = load_input(input_path)
        alert = normalize_alert(raw, hint=fmt)  # type: ignore[arg-type]
        extraction = extract_entities(alert)
    except MissingAPIKeyError as e:
        _fail(str(e))
    except IngestError as e:
        typer.secho(f"✗ {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from e

    use_llm = False if no_llm else None
    ti = enrich_ti_sync(extraction.entities, config=cfg.threat_intel)
    correlation = correlate(alert, extraction.entities, config=cfg.history)
    attack = map_attack(
        alert,
        extraction.entities,
        ti.block,
        correlation.block,
        use_llm=use_llm,
        config=cfg.attack,
    )
    risk = score_risk(alert, ti.block, correlation.block, config=cfg.scoring)
    triaged = triage_alert(
        alert,
        extraction.entities,
        ti.block,
        correlation.block,
        attack.mappings,
        risk,
        use_llm=use_llm,
        config=cfg,
    )
    briefed = brief_alert(
        alert,
        extraction.entities,
        ti.block,
        correlation.block,
        attack.mappings,
        risk,
        triaged.recommendation,
        use_llm=use_llm,
        config=cfg,
    )

    errors = [
        e.model_dump(mode="json")
        for e in (
            *extraction.errors,
            *ti.errors,
            *correlation.errors,
            *attack.errors,
            *triaged.errors,
            *briefed.errors,
        )
    ]
    payload = {
        "alert_id": alert.alert_id,
        "risk": risk.model_dump(mode="json"),
        "recommendation": triaged.recommendation.model_dump(mode="json"),
        "briefing": briefed.briefing.model_dump(mode="json"),
        "errors": errors,
        "dropped": triaged.dropped,
        "overridden": triaged.overridden,
        "clamped": triaged.clamped,
        "llm_used": triaged.llm_used,
    }
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
def seed(
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite an existing history.db.")
    ] = False,
    epoch: Annotated[
        str | None,
        typer.Option("--epoch", help="ISO-8601 corpus epoch (default 2026-07-20T12:00:00Z)."),
    ] = None,
) -> None:
    """Build local seed data: data/history.db (spec 05)."""
    from datetime import datetime

    from soc_agent.providers.history.seed import CORPUS_EPOCH, build_seeded_db

    cfg = get_config()
    path = Path(cfg.history.path)
    if path.exists():
        if not force:
            _fail(f"{path} already exists — pass --force to rebuild it.")
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)

    anchor = CORPUS_EPOCH
    if epoch is not None:
        try:
            anchor = datetime.fromisoformat(epoch.replace("Z", "+00:00"))
        except ValueError as e:
            raise typer.BadParameter(f"--epoch must be ISO-8601: {epoch!r}") from e
        if anchor.tzinfo is None:
            raise typer.BadParameter("--epoch must carry a timezone offset")

    summary = build_seeded_db(str(path), epoch=anchor)
    typer.secho(f"✓ seeded {summary.alerts} alerts into {path}", fg=typer.colors.GREEN, err=True)
    typer.secho(f"  epoch:        {summary.epoch}", err=True)
    typer.secho(f"  rules:        {len(summary.rules)}", err=True)
    for disposition, count in sorted(summary.dispositions.items()):
        typer.secho(f"  {disposition + ':':<14}{count}", err=True)


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
