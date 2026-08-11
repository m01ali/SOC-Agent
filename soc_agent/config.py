"""Configuration system: config.yaml + SOC_AGENT_* env overrides.

Spec: project-setup-01-spec.md §7 (Architecture §9).
Precedence (highest wins): process env > config.yaml > built-in defaults.
"""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

DEFAULT_CONFIG_FILE = Path("config.yaml")

_explicit_path: Path | None = None


class ConfigError(RuntimeError):
    """Invalid or unreadable configuration."""


class ModelsConfig(BaseModel):
    default: str = "qwen3.7-max"
    overrides: dict[str, str] = Field(default_factory=dict)


class LLMConfig(BaseModel):
    base_url: str = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
    max_tokens: int = Field(default=4096, gt=0)
    temperature: float = 0.0
    enable_thinking: bool = False
    timeout_s: int = 120
    max_retries: int = 2


# Allowlists (enrichment-05-spec.md §9.3, §17). An unknown name is a ConfigError, never a
# lazily-imported adapter: this is the POC's guard against an accidental outbound call.
TI_PROVIDER_NAMES: frozenset[str] = frozenset({"mock", "failing", "timeout"})
HISTORY_STORE_NAMES: frozenset[str] = frozenset({"sqlite", "memory"})


class ThreatIntelConfig(BaseModel):
    providers: list[str] = Field(default_factory=lambda: ["mock"])
    lookup_timeout_s: int = 5
    cache_ttl_s: int = 3600
    max_concurrency: int = Field(default=10, gt=0)
    simulate_latency: bool = True
    seed_path: str = "data/ti_seed.yaml"

    @field_validator("providers")
    @classmethod
    def _validate_providers(cls, value: list[str]) -> list[str]:
        for name in value:
            if name not in TI_PROVIDER_NAMES:
                raise ValueError(
                    f"unknown threat_intel provider {name!r} (known: {sorted(TI_PROVIDER_NAMES)})"
                )
        return value


class HistoryConfig(BaseModel):
    store: str = "sqlite"
    path: str = "data/history.db"
    window_days: int = 30
    max_related: int = Field(default=20, gt=0)
    value_stoplist: list[str] = Field(default_factory=list)

    @field_validator("store")
    @classmethod
    def _validate_store(cls, value: str) -> str:
        if value not in HISTORY_STORE_NAMES:
            raise ValueError(
                f"unknown history store {value!r} (known: {sorted(HISTORY_STORE_NAMES)})"
            )
        return value


class AttackConfig(BaseModel):
    catalog: str = "data/attack_catalog.json"
    candidate_top_k: int = Field(default=12, gt=0)
    max_techniques: int = Field(default=5, gt=0)
    use_llm: bool = True
    rule_hints: str = "data/rule_hints.yaml"
    keywords: str = "data/attack_keywords.yaml"
    max_bundle_chars: int = Field(default=4000, gt=0)


class ScoringWeights(BaseModel):
    ti: float = 0.45
    severity: float = 0.30
    history: float = 0.25


class ScoringBands(BaseModel):
    escalate: int = 70
    investigate: int = 40


class ScoringConfig(BaseModel):
    weights: ScoringWeights = Field(default_factory=ScoringWeights)
    bands: ScoringBands = Field(default_factory=ScoringBands)

    @model_validator(mode="after")
    def _validate(self) -> ScoringConfig:
        total = self.weights.ti + self.weights.severity + self.weights.history
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"scoring.weights must sum to 1.0 (got {total:.3f})")
        if self.bands.escalate <= self.bands.investigate:
            raise ValueError(
                "scoring.bands.escalate must be greater than scoring.bands.investigate"
            )
        return self


class BriefingConfig(BaseModel):
    max_words: int = 200


_DEFAULT_INTERNAL_RANGES: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

LLMAssistMode = Literal["freetext", "always", "never"]


class ExtractionConfig(BaseModel):
    llm_assist: LLMAssistMode = "freetext"
    max_entities: int = Field(default=200, gt=0)
    max_llm_additions: int = Field(default=20, gt=0)
    llm_confidence: float = Field(default=0.6, ge=0, le=1)
    aggressive_refang: bool = False
    derive_email_domain: bool = False
    sweep_observed_fields: bool = False
    internal_ranges: list[str] = Field(default_factory=lambda: list(_DEFAULT_INTERNAL_RANGES))

    @field_validator("internal_ranges")
    @classmethod
    def _validate_ranges(cls, value: list[str]) -> list[str]:
        for cidr in value:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                raise ValueError(f"invalid CIDR in extraction.internal_ranges: {cidr!r}") from e
        return value


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SOC_AGENT_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    models: ModelsConfig = Field(default_factory=ModelsConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)
    attack: AttackConfig = Field(default_factory=AttackConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    briefing: BriefingConfig = Field(default_factory=BriefingConfig)
    extraction: ExtractionConfig = Field(default_factory=ExtractionConfig)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # First source wins: env vars override the YAML passed as init values.
        return (env_settings, init_settings, dotenv_settings, file_secret_settings)


def resolve_config_path(explicit: Path | None = None) -> Path | None:
    """--config flag > SOC_AGENT_CONFIG env > ./config.yaml > None (built-in defaults)."""
    if explicit is not None:
        return explicit
    env_path = os.environ.get("SOC_AGENT_CONFIG")
    if env_path:
        return Path(env_path)
    if DEFAULT_CONFIG_FILE.exists():
        return DEFAULT_CONFIG_FILE
    return None


def load_config(path: Path | None = None) -> AppConfig:
    resolved = resolve_config_path(path)
    data: dict = {}
    if resolved is not None:
        try:
            raw = yaml.safe_load(resolved.read_text())
        except FileNotFoundError as e:
            raise ConfigError(f"config file not found: {resolved}") from e
        except yaml.YAMLError as e:
            raise ConfigError(f"invalid YAML in {resolved}: {e}") from e
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise ConfigError(f"config root must be a mapping, got {type(raw).__name__}")
        data = raw
    try:
        return AppConfig(**data)
    except ValidationError as e:
        raise ConfigError(str(e)) from e


def set_config_path(path: Path | None) -> None:
    """Set the explicit config path (from --config) and invalidate the cache."""
    global _explicit_path
    _explicit_path = path
    reset_config()


def current_config_path() -> Path | None:
    """The config file the next get_config() call will use (None = built-in defaults)."""
    return resolve_config_path(_explicit_path)


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    return load_config(_explicit_path)


def reset_config() -> None:
    """Clear the cached config (used by tests and set_config_path)."""
    get_config.cache_clear()
