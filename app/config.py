"""Configuration loading for ProcSentry."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DuplicateDetectionConfig(BaseModel):
    """Duplicate detection thresholds and switches."""

    enabled: bool = True
    confidence_threshold: int = Field(default=75, ge=0, le=100)
    suppression_window_seconds: int = Field(default=300, ge=0)
    restart_loop_window_seconds: int = Field(default=120, ge=1)
    restart_loop_threshold: int = Field(default=3, ge=2)
    allowlist_fingerprints: tuple[str, ...] = ()
    allowlist_commands: tuple[str, ...] = ()


class StorageConfig(BaseModel):
    """Storage maintenance settings."""

    history_sample_interval_seconds: int = Field(default=15, ge=1)
    maintenance_interval_seconds: int = Field(default=3600, ge=60)
    wal_checkpoint_interval_seconds: int = Field(default=3600, ge=60)
    vacuum_interval_seconds: int = Field(default=86400, ge=3600)


class AlertConfig(BaseModel):
    """Resource alert thresholds."""

    ram_threshold_mb: float = Field(default=2000, ge=0)
    cpu_threshold_percent: float = Field(default=90, ge=0, le=1000)


class SecurityConfig(BaseModel):
    """Security heuristic settings."""

    enabled: bool = True
    random_name_entropy_threshold: float = Field(default=3.2, ge=0)
    excessive_cpu_percent: float = Field(default=90, ge=0)


class WebConfig(BaseModel):
    """Web dashboard bind settings."""

    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    auth_enabled: bool = False
    auth_username: str = "admin"
    auth_password: str | None = None
    session_secret: str | None = None
    csrf_enabled: bool = True
    secure_cookies: bool = False


class RemoteHostConfig(BaseModel):
    """A remote machine reachable over SSH for process inspection."""

    name: str
    host: str
    port: int = Field(default=22, ge=1, le=65535)
    username: str
    password: str | None = None


class HealingConfig(BaseModel):
    """Auto-healing settings. Disabled by default by design."""

    enabled: bool = False
    dry_run: bool = True


class Settings(BaseSettings):
    """Runtime settings loaded from defaults, YAML, and environment variables."""

    model_config = SettingsConfigDict(env_prefix="PROCSENTRY_", env_nested_delimiter="__")

    app_name: str = "ProcSentry"
    data_dir: Path = Path("/var/lib/procsentry")
    log_level: str = "INFO"
    scan_interval: float = Field(default=5.0, gt=0)
    history_retention_days: int = Field(default=7, ge=1)
    database_url: str = "sqlite:////var/lib/procsentry/procsentry.db"
    duplicate_detection: DuplicateDetectionConfig = Field(default_factory=DuplicateDetectionConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    healing: HealingConfig = Field(default_factory=HealingConfig)
    remote_hosts: tuple[RemoteHostConfig, ...] = ()


def _merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge two dictionaries without mutating inputs."""

    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_settings(config_path: str | Path | None = None) -> Settings:
    """Load settings from an optional YAML file plus environment overrides."""

    data: dict[str, Any] = {}
    if config_path:
        path = Path(config_path)
        if path.exists():
            with path.open("r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle) or {}
                if not isinstance(loaded, dict):
                    raise ValueError(f"Config file {path} must contain a YAML mapping")
                data = _merge_dict(data, loaded)
    return Settings(**data)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached default settings."""

    default_path = Path("config/procsentry.yml")
    return load_settings(default_path if default_path.exists() else None)
