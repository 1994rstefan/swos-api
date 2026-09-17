"""Layered TOML, dotenv, environment, and CLI configuration."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from dotenv import dotenv_values
from platformdirs import user_config_path
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, SecretStr, ValidationError

from swos_cli.output import OutputFormat


class ConfigurationError(Exception):
    """Configuration could not be loaded or validated safely."""


class CliSettings(BaseModel):
    """Effective CLI settings after all precedence layers are applied."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    device: str | None = None
    output: OutputFormat = OutputFormat.HUMAN
    url: AnyHttpUrl | None = None
    username: str = "admin"
    password: SecretStr = SecretStr("")
    model: str = "auto"
    firmware: str = "auto"
    timeout: float = Field(default=10.0, gt=0)
    verify_tls: bool = True


class FileConfiguration(BaseModel):
    """Validated top-level shape of a TOML configuration file."""

    model_config = ConfigDict(extra="forbid")

    defaults: dict[str, Any] = Field(default_factory=dict)
    devices: dict[str, dict[str, Any]] = Field(default_factory=dict)


class ResolvedConfiguration(BaseModel):
    """Effective settings and the optional TOML file that contributed to them."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    settings: CliSettings
    config_path: Path | None = None


ENVIRONMENT_KEYS = {
    "SWOS_DEVICE": "device",
    "SWOS_OUTPUT": "output",
    "SWOS_URL": "url",
    "SWOS_USERNAME": "username",
    "SWOS_PASSWORD": "password",
    "SWOS_MODEL": "model",
    "SWOS_FIRMWARE": "firmware",
    "SWOS_TIMEOUT": "timeout",
    "SWOS_VERIFY_TLS": "verify_tls",
}


def default_config_path() -> Path:
    """Return the platform-specific default TOML path."""

    return user_config_path("swos-api", appauthor=False) / "config.toml"


def load_configuration(
    cli_values: Mapping[str, Any] | None = None,
    *,
    config_path: Path | None = None,
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> ResolvedConfiguration:
    """Load settings using the documented low-to-high precedence order."""

    cli = {key: value for key, value in (cli_values or {}).items() if value is not None}
    process_environment = dict(os.environ if environ is None else environ)
    working_directory = Path.cwd() if cwd is None else cwd
    dotenv_environment = {
        key: value
        for key, value in dotenv_values(working_directory / ".env").items()
        if value is not None
    }

    selected_config_path, path_is_explicit = _resolve_config_path(
        config_path,
        process_environment,
        dotenv_environment,
        working_directory,
    )
    file_configuration = _load_file(selected_config_path, required=path_is_explicit)

    defaults = dict(file_configuration.defaults)
    selected_device = _first_defined(
        cli.get("device"),
        process_environment.get("SWOS_DEVICE"),
        dotenv_environment.get("SWOS_DEVICE"),
        defaults.get("device"),
    )

    merged: dict[str, Any] = dict(defaults)
    if selected_device is not None:
        try:
            merged.update(file_configuration.devices[str(selected_device)])
        except KeyError as exc:
            raise ConfigurationError(
                f"Device profile {selected_device!r} was not found in {selected_config_path}"
            ) from exc
        merged["device"] = selected_device

    _apply_environment(merged, dotenv_environment)
    _apply_environment(merged, process_environment)
    merged.update(cli)

    try:
        settings = CliSettings.model_validate(merged)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_input=False)
        )
        raise ConfigurationError(f"Invalid configuration: {details}") from exc

    effective_path = selected_config_path if selected_config_path.is_file() else None
    return ResolvedConfiguration(settings=settings, config_path=effective_path)


def _resolve_config_path(
    cli_path: Path | None,
    process_environment: Mapping[str, str],
    dotenv_environment: Mapping[str, str],
    cwd: Path,
) -> tuple[Path, bool]:
    raw_path = _first_defined(
        cli_path,
        process_environment.get("SWOS_CONFIG"),
        dotenv_environment.get("SWOS_CONFIG"),
    )
    if raw_path is None:
        return default_config_path(), False

    path = Path(cast(str | Path, raw_path)).expanduser()
    if not path.is_absolute():
        path = cwd / path
    return path, True


def _load_file(path: Path, *, required: bool) -> FileConfiguration:
    if not path.is_file():
        if required:
            raise ConfigurationError(f"Configuration file not found: {path}")
        return FileConfiguration()

    try:
        with path.open("rb") as config_file:
            data = tomllib.load(config_file)
        return FileConfiguration.model_validate(data)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"Could not read configuration file {path}: {exc}") from exc
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_input=False)
        )
        raise ConfigurationError(f"Invalid configuration file {path}: {details}") from exc


def _apply_environment(target: dict[str, Any], source: Mapping[str, str]) -> None:
    for environment_name, setting_name in ENVIRONMENT_KEYS.items():
        if environment_name in source:
            target[setting_name] = source[environment_name]


def _first_defined(*values: object | None) -> object | None:
    return next((value for value in values if value is not None), None)
