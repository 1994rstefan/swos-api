"""swos command-line application."""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import typer
import typer._click as click
from dotenv import dotenv_values
from swos_core.safety import FirmwareSafetyPolicy
from typer.core import TyperGroup

from swos_cli import __version__
from swos_cli.config import (
    ConfigurationError,
    ResolvedConfiguration,
    default_config_path,
    load_configuration,
)
from swos_cli.output import OutputFormat, OutputRenderer


@dataclass(frozen=True, slots=True)
class CliContext:
    """Configuration and invocation-only safety controls for CLI commands."""

    configuration: ResolvedConfiguration
    firmware_policy: FirmwareSafetyPolicy


class OutputAwareGroup(TyperGroup):
    """Render parser errors as JSON when machine output was requested."""

    def main(self, *args: Any, **kwargs: Any) -> Any:
        raw_args = kwargs.get("args")
        if raw_args is None:
            raw_args = args[0] if args else sys.argv[1:]
        argument_list = list(raw_args)
        standalone_mode = bool(kwargs.pop("standalone_mode", True))
        kwargs["standalone_mode"] = False

        try:
            result = super().main(*args, **kwargs)
        except click.ClickException as exc:
            output_format = _fallback_output_format(
                _output_argument(argument_list),
                arguments=argument_list,
            )
            if output_format is OutputFormat.HUMAN:
                exc.show(file=sys.stderr)
            else:
                OutputRenderer(output_format).error("cli_usage_error", exc.format_message())
            if standalone_mode:
                raise SystemExit(exc.exit_code) from exc
            raise typer.Exit(exc.exit_code) from exc
        if isinstance(result, int) and result != 0:
            if standalone_mode:
                raise SystemExit(result)
            raise typer.Exit(result)
        return result


app = typer.Typer(
    add_completion=False,
    cls=OutputAwareGroup,
    help="Manage MikroTik SwOS devices through the swos-core API.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", help="Show the CLI version and exit."),
    ] = False,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output format: human, json, or json-pretty."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to the TOML configuration file."),
    ] = None,
    device: Annotated[
        str | None,
        typer.Option("--device", help="Select a configured device."),
    ] = None,
    url: Annotated[
        str | None,
        typer.Option("--url", help="Override the device URL."),
    ] = None,
    username: Annotated[
        str | None,
        typer.Option("--username", help="Override the username."),
    ] = None,
    password: Annotated[
        str | None,
        typer.Option("--password", help="Override the password."),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Override the device model."),
    ] = None,
    firmware: Annotated[
        str | None,
        typer.Option("--firmware", help="Override the expected firmware version."),
    ] = None,
    timeout: Annotated[float | None, typer.Option("--timeout", min=0.001)] = None,
    verify_tls: Annotated[
        bool | None,
        typer.Option("--verify-tls/--no-verify-tls"),
    ] = None,
    allow_untested_firmware: Annotated[
        bool,
        typer.Option(
            "--allow-untested-firmware",
            help="Allow reads using an explicitly selected untested firmware profile.",
        ),
    ] = False,
    allow_untested_firmware_writes: Annotated[
        bool,
        typer.Option(
            "--allow-untested-firmware-writes",
            help="Allow writes to untested firmware; also permits reads.",
        ),
    ] = False,
) -> None:
    """Resolve global settings and dispatch a command."""

    cli_values: dict[str, Any] = {
        "output": output,
        "device": device,
        "url": url,
        "username": username,
        "password": password,
        "model": model,
        "firmware": firmware,
        "timeout": timeout,
        "verify_tls": verify_tls,
    }
    try:
        resolved = load_configuration(cli_values, config_path=config)
    except ConfigurationError as exc:
        renderer = OutputRenderer(
            _fallback_output_format(output, config_path=config, device=device)
        )
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc

    renderer = OutputRenderer(resolved.settings.output)
    ctx.obj = CliContext(
        configuration=resolved,
        firmware_policy=FirmwareSafetyPolicy(
            allow_untested_firmware=allow_untested_firmware,
            allow_untested_firmware_writes=allow_untested_firmware_writes,
        ),
    )

    if version:
        renderer.success(
            {"name": "swos-cli", "version": __version__},
            human=f"swos-cli {__version__}",
        )
        raise typer.Exit()


def _fallback_output_format(
    cli_output: str | None,
    *,
    arguments: list[str] | None = None,
    config_path: Path | None = None,
    device: str | None = None,
) -> OutputFormat:
    dotenv_environment = dotenv_values(Path.cwd() / ".env")
    dotenv_output = dotenv_environment.get("SWOS_OUTPUT")
    config_output = _config_output_hint(
        arguments=arguments or [],
        config_path=config_path,
        device=device,
        dotenv_environment=dotenv_environment,
    )
    candidate = (
        cli_output
        or os.environ.get("SWOS_OUTPUT")
        or dotenv_output
        or config_output
        or OutputFormat.HUMAN.value
    )
    try:
        return OutputFormat(candidate)
    except ValueError:
        return OutputFormat.HUMAN


def _output_argument(arguments: list[str]) -> str | None:
    for index, argument in enumerate(arguments):
        if argument in {"--output", "-o"}:
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument.startswith("--output="):
            return argument.partition("=")[2]
        if argument.startswith("-o") and len(argument) > 2:
            return argument[2:]
    return None


def _config_output_hint(
    *,
    arguments: list[str],
    config_path: Path | None,
    device: str | None,
    dotenv_environment: dict[str, str | None],
) -> str | None:
    raw_path: str | Path = (
        config_path
        or _argument_value(arguments, "--config")
        or os.environ.get("SWOS_CONFIG")
        or dotenv_environment.get("SWOS_CONFIG")
        or default_config_path()
    )
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.is_file():
        return None

    try:
        with path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError):
        return None

    defaults = data.get("defaults", {})
    if not isinstance(defaults, dict):
        return None
    selected_device = (
        device
        or _argument_value(arguments, "--device")
        or os.environ.get("SWOS_DEVICE")
        or dotenv_environment.get("SWOS_DEVICE")
        or defaults.get("device")
    )
    devices = data.get("devices", {})
    if selected_device is not None and isinstance(devices, dict):
        profile = devices.get(str(selected_device), {})
        if isinstance(profile, dict) and "output" in profile:
            profile_output = profile["output"]
            return profile_output if isinstance(profile_output, str) else None
    default_output = defaults.get("output")
    return default_output if isinstance(default_output, str) else None


def _argument_value(arguments: list[str], name: str) -> str | None:
    for index, argument in enumerate(arguments):
        if argument == name:
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument.startswith(name + "="):
            return argument.partition("=")[2]
    return None


def run() -> None:
    """Console script entry point."""

    app(prog_name="swos")
