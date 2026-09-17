"""swosctl command-line application."""

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
from swos_core import DeviceConnection, PluginRegistry, SwOSDevice
from swos_core.errors import SwOSError
from swos_core.safety import FirmwareSafetyPolicy
from typer.core import TyperGroup, TyperOption

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

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        """Allow root options before, between, or after nested command names."""

        option_arity: dict[str, int] = {}
        for parameter in self.params:
            if isinstance(parameter, TyperOption):
                arity = 0 if parameter.is_flag or parameter.count else parameter.nargs
                for option in (*parameter.opts, *parameter.secondary_opts):
                    option_arity[option] = arity

        global_arguments: list[str] = []
        command_arguments: list[str] = []
        index = 0
        while index < len(args):
            argument = args[index]
            if argument == "--":
                command_arguments.extend(args[index:])
                break

            option = argument
            attached_value = False
            if argument.startswith("--") and "=" in argument:
                option = argument.partition("=")[0]
                attached_value = option in option_arity
            elif argument.startswith("-") and not argument.startswith("--"):
                short_option = next(
                    (
                        name
                        for name, arity in option_arity.items()
                        if arity == 1
                        and name.startswith("-")
                        and not name.startswith("--")
                        and argument.startswith(name)
                        and argument != name
                    ),
                    None,
                )
                if short_option is not None:
                    option = short_option
                    attached_value = True

            if option not in option_arity:
                command_arguments.append(argument)
                index += 1
                continue

            global_arguments.append(argument)
            arity = option_arity[option]
            if not attached_value and arity:
                values = args[index + 1 : index + 1 + arity]
                global_arguments.extend(values)
                index += len(values)
            index += 1

        return super().parse_args(ctx, global_arguments + command_arguments)

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
system_app = typer.Typer(help="Read system information.", no_args_is_help=True)
app.add_typer(system_app, name="system")
port_app = typer.Typer(help="Read port state.", no_args_is_help=True)
app.add_typer(port_app, name="port")
host_app = typer.Typer(help="Read forwarding-database entries.", no_args_is_help=True)
app.add_typer(host_app, name="host")
rstp_app = typer.Typer(help="Read spanning-tree state.", no_args_is_help=True)
app.add_typer(rstp_app, name="rstp")
snmp_app = typer.Typer(help="Read SNMP configuration.", no_args_is_help=True)
app.add_typer(snmp_app, name="snmp")
vlan_app = typer.Typer(help="Read VLAN configuration.", no_args_is_help=True)
app.add_typer(vlan_app, name="vlan")


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


@system_app.command("show")
def system_show(ctx: typer.Context) -> None:
    """Show normalized system information from the selected device."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    settings = cli_context.configuration.settings
    renderer = OutputRenderer(settings.output)
    try:
        connected_device = _connect_device(cli_context)
        info = connected_device.get_system_info()
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data = info.model_dump(mode="json")
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    identity = info.identity
    model = identity.marketing_name or identity.product_code
    details = [
        f"Name: {info.name}",
        f"Model: {model} ({identity.product_code})",
        f"Firmware: SwOS {identity.firmware_version}",
        f"Uptime: {_format_uptime(info.uptime_seconds)}",
    ]
    if identity.build_id is not None:
        details.insert(3, f"Build: {identity.build_id}")
    if info.serial_number is not None:
        details.append(f"Serial Number: {info.serial_number}")
    if info.mac_address is not None:
        details.append(f"MAC Address: {info.mac_address}")
    if info.current_ip is not None:
        details.append(f"Current IP: {info.current_ip}")
    if info.static_ip is not None:
        details.append(f"Static IP: {info.static_ip}")
    details.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(details))


@port_app.command("list")
def port_list(ctx: typer.Context) -> None:
    """List normalized operational state for every port."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        ports = connected_device.get_ports()
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "ports": [port.model_dump(mode="json") for port in ports],
    }
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    lines = ["PORT  NAME   ENABLED  LINK  SPEED      DUPLEX  AUTONEG  FLOW-CONTROL"]
    for port in ports:
        speed = f"{port.speed_mbps} Mbps" if port.speed_mbps is not None else "-"
        duplex = "full" if port.full_duplex else "half" if port.full_duplex is not None else "-"
        lines.append(
            f"{port.number:<5} {port.name:<6} {_yes_no(port.enabled):<8} "
            f"{'up' if port.link_up else 'down':<5} {speed:<10} {duplex:<7} "
            f"{_yes_no(port.auto_negotiation):<8} {_yes_no(port.flow_control)}"
        )
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@port_app.command("stats")
def port_stats(ctx: typer.Context) -> None:
    """List cumulative traffic and error counters for every port."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        statistics = connected_device.get_port_statistics()
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "ports": [port.model_dump(mode="json") for port in statistics],
    }
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    lines = ["PORT  RX BYTES      TX BYTES      RX PACKETS  TX PACKETS  RX ERRORS  TX ERRORS"]
    for port in statistics:
        lines.append(
            f"{port.number:<5} {port.rx_bytes:<13} {port.tx_bytes:<13} "
            f"{port.rx_packets:<11} {port.tx_packets:<11} "
            f"{port.rx_errors:<10} {port.tx_errors}"
        )
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@host_app.command("list")
def host_list(ctx: typer.Context) -> None:
    """List normalized static and dynamically learned host entries."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        hosts = connected_device.get_hosts()
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "hosts": [host.model_dump(mode="json") for host in hosts],
    }
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    lines = ["TYPE     MAC ADDRESS        VLAN  PORTS  DROP  MIRROR"]
    for host in hosts:
        vlan_id = str(host.vlan_id) if host.vlan_id is not None else "-"
        ports = ",".join(str(port) for port in host.port_numbers) or "-"
        lines.append(
            f"{host.entry_type.value:<8} {host.mac_address:<18} {vlan_id:<5} "
            f"{ports:<6} {_yes_no(host.drop):<5} {_yes_no(host.mirror)}"
        )
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@rstp_app.command("show")
def rstp_show(ctx: typer.Context) -> None:
    """Show normalized bridge and per-port spanning-tree state."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        info = connected_device.get_rstp()
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data = info.model_dump(mode="json")
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    lines = [
        f"Bridge Priority: 0x{info.bridge_priority:04x}",
        f"Cost Mode: {info.cost_mode.value}",
        f"Forward Reserved Multicast: {_yes_no(info.forward_reserved_multicast)}",
        f"Root Bridge: 0x{info.root_bridge_priority:04x}.{info.root_bridge_mac}",
        "",
        "PORT  ENABLED  PROTOCOL  ROLE        ROOT COST  TYPE            STATE",
    ]
    for port in info.ports:
        lines.append(
            f"{port.number:<5} {_yes_no(port.enabled):<8} {port.protocol.value:<9} "
            f"{port.role.value:<11} {port.root_path_cost:<10} "
            f"{port.port_type.value.replace('_', ' '):<15} {port.state.value}"
        )
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@snmp_app.command("show")
def snmp_show(ctx: typer.Context) -> None:
    """Show normalized SNMP service configuration."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        info = connected_device.get_snmp()
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data = info.model_dump(mode="json")
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    lines = [
        f"Enabled: {_yes_no(info.enabled)}",
        f"Community: {info.community}",
        f"Contact: {info.contact}",
        f"Location: {info.location}",
    ]
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@vlan_app.command("ports")
def vlan_ports(ctx: typer.Context) -> None:
    """List normalized VLAN policy for every port."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        ports = connected_device.get_port_vlans()
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "ports": [port.model_dump(mode="json") for port in ports],
    }
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    lines = ["PORT  MODE      RECEIVE        DEFAULT VLAN  FORCE  EGRESS"]
    for port in ports:
        lines.append(
            f"{port.number:<5} {port.mode.value:<9} "
            f"{port.receive.value.replace('_', ' '):<14} {port.default_vlan_id:<13} "
            f"{_yes_no(port.force_vlan_id):<6} {port.egress.value.replace('_', ' ')}"
        )
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@vlan_app.command("list")
def vlan_list(ctx: typer.Context) -> None:
    """List normalized configured VLAN table entries."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        vlans = connected_device.get_vlans()
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "vlans": [vlan.model_dump(mode="json") for vlan in vlans],
    }
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    lines = ["VLAN  IVL  IGMP SNOOPING  PORT MODES"]
    for vlan in vlans:
        port_modes = ", ".join(
            f"{port.port_number}={port.mode.value.replace('_', ' ')}" for port in vlan.ports
        )
        lines.append(
            f"{vlan.vlan_id:<5} {_yes_no(vlan.independent_learning):<4} "
            f"{_yes_no(vlan.igmp_snooping):<14} {port_modes}"
        )
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


def _connect_device(cli_context: CliContext) -> SwOSDevice:
    settings = cli_context.configuration.settings
    if settings.url is None:
        raise ConfigurationError("A device URL is required")
    connection = DeviceConnection(
        url=settings.url,
        username=settings.username,
        password=settings.password,
        timeout=settings.timeout,
        verify_tls=settings.verify_tls,
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    expected_models = {identity.product_code.casefold()}
    if identity.marketing_name is not None:
        expected_models.add(identity.marketing_name.casefold())
    if settings.model.casefold() != "auto" and settings.model.casefold() not in expected_models:
        raise ConfigurationError(
            f"Configured model {settings.model!r} does not match detected "
            f"device {identity.product_code!r}"
        )
    if settings.firmware != "auto" and settings.firmware != identity.firmware_version:
        raise ConfigurationError(
            f"Configured firmware {settings.firmware!r} does not match detected "
            f"firmware {identity.firmware_version!r}"
        )
    return registry.connect(identity, connection, cli_context.firmware_policy)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _error_code(error: SwOSError) -> str:
    name = type(error).__name__
    return "".join(
        f"_{character.lower()}" if character.isupper() else character for character in name
    ).lstrip("_")


def _format_uptime(seconds: int) -> str:
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"


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

    app(prog_name="swosctl")
