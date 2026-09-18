"""swosctl command-line application."""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, cast

import typer
import typer._click as click
from dotenv import dotenv_values
from pydantic import SecretStr, ValidationError
from swos_core import (
    AclRule,
    AclVlanTagMode,
    AddressMode,
    DeviceConnection,
    DeviceNameUpdate,
    ForcedPortNegotiation,
    ForwardingInfo,
    ForwardingPortPolicyUpdate,
    HostEntry,
    HostEntryType,
    IgmpVersion,
    OperationResult,
    PacketSizeStatistics,
    PasswordUpdate,
    PluginRegistry,
    PortConfigurationUpdate,
    PortErrorStatistics,
    PortInfo,
    PortNameUpdate,
    PortVlanPolicyUpdate,
    RstpInfo,
    RstpPortEnableUpdate,
    SnmpInfo,
    SnmpMetadataUpdate,
    SwOSDevice,
    SystemConfigurationUpdate,
    SystemInfo,
    VlanEgressMode,
    VlanInfo,
    VlanMembershipMode,
    VlanMode,
    VlanPortMembership,
    VlanReceiveMode,
)
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


class NegotiationOption(StrEnum):
    AUTO = "auto"
    FORCED = "forced"


class DuplexOption(StrEnum):
    FULL = "full"
    HALF = "half"


class PortStateOption(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"


class ToggleOption(StrEnum):
    ON = "on"
    OFF = "off"


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
system_app = typer.Typer(help="Read and configure system information.", no_args_is_help=True)
app.add_typer(system_app, name="system")
system_password_app = typer.Typer(help="Rotate administrator credentials.", no_args_is_help=True)
system_app.add_typer(system_password_app, name="password")
port_app = typer.Typer(help="Read and configure port state.", no_args_is_help=True)
app.add_typer(port_app, name="port")
host_app = typer.Typer(help="Read forwarding-database entries.", no_args_is_help=True)
app.add_typer(host_app, name="host")
rstp_app = typer.Typer(help="Read spanning-tree state.", no_args_is_help=True)
app.add_typer(rstp_app, name="rstp")
snmp_app = typer.Typer(help="Read and configure SNMP metadata.", no_args_is_help=True)
app.add_typer(snmp_app, name="snmp")
snmp_metadata_app = typer.Typer(help="Configure SNMP metadata.", no_args_is_help=True)
snmp_app.add_typer(snmp_metadata_app, name="metadata")
vlan_app = typer.Typer(help="Read VLAN configuration.", no_args_is_help=True)
app.add_typer(vlan_app, name="vlan")
sfp_app = typer.Typer(help="Read SFP identity and diagnostics.", no_args_is_help=True)
app.add_typer(sfp_app, name="sfp")
forwarding_app = typer.Typer(help="Read forwarding policy.", no_args_is_help=True)
app.add_typer(forwarding_app, name="forwarding")
igmp_app = typer.Typer(help="Read dynamic IGMP groups.", no_args_is_help=True)
app.add_typer(igmp_app, name="igmp")
acl_app = typer.Typer(help="Read access-control rules.", no_args_is_help=True)
app.add_typer(acl_app, name="acl")


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
    if info.management is not None:
        management = info.management
        details.extend(
            [
                f"Address Mode: {management.address_mode.value.replace('_', ' ')}",
                f"Admin MAC: {management.admin_mac_address or '-'}",
                f"Allow From: {_network(management.allow_from, management.allow_prefix_length)}",
                f"Allowed Ports: {_ports(management.allowed_port_numbers)}",
                f"Allowed VLAN: {management.allowed_vlan_id or '-'}",
                f"Watchdog: {_yes_no(management.watchdog_enabled)}",
            ]
        )
    if info.independent_vlan_lookup is not None:
        details.append(f"Independent VLAN Lookup: {_yes_no(info.independent_vlan_lookup)}")
    if info.igmp is not None:
        details.extend(
            [
                f"IGMP Snooping: {_yes_no(info.igmp.enabled)}",
                f"IGMP Querier Configured: {_yes_no(info.igmp.querier_configured)}",
                f"IGMP Querier Effective: {_yes_no(info.igmp.querier_effective)}",
                f"IGMP Version: {info.igmp.version.value}",
                f"IGMP Fast Leave Ports: {_ports(info.igmp.fast_leave_port_numbers)}",
            ]
        )
    details.append(f"Discovery Protocol Ports: {_ports(info.discovery_protocol_port_numbers)}")
    if info.health is not None:
        voltage = info.health.input_voltage_volts
        temperature = info.health.temperature_celsius
        details.extend(
            [
                f"Input Voltage: {f'{voltage:g} V' if voltage is not None else '-'}",
                f"Temperature: {f'{temperature} C' if temperature is not None else '-'}",
                "PoE-in Long Cable: "
                + (
                    _yes_no(info.health.poe_in_long_cable)
                    if info.health.poe_in_long_cable is not None
                    else "-"
                ),
            ]
        )
    details.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(details))


@system_app.command("rename")
def system_rename(
    ctx: typer.Context,
    name: Annotated[
        str, typer.Argument(help="New device name (up to 16 printable ASCII characters).")
    ],
) -> None:
    """Set and verify the configured device name."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        result: OperationResult[SystemInfo] = connected_device.set_device_name(
            DeviceNameUpdate(name=name)
        )
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "changed": result.changed,
        "system": result.value.model_dump(mode="json"),
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    human = (
        f"Device name changed to {result.value.name!r}."
        if result.changed
        else f"Device name is already {result.value.name!r}; no change required."
    )
    if result.warnings:
        human += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=human)


@system_password_app.command("set")
def system_password_set(
    ctx: typer.Context,
    new_password_stdin: Annotated[
        bool,
        typer.Option(
            "--new-password-stdin",
            help="Read the new password from noninteractive standard input.",
        ),
    ] = False,
    new_password_env: Annotated[
        str | None,
        typer.Option(
            "--new-password-env",
            metavar="NAME",
            help="Read the new password from environment variable NAME.",
        ),
    ] = None,
) -> None:
    """Set and verify a new administrator password without exposing it in argv."""

    if new_password_stdin == (new_password_env is not None):
        raise typer.BadParameter(
            "Exactly one of --new-password-stdin or --new-password-env is required"
        )
    if new_password_env is not None:
        if not new_password_env:
            raise typer.BadParameter("--new-password-env requires a non-empty variable name")
        if new_password_env not in os.environ:
            raise typer.BadParameter(
                f"Environment variable {new_password_env!r} is not set",
                param_hint="--new-password-env",
            )
        new_password = os.environ[new_password_env]
    else:
        if sys.stdin.isatty():
            raise typer.BadParameter(
                "--new-password-stdin requires piped standard input",
                param_hint="--new-password-stdin",
            )
        new_password = _read_password_stdin()

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        result = connected_device.set_admin_password(
            PasswordUpdate(new_password=SecretStr(new_password))
        )
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "changed": result.changed,
        "system": result.value.model_dump(mode="json"),
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    human = "Administrator password changed and verified with the new credentials."
    if result.warnings:
        human += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=human)


@system_app.command("configure")
def system_configure(
    ctx: typer.Context,
    address_mode: Annotated[AddressMode | None, typer.Option("--address-mode")] = None,
    static_ip: Annotated[str | None, typer.Option("--static-ip")] = None,
    readback_url: Annotated[
        str | None,
        typer.Option(
            "--readback-url",
            help="Device base URL to verify after a management address or VLAN change.",
        ),
    ] = None,
    unset_static_ip: Annotated[bool, typer.Option("--unset-static-ip")] = False,
    admin_mac: Annotated[str | None, typer.Option("--admin-mac")] = None,
    unset_admin_mac: Annotated[bool, typer.Option("--unset-admin-mac")] = False,
    name: Annotated[str | None, typer.Option("--name")] = None,
    allow_from: Annotated[str | None, typer.Option("--allow-from")] = None,
    unset_allow_from: Annotated[bool, typer.Option("--unset-allow-from")] = False,
    allow_prefix_length: Annotated[
        int | None, typer.Option("--allow-prefix-length", min=0, max=32)
    ] = None,
    allow_port: Annotated[
        list[int] | None,
        typer.Option("--allow-port", min=1, max=6, help="Repeat for the full allowed mask."),
    ] = None,
    allow_vlan: Annotated[int | None, typer.Option("--allow-vlan", min=1, max=4095)] = None,
    unset_allow_vlan: Annotated[bool, typer.Option("--unset-allow-vlan")] = False,
    independent_vlan_lookup: Annotated[
        ToggleOption | None, typer.Option("--independent-vlan-lookup")
    ] = None,
    igmp_snooping: Annotated[ToggleOption | None, typer.Option("--igmp-snooping")] = None,
    igmp_querier: Annotated[ToggleOption | None, typer.Option("--igmp-querier")] = None,
    igmp_fast_leave_port: Annotated[
        list[int] | None,
        typer.Option(
            "--igmp-fast-leave-port",
            min=1,
            max=6,
            help="Repeat for the full fast-leave mask.",
        ),
    ] = None,
    clear_igmp_fast_leave_ports: Annotated[
        bool, typer.Option("--clear-igmp-fast-leave-ports")
    ] = False,
    igmp_version: Annotated[IgmpVersion | None, typer.Option("--igmp-version")] = None,
    discovery_port: Annotated[
        list[int] | None,
        typer.Option(
            "--discovery-port",
            min=1,
            max=6,
            help="Repeat for the full discovery mask.",
        ),
    ] = None,
    clear_discovery_ports: Annotated[bool, typer.Option("--clear-discovery-ports")] = False,
) -> None:
    """Set and verify system configuration without prompting."""

    conflicting = (
        (static_ip is not None and unset_static_ip, "--static-ip and --unset-static-ip"),
        (admin_mac is not None and unset_admin_mac, "--admin-mac and --unset-admin-mac"),
        (allow_from is not None and unset_allow_from, "--allow-from and --unset-allow-from"),
        (allow_vlan is not None and unset_allow_vlan, "--allow-vlan and --unset-allow-vlan"),
        (
            igmp_fast_leave_port is not None and clear_igmp_fast_leave_ports,
            "--igmp-fast-leave-port and --clear-igmp-fast-leave-ports",
        ),
        (
            discovery_port is not None and clear_discovery_ports,
            "--discovery-port and --clear-discovery-ports",
        ),
    )
    for is_conflicting, options in conflicting:
        if is_conflicting:
            raise typer.BadParameter(f"{options} cannot be used together")
    if not any(
        value is not None
        for value in (
            address_mode,
            static_ip,
            admin_mac,
            name,
            allow_from,
            allow_prefix_length,
            allow_port,
            allow_vlan,
            independent_vlan_lookup,
            igmp_snooping,
            igmp_querier,
            igmp_fast_leave_port,
            igmp_version,
            discovery_port,
        )
    ) and not any(
        (
            unset_static_ip,
            unset_admin_mac,
            unset_allow_from,
            unset_allow_vlan,
            clear_igmp_fast_leave_ports,
            clear_discovery_ports,
        )
    ):
        raise typer.BadParameter("At least one system configuration option is required")

    allowed_ports = _system_ports(allow_port, "--allow-port")
    if allowed_ports is not None and 6 not in allowed_ports:
        raise typer.BadParameter("--allow-port must include management port 6")
    fast_leave_ports = _system_ports(igmp_fast_leave_port, "--igmp-fast-leave-port")
    discovery_ports = _system_ports(discovery_port, "--discovery-port")
    try:
        update = SystemConfigurationUpdate(
            address_mode=address_mode,
            static_ip="unset" if unset_static_ip else static_ip,
            admin_mac_address="unset" if unset_admin_mac else admin_mac,
            name=name,
            allow_from="unset" if unset_allow_from else allow_from,
            allow_prefix_length=allow_prefix_length,
            allowed_port_numbers=allowed_ports,
            allowed_vlan_id="unset" if unset_allow_vlan else allow_vlan,
            independent_vlan_lookup=(
                None
                if independent_vlan_lookup is None
                else independent_vlan_lookup is ToggleOption.ON
            ),
            igmp_enabled=None if igmp_snooping is None else igmp_snooping is ToggleOption.ON,
            igmp_querier=None if igmp_querier is None else igmp_querier is ToggleOption.ON,
            igmp_fast_leave_port_numbers=(() if clear_igmp_fast_leave_ports else fast_leave_ports),
            igmp_version=igmp_version,
            discovery_protocol_port_numbers=(() if clear_discovery_ports else discovery_ports),
        )
    except ValidationError as exc:
        raise typer.BadParameter(str(exc)) from exc

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        current = connected_device.get_system_info()
        result = connected_device.set_system_configuration(
            update,
            expected_current=current,
            readback_url=readback_url,
        )
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "changed": result.changed,
        "system": result.value.model_dump(mode="json"),
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    human = (
        "System configuration changed."
        if result.changed
        else "System configuration already matches; no change required."
    )
    if result.warnings:
        human += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=human)


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

    data: dict[str, Any] = {"ports": [_serialize_port(port) for port in ports]}
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    name_width = max(4, max((len(port.name) for port in ports), default=0))
    lines = [
        f"{'PORT':<4}   {'NAME':<{name_width}}   {'EN':<3}   {'LINK':<4}   "
        f"{'SPEED':<9}   {'NEGOTIATION':<17}   FLOW-CTRL"
    ]
    for port in ports:
        speed = _format_bit_rate(port.speed_bps)
        negotiation = (
            "auto"
            if port.auto_negotiation
            else f"{_format_bit_rate(port.configured_speed_bps)} "
            f"({'full' if port.configured_full_duplex else 'half'})"
        )
        lines.append(
            f"{port.number:<4}   {port.name:<{name_width}}   {_yes_no(port.enabled):<3}   "
            f"{'up' if port.link_up else 'down':<4}   {speed:<9}   {negotiation:<17}   "
            f"{_yes_no(port.flow_control)}"
        )
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@port_app.command("rename")
def port_rename(
    ctx: typer.Context,
    number: Annotated[int, typer.Argument(min=1, help="Port number to rename.")],
    name: Annotated[
        str, typer.Argument(help="New port name (up to 16 printable ASCII characters).")
    ],
) -> None:
    """Set and verify the configured name of one port."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    settings = cli_context.configuration.settings
    renderer = OutputRenderer(settings.output)

    try:
        connected_device = _connect_device(cli_context)
        result: OperationResult[PortInfo] = connected_device.set_port_name(
            PortNameUpdate(number=number, name=name)
        )
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "changed": result.changed,
        "port": _serialize_port(result.value),
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    if result.changed:
        human = f"Port {result.value.number} name changed to {result.value.name!r}."
    else:
        human = (
            f"Port {result.value.number} name is already {result.value.name!r}; no change required."
        )
    if result.warnings:
        human += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=human)


@port_app.command("configure")
def port_configure(
    ctx: typer.Context,
    number: Annotated[
        int, typer.Argument(min=1, max=5, help="Ethernet port number to configure (1-5).")
    ],
    state: Annotated[
        PortStateOption | None,
        typer.Option("--state", help="Set the port state: enabled or disabled."),
    ] = None,
    negotiation: Annotated[
        NegotiationOption | None,
        typer.Option("--negotiation", help="Select auto or forced negotiation."),
    ] = None,
    speed_bps: Annotated[
        int | None,
        typer.Option("--speed-bps", help="Forced speed: 10000000 or 100000000 bps."),
    ] = None,
    duplex: Annotated[
        DuplexOption | None,
        typer.Option("--duplex", help="Forced duplex: full or half."),
    ] = None,
    flow_control: Annotated[
        ToggleOption | None,
        typer.Option("--flow-control", help="Set flow control: on or off."),
    ] = None,
) -> None:
    """Set and verify Ethernet port configuration without prompting."""

    if state is None and negotiation is None and flow_control is None:
        raise typer.BadParameter("At least one configuration option is required")
    if negotiation is NegotiationOption.FORCED:
        if speed_bps is None or duplex is None:
            raise typer.BadParameter("--negotiation forced requires both --speed-bps and --duplex")
        if speed_bps not in (10_000_000, 100_000_000):
            raise typer.BadParameter("--speed-bps must be 10000000 or 100000000")
    elif speed_bps is not None or duplex is not None:
        raise typer.BadParameter(
            "--speed-bps and --duplex are valid only with --negotiation forced"
        )

    desired_negotiation: Literal["auto"] | ForcedPortNegotiation | None = None
    if negotiation is NegotiationOption.AUTO:
        desired_negotiation = "auto"
    elif negotiation is NegotiationOption.FORCED:
        assert speed_bps is not None and duplex is not None
        desired_negotiation = ForcedPortNegotiation(
            speed_bps=cast(Literal[10_000_000, 100_000_000], speed_bps),
            duplex=duplex.value,
        )
    update = PortConfigurationUpdate(
        number=number,
        enabled=None if state is None else state is PortStateOption.ENABLED,
        negotiation=desired_negotiation,
        flow_control=None if flow_control is None else flow_control is ToggleOption.ON,
    )

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        result: OperationResult[PortInfo] = connected_device.set_port_configuration(update)
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "changed": result.changed,
        "port": _serialize_port(result.value),
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    human = (
        f"Port {result.value.number} configuration changed."
        if result.changed
        else f"Port {result.value.number} already has the requested configuration; "
        "no change required."
    )
    if result.warnings:
        human += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=human)


@port_app.command("stats")
def port_stats(
    ctx: typer.Context,
    errors: Annotated[bool, typer.Option("--errors", help="Include detailed errors.")] = False,
    rates: Annotated[bool, typer.Option("--rates", help="Include current rates.")] = False,
    traffic: Annotated[
        bool, typer.Option("--traffic", help="Include unicast/broadcast/multicast counters.")
    ] = False,
    sizes: Annotated[bool, typer.Option("--sizes", help="Include packet-size counters.")] = False,
    full: Annotated[bool, typer.Option("--full", help="Include all statistic groups.")] = False,
) -> None:
    """List traffic, rate, size, and error counters for every port."""

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

    errors = errors or full
    rates = rates or full
    traffic = traffic or full
    sizes = sizes or full
    serialized_ports: list[dict[str, Any]] = []
    for port in statistics:
        serialized = port.model_dump(mode="json")
        if not errors:
            serialized.pop("detailed_errors")
        if not rates:
            serialized.pop("rates")
        if not traffic:
            serialized.pop("traffic")
        if not sizes:
            serialized.pop("rx_sizes")
            serialized.pop("tx_sizes")
        serialized_ports.append(serialized)
    data: dict[str, Any] = {"ports": serialized_ports}
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
    if errors or rates or traffic or sizes:
        for port in statistics:
            lines.extend(["", f"Port {port.number}"])
            if rates:
                lines.append(
                    "  Rates: "
                    f"RX {_format_bit_rate(port.rates.rx_bits_per_second)} / "
                    f"{port.rates.rx_packets_per_second:g} pps, "
                    f"TX {_format_bit_rate(port.rates.tx_bits_per_second)} / "
                    f"{port.rates.tx_packets_per_second:g} pps"
                )
            if traffic:
                value = port.traffic
                lines.append(
                    "  Traffic: "
                    f"RX unicast={value.rx_unicast_packets}, "
                    f"broadcast={value.rx_broadcast_packets}, "
                    f"multicast={value.rx_multicast_packets}; "
                    f"TX unicast={value.tx_unicast_packets}, "
                    f"broadcast={value.tx_broadcast_packets}, "
                    f"multicast={value.tx_multicast_packets}"
                )
            if sizes:
                lines.append(f"  RX sizes: {_packet_sizes(port.rx_sizes)}")
                lines.append(f"  TX sizes: {_packet_sizes(port.tx_sizes)}")
            if errors:
                lines.extend(_error_counter_lines(port.detailed_errors))
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@sfp_app.command("show")
def sfp_show(ctx: typer.Context) -> None:
    """Show SFP module identity and diagnostics."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        info = connected_device.get_sfp()
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
        f"Vendor: {info.vendor or '-'}",
        f"Part Number: {info.part_number or '-'}",
        f"Revision: {info.revision or '-'}",
        f"Serial Number: {info.serial_number or '-'}",
        f"Manufacturing Date: {info.manufacturing_date or '-'}",
        f"Media Type: {info.media_type or '-'}",
        f"Temperature: {_measurement(info.temperature_celsius, 'C')}",
        f"Supply Voltage: {_measurement(info.supply_voltage_volts, 'V')}",
        f"TX Bias: {_measurement(info.tx_bias_ma, 'mA')}",
        f"TX Power: {_measurement(info.tx_power_dbm, 'dBm')}",
        f"RX Power: {_measurement(info.rx_power_dbm, 'dBm')}",
    ]
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@forwarding_app.command("show")
def forwarding_show(ctx: typer.Context) -> None:
    """Show forwarding, port-lock, mirror, and egress-rate policy."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        info = connected_device.get_forwarding()
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
        f"Mirror Target: {info.mirror_target_port or '-'}",
        "",
        "PORT  FORWARD TO   LOCK  LOCK FIRST  MIRROR RX  MIRROR TX  EGRESS LIMIT",
    ]
    for port in info.ports:
        limit = (
            _format_bit_rate(port.egress_rate_limit_bps)
            if port.egress_rate_limit_bps
            else "unlimited"
        )
        lines.append(
            f"{port.number:<5} {_ports(port.destination_port_numbers):<12} "
            f"{_yes_no(port.lock):<5} {_yes_no(port.lock_on_first):<11} "
            f"{_yes_no(port.mirror_ingress):<10} {_yes_no(port.mirror_egress):<10} {limit}"
        )
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@forwarding_app.command("configure")
def forwarding_configure(
    ctx: typer.Context,
    number: Annotated[
        int, typer.Argument(min=1, max=5, help="Ethernet port number to configure (1-5).")
    ],
    lock: Annotated[
        ToggleOption | None, typer.Option("--lock", help="Set port locking on or off.")
    ] = None,
    lock_on_first: Annotated[
        ToggleOption | None,
        typer.Option("--lock-on-first", help="Set lock-on-first on or off."),
    ] = None,
    egress_rate_bps: Annotated[
        int | None,
        typer.Option("--egress-rate-bps", min=1, max=0xFFFFFFFF),
    ] = None,
    egress_unlimited: Annotated[
        bool,
        typer.Option("--egress-unlimited", help="Remove the egress rate limit."),
    ] = False,
) -> None:
    """Set and verify safe per-port forwarding policy without prompting."""

    if lock is None and lock_on_first is None and egress_rate_bps is None and not egress_unlimited:
        raise typer.BadParameter("At least one forwarding policy option is required")
    if egress_rate_bps is not None and egress_unlimited:
        raise typer.BadParameter("--egress-rate-bps cannot be combined with --egress-unlimited")
    rate: int | Literal["unlimited"] | None = egress_rate_bps
    if egress_unlimited:
        rate = "unlimited"
    update = ForwardingPortPolicyUpdate(
        number=number,
        lock=None if lock is None else lock is ToggleOption.ON,
        lock_on_first=None if lock_on_first is None else lock_on_first is ToggleOption.ON,
        egress_rate_limit_bps=rate,
    )

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        current = connected_device.get_forwarding()
        result: OperationResult[ForwardingInfo] = connected_device.set_forwarding_port_policy(
            update, expected_current=current
        )
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    port = result.value.ports[number - 1]
    data: dict[str, Any] = {
        "changed": result.changed,
        "forwarding": result.value.model_dump(mode="json"),
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    action = "changed" if result.changed else "already configured; no change required"
    human = "\n".join(
        [
            f"Port {number} forwarding policy {action}.",
            f"Lock: {_yes_no(port.lock)}",
            f"Lock on first: {_yes_no(port.lock_on_first)}",
            "Egress limit: "
            + (
                _format_bit_rate(port.egress_rate_limit_bps)
                if port.egress_rate_limit_bps is not None
                else "unlimited"
            ),
        ]
    )
    if result.warnings:
        human += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=human)


@igmp_app.command("list")
def igmp_list(ctx: typer.Context) -> None:
    """List dynamically learned multicast groups."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        groups = connected_device.get_igmp_groups()
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {"groups": [group.model_dump(mode="json") for group in groups]}
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    lines = ["GROUP ADDRESS    VLAN  PORTS"]
    lines.extend(
        f"{group.address:<16} {group.vlan_id:<5} {_ports(group.port_numbers)}" for group in groups
    )
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@acl_app.command("list")
def acl_list(ctx: typer.Context) -> None:
    """List ordered access-control rules."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        rules = connected_device.get_acl_rules()
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {"rules": [rule.model_dump(mode="json") for rule in rules]}
    if connected_device.warnings:
        data["warnings"] = [
            warning.model_dump(mode="json") for warning in connected_device.warnings
        ]
    lines: list[str] = []
    for rule in rules:
        actions = []
        if rule.drop:
            actions.append("drop")
        elif rule.redirect_enabled:
            actions.append(f"redirect={_ports(rule.redirect_port_numbers)}")
        if rule.mirror:
            actions.append("mirror")
        if rule.ingress_rate_limit_bps is not None:
            actions.append(f"rate={_format_bit_rate(rule.ingress_rate_limit_bps)}")
        if rule.set_vlan_id is not None:
            actions.append(f"set-vlan={rule.set_vlan_id}")
        if rule.set_vlan_priority is not None:
            actions.append(f"set-priority={rule.set_vlan_priority}")
        lines.extend(
            [
                f"Rule {rule.number}",
                f"  Ingress Ports: {_ports(rule.ingress_port_numbers)}",
                f"  Source MAC: {rule.source_mac or '*'} / {rule.source_mac_mask}",
                f"  Destination MAC: {rule.destination_mac or '*'} / {rule.destination_mac_mask}",
                f"  EtherType: 0x{rule.ether_type:04x}",
                f"  VLAN: {rule.vlan_tag.value.replace('_', ' ')}, "
                f"IDs {rule.vlan_id_min}-{rule.vlan_id_max}, "
                f"priority {rule.vlan_priority if rule.vlan_priority is not None else '*'}",
                f"  Source: {_network(rule.source_ip, rule.source_prefix_length)} "
                f"ports {rule.source_port_min}-{rule.source_port_max}",
                f"  Destination: {_network(rule.destination_ip, rule.destination_prefix_length)} "
                f"ports {rule.destination_port_min}-{rule.destination_port_max}",
                f"  Protocol: {rule.protocol_number}, DSCP: "
                f"{rule.dscp if rule.dscp is not None else '*'}",
                f"  Actions: {', '.join(actions) or 'none'}",
                "",
            ]
        )
    if not rules:
        lines.append("No ACL rules configured.")
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines).rstrip())


@acl_app.command("add")
def acl_add(
    ctx: typer.Context,
    ingress_port: Annotated[
        list[int], typer.Option("--ingress-port", min=1, max=5, help="Ingress port (repeatable).")
    ],
    source_mac: Annotated[str | None, typer.Option("--source-mac")] = None,
    source_mac_mask: Annotated[str, typer.Option("--source-mac-mask")] = "ff:ff:ff:ff:ff:ff",
    destination_mac: Annotated[str | None, typer.Option("--destination-mac")] = None,
    destination_mac_mask: Annotated[
        str, typer.Option("--destination-mac-mask")
    ] = "ff:ff:ff:ff:ff:ff",
    ether_type: Annotated[int, typer.Option("--ether-type", min=0, max=0xFFFF)] = 0,
    vlan_tag: Annotated[AclVlanTagMode, typer.Option("--vlan-tag")] = AclVlanTagMode.ANY,
    vlan_id_min: Annotated[int, typer.Option("--vlan-id-min", min=0, max=4095)] = 0,
    vlan_id_max: Annotated[int, typer.Option("--vlan-id-max", min=0, max=4095)] = 0,
    vlan_priority: Annotated[int | None, typer.Option("--vlan-priority", min=0, max=7)] = None,
    source_ip: Annotated[str | None, typer.Option("--source-ip")] = None,
    source_prefix_length: Annotated[int, typer.Option("--source-prefix-length", min=0, max=32)] = 0,
    source_port_min: Annotated[int, typer.Option("--source-port-min", min=0, max=0xFFFF)] = 0,
    source_port_max: Annotated[int, typer.Option("--source-port-max", min=0, max=0xFFFF)] = 0,
    destination_ip: Annotated[str | None, typer.Option("--destination-ip")] = None,
    destination_prefix_length: Annotated[
        int, typer.Option("--destination-prefix-length", min=0, max=32)
    ] = 0,
    destination_port_min: Annotated[
        int, typer.Option("--destination-port-min", min=0, max=0xFFFF)
    ] = 0,
    destination_port_max: Annotated[
        int, typer.Option("--destination-port-max", min=0, max=0xFFFF)
    ] = 0,
    protocol_number: Annotated[int, typer.Option("--protocol-number", min=0, max=0xFF)] = 0,
    dscp: Annotated[int | None, typer.Option("--dscp", min=0, max=63)] = None,
    redirect_port: Annotated[
        list[int] | None,
        typer.Option("--redirect-port", min=1, max=6, help="Redirect target (repeatable)."),
    ] = None,
    drop: Annotated[bool, typer.Option("--drop", help="Drop matching traffic.")] = False,
    mirror: Annotated[bool, typer.Option("--mirror", help="Mirror matching traffic.")] = False,
    rate_bps: Annotated[int | None, typer.Option("--rate-bps", min=1, max=0xFFFFFFFF)] = None,
    set_vlan_id: Annotated[int | None, typer.Option("--set-vlan-id", min=1, max=4095)] = None,
    set_vlan_priority: Annotated[
        int | None, typer.Option("--set-vlan-priority", min=0, max=7)
    ] = None,
) -> None:
    """Append and verify one fully typed ACL rule without prompting."""

    if drop and redirect_port:
        raise typer.BadParameter("--drop cannot be combined with --redirect-port")
    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        current = connected_device.get_acl_rules()
        redirect_ports = tuple(sorted(redirect_port or ()))
        rule = AclRule(
            number=len(current) + 1,
            ingress_port_numbers=tuple(sorted(ingress_port)),
            source_mac=source_mac,
            source_mac_mask=source_mac_mask,
            destination_mac=destination_mac,
            destination_mac_mask=destination_mac_mask,
            ether_type=ether_type,
            vlan_tag=vlan_tag,
            vlan_id_min=vlan_id_min,
            vlan_id_max=vlan_id_max,
            vlan_priority=vlan_priority,
            source_ip=source_ip,
            source_prefix_length=source_prefix_length,
            source_port_min=source_port_min,
            source_port_max=source_port_max,
            destination_ip=destination_ip,
            destination_prefix_length=destination_prefix_length,
            destination_port_min=destination_port_min,
            destination_port_max=destination_port_max,
            protocol_number=protocol_number,
            dscp=dscp,
            redirect_enabled=drop or bool(redirect_ports),
            redirect_port_numbers=redirect_ports,
            drop=drop,
            mirror=mirror,
            ingress_rate_limit_bps=rate_bps,
            set_vlan_id=set_vlan_id,
            set_vlan_priority=set_vlan_priority,
        )
        result = connected_device.replace_acl_rules((*current, rule), expected_current=current)
    except ValidationError as exc:
        renderer.error("invalid_acl_rule", str(exc))
        raise typer.Exit(code=2) from exc
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    _render_acl_write(renderer, result, "ACL rule appended")


@acl_app.command("remove")
def acl_remove(
    ctx: typer.Context,
    number: Annotated[int, typer.Argument(min=1, help="Ordered ACL rule number to remove.")],
) -> None:
    """Remove an ACL rule by number and verify the complete remaining table."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        current = connected_device.get_acl_rules()
        desired = tuple(
            rule.model_copy(update={"number": index})
            for index, rule in enumerate(
                (rule for rule in current if rule.number != number), start=1
            )
        )
        result = connected_device.replace_acl_rules(desired, expected_current=current)
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    _render_acl_write(renderer, result, f"ACL rule {number} removed")


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


@host_app.command("add")
def host_add(
    ctx: typer.Context,
    mac_address: Annotated[str, typer.Option("--mac", help="Static host MAC address.")],
    vlan_id: Annotated[int, typer.Option("--vlan", min=1, max=4095)],
    port: Annotated[
        list[int] | None,
        typer.Option("--port", min=1, max=5, help="Target Ethernet port (repeatable)."),
    ] = None,
    drop: Annotated[bool, typer.Option("--drop")] = False,
    mirror: Annotated[bool, typer.Option("--mirror")] = False,
) -> None:
    """Add or replace one static host by MAC and VLAN without prompting."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        current = tuple(
            host for host in connected_device.get_hosts() if host.entry_type is HostEntryType.STATIC
        )
        host = HostEntry(
            entry_type=HostEntryType.STATIC,
            mac_address=mac_address,
            vlan_id=vlan_id,
            port_numbers=tuple(sorted(port or ())),
            drop=drop,
            mirror=mirror,
        )
        desired = list(current)
        for index, existing in enumerate(desired):
            if (existing.mac_address, existing.vlan_id) == (host.mac_address, host.vlan_id):
                desired[index] = host
                break
        else:
            desired.append(host)
        result = connected_device.replace_static_hosts(tuple(desired), expected_current=current)
    except ValidationError as exc:
        renderer.error("invalid_static_host", str(exc))
        raise typer.Exit(code=2) from exc
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    _render_host_write(renderer, result, "Static host added or updated")


@host_app.command("remove")
def host_remove(
    ctx: typer.Context,
    mac_address: Annotated[str, typer.Option("--mac", help="Static host MAC address.")],
    vlan_id: Annotated[int, typer.Option("--vlan", min=1, max=4095)],
) -> None:
    """Remove one static host by exact MAC and VLAN identity."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        key = HostEntry(
            entry_type=HostEntryType.STATIC,
            mac_address=mac_address,
            vlan_id=vlan_id,
            port_numbers=(),
        )
        connected_device = _connect_device(cli_context)
        current = tuple(
            host for host in connected_device.get_hosts() if host.entry_type is HostEntryType.STATIC
        )
        desired = tuple(
            host
            for host in current
            if (host.mac_address, host.vlan_id) != (key.mac_address, key.vlan_id)
        )
        result = connected_device.replace_static_hosts(desired, expected_current=current)
    except ValidationError as exc:
        renderer.error("invalid_static_host", str(exc))
        raise typer.Exit(code=2) from exc
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    _render_host_write(renderer, result, "Static host removed")


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
        "PORT  ENABLED  PROTOCOL  ROLE        CONFIG COST  ROOT COST  TYPE            STATE",
    ]
    for port in info.ports:
        lines.append(
            f"{port.number:<5} {_yes_no(port.enabled):<8} {port.protocol.value:<9} "
            f"{port.role.value:<11} {port.configured_path_cost:<12} "
            f"{port.root_path_cost:<10} "
            f"{port.port_type.value.replace('_', ' '):<15} {port.state.value}"
        )
    lines.extend(f"Warning: {warning.message}" for warning in connected_device.warnings)
    renderer.success(data, human="\n".join(lines))


@rstp_app.command("configure")
def rstp_configure(
    ctx: typer.Context,
    number: Annotated[
        int, typer.Argument(min=1, max=5, help="Ethernet port number to configure (1-5).")
    ],
    state: Annotated[
        PortStateOption, typer.Option("--state", help="Set RSTP enabled or disabled.")
    ],
) -> None:
    """Set and verify one port's RSTP enable state without prompting."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        current = connected_device.get_rstp()
        result: OperationResult[RstpInfo] = connected_device.set_rstp_port_enabled(
            RstpPortEnableUpdate(
                number=number,
                enabled=state is PortStateOption.ENABLED,
            ),
            expected_current=current,
        )
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    port = result.value.ports[number - 1]
    data: dict[str, Any] = {
        "changed": result.changed,
        "rstp": result.value.model_dump(mode="json"),
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    action = "changed" if result.changed else "already configured; no change required"
    human = f"Port {number} RSTP state {action}.\nEnabled: {_yes_no(port.enabled)}"
    if result.warnings:
        human += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=human)


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


@snmp_metadata_app.command("set")
def snmp_metadata_set(
    ctx: typer.Context,
    contact: Annotated[
        str | None,
        typer.Option(
            "--contact",
            help="SNMP contact; omit to preserve or pass an empty string to clear.",
        ),
    ] = None,
    location: Annotated[
        str | None,
        typer.Option(
            "--location",
            help="SNMP location; omit to preserve or pass an empty string to clear.",
        ),
    ] = None,
) -> None:
    """Set and verify SNMP contact and location metadata."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        result: OperationResult[SnmpInfo] = connected_device.set_snmp_metadata(
            SnmpMetadataUpdate(contact=contact, location=location)
        )
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    data: dict[str, Any] = {
        "changed": result.changed,
        "snmp": {
            "enabled": result.value.enabled,
            "contact": result.value.contact,
            "location": result.value.location,
        },
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    action = "changed" if result.changed else "already configured; no change required"
    human = "\n".join(
        [
            f"SNMP metadata {action}.",
            f"Contact: {result.value.contact}",
            f"Location: {result.value.location}",
        ]
    )
    if result.warnings:
        human += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=human)


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


@vlan_app.command("configure-port")
def vlan_configure_port(
    ctx: typer.Context,
    number: Annotated[
        int, typer.Argument(min=1, max=5, help="Ethernet port number to configure (1-5).")
    ],
    mode: Annotated[VlanMode | None, typer.Option("--mode")] = None,
    receive: Annotated[VlanReceiveMode | None, typer.Option("--receive")] = None,
    default_vlan_id: Annotated[
        int | None, typer.Option("--default-vlan-id", min=1, max=4095)
    ] = None,
    force_vlan_id: Annotated[
        ToggleOption | None, typer.Option("--force-vlan-id", help="Set forced VLAN ID on or off.")
    ] = None,
    egress: Annotated[VlanEgressMode | None, typer.Option("--egress")] = None,
) -> None:
    """Set and verify one Ethernet port's VLAN policy without prompting."""

    if all(value is None for value in (mode, receive, default_vlan_id, force_vlan_id, egress)):
        raise typer.BadParameter("At least one VLAN policy option is required")
    update = PortVlanPolicyUpdate(
        number=number,
        mode=mode,
        receive=receive,
        default_vlan_id=default_vlan_id,
        force_vlan_id=(None if force_vlan_id is None else force_vlan_id is ToggleOption.ON),
        egress=egress,
    )
    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        current = connected_device.get_port_vlans()
        result = connected_device.set_port_vlan_policy(update, expected_current=current)
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    port = next(port for port in result.value if port.number == number)
    data: dict[str, Any] = {
        "changed": result.changed,
        "ports": [item.model_dump(mode="json") for item in result.value],
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    action = "changed" if result.changed else "already configured; no change required"
    human = "\n".join(
        [
            f"Port {number} VLAN policy {action}.",
            f"Mode: {port.mode.value}",
            f"Receive: {port.receive.value.replace('_', ' ')}",
            f"Default VLAN: {port.default_vlan_id}",
            f"Force VLAN ID: {_yes_no(port.force_vlan_id)}",
            f"Egress: {port.egress.value.replace('_', ' ')}",
        ]
    )
    if result.warnings:
        human += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=human)


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


@vlan_app.command("set")
def vlan_set(
    ctx: typer.Context,
    vlan_id: Annotated[int, typer.Argument(min=1, max=4095)],
    independent_learning: Annotated[
        ToggleOption | None, typer.Option("--independent-learning")
    ] = None,
    igmp_snooping: Annotated[ToggleOption | None, typer.Option("--igmp-snooping")] = None,
    port_mode: Annotated[
        list[str] | None,
        typer.Option(
            "--port-mode",
            help="Ethernet membership as PORT=MODE; repeat for ports 1-5.",
        ),
    ] = None,
) -> None:
    """Add or replace one VLAN row through a guarded full-table write."""

    parsed_port_modes = _parse_vlan_port_modes(port_mode or [])
    if independent_learning is None and igmp_snooping is None and not parsed_port_modes:
        raise typer.BadParameter("At least one VLAN table option is required")
    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        current = connected_device.get_vlans()
        existing = next((vlan for vlan in current if vlan.vlan_id == vlan_id), None)
        memberships = (
            {port.port_number: port.mode for port in existing.ports}
            if existing is not None
            else {number: VlanMembershipMode.NOT_MEMBER for number in range(1, 7)}
        )
        memberships.update(parsed_port_modes)
        desired_vlan = VlanInfo(
            vlan_id=vlan_id,
            independent_learning=(
                existing.independent_learning
                if independent_learning is None and existing is not None
                else independent_learning is ToggleOption.ON
            ),
            igmp_snooping=(
                existing.igmp_snooping
                if igmp_snooping is None and existing is not None
                else igmp_snooping is ToggleOption.ON
            ),
            ports=tuple(
                VlanPortMembership(port_number=number, mode=memberships[number])
                for number in range(1, 7)
            ),
        )
        desired = tuple(
            sorted(
                (*tuple(vlan for vlan in current if vlan.vlan_id != vlan_id), desired_vlan),
                key=lambda vlan: vlan.vlan_id,
            )
        )
        result = connected_device.replace_vlans(desired, expected_current=current)
    except ValidationError as exc:
        renderer.error("invalid_vlan", str(exc))
        raise typer.Exit(code=2) from exc
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    _render_vlan_write(renderer, result, f"VLAN {vlan_id} added or updated")


@vlan_app.command("remove")
def vlan_remove(
    ctx: typer.Context,
    vlan_id: Annotated[int, typer.Argument(min=1, max=4095)],
) -> None:
    """Remove one VLAN row through a guarded full-table write."""

    cli_context: CliContext = ctx.ensure_object(CliContext)
    renderer = OutputRenderer(cli_context.configuration.settings.output)
    try:
        connected_device = _connect_device(cli_context)
        current = connected_device.get_vlans()
        desired = tuple(vlan for vlan in current if vlan.vlan_id != vlan_id)
        result = connected_device.replace_vlans(desired, expected_current=current)
    except ConfigurationError as exc:
        renderer.error("configuration_error", str(exc))
        raise typer.Exit(code=2) from exc
    except SwOSError as exc:
        renderer.error(_error_code(exc), str(exc))
        raise typer.Exit(code=1) from exc

    _render_vlan_write(renderer, result, f"VLAN {vlan_id} removed")


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


def _read_password_stdin() -> str:
    value = sys.stdin.read()
    if value.endswith("\n"):
        value = value[:-1]
        if value.endswith("\r"):
            value = value[:-1]
    return value


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _ports(port_numbers: tuple[int, ...]) -> str:
    return ",".join(str(number) for number in port_numbers) or "-"


def _system_ports(values: list[int] | None, option: str) -> tuple[int, ...] | None:
    if values is None:
        return None
    if len(values) != len(set(values)):
        raise typer.BadParameter(f"{option} cannot repeat a port")
    return tuple(sorted(values))


def _render_host_write(
    renderer: OutputRenderer,
    result: OperationResult[tuple[HostEntry, ...]],
    action: str,
) -> None:
    data: dict[str, Any] = {
        "changed": result.changed,
        "hosts": [host.model_dump(mode="json") for host in result.value],
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    message = f"{action}." if result.changed else "Static host table unchanged; no change required."
    if result.warnings:
        message += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=message)


def _render_acl_write(
    renderer: OutputRenderer,
    result: OperationResult[tuple[AclRule, ...]],
    action: str,
) -> None:
    data: dict[str, Any] = {
        "changed": result.changed,
        "rules": [rule.model_dump(mode="json") for rule in result.value],
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    message = f"{action}." if result.changed else "ACL table unchanged; no change required."
    if result.warnings:
        message += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=message)


def _render_vlan_write(
    renderer: OutputRenderer,
    result: OperationResult[tuple[VlanInfo, ...]],
    action: str,
) -> None:
    data: dict[str, Any] = {
        "changed": result.changed,
        "vlans": [vlan.model_dump(mode="json") for vlan in result.value],
    }
    if result.warnings:
        data["warnings"] = [warning.model_dump(mode="json") for warning in result.warnings]
    message = f"{action}." if result.changed else "VLAN table unchanged; no change required."
    if result.warnings:
        message += "\n" + "\n".join(f"Warning: {warning.message}" for warning in result.warnings)
    renderer.success(data, human=message)


def _parse_vlan_port_modes(values: list[str]) -> dict[int, VlanMembershipMode]:
    parsed: dict[int, VlanMembershipMode] = {}
    choices = ", ".join(mode.value for mode in VlanMembershipMode)
    for value in values:
        number_text, separator, mode_text = value.partition("=")
        try:
            number = int(number_text)
            mode = VlanMembershipMode(mode_text)
        except ValueError as exc:
            raise typer.BadParameter(
                f"--port-mode must be PORT=MODE with MODE one of: {choices}"
            ) from exc
        if not separator or number not in range(1, 6):
            raise typer.BadParameter("--port-mode port must be between 1 and 5")
        if number in parsed:
            raise typer.BadParameter(f"--port-mode repeats port {number}")
        parsed[number] = mode
    return parsed


def _network(address: str | None, prefix_length: int) -> str:
    return f"{address}/{prefix_length}" if address is not None else "*"


def _measurement(value: int | float | None, unit: str) -> str:
    return f"{value:g} {unit}" if value is not None else "-"


def _serialize_port(port: PortInfo) -> dict[str, Any]:
    serialized = port.model_dump(mode="json")
    auto_negotiation = serialized.pop("auto_negotiation")
    configured_speed = serialized.pop("configured_speed_bps")
    configured_duplex = serialized.pop("configured_full_duplex")
    serialized["negotiation"] = (
        "auto"
        if auto_negotiation
        else {
            "speed_bps": configured_speed,
            "duplex": "full" if configured_duplex else "half",
        }
    )
    return serialized


def _format_bit_rate(bits_per_second: int | float | None) -> str:
    if bits_per_second is None:
        return "-"
    if bits_per_second >= 1_000_000_000:
        return f"{bits_per_second / 1_000_000_000:g} Gbps"
    if bits_per_second >= 1_000_000:
        return f"{bits_per_second / 1_000_000:g} Mbps"
    if bits_per_second >= 1_000:
        return f"{bits_per_second / 1_000:g} Kbps"
    return f"{bits_per_second:g} bps"


def _packet_sizes(value: PacketSizeStatistics) -> str:
    return (
        f"64={value.frames_64_bytes}, 65-127={value.frames_65_to_127_bytes}, "
        f"128-255={value.frames_128_to_255_bytes}, "
        f"256-511={value.frames_256_to_511_bytes}, "
        f"512-1023={value.frames_512_to_1023_bytes}, "
        f"1024-1518={value.frames_1024_to_1518_bytes}, "
        f"1519-max={value.frames_1519_to_max_bytes}"
    )


def _error_counter_lines(value: PortErrorStatistics) -> list[str]:
    return [
        "  RX errors: "
        f"pause={value.rx_pause_frames}, fcs={value.rx_fcs_errors}, "
        f"alignment={value.rx_alignment_errors}, runts={value.rx_runts}, "
        f"fragments={value.rx_fragments}, too-long={value.rx_too_long}, "
        f"overflows={value.rx_overflows}",
        "  TX errors: "
        f"pause={value.tx_pause_frames}, underruns={value.tx_underruns}, "
        f"too-long={value.tx_too_long}, collisions={value.tx_collisions}, "
        f"excessive-collisions={value.tx_excessive_collisions}, "
        f"multiple-collisions={value.tx_multiple_collisions}, "
        f"single-collisions={value.tx_single_collisions}, "
        f"excessive-deferred={value.tx_excessive_deferred}, "
        f"deferred={value.tx_deferred}, late-collisions={value.tx_late_collisions}",
    ]


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
