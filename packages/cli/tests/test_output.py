import json
from importlib import import_module
from typing import ClassVar

import pytest
from swos_cli import __version__
from swos_cli.output import OutputFormat, OutputRenderer
from swos_core.errors import AuthenticationError
from swos_core.models import (
    AclRule,
    DeviceIdentity,
    DeviceNameUpdate,
    ForcedPortNegotiation,
    ForwardingInfo,
    ForwardingMatrixUpdate,
    ForwardingMirroringUpdate,
    ForwardingPortPolicyUpdate,
    HostEntry,
    IgmpGroup,
    IgmpInfo,
    OperationResult,
    PacketSizeStatistics,
    PasswordUpdate,
    PortConfigurationUpdate,
    PortErrorStatistics,
    PortForwardingInfo,
    PortInfo,
    PortNameUpdate,
    PortRateStatistics,
    PortStatistics,
    PortTrafficStatistics,
    PortVlanInfo,
    PortVlanPolicyUpdate,
    RstpBridgeUpdate,
    RstpInfo,
    RstpPortEnableUpdate,
    RstpPortInfo,
    SfpInfo,
    SnmpConfigurationUpdate,
    SnmpInfo,
    SnmpMetadataUpdate,
    SystemConfigurationUpdate,
    SystemHealth,
    SystemInfo,
    SystemManagementInfo,
    VlanInfo,
    VlanPortMembership,
)
from swos_core.safety import SafetyWarning
from typer.testing import CliRunner

app_module = import_module("swos_cli.app")
app = app_module.app
runner = CliRunner()


def test_output_renderer_sanitizes_human_controls_and_json_escapes_them(capsys) -> None:  # type: ignore[no-untyped-def]
    OutputRenderer(OutputFormat.HUMAN).success({}, human="safe\nunsafe\x1b[31m")
    assert capsys.readouterr().out == "safe\nunsafe\ufffd[31m\n"

    OutputRenderer(OutputFormat.JSON).success({"value": "unsafe\x1b"}, human="")
    output = capsys.readouterr().out
    assert "\\u001b" in output
    assert "\x1b" not in output


def _packet_sizes(base: int) -> PacketSizeStatistics:
    return PacketSizeStatistics(
        frames_64_bytes=base,
        frames_65_to_127_bytes=base + 1,
        frames_128_to_255_bytes=base + 2,
        frames_256_to_511_bytes=base + 3,
        frames_512_to_1023_bytes=base + 4,
        frames_1024_to_1518_bytes=base + 5,
        frames_1519_to_max_bytes=base + 6,
    )


def _detailed_errors() -> PortErrorStatistics:
    return PortErrorStatistics(
        rx_pause_frames=1,
        rx_fcs_errors=2,
        rx_alignment_errors=3,
        rx_runts=4,
        rx_fragments=5,
        rx_too_long=6,
        rx_overflows=7,
        tx_pause_frames=8,
        tx_underruns=9,
        tx_too_long=10,
        tx_collisions=11,
        tx_excessive_collisions=12,
        tx_multiple_collisions=13,
        tx_single_collisions=14,
        tx_excessive_deferred=15,
        tx_deferred=16,
        tx_late_collisions=17,
    )


class FakeDevice:
    password_updates: ClassVar[list[str]] = []
    snmp_community_updates: ClassVar[list[str]] = []
    system_readback_urls: ClassVar[list[str | None]] = []

    def __init__(
        self,
        identity: DeviceIdentity,
        warnings: tuple[SafetyWarning, ...] = (),
    ) -> None:
        self.identity = identity
        self.warnings = warnings

    def get_system_info(self) -> SystemInfo:
        return SystemInfo(
            identity=self.identity,
            name="Office Switch",
            uptime_seconds=90061,
            current_ip="192.168.88.1",
            static_ip="192.168.88.1",
            mac_address="02:00:00:00:00:01",
            serial_number="TEST1234",
            management=SystemManagementInfo(
                address_mode="dhcp_with_fallback",
                admin_mac_address=None,
                allow_from="192.168.88.0",
                allow_prefix_length=24,
                allowed_port_numbers=(1, 6),
                allowed_vlan_id=10,
                watchdog_enabled=True,
            ),
            independent_vlan_lookup=True,
            igmp=IgmpInfo(
                enabled=True,
                querier_configured=True,
                querier_effective=True,
                fast_leave_port_numbers=(2,),
                version="v3",
            ),
            discovery_protocol_port_numbers=(1, 2),
            health=SystemHealth(
                input_voltage_volts=24.2,
                temperature_celsius=41,
                poe_in_long_cable=False,
            ),
        )

    def get_ports(self) -> tuple[PortInfo, ...]:
        return (
            PortInfo(
                number=1,
                name="LongPortName1234",
                enabled=True,
                link_up=True,
                speed_bps=1_000_000_000,
                full_duplex=True,
                auto_negotiation=True,
                configured_speed_bps=100_000_000,
                configured_full_duplex=True,
                flow_control=True,
            ),
            PortInfo(
                number=2,
                name="Port2",
                enabled=True,
                link_up=False,
                auto_negotiation=False,
                configured_speed_bps=10_000_000,
                configured_full_duplex=False,
                flow_control=False,
            ),
        )

    def get_port_statistics(self) -> tuple[PortStatistics, ...]:
        return (
            PortStatistics(
                number=1,
                rx_bytes=1234,
                tx_bytes=5678,
                rx_packets=12,
                tx_packets=34,
                rx_errors=0,
                tx_errors=1,
                rates=PortRateStatistics(
                    rx_bits_per_second=1000,
                    tx_bits_per_second=2000,
                    rx_packets_per_second=10,
                    tx_packets_per_second=20,
                ),
                traffic=PortTrafficStatistics(
                    rx_unicast_packets=10,
                    tx_unicast_packets=20,
                    rx_broadcast_packets=1,
                    tx_broadcast_packets=2,
                    rx_multicast_packets=3,
                    tx_multicast_packets=4,
                ),
                rx_sizes=_packet_sizes(1),
                tx_sizes=_packet_sizes(2),
                detailed_errors=_detailed_errors(),
            ),
        )

    def get_hosts(self) -> tuple[HostEntry, ...]:
        return (
            HostEntry(
                entry_type="static",
                mac_address="02:00:00:00:00:01",
                vlan_id=10,
                port_numbers=(1, 2),
                mirror=True,
            ),
            HostEntry(
                entry_type="dynamic",
                mac_address="02:00:00:00:00:02",
                port_numbers=(6,),
            ),
        )

    def get_rstp(self) -> RstpInfo:
        return RstpInfo(
            bridge_priority=0x8000,
            cost_mode="short",
            forward_reserved_multicast=False,
            root_bridge_priority=0x8000,
            root_bridge_mac="02:00:00:00:00:01",
            ports=(
                RstpPortInfo(
                    number=1,
                    enabled=True,
                    protocol="rstp",
                    role="designated",
                    root_path_cost=0,
                    point_to_point=True,
                    edge=True,
                    port_type="edge",
                    state="forwarding",
                ),
            ),
        )

    def get_snmp(self) -> SnmpInfo:
        return SnmpInfo(enabled=True, community="public", contact="Ops", location="Office")

    def get_sfp(self) -> SfpInfo:
        return SfpInfo(
            vendor="Test Optics",
            part_number="MOD-1000SX",
            revision="A1",
            serial_number="SFPTEST001",
            manufacturing_date="2026-09-01",
            media_type="multi-mode fiber",
            temperature_celsius=25,
            supply_voltage_volts=3.3,
            tx_bias_ma=7,
            tx_power_dbm=0,
            rx_power_dbm=-10,
        )

    def get_forwarding(self) -> ForwardingInfo:
        return ForwardingInfo(
            mirror_target_port=6,
            ports=(
                PortForwardingInfo(
                    number=1,
                    destination_port_numbers=(2, 6),
                    lock=True,
                    lock_on_first=False,
                    mirror_ingress=True,
                    mirror_egress=False,
                    egress_rate_limit_bps=1_000_000,
                ),
                PortForwardingInfo(
                    number=2,
                    destination_port_numbers=(1, 6),
                    lock=False,
                    lock_on_first=False,
                    mirror_ingress=False,
                    mirror_egress=False,
                ),
                PortForwardingInfo(
                    number=6,
                    destination_port_numbers=(1, 2),
                    lock=False,
                    lock_on_first=False,
                    mirror_ingress=False,
                    mirror_egress=False,
                ),
            ),
        )

    def get_igmp_groups(self) -> tuple[IgmpGroup, ...]:
        return (IgmpGroup(address="239.1.2.3", vlan_id=10, port_numbers=(1, 3)),)

    def get_acl_rules(self) -> tuple[AclRule, ...]:
        return (
            AclRule(
                number=1,
                ingress_port_numbers=(1, 2),
                source_mac="02:00:00:00:00:01",
                source_mac_mask="ff:ff:ff:ff:ff:ff",
                destination_mac=None,
                destination_mac_mask="ff:ff:ff:ff:ff:ff",
                ether_type=0x0800,
                vlan_tag="present",
                vlan_id_min=10,
                vlan_id_max=20,
                source_prefix_length=0,
                source_port_min=0,
                source_port_max=65535,
                destination_prefix_length=0,
                destination_port_min=80,
                destination_port_max=80,
                protocol_number=6,
                redirect_enabled=True,
                redirect_port_numbers=(6,),
                drop=False,
                mirror=True,
                ingress_rate_limit_bps=1_000_000,
            ),
        )

    def get_port_vlans(self) -> tuple[PortVlanInfo, ...]:
        return (
            PortVlanInfo(
                number=1,
                mode="strict",
                receive="tagged_only",
                default_vlan_id=10,
                force_vlan_id=True,
                egress="preserve",
            ),
        )

    def get_vlans(self) -> tuple[VlanInfo, ...]:
        return (
            VlanInfo(
                vlan_id=10,
                independent_learning=True,
                igmp_snooping=False,
                ports=(
                    VlanPortMembership(port_number=1, mode="strip"),
                    VlanPortMembership(port_number=2, mode="not_member"),
                    VlanPortMembership(port_number=3, mode="not_member"),
                    VlanPortMembership(port_number=4, mode="not_member"),
                    VlanPortMembership(port_number=5, mode="not_member"),
                    VlanPortMembership(port_number=6, mode="not_member"),
                ),
            ),
        )

    def set_port_name(self, update: PortNameUpdate) -> OperationResult[PortInfo]:
        port = self.get_ports()[0].model_copy(update={"number": update.number, "name": update.name})
        return OperationResult[PortInfo](changed=update.name != "LongPortName1234", value=port)

    def set_port_configuration(self, update: PortConfigurationUpdate) -> OperationResult[PortInfo]:
        port = self.get_ports()[update.number - 1]
        changes: dict[str, object] = {}
        if update.enabled is not None:
            changes["enabled"] = update.enabled
        if update.flow_control is not None:
            changes["flow_control"] = update.flow_control
        if update.negotiation == "auto":
            changes["auto_negotiation"] = True
        elif isinstance(update.negotiation, ForcedPortNegotiation):
            changes.update(
                auto_negotiation=False,
                configured_speed_bps=update.negotiation.speed_bps,
                configured_full_duplex=update.negotiation.duplex == "full",
            )
        changed = any(getattr(port, field) != value for field, value in changes.items())
        return OperationResult[PortInfo](changed=changed, value=port.model_copy(update=changes))

    def set_device_name(self, update: DeviceNameUpdate) -> OperationResult[SystemInfo]:
        info = self.get_system_info().model_copy(update={"name": update.name})
        return OperationResult[SystemInfo](changed=update.name != "Office Switch", value=info)

    def set_admin_password(self, update: PasswordUpdate) -> OperationResult[SystemInfo]:
        self.password_updates.append(update.new_password.get_secret_value())
        return OperationResult[SystemInfo](
            changed=True,
            value=self.get_system_info(),
            warnings=(
                SafetyWarning(
                    code="administrator_credentials_changed",
                    message="Administrator credentials changed; future connections need them.",
                ),
            ),
        )

    def set_system_configuration(
        self,
        update: SystemConfigurationUpdate,
        *,
        expected_current: SystemInfo,
        readback_url: str | None = None,
    ) -> OperationResult[SystemInfo]:
        self.system_readback_urls.append(readback_url)
        assert expected_current == self.get_system_info()
        before = expected_current
        management = before.management
        igmp = before.igmp
        assert management is not None and igmp is not None
        management_changes: dict[str, object] = {}
        for source, target in (
            (update.address_mode, "address_mode"),
            (update.admin_mac_address, "admin_mac_address"),
            (update.allow_from, "allow_from"),
            (update.allow_prefix_length, "allow_prefix_length"),
            (update.allowed_port_numbers, "allowed_port_numbers"),
            (update.allowed_vlan_id, "allowed_vlan_id"),
        ):
            if source is not None:
                management_changes[target] = None if source == "unset" else source
        igmp_changes: dict[str, object] = {}
        for source, target in (
            (update.igmp_enabled, "enabled"),
            (update.igmp_querier, "querier_configured"),
            (update.igmp_fast_leave_port_numbers, "fast_leave_port_numbers"),
            (update.igmp_version, "version"),
        ):
            if source is not None:
                igmp_changes[target] = source
        configured_igmp = igmp.model_copy(update=igmp_changes)
        configured_igmp = configured_igmp.model_copy(
            update={
                "querier_effective": (
                    configured_igmp.enabled and configured_igmp.querier_configured
                )
            }
        )
        changes: dict[str, object] = {
            "management": management.model_copy(update=management_changes),
            "igmp": configured_igmp,
        }
        if update.name is not None:
            changes["name"] = update.name
        if update.static_ip is not None:
            changes["static_ip"] = None if update.static_ip == "unset" else update.static_ip
        if update.independent_vlan_lookup is not None:
            changes["independent_vlan_lookup"] = update.independent_vlan_lookup
        if update.discovery_protocol_port_numbers is not None:
            changes["discovery_protocol_port_numbers"] = update.discovery_protocol_port_numbers
        value = before.model_copy(update=changes)
        management_changed = any(
            item is not None
            for item in (
                update.admin_mac_address,
                update.allow_from,
                update.allow_prefix_length,
                update.allowed_port_numbers,
            )
        )
        warnings = (
            (
                SafetyWarning(
                    code="management_lockout_risk",
                    message="Management access changed; old -> new; outcome uncertain.",
                ),
            )
            if management_changed
            else ()
        )
        return OperationResult[SystemInfo](
            changed=value != before,
            value=value,
            warnings=warnings,
        )

    def set_snmp_metadata(self, update: SnmpMetadataUpdate) -> OperationResult[SnmpInfo]:
        before = self.get_snmp()
        info = before.model_copy(
            update={
                "contact": before.contact if update.contact is None else update.contact,
                "location": before.location if update.location is None else update.location,
            }
        )
        return OperationResult[SnmpInfo](changed=info != before, value=info)

    def set_snmp_configuration(self, update: SnmpConfigurationUpdate) -> OperationResult[SnmpInfo]:
        before = self.get_snmp()
        changes: dict[str, object] = {}
        if update.enabled is not None:
            changes["enabled"] = update.enabled
        if update.community is not None:
            community = update.community.get_secret_value()
            self.snmp_community_updates.append(community)
            changes["community"] = community
        if update.contact is not None:
            changes["contact"] = update.contact
        if update.location is not None:
            changes["location"] = update.location
        value = before.model_copy(update=changes)
        return OperationResult[SnmpInfo](changed=value != before, value=value)

    def set_rstp_port_enabled(
        self,
        update: RstpPortEnableUpdate,
        *,
        expected_current: RstpInfo,
    ) -> OperationResult[RstpInfo]:
        assert expected_current == self.get_rstp()
        before = expected_current
        ports = tuple(
            port.model_copy(update={"enabled": update.enabled})
            if port.number == update.number
            else port
            for port in before.ports
        )
        value = before.model_copy(update={"ports": ports})
        return OperationResult[RstpInfo](changed=value != before, value=value)

    def set_rstp_bridge(
        self,
        update: RstpBridgeUpdate,
        *,
        expected_current: RstpInfo,
    ) -> OperationResult[RstpInfo]:
        assert expected_current == self.get_rstp()
        value = expected_current.model_copy(update=update.model_dump(exclude_none=True))
        return OperationResult[RstpInfo](changed=value != expected_current, value=value)

    def set_forwarding_port_policy(
        self,
        update: ForwardingPortPolicyUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        assert expected_current == self.get_forwarding()
        before = expected_current
        changes = update.model_dump(exclude={"number"}, exclude_none=True)
        if changes.get("egress_rate_limit_bps") == "unlimited":
            changes["egress_rate_limit_bps"] = None
        ports = tuple(
            port.model_copy(update=changes) if port.number == update.number else port
            for port in before.ports
        )
        value = before.model_copy(update={"ports": ports})
        return OperationResult[ForwardingInfo](changed=value != before, value=value)

    def set_forwarding_matrix(
        self,
        update: ForwardingMatrixUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        assert expected_current == self.get_forwarding()
        ports = tuple(
            port.model_copy(update={"destination_port_numbers": update.destination_port_numbers})
            if port.number == update.number
            else port
            for port in expected_current.ports
        )
        value = expected_current.model_copy(update={"ports": ports})
        return OperationResult[ForwardingInfo](changed=value != expected_current, value=value)

    def set_forwarding_mirroring(
        self,
        update: ForwardingMirroringUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        assert expected_current == self.get_forwarding()
        source_changes: dict[str, object] = {}
        if update.mirror_ingress is not None:
            source_changes["mirror_ingress"] = update.mirror_ingress
        if update.mirror_egress is not None:
            source_changes["mirror_egress"] = update.mirror_egress
        ports = tuple(
            port.model_copy(update=source_changes)
            if port.number == update.source_port_number
            else port
            for port in expected_current.ports
        )
        target = expected_current.mirror_target_port
        if update.mirror_target_port is not None:
            target = None if update.mirror_target_port == "none" else update.mirror_target_port
        value = expected_current.model_copy(update={"ports": ports, "mirror_target_port": target})
        return OperationResult[ForwardingInfo](changed=value != expected_current, value=value)

    def replace_static_hosts(
        self,
        hosts: tuple[HostEntry, ...],
        *,
        expected_current: tuple[HostEntry, ...],
    ) -> OperationResult[tuple[HostEntry, ...]]:
        current = tuple(host for host in self.get_hosts() if host.entry_type.value == "static")
        assert expected_current == current
        return OperationResult[tuple[HostEntry, ...]](changed=hosts != current, value=hosts)

    def replace_acl_rules(
        self,
        rules: tuple[AclRule, ...],
        *,
        expected_current: tuple[AclRule, ...],
    ) -> OperationResult[tuple[AclRule, ...]]:
        assert expected_current == self.get_acl_rules()
        return OperationResult[tuple[AclRule, ...]](
            changed=rules != self.get_acl_rules(), value=rules
        )

    def set_port_vlan_policy(
        self,
        update: PortVlanPolicyUpdate,
        *,
        expected_current: tuple[PortVlanInfo, ...],
    ) -> OperationResult[tuple[PortVlanInfo, ...]]:
        assert expected_current == self.get_port_vlans()
        changes = update.model_dump(exclude={"number"}, exclude_none=True)
        value = tuple(
            port.model_copy(update=changes) if port.number == update.number else port
            for port in expected_current
        )
        return OperationResult[tuple[PortVlanInfo, ...]](
            changed=value != expected_current, value=value
        )

    def replace_vlans(
        self,
        vlans: tuple[VlanInfo, ...],
        *,
        expected_current: tuple[VlanInfo, ...],
    ) -> OperationResult[tuple[VlanInfo, ...]]:
        assert expected_current == self.get_vlans()
        return OperationResult[tuple[VlanInfo, ...]](changed=vlans != expected_current, value=vlans)


class FakeRegistry:
    identity = DeviceIdentity(
        firmware_family="css106",
        product_code="CSS106-5G-1S",
        firmware_version="2.19",
        marketing_name="RB260GS",
        build_id="0x6a181cd5",
    )

    def probe(self, connection):  # type: ignore[no-untyped-def]
        del connection
        return self.identity

    def connect(self, identity, connection, policy):  # type: ignore[no-untyped-def]
        del connection, policy
        return FakeDevice(identity)


def mock_registry(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        app_module.PluginRegistry,
        "discover",
        classmethod(lambda cls: FakeRegistry()),
    )


def test_human_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == f"swos-cli {__version__}\n"


def test_compact_json_version() -> None:
    result = runner.invoke(app, ["--output", "json", "--version"])

    assert result.exit_code == 0
    assert result.stdout == (
        f'{{"ok":true,"data":{{"name":"swos-cli","version":"{__version__}"}}}}\n'
    )
    assert "\x1b" not in result.stdout


def test_pretty_json_has_same_content() -> None:
    compact = runner.invoke(app, ["-o", "json", "--version"])
    pretty = runner.invoke(app, ["--version", "-o", "json-pretty"])

    assert pretty.exit_code == 0
    assert pretty.stdout.startswith("{\n")
    assert json.loads(pretty.stdout) == json.loads(compact.stdout)
    assert "\x1b" not in pretty.stdout


def test_environment_selects_output() -> None:
    result = runner.invoke(app, ["--version"], env={"SWOS_OUTPUT": "json"})

    assert result.exit_code == 0
    assert json.loads(result.stdout)["data"]["name"] == "swos-cli"


def test_cli_output_overrides_environment() -> None:
    result = runner.invoke(
        app,
        ["--version", "--output", "human"],
        env={"SWOS_OUTPUT": "json"},
    )

    assert result.exit_code == 0
    assert result.stdout == f"swos-cli {__version__}\n"


def test_json_configuration_error_is_structured(tmp_path) -> None:  # type: ignore[no-untyped-def]
    result = runner.invoke(
        app,
        ["--version", "-o", "json", "--config", str(tmp_path / "missing.toml")],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "configuration_error"


def test_dotenv_output_applies_to_configuration_errors(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "SWOS_OUTPUT=json\nSWOS_CONFIG=missing.toml\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"]["code"] == "configuration_error"
    assert result.stderr == ""


def test_json_parser_error_is_structured() -> None:
    result = runner.invoke(app, ["--output", "json", "--timeout", "invalid", "--version"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "cli_usage_error"
    assert result.stderr == ""


def test_json_unknown_option_is_structured() -> None:
    result = runner.invoke(app, ["-ojson-pretty", "--unknown", "--version"])

    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"]["code"] == "cli_usage_error"


def test_config_output_applies_to_parser_errors(tmp_path) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "config.toml"
    config.write_text('[defaults]\noutput = "json"\n', encoding="utf-8")

    result = runner.invoke(
        app,
        ["--config", str(config), "--timeout", "invalid", "--version"],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"]["code"] == "cli_usage_error"


def test_untested_firmware_safety_flags_are_global_options() -> None:
    result = runner.invoke(
        app,
        [
            "--allow-untested-firmware",
            "--allow-untested-firmware-writes",
            "--version",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout.startswith("swos-cli ")


def test_system_show_human_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(app, ["--url", "http://192.0.2.1", "system", "show"])

    assert result.exit_code == 0
    assert "Model: RB260GS (CSS106-5G-1S)" in result.stdout
    assert "Firmware: SwOS 2.19" in result.stdout
    assert "Uptime: 1d 01:01:01" in result.stdout
    assert "Current IP: 192.168.88.1" in result.stdout
    assert "Address Mode: dhcp with fallback" in result.stdout
    assert "IGMP Querier Effective: yes" in result.stdout
    assert "Input Voltage: 24.2 V" in result.stdout


def test_system_show_accepts_global_url_after_command(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    after_command = runner.invoke(
        app,
        ["system", "show", "--url", "https://192.0.2.1"],
    )
    between_commands = runner.invoke(
        app,
        ["system", "--url", "https://192.0.2.1", "show"],
    )

    assert after_command.exit_code == 0
    assert between_commands.exit_code == 0
    assert "Model: RB260GS (CSS106-5G-1S)" in after_command.stdout
    assert "Model: RB260GS (CSS106-5G-1S)" in between_commands.stdout


def test_system_show_accepts_all_global_options_after_command(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "system",
            "show",
            "--url",
            "http://192.0.2.1",
            "--username",
            "admin",
            "--password",
            "secret",
            "--model",
            "RB260GS",
            "--firmware",
            "2.19",
            "--timeout",
            "3",
            "--no-verify-tls",
            "--allow-untested-firmware",
            "-ojson",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["data"]["identity"]["product_code"] == "CSS106-5G-1S"


def test_system_show_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        ["--url", "http://192.0.2.1", "-o", "json", "system", "show"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["data"]["identity"]["product_code"] == "CSS106-5G-1S"
    assert payload["data"]["serial_number"] == "TEST1234"


def test_system_rename_human_and_json_output_without_confirmation(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(
        app,
        ["system", "rename", "Core Switch", "--url", "http://192.0.2.1"],
    )
    machine = runner.invoke(
        app,
        [
            "system",
            "rename",
            "Office Switch",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert human.exit_code == 0
    assert human.stdout == "Device name changed to 'Core Switch'.\n"
    assert machine.exit_code == 0
    data = json.loads(machine.stdout)["data"]
    assert data["changed"] is False
    assert data["system"]["name"] == "Office Switch"


def test_system_password_set_reads_environment_without_output_leakage(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)
    FakeDevice.password_updates.clear()
    secret = "rotation-secret-1"

    result = runner.invoke(
        app,
        [
            "system",
            "password",
            "set",
            "--new-password-env",
            "ROTATION_SECRET",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
        env={"ROTATION_SECRET": secret},
    )

    assert result.exit_code == 0
    assert FakeDevice.password_updates == [secret]
    payload = json.loads(result.stdout)
    assert payload["data"]["changed"] is True
    assert payload["data"]["system"]["identity"]["product_code"] == "CSS106-5G-1S"
    assert payload["data"]["warnings"][0]["code"] == "administrator_credentials_changed"
    assert secret not in result.stdout
    assert secret not in result.stderr


@pytest.mark.parametrize(
    "stdin_value, expected",
    [
        ("stdin-secret\n", "stdin-secret"),
        ("\n", ""),
        ("", ""),
    ],
)
def test_system_password_set_reads_stdin_and_preserves_empty_password(
    monkeypatch,
    stdin_value: str,
    expected: str,
) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)
    FakeDevice.password_updates.clear()

    result = runner.invoke(
        app,
        [
            "system",
            "password",
            "set",
            "--new-password-stdin",
            "--url",
            "http://192.0.2.1",
        ],
        input=stdin_value,
    )

    assert result.exit_code == 0
    assert FakeDevice.password_updates == [expected]
    assert "Administrator password changed and verified" in result.stdout
    if expected:
        assert expected not in result.stdout
        assert expected not in result.stderr


def test_system_password_set_preserves_empty_environment_value(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)
    FakeDevice.password_updates.clear()

    result = runner.invoke(
        app,
        [
            "system",
            "password",
            "set",
            "--new-password-env",
            "EMPTY_PASSWORD",
            "--url",
            "http://192.0.2.1",
        ],
        env={"EMPTY_PASSWORD": ""},
    )

    assert result.exit_code == 0
    assert FakeDevice.password_updates == [""]


@pytest.mark.parametrize(
    "arguments, message",
    [
        ([], "Exactly one"),
        (
            ["--new-password-stdin", "--new-password-env", "ROTATION_SECRET"],
            "Exactly one",
        ),
        (["--new-password-env", "MISSING_ROTATION_SECRET"], "is not set"),
        (["--new-password", "plaintext"], "No such option"),
    ],
)
def test_system_password_set_requires_exactly_one_secure_source(
    arguments: list[str],
    message: str,
) -> None:
    result = runner.invoke(app, ["system", "password", "set", *arguments], input="ignored")

    assert result.exit_code == 2
    assert message in result.stderr


def test_system_password_set_authentication_failure_is_structured_and_secret_free(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    secret = "never-render-this-secret"

    def fail(self: FakeDevice, update: PasswordUpdate) -> OperationResult[SystemInfo]:
        del self, update
        raise AuthenticationError("The SwOS device rejected the supplied credentials")

    monkeypatch.setattr(FakeDevice, "set_admin_password", fail)
    mock_registry(monkeypatch)
    result = runner.invoke(
        app,
        [
            "system",
            "password",
            "set",
            "--new-password-env",
            "ROTATION_SECRET",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
        env={"ROTATION_SECRET": secret},
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "authentication_error"
    assert secret not in result.stdout
    assert secret not in result.stderr


def test_system_configure_uses_explicit_options_and_full_baseline(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    FakeDevice.system_readback_urls.clear()
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "system",
            "configure",
            "--static-ip",
            "192.0.2.10",
            "--readback-url",
            "http://192.0.2.10",
            "--admin-mac",
            "02:00:00:00:00:05",
            "--name",
            "Core Switch",
            "--allow-from",
            "198.51.100.0",
            "--allow-prefix-length",
            "24",
            "--allow-port",
            "1",
            "--allow-port",
            "6",
            "--allow-vlan",
            "10",
            "--independent-vlan-lookup",
            "off",
            "--igmp-snooping",
            "off",
            "--igmp-querier",
            "off",
            "--igmp-fast-leave-port",
            "2",
            "--igmp-version",
            "v2",
            "--discovery-port",
            "1",
            "--discovery-port",
            "2",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["changed"] is True
    assert data["system"]["name"] == "Core Switch"
    assert data["system"]["static_ip"] == "192.0.2.10"
    assert data["system"]["management"]["admin_mac_address"] == "02:00:00:00:00:05"
    assert data["system"]["management"]["allowed_port_numbers"] == [1, 6]
    assert data["system"]["igmp"]["version"] == "v2"
    assert data["warnings"][0]["code"] == "management_lockout_risk"
    assert FakeDevice.system_readback_urls == ["http://192.0.2.10"]


@pytest.mark.parametrize(
    "arguments, message",
    [
        ([], "At least one system configuration option"),
        (["--allow-port", "1"], "must include management port 6"),
        (
            ["--static-ip", "192.0.2.10", "--unset-static-ip"],
            "cannot be used together",
        ),
        (["--admin-mac", "not-a-mac"], "hexadecimal octets"),
    ],
)
def test_system_configure_rejects_invalid_option_combinations(
    arguments: list[str], message: str
) -> None:
    result = runner.invoke(app, ["system", "configure", *arguments])

    assert result.exit_code == 2
    assert message in result.stderr


def test_system_show_requires_url() -> None:
    result = runner.invoke(app, ["system", "show"])

    assert result.exit_code == 2
    assert "A device URL is required" in result.stderr


@pytest.mark.parametrize(
    "command",
    [
        ["port", "list"],
        ["port", "stats"],
        ["sfp", "show"],
        ["forwarding", "show"],
        ["host", "list"],
        ["igmp", "list"],
        ["acl", "list"],
        ["rstp", "show"],
        ["snmp", "show"],
        ["vlan", "ports"],
        ["vlan", "list"],
    ],
)
def test_read_commands_require_url(command: list[str]) -> None:
    result = runner.invoke(app, command)

    assert result.exit_code == 2
    assert "A device URL is required" in result.stderr


def test_system_show_checks_configured_model(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        ["--url", "http://192.0.2.1", "--model", "RB260GSP", "system", "show"],
    )

    assert result.exit_code == 2
    assert "does not match detected device" in result.stderr


def test_system_show_includes_firmware_warnings(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class WarningRegistry(FakeRegistry):
        def connect(self, identity, connection, policy):  # type: ignore[no-untyped-def]
            del connection, policy
            warning = SafetyWarning(code="untested_firmware", message="Firmware is untested")
            return FakeDevice(identity, (warning,))

    monkeypatch.setattr(
        app_module.PluginRegistry,
        "discover",
        classmethod(lambda cls: WarningRegistry()),
    )

    result = runner.invoke(
        app,
        ["--url", "http://192.0.2.1", "-o", "json", "system", "show"],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["data"]["warnings"][0]["code"] == "untested_firmware"


def test_port_list_human_output_and_trailing_options(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        ["port", "list", "--url", "http://192.0.2.1"],
    )

    assert result.exit_code == 0
    assert "PORT   NAME" in result.stdout
    assert "LongPortName1234" in result.stdout
    assert "1 Gbps" in result.stdout
    assert "Port2" in result.stdout
    assert "down" in result.stdout
    assert "1 Gbps      auto" in result.stdout
    assert "10 Mbps (half)" in result.stdout
    assert len(result.stdout.splitlines()[0]) == 80
    assert all(len(line) <= 80 for line in result.stdout.splitlines())
    assert len(result.stdout.splitlines()) == 3


def test_port_list_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        ["port", "list", "--url", "http://192.0.2.1", "-o", "json"],
    )

    assert result.exit_code == 0
    ports = json.loads(result.stdout)["data"]["ports"]
    assert ports[0]["speed_bps"] == 1_000_000_000
    assert ports[0]["full_duplex"] is True
    assert ports[0]["negotiation"] == "auto"
    assert ports[1]["speed_bps"] is None
    assert ports[1]["negotiation"] == {"speed_bps": 10_000_000, "duplex": "half"}
    assert "auto_negotiation" not in ports[0]
    assert "configured_speed_bps" not in ports[0]
    assert "configured_full_duplex" not in ports[0]


def test_port_rename_human_changed_and_no_change(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    changed = runner.invoke(
        app,
        ["port", "rename", "1", "Uplink", "--url", "http://192.0.2.1"],
    )
    unchanged = runner.invoke(
        app,
        ["port", "rename", "1", "LongPortName1234", "--url", "http://192.0.2.1"],
    )

    assert changed.exit_code == 0
    assert "name changed to 'Uplink'" in changed.stdout
    assert unchanged.exit_code == 0
    assert "no change required" in unchanged.stdout


def test_port_rename_json_success(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "port",
            "rename",
            "1",
            "Uplink",
            "--url",
            "http://192.0.2.1",
            "-o",
            "json",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["changed"] is True
    assert data["port"]["number"] == 1
    assert data["port"]["name"] == "Uplink"
    assert data["port"]["speed_bps"] == 1_000_000_000
    assert data["port"]["negotiation"] == "auto"


def test_port_configure_forced_json_uses_bps(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "port",
            "configure",
            "2",
            "--negotiation",
            "forced",
            "--speed-bps",
            "100000000",
            "--duplex",
            "full",
            "--flow-control",
            "on",
            "--url",
            "http://192.0.2.1",
            "-o",
            "json",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["changed"] is True
    assert data["port"]["number"] == 2
    assert data["port"]["negotiation"] == {
        "speed_bps": 100_000_000,
        "duplex": "full",
    }
    assert data["port"]["flow_control"] is True


def test_port_configure_auto_and_no_change_human(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    changed = runner.invoke(
        app,
        ["port", "configure", "2", "--negotiation", "auto", "--url", "http://192.0.2.1"],
    )
    unchanged = runner.invoke(
        app,
        ["port", "configure", "2", "--flow-control", "off", "--url", "http://192.0.2.1"],
    )

    assert changed.exit_code == 0
    assert "configuration changed" in changed.stdout
    assert unchanged.exit_code == 0
    assert "no change required" in unchanged.stdout


@pytest.mark.parametrize(
    "arguments, message",
    [
        (["port", "configure", "1"], "At least one configuration option"),
        (
            ["port", "configure", "1", "--negotiation", "forced"],
            "requires both --speed-bps and --duplex",
        ),
        (
            [
                "port",
                "configure",
                "1",
                "--negotiation",
                "auto",
                "--speed-bps",
                "100000000",
            ],
            "valid only with --negotiation forced",
        ),
        (
            [
                "port",
                "configure",
                "1",
                "--negotiation",
                "forced",
                "--speed-bps",
                "1000000000",
                "--duplex",
                "full",
            ],
            "must be 10000000 or 100000000",
        ),
        (["port", "configure", "6", "--flow-control", "on"], "not in the range 1<=x<=5"),
    ],
)
def test_port_configure_rejects_invalid_option_combinations(
    arguments: list[str], message: str
) -> None:
    result = runner.invoke(app, [*arguments, "--url", "http://192.0.2.1"])

    assert result.exit_code == 2
    assert message in result.stderr


def test_port_stats_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["port", "stats", "--url", "http://192.0.2.1"])
    machine = runner.invoke(
        app,
        ["port", "stats", "--url", "http://192.0.2.1", "-ojson"],
    )

    assert human.exit_code == 0
    assert "RX BYTES" in human.stdout
    assert "1234" in human.stdout
    assert machine.exit_code == 0
    port = json.loads(machine.stdout)["data"]["ports"][0]
    assert port["tx_errors"] == 1
    assert "rates" not in port


def test_port_stats_optional_groups_and_full_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    selected = runner.invoke(
        app,
        ["port", "stats", "--rates", "--errors", "--url", "http://192.0.2.1", "-ojson"],
    )
    full = runner.invoke(
        app,
        ["port", "stats", "--full", "--url", "http://192.0.2.1"],
    )

    assert selected.exit_code == 0
    port = json.loads(selected.stdout)["data"]["ports"][0]
    assert port["rates"]["rx_bits_per_second"] == 1000
    assert port["detailed_errors"]["rx_fcs_errors"] == 2
    assert "traffic" not in port
    assert "rx_sizes" not in port
    assert full.exit_code == 0
    assert "RX 1 Kbps" in full.stdout
    assert "RX sizes:" in full.stdout
    assert "TX errors:" in full.stdout


def test_sfp_show_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["sfp", "show", "--url", "http://192.0.2.1"])
    machine = runner.invoke(app, ["sfp", "show", "--url", "http://192.0.2.1", "-ojson"])

    assert human.exit_code == 0
    assert "Vendor: Test Optics" in human.stdout
    assert "RX Power: -10 dBm" in human.stdout
    assert machine.exit_code == 0
    assert json.loads(machine.stdout)["data"]["media_type"] == "multi-mode fiber"


def test_forwarding_show_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["forwarding", "show", "--url", "http://192.0.2.1"])
    machine = runner.invoke(app, ["forwarding", "show", "--url", "http://192.0.2.1", "-ojson"])

    assert human.exit_code == 0
    assert "Mirror Target: 6" in human.stdout
    assert "1 Mbps" in human.stdout
    assert machine.exit_code == 0
    assert json.loads(machine.stdout)["data"]["ports"][0]["lock"] is True


def test_forwarding_configure_is_direct_and_returns_verified_state(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    changed = runner.invoke(
        app,
        [
            "forwarding",
            "configure",
            "2",
            "--lock",
            "on",
            "--lock-on-first",
            "on",
            "--egress-rate-bps",
            "1000000",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )
    cleared = runner.invoke(
        app,
        [
            "forwarding",
            "configure",
            "1",
            "--egress-unlimited",
            "--url",
            "http://192.0.2.1",
        ],
    )

    assert changed.exit_code == 0
    data = json.loads(changed.stdout)["data"]
    assert data["changed"] is True
    assert data["forwarding"]["ports"][1]["lock"] is True
    assert data["forwarding"]["ports"][1]["lock_on_first"] is True
    assert data["forwarding"]["ports"][1]["egress_rate_limit_bps"] == 1_000_000
    assert cleared.exit_code == 0
    assert "no change required" not in cleared.stdout
    assert "unlimited" in cleared.stdout


def test_forwarding_matrix_preserves_port_6_and_returns_verified_state(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "forwarding",
            "configure-matrix",
            "1",
            "--destination-port",
            "1",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["changed"] is True
    assert data["forwarding"]["ports"][0]["destination_port_numbers"] == [1, 6]


def test_forwarding_matrix_allows_explicit_empty_ethernet_destinations(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "forwarding",
            "configure-matrix",
            "2",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["changed"] is True
    assert data["forwarding"]["ports"][1]["destination_port_numbers"] == [6]


def test_forwarding_mirroring_configures_nonmanagement_source_and_target(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "forwarding",
            "configure-mirroring",
            "2",
            "--ingress",
            "on",
            "--target-port",
            "1",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["forwarding"]["ports"][1]["mirror_ingress"] is True
    assert data["forwarding"]["mirror_target_port"] == 1


def test_igmp_list_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["igmp", "list", "--url", "http://192.0.2.1"])
    machine = runner.invoke(app, ["igmp", "list", "--url", "http://192.0.2.1", "-ojson"])

    assert human.exit_code == 0
    assert "239.1.2.3" in human.stdout
    assert machine.exit_code == 0
    assert json.loads(machine.stdout)["data"]["groups"][0]["port_numbers"] == [1, 3]


def test_acl_list_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["acl", "list", "--url", "http://192.0.2.1"])
    machine = runner.invoke(app, ["acl", "list", "--url", "http://192.0.2.1", "-ojson"])

    assert human.exit_code == 0
    assert "Rule 1" in human.stdout
    assert "redirect=6" in human.stdout
    assert "rate=1 Mbps" in human.stdout
    assert machine.exit_code == 0
    rule = json.loads(machine.stdout)["data"]["rules"][0]
    assert rule["ether_type"] == 0x0800
    assert rule["ingress_rate_limit_bps"] == 1_000_000


def test_host_list_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["host", "list", "--url", "http://192.0.2.1"])
    machine = runner.invoke(
        app,
        ["host", "list", "--url", "http://192.0.2.1", "-ojson"],
    )

    assert human.exit_code == 0
    assert "MAC ADDRESS" in human.stdout
    assert "02:00:00:00:00:01" in human.stdout
    assert "dynamic" in human.stdout
    assert machine.exit_code == 0
    hosts = json.loads(machine.stdout)["data"]["hosts"]
    assert hosts[0]["port_numbers"] == [1, 2]
    assert hosts[0]["mirror"] is True
    assert hosts[1]["vlan_id"] is None


def test_host_add_and_remove_emit_verified_machine_tables(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    added = runner.invoke(
        app,
        [
            "host",
            "add",
            "--mac",
            "02:00:00:00:00:03",
            "--vlan",
            "20",
            "--port",
            "5",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )
    removed = runner.invoke(
        app,
        [
            "host",
            "remove",
            "--mac",
            "02:00:00:00:00:01",
            "--vlan",
            "10",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert added.exit_code == 0
    added_data = json.loads(added.stdout)["data"]
    assert added_data["changed"] is True
    assert len(added_data["hosts"]) == 2
    assert added_data["hosts"][0]["mac_address"] == "02:00:00:00:00:01"
    assert added_data["hosts"][-1]["port_numbers"] == [5]
    assert added_data["hosts"][-1]["mac_address"] == "02:00:00:00:00:03"
    assert removed.exit_code == 0
    assert json.loads(removed.stdout)["data"]["hosts"] == []


def test_host_add_updates_existing_key_in_place(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def two_static_hosts(self) -> tuple[HostEntry, ...]:  # type: ignore[no-untyped-def]
        del self
        return (
            HostEntry(
                entry_type="static",
                mac_address="02:00:00:00:00:01",
                vlan_id=10,
                port_numbers=(1,),
            ),
            HostEntry(
                entry_type="static",
                mac_address="02:00:00:00:00:02",
                vlan_id=20,
                port_numbers=(2,),
            ),
        )

    monkeypatch.setattr(FakeDevice, "get_hosts", two_static_hosts)
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "host",
            "add",
            "--mac",
            "02:00:00:00:00:01",
            "--vlan",
            "10",
            "--port",
            "5",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert result.exit_code == 0
    hosts = json.loads(result.stdout)["data"]["hosts"]
    assert [host["mac_address"] for host in hosts] == [
        "02:00:00:00:00:01",
        "02:00:00:00:00:02",
    ]
    assert hosts[0]["port_numbers"] == [5]


def test_acl_add_and_remove_emit_verified_machine_tables(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    added = runner.invoke(
        app,
        [
            "acl",
            "add",
            "--ingress-port",
            "5",
            "--drop",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )
    removed = runner.invoke(
        app,
        [
            "acl",
            "remove",
            "1",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert added.exit_code == 0
    added_data = json.loads(added.stdout)["data"]
    assert len(added_data["rules"]) == 2
    assert added_data["rules"][0]["ingress_port_numbers"] == [1, 2]
    assert added_data["rules"][-1]["number"] == 2
    assert added_data["rules"][-1]["drop"] is True
    assert added_data["rules"][-1]["ingress_port_numbers"] == [5]
    assert removed.exit_code == 0
    assert json.loads(removed.stdout)["data"]["rules"] == []


def test_rstp_show_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["rstp", "show", "--url", "http://192.0.2.1"])
    machine = runner.invoke(
        app,
        ["rstp", "show", "--url", "http://192.0.2.1", "-ojson"],
    )

    assert human.exit_code == 0
    assert "Bridge Priority: 0x8000" in human.stdout
    assert "CONFIG COST" in human.stdout
    assert "designated" in human.stdout
    assert machine.exit_code == 0
    data = json.loads(machine.stdout)["data"]
    assert data["cost_mode"] == "short"
    assert data["ports"][0]["state"] == "forwarding"


def test_rstp_configure_is_direct_and_returns_verified_state(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    changed = runner.invoke(
        app,
        [
            "rstp",
            "configure",
            "1",
            "--state",
            "disabled",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )
    no_op = runner.invoke(
        app,
        [
            "rstp",
            "configure",
            "1",
            "--state",
            "enabled",
            "--url",
            "http://192.0.2.1",
        ],
    )

    assert changed.exit_code == 0
    data = json.loads(changed.stdout)["data"]
    assert data["changed"] is True
    assert data["rstp"]["ports"][0]["enabled"] is False
    assert no_op.exit_code == 0
    assert "no change required" in no_op.stdout


def test_rstp_bridge_configure_returns_complete_verified_state(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "rstp",
            "configure-bridge",
            "--bridge-priority",
            "36864",
            "--cost-mode",
            "long",
            "--forward-reserved-multicast",
            "on",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["changed"] is True
    assert data["rstp"]["bridge_priority"] == 0x9000
    assert data["rstp"]["cost_mode"] == "long"
    assert data["rstp"]["forward_reserved_multicast"] is True


def test_snmp_show_preserves_established_read_community(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["snmp", "show", "--url", "http://192.0.2.1"])
    machine = runner.invoke(
        app,
        ["snmp", "show", "--url", "http://192.0.2.1", "-ojson"],
    )

    assert human.exit_code == 0
    assert "Community: public" in human.stdout
    assert machine.exit_code == 0
    data = json.loads(machine.stdout)["data"]
    assert data["community"] == "public"
    assert "community_configured" not in data


def test_snmp_configure_reads_secure_community_source_and_redacts_result(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)
    FakeDevice.snmp_community_updates.clear()
    secret = "private-community"

    result = runner.invoke(
        app,
        [
            "snmp",
            "configure",
            "--enabled",
            "off",
            "--community-env",
            "SNMP_SECRET",
            "--contact",
            "NOC",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
        env={"SNMP_SECRET": secret},
    )

    assert result.exit_code == 0
    assert FakeDevice.snmp_community_updates == [secret]
    data = json.loads(result.stdout)["data"]
    assert data["snmp"]["enabled"] is False
    assert data["snmp"]["community_configured"] is True
    assert "community" not in data["snmp"]
    assert secret not in result.stdout
    assert secret not in result.stderr


def test_snmp_configure_reads_community_from_stdin_and_redacts_result(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)
    FakeDevice.snmp_community_updates.clear()
    secret = "stdin-community"

    result = runner.invoke(
        app,
        [
            "snmp",
            "configure",
            "--community-stdin",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
        input=secret + "\n",
    )

    assert result.exit_code == 0
    assert FakeDevice.snmp_community_updates == [secret]
    snmp = json.loads(result.stdout)["data"]["snmp"]
    assert snmp["community_configured"] is True
    assert "community" not in snmp
    assert secret not in result.stdout
    assert secret not in result.stderr


@pytest.mark.parametrize(
    "arguments, message",
    [
        ([], "At least one"),
        (["--community", "plaintext"], "No such option"),
        (["--community-env", "MISSING"], "is not set"),
        (["--community-env", "SNMP_SECRET", "--community-stdin"], "cannot be combined"),
    ],
)
def test_snmp_configure_rejects_plaintext_and_invalid_secure_sources(
    arguments: list[str], message: str
) -> None:
    result = runner.invoke(app, ["snmp", "configure", *arguments], input="ignored")

    assert result.exit_code == 2
    assert message in result.stderr


def test_snmp_metadata_set_preserves_omitted_and_allows_explicit_clear(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(
        app,
        [
            "snmp",
            "metadata",
            "set",
            "--contact",
            "NOC",
            "--url",
            "http://192.0.2.1",
        ],
    )
    machine = runner.invoke(
        app,
        [
            "snmp",
            "metadata",
            "set",
            "--location",
            "",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert human.exit_code == 0
    assert "SNMP metadata changed." in human.stdout
    assert "Contact: NOC" in human.stdout
    assert "Location: Office" in human.stdout
    assert machine.exit_code == 0
    data = json.loads(machine.stdout)["data"]
    assert data == {
        "changed": True,
        "snmp": {
            "enabled": True,
            "contact": "Ops",
            "location": "",
        },
    }


def test_snmp_metadata_set_with_no_options_is_a_no_op(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        ["snmp", "metadata", "set", "--url", "http://192.0.2.1"],
    )

    assert result.exit_code == 0
    assert "already configured; no change required" in result.stdout


def test_vlan_ports_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["vlan", "ports", "--url", "http://192.0.2.1"])
    machine = runner.invoke(
        app,
        ["vlan", "ports", "--url", "http://192.0.2.1", "-ojson"],
    )

    assert human.exit_code == 0
    assert "DEFAULT VLAN" in human.stdout
    assert "tagged only" in human.stdout
    assert machine.exit_code == 0
    port = json.loads(machine.stdout)["data"]["ports"][0]
    assert port["mode"] == "strict"
    assert port["force_vlan_id"] is True


def test_vlan_list_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["vlan", "list", "--url", "http://192.0.2.1"])
    machine = runner.invoke(
        app,
        ["vlan", "list", "--url", "http://192.0.2.1", "-ojson"],
    )

    assert human.exit_code == 0
    assert "IGMP SNOOPING" in human.stdout
    assert "1=strip" in human.stdout
    assert machine.exit_code == 0
    vlan = json.loads(machine.stdout)["data"]["vlans"][0]
    assert vlan["vlan_id"] == 10
    assert vlan["ports"][1]["mode"] == "not_member"


def test_vlan_port_configure_is_direct_and_returns_verified_state(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "vlan",
            "configure-port",
            "1",
            "--receive",
            "untagged_only",
            "--force-vlan-id",
            "off",
            "--egress",
            "strip",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["changed"] is True
    assert data["ports"][0]["receive"] == "untagged_only"
    assert data["ports"][0]["force_vlan_id"] is False
    assert data["ports"][0]["egress"] == "strip"


def test_vlan_table_set_and_remove_are_direct_full_table_plans(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    changed = runner.invoke(
        app,
        [
            "vlan",
            "set",
            "10",
            "--igmp-snooping",
            "on",
            "--port-mode",
            "5=strip",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )
    removed = runner.invoke(
        app,
        [
            "vlan",
            "remove",
            "10",
            "--url",
            "http://192.0.2.1",
            "-ojson",
        ],
    )

    assert changed.exit_code == 0
    changed_vlan = json.loads(changed.stdout)["data"]["vlans"][0]
    assert changed_vlan["igmp_snooping"] is True
    assert changed_vlan["ports"][4]["mode"] == "strip"
    assert changed_vlan["ports"][5]["mode"] == "not_member"
    assert removed.exit_code == 0
    assert json.loads(removed.stdout)["data"]["vlans"] == []


def test_vlan_table_cli_rejects_port_6_without_prompting(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "vlan",
            "set",
            "10",
            "--port-mode",
            "6=strip",
            "--url",
            "http://192.0.2.1",
        ],
    )

    assert result.exit_code == 2
    assert "between 1 and 5" in result.output
