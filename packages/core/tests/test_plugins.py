from __future__ import annotations

import pytest
from swos_core.api import DeviceAdapter
from swos_core.errors import (
    DeviceDetectionError,
    DuplicateDevicePluginError,
    MissingDevicePluginError,
    ProtocolError,
    UnsupportedFeatureError,
    UnsupportedFirmwareError,
)
from swos_core.models import (
    AclRule,
    DeviceCapabilities,
    DeviceConnection,
    DeviceIdentity,
    DeviceNameUpdate,
    ForcedPortNegotiation,
    ForwardingInfo,
    ForwardingMatrixUpdate,
    ForwardingMirroringUpdate,
    ForwardingPortPolicyUpdate,
    HostEntry,
    IgmpGroup,
    OperationResult,
    PacketSizeStatistics,
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
    SnmpInfo,
    SnmpMetadataUpdate,
    SystemInfo,
    VlanInfo,
    VlanPortMembership,
)
from swos_core.plugins import PluginRegistry, SupportRecord
from swos_core.safety import FirmwareSafetyPolicy


class FakePlugin:
    family = "css106"
    distribution_name = "swos-device-css106"

    def support_records(self) -> tuple[SupportRecord, ...]:
        return (
            SupportRecord(
                firmware_family="css106",
                product_code="CSS106-5G-1S",
                firmware_version="2.19",
                marketing_names=("RB260GS",),
            ),
        )

    def probe(self, connection: DeviceConnection) -> DeviceIdentity | None:
        del connection
        return identity()

    def create(
        self,
        *,
        identity: DeviceIdentity,
        connection: DeviceConnection,
        policy: FirmwareSafetyPolicy,
        support: SupportRecord | None,
    ) -> DeviceAdapter:
        del connection, policy, support
        return FakeAdapter(identity)


class FakeAdapter:
    def __init__(self, device_identity: DeviceIdentity) -> None:
        self._identity = device_identity

    @property
    def identity(self) -> DeviceIdentity:
        return self._identity

    @property
    def capabilities(self) -> DeviceCapabilities:
        return DeviceCapabilities(
            features=frozenset(
                {
                    "acl",
                    "acl_write",
                    "device_name_write",
                    "forwarding",
                    "forwarding_matrix_write",
                    "forwarding_mirroring_write",
                    "forwarding_port_policy_write",
                    "hosts",
                    "igmp_groups",
                    "port_statistics",
                    "ports",
                    "port_configuration_write",
                    "port_name_write",
                    "rstp",
                    "rstp_bridge_write",
                    "rstp_port_enable_write",
                    "sfp",
                    "snmp",
                    "snmp_metadata_write",
                    "static_hosts_write",
                    "system",
                    "vlan",
                    "vlan_port_policy_write",
                    "vlan_table_write",
                }
            )
        )

    def get_system_info(self) -> SystemInfo:
        return SystemInfo(identity=self.identity, name="test", uptime_seconds=1)

    def get_ports(self) -> tuple[PortInfo, ...]:
        return (
            PortInfo(
                number=1,
                name="Port1",
                enabled=True,
                link_up=True,
                speed_bps=1_000_000_000,
                full_duplex=True,
                auto_negotiation=True,
                flow_control=True,
                configured_speed_bps=100_000_000,
                configured_full_duplex=True,
            ),
        )

    def get_port_statistics(self) -> tuple[PortStatistics, ...]:
        return (
            PortStatistics(
                number=1,
                rx_bytes=1,
                tx_bytes=2,
                rx_packets=3,
                tx_packets=4,
                rx_errors=0,
                tx_errors=0,
                rates=PortRateStatistics(
                    rx_bits_per_second=1,
                    tx_bits_per_second=2,
                    rx_packets_per_second=3,
                    tx_packets_per_second=4,
                ),
                traffic=PortTrafficStatistics(
                    rx_unicast_packets=1,
                    tx_unicast_packets=2,
                    rx_broadcast_packets=3,
                    tx_broadcast_packets=4,
                    rx_multicast_packets=5,
                    tx_multicast_packets=6,
                ),
                rx_sizes=_packet_sizes(),
                tx_sizes=_packet_sizes(),
                detailed_errors=_errors(),
            ),
        )

    def get_hosts(self) -> tuple[HostEntry, ...]:
        return (
            HostEntry(
                entry_type="dynamic",
                mac_address="02:00:00:00:00:01",
                port_numbers=(1,),
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
        return SfpInfo(vendor="Test")

    def get_forwarding(self) -> ForwardingInfo:
        return ForwardingInfo(
            mirror_target_port=None,
            ports=(
                PortForwardingInfo(
                    number=1,
                    destination_port_numbers=(1,),
                    lock=False,
                    lock_on_first=False,
                    mirror_ingress=False,
                    mirror_egress=False,
                ),
            ),
        )

    def get_igmp_groups(self) -> tuple[IgmpGroup, ...]:
        return (IgmpGroup(address="239.1.2.3", vlan_id=1, port_numbers=(1,)),)

    def get_acl_rules(self) -> tuple[AclRule, ...]:
        return ()

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
                ports=(VlanPortMembership(port_number=1, mode="strip"),),
            ),
        )

    def set_port_name(self, update: PortNameUpdate) -> OperationResult[PortInfo]:
        port = self.get_ports()[0].model_copy(update={"number": update.number, "name": update.name})
        return OperationResult[PortInfo](changed=True, value=port)

    def validate_port_name(self, update: PortNameUpdate) -> None:
        del update

    def set_port_configuration(self, update: PortConfigurationUpdate) -> OperationResult[PortInfo]:
        port = self.get_ports()[0]
        changes: dict[str, object] = {}
        if update.enabled is not None:
            changes["enabled"] = update.enabled
        if update.flow_control is not None:
            changes["flow_control"] = update.flow_control
        if update.negotiation == "auto":
            changes["auto_negotiation"] = True
        elif update.negotiation is not None:
            changes.update(
                auto_negotiation=False,
                configured_speed_bps=update.negotiation.speed_bps,
                configured_full_duplex=update.negotiation.duplex == "full",
            )
        return OperationResult[PortInfo](changed=True, value=port.model_copy(update=changes))

    def validate_port_configuration(
        self,
        update: PortConfigurationUpdate,
        *,
        current: PortInfo,
    ) -> None:
        del update, current

    def set_device_name(self, update: DeviceNameUpdate) -> OperationResult[SystemInfo]:
        return OperationResult[SystemInfo](
            changed=True,
            value=self.get_system_info().model_copy(update={"name": update.name}),
        )

    def validate_device_name(self, update: DeviceNameUpdate) -> None:
        del update

    def set_snmp_metadata(self, update: SnmpMetadataUpdate) -> OperationResult[SnmpInfo]:
        before = self.get_snmp()
        return OperationResult[SnmpInfo](
            changed=True,
            value=before.model_copy(
                update={
                    "contact": before.contact if update.contact is None else update.contact,
                    "location": before.location if update.location is None else update.location,
                }
            ),
        )

    def validate_snmp_metadata(self, update: SnmpMetadataUpdate) -> None:
        del update

    def set_rstp_port_enabled(
        self,
        update: RstpPortEnableUpdate,
        *,
        expected_current: RstpInfo,
    ) -> OperationResult[RstpInfo]:
        before = self.get_rstp()
        assert expected_current == before
        ports = tuple(
            port.model_copy(update={"enabled": update.enabled})
            if port.number == update.number
            else port
            for port in before.ports
        )
        return OperationResult[RstpInfo](
            changed=ports != before.ports,
            value=before.model_copy(update={"ports": ports}),
        )

    def validate_rstp_port_enabled(
        self,
        update: RstpPortEnableUpdate,
        *,
        current: RstpInfo,
    ) -> None:
        del update, current

    def set_rstp_bridge(
        self,
        update: RstpBridgeUpdate,
        *,
        expected_current: RstpInfo,
    ) -> OperationResult[RstpInfo]:
        before = self.get_rstp()
        assert expected_current == before
        changes = update.model_dump(exclude_none=True)
        value = before.model_copy(update=changes)
        return OperationResult[RstpInfo](changed=value != before, value=value)

    def set_forwarding_port_policy(
        self,
        update: ForwardingPortPolicyUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        before = self.get_forwarding()
        assert expected_current == before
        changes = update.model_dump(exclude={"number"}, exclude_none=True)
        if changes.get("egress_rate_limit_bps") == "unlimited":
            changes["egress_rate_limit_bps"] = None
        ports = tuple(
            port.model_copy(update=changes) if port.number == update.number else port
            for port in before.ports
        )
        value = before.model_copy(update={"ports": ports})
        return OperationResult[ForwardingInfo](changed=value != before, value=value)

    def validate_forwarding_port_policy(
        self,
        update: ForwardingPortPolicyUpdate,
        *,
        current: ForwardingInfo,
    ) -> None:
        del update, current

    def set_forwarding_matrix(
        self,
        update: ForwardingMatrixUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        before = self.get_forwarding()
        assert expected_current == before
        ports = tuple(
            port.model_copy(update={"destination_port_numbers": update.destination_port_numbers})
            if port.number == update.number
            else port
            for port in before.ports
        )
        value = before.model_copy(update={"ports": ports})
        return OperationResult[ForwardingInfo](changed=value != before, value=value)

    def set_forwarding_mirroring(
        self,
        update: ForwardingMirroringUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        before = self.get_forwarding()
        assert expected_current == before
        return OperationResult[ForwardingInfo](changed=False, value=before)

    def replace_static_hosts(
        self,
        hosts: tuple[HostEntry, ...],
        *,
        expected_current: tuple[HostEntry, ...],
    ) -> OperationResult[tuple[HostEntry, ...]]:
        del expected_current
        return OperationResult[tuple[HostEntry, ...]](changed=True, value=hosts)

    def validate_static_hosts(self, hosts: tuple[HostEntry, ...]) -> None:
        del hosts

    def replace_acl_rules(
        self,
        rules: tuple[AclRule, ...],
        *,
        expected_current: tuple[AclRule, ...],
    ) -> OperationResult[tuple[AclRule, ...]]:
        del expected_current
        return OperationResult[tuple[AclRule, ...]](changed=True, value=rules)

    def set_port_vlan_policy(
        self,
        update: PortVlanPolicyUpdate,
        *,
        expected_current: tuple[PortVlanInfo, ...],
    ) -> OperationResult[tuple[PortVlanInfo, ...]]:
        before = self.get_port_vlans()
        assert expected_current == before
        changes = update.model_dump(exclude={"number"}, exclude_none=True)
        value = tuple(
            port.model_copy(update=changes) if port.number == update.number else port
            for port in before
        )
        return OperationResult[tuple[PortVlanInfo, ...]](changed=value != before, value=value)

    def validate_port_vlan_policy(
        self,
        update: PortVlanPolicyUpdate,
        *,
        current: tuple[PortVlanInfo, ...],
    ) -> None:
        del update, current

    def replace_vlans(
        self,
        vlans: tuple[VlanInfo, ...],
        *,
        expected_current: tuple[VlanInfo, ...],
    ) -> OperationResult[tuple[VlanInfo, ...]]:
        assert expected_current == self.get_vlans()
        return OperationResult[tuple[VlanInfo, ...]](changed=vlans != expected_current, value=vlans)


def identity(version: str = "2.19") -> DeviceIdentity:
    return DeviceIdentity(
        firmware_family="css106",
        product_code="CSS106-5G-1S",
        firmware_version=version,
        marketing_name="RB260GS",
    )


def _packet_sizes() -> PacketSizeStatistics:
    return PacketSizeStatistics(
        frames_64_bytes=0,
        frames_65_to_127_bytes=0,
        frames_128_to_255_bytes=0,
        frames_256_to_511_bytes=0,
        frames_512_to_1023_bytes=0,
        frames_1024_to_1518_bytes=0,
        frames_1519_to_max_bytes=0,
    )


def _errors() -> PortErrorStatistics:
    return PortErrorStatistics(
        rx_pause_frames=0,
        rx_fcs_errors=0,
        rx_alignment_errors=0,
        rx_runts=0,
        rx_fragments=0,
        rx_too_long=0,
        rx_overflows=0,
        tx_pause_frames=0,
        tx_underruns=0,
        tx_too_long=0,
        tx_collisions=0,
        tx_excessive_collisions=0,
        tx_multiple_collisions=0,
        tx_single_collisions=0,
        tx_excessive_deferred=0,
        tx_deferred=0,
        tx_late_collisions=0,
    )


def test_registry_resolves_exact_support() -> None:
    resolution = PluginRegistry([FakePlugin()]).resolve(
        identity(),
        FirmwareSafetyPolicy(),
    )

    assert resolution.distribution_name == "swos-device-css106"
    assert resolution.support is not None
    assert resolution.warnings == ()


def test_registry_probes_and_connects_a_device() -> None:
    registry = PluginRegistry([FakePlugin()])
    connection = DeviceConnection(url="http://192.0.2.1")

    detected = registry.probe(connection)
    device = registry.connect_auto(connection, FirmwareSafetyPolicy())

    assert detected == identity()
    assert device.identity == identity()


def test_registry_rejects_unknown_firmware() -> None:
    with pytest.raises(UnsupportedFirmwareError):
        PluginRegistry([FakePlugin()]).resolve(
            identity("2.20"),
            FirmwareSafetyPolicy(),
        )


def test_registry_allows_explicit_untested_read() -> None:
    resolution = PluginRegistry([FakePlugin()]).resolve(
        identity("2.20"),
        FirmwareSafetyPolicy(allow_untested_firmware=True),
    )

    assert resolution.support is None
    assert resolution.warnings[0].code == "untested_firmware"


def test_policy_bound_device_rechecks_read_permission() -> None:
    registry = PluginRegistry([FakePlugin()])
    device = registry.connect(
        identity("2.20"),
        DeviceConnection(url="http://192.0.2.1"),
        FirmwareSafetyPolicy(allow_untested_firmware=True),
    )

    assert device.get_system_info().name == "test"
    assert device.get_ports()[0].name == "Port1"
    assert device.get_port_statistics()[0].tx_bytes == 2
    assert device.get_hosts()[0].port_numbers == (1,)
    assert device.get_rstp().ports[0].role.value == "designated"
    assert device.get_snmp().community == "public"
    assert device.get_sfp().vendor == "Test"
    assert device.get_forwarding().ports[0].number == 1
    assert device.get_igmp_groups()[0].vlan_id == 1
    assert device.get_acl_rules() == ()
    assert device.get_port_vlans()[0].default_vlan_id == 10
    assert device.get_vlans()[0].vlan_id == 10
    assert device.warnings[0].code == "untested_firmware"
    with pytest.raises(UnsupportedFirmwareError):
        device._authorize(write=True)


def test_policy_bound_device_rejects_unsupported_feature() -> None:
    class SystemOnlyAdapter(FakeAdapter):
        @property
        def capabilities(self) -> DeviceCapabilities:
            return DeviceCapabilities(features=frozenset({"system"}))

    class SystemOnlyPlugin(FakePlugin):
        def create(
            self,
            *,
            identity: DeviceIdentity,
            connection: DeviceConnection,
            policy: FirmwareSafetyPolicy,
            support: SupportRecord | None,
        ) -> DeviceAdapter:
            del connection, policy, support
            return SystemOnlyAdapter(identity)

    device = PluginRegistry([SystemOnlyPlugin()]).connect(
        identity(),
        DeviceConnection(url="http://192.0.2.1"),
        FirmwareSafetyPolicy(),
    )

    with pytest.raises(UnsupportedFeatureError, match="ports"):
        device.get_ports()
    with pytest.raises(UnsupportedFeatureError, match="port statistics") as error:
        device.get_port_statistics()
    assert error.value.feature == "port_statistics"
    with pytest.raises(UnsupportedFeatureError, match="hosts"):
        device.get_hosts()
    with pytest.raises(UnsupportedFeatureError, match="rstp"):
        device.get_rstp()
    with pytest.raises(UnsupportedFeatureError, match="snmp"):
        device.get_snmp()
    with pytest.raises(UnsupportedFeatureError, match="sfp"):
        device.get_sfp()
    with pytest.raises(UnsupportedFeatureError, match="forwarding"):
        device.get_forwarding()
    with pytest.raises(UnsupportedFeatureError, match="igmp groups"):
        device.get_igmp_groups()
    with pytest.raises(UnsupportedFeatureError, match="acl"):
        device.get_acl_rules()
    with pytest.raises(UnsupportedFeatureError, match="vlan"):
        device.get_port_vlans()
    with pytest.raises(UnsupportedFeatureError, match="vlan"):
        device.get_vlans()
    with pytest.raises(UnsupportedFeatureError, match="port name write"):
        device.set_port_name(PortNameUpdate(number=1, name="Uplink"))
    with pytest.raises(UnsupportedFeatureError, match="port configuration write"):
        device.set_port_configuration(PortConfigurationUpdate(number=1, flow_control=False))
    with pytest.raises(UnsupportedFeatureError, match="device name write"):
        device.set_device_name(DeviceNameUpdate(name="Core Switch"))
    with pytest.raises(UnsupportedFeatureError, match="device name write"):
        device.validate_device_name(DeviceNameUpdate(name="Core Switch"))
    with pytest.raises(UnsupportedFeatureError, match="snmp metadata write"):
        device.set_snmp_metadata(SnmpMetadataUpdate(contact="Ops"))
    with pytest.raises(UnsupportedFeatureError, match="static hosts write"):
        device.replace_static_hosts((), expected_current=())
    with pytest.raises(UnsupportedFeatureError, match="acl write"):
        device.replace_acl_rules((), expected_current=())
    port_vlans = FakeAdapter(identity()).get_port_vlans()
    with pytest.raises(UnsupportedFeatureError, match="vlan port policy write"):
        device.set_port_vlan_policy(
            PortVlanPolicyUpdate(number=1, force_vlan_id=False),
            expected_current=port_vlans,
        )
    vlans = FakeAdapter(identity()).get_vlans()
    with pytest.raises(UnsupportedFeatureError, match="vlan table write"):
        device.replace_vlans(vlans, expected_current=vlans)
    rstp = FakeAdapter(identity()).get_rstp()
    with pytest.raises(UnsupportedFeatureError, match="rstp port enable write"):
        device.set_rstp_port_enabled(
            RstpPortEnableUpdate(number=1, enabled=False), expected_current=rstp
        )
    forwarding = FakeAdapter(identity()).get_forwarding()
    with pytest.raises(UnsupportedFeatureError, match="forwarding port policy write"):
        device.set_forwarding_port_policy(
            ForwardingPortPolicyUpdate(number=1, lock=True), expected_current=forwarding
        )


def test_policy_bound_device_authorizes_and_returns_write_result() -> None:
    device = PluginRegistry([FakePlugin()]).connect(
        identity(),
        DeviceConnection(url="http://192.0.2.1"),
        FirmwareSafetyPolicy(),
    )

    result = device.set_port_name(PortNameUpdate(number=1, name="Uplink"))
    configured = device.set_port_configuration(
        PortConfigurationUpdate(
            number=1,
            negotiation=ForcedPortNegotiation(speed_bps=10_000_000, duplex="half"),
        )
    )
    hosts = device.replace_static_hosts((), expected_current=())
    rules = device.replace_acl_rules((), expected_current=())
    rstp_before = device.get_rstp()
    rstp = device.set_rstp_port_enabled(
        RstpPortEnableUpdate(number=1, enabled=False), expected_current=rstp_before
    )
    forwarding_before = device.get_forwarding()
    forwarding = device.set_forwarding_port_policy(
        ForwardingPortPolicyUpdate(number=1, lock=True),
        expected_current=forwarding_before,
    )
    port_vlans_before = device.get_port_vlans()
    port_vlans = device.set_port_vlan_policy(
        PortVlanPolicyUpdate(number=1, force_vlan_id=False),
        expected_current=port_vlans_before,
    )
    vlans_before = device.get_vlans()
    vlans = device.replace_vlans((), expected_current=vlans_before)

    assert result.changed
    assert result.value.name == "Uplink"
    assert result.warnings == ()
    assert configured.value.configured_speed_bps == 10_000_000
    assert not configured.value.configured_full_duplex
    assert hosts.changed
    assert hosts.value == ()
    assert rules.changed
    assert rules.value == ()
    assert not rstp.value.ports[0].enabled
    assert forwarding.value.ports[0].lock
    assert not port_vlans.value[0].force_vlan_id
    assert vlans.value == ()
    assert configured.warnings == ()

    device_name = device.set_device_name(DeviceNameUpdate(name="Core Switch"))
    metadata = device.set_snmp_metadata(SnmpMetadataUpdate(contact="NOC", location="Rack 1"))

    assert device_name.value.name == "Core Switch"
    assert device_name.warnings == ()
    assert metadata.value.contact == "NOC"
    assert metadata.value.location == "Rack 1"
    assert metadata.value.community == "public"
    assert metadata.warnings == ()

    assert device.validate_device_name(DeviceNameUpdate(name="Core Switch")) == ()
    assert device.validate_port_name(PortNameUpdate(number=1, name="Uplink")) == ()
    assert (
        device.validate_port_configuration(
            PortConfigurationUpdate(number=1, flow_control=False),
            current=device.get_ports()[0],
        )
        == ()
    )
    assert device.validate_snmp_metadata(SnmpMetadataUpdate(contact="NOC")) == ()
    assert device.validate_static_hosts(()) == ()
    assert (
        device.validate_rstp_port_enabled(
            RstpPortEnableUpdate(number=1, enabled=False),
            current=device.get_rstp(),
        )
        == ()
    )
    assert (
        device.validate_forwarding_port_policy(
            ForwardingPortPolicyUpdate(number=1, lock=True),
            current=device.get_forwarding(),
        )
        == ()
    )
    assert (
        device.validate_port_vlan_policy(
            PortVlanPolicyUpdate(number=1, force_vlan_id=False),
            current=device.get_port_vlans(),
        )
        == ()
    )


def test_policy_bound_device_requires_explicit_untested_write_permission() -> None:
    registry = PluginRegistry([FakePlugin()])
    connection = DeviceConnection(url="http://192.0.2.1")
    read_only = registry.connect(
        identity("2.20"),
        connection,
        FirmwareSafetyPolicy(allow_untested_firmware=True),
    )

    with pytest.raises(UnsupportedFirmwareError, match="write operations"):
        read_only.set_port_name(PortNameUpdate(number=1, name="Uplink"))

    writable = registry.connect(
        identity("2.20"),
        connection,
        FirmwareSafetyPolicy(allow_untested_firmware_writes=True),
    )
    result = writable.set_port_name(PortNameUpdate(number=1, name="Uplink"))

    assert result.warnings[0].code == "untested_firmware_write"
    assert (
        writable.validate_port_name(PortNameUpdate(number=1, name="Uplink"))[0].code
        == "untested_firmware_write"
    )
    assert (
        writable.set_port_configuration(PortConfigurationUpdate(number=1, flow_control=False))
        .warnings[0]
        .code
        == "untested_firmware_write"
    )
    assert (
        writable.set_device_name(DeviceNameUpdate(name="Core Switch")).warnings[0].code
        == "untested_firmware_write"
    )
    assert (
        writable.set_snmp_metadata(SnmpMetadataUpdate(location="Rack 1")).warnings[0].code
        == "untested_firmware_write"
    )


def test_registry_reports_missing_plugin() -> None:
    with pytest.raises(MissingDevicePluginError) as error:
        PluginRegistry().resolve(identity(), FirmwareSafetyPolicy())

    assert error.value.suggested_package == "swos-device-css106"


def test_registry_reports_an_unrecognized_device() -> None:
    with pytest.raises(DeviceDetectionError):
        PluginRegistry().probe(DeviceConnection(url="http://192.0.2.1"))


def test_registry_ignores_plugin_protocol_mismatches_during_probe() -> None:
    class NonMatchingPlugin(FakePlugin):
        family = "other"

        def probe(self, connection: DeviceConnection) -> DeviceIdentity | None:
            del connection
            raise ProtocolError("not this protocol")

    detected = PluginRegistry([NonMatchingPlugin(), FakePlugin()]).probe(
        DeviceConnection(url="http://192.0.2.1")
    )

    assert detected == identity()


def test_registry_rejects_duplicate_family() -> None:
    with pytest.raises(DuplicateDevicePluginError):
        PluginRegistry([FakePlugin(), FakePlugin()])


@pytest.mark.parametrize("reported_version", ["2.19.0", "v2.19", "not a version"])
def test_firmware_identifiers_are_matched_exactly(reported_version: str) -> None:
    record = FakePlugin().support_records()[0]

    assert not record.matches(identity(reported_version))


def test_build_id_is_exact_when_declared() -> None:
    record = SupportRecord(
        firmware_family="css106",
        product_code="CSS106-5G-1S",
        firmware_version="2.19",
        build_id="known-build",
    )
    reported = identity().model_copy(update={"build_id": "different-build"})

    assert not record.matches(reported)
