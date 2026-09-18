import os
import socket
import sys
from ipaddress import IPv4Address, IPv4Network
from socket import create_connection
from typing import Literal, TypeVar
from urllib.parse import urlsplit, urlunsplit

import pytest
from swos_core import (
    AclRule,
    AclVlanTagMode,
    AddressMode,
    DeviceConnection,
    DeviceIdentity,
    DeviceNameUpdate,
    ForwardingInfo,
    ForwardingMatrixUpdate,
    ForwardingMirroringUpdate,
    ForwardingPortPolicyUpdate,
    HostEntry,
    HostEntryType,
    IgmpInfo,
    ManagementStateUncertainError,
    OperationResult,
    PluginRegistry,
    PortConfigurationUpdate,
    PortNameUpdate,
    PortVlanInfo,
    PortVlanPolicyUpdate,
    RstpBridgeUpdate,
    RstpCostMode,
    RstpInfo,
    RstpPortEnableUpdate,
    SnmpMetadataUpdate,
    SwOSDevice,
    SystemConfigurationUpdate,
    SystemInfo,
    SystemManagementInfo,
    VlanEgressMode,
    VlanInfo,
    VlanMembershipMode,
    VlanMode,
    VlanPortMembership,
    VlanReceiveMode,
)
from swos_core.errors import (
    AuthenticationError,
    DeviceDetectionError,
    HttpStatusError,
    ProtocolError,
    SwOSError,
    TransportError,
)
from swos_core.safety import FirmwareSafetyPolicy


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_port_name_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    port_number = int(os.environ.get("SWOS_INTEGRATION_WRITE_PORT", "5"))
    assert 1 <= port_number <= 5, "SWOS_INTEGRATION_WRITE_PORT must be an Ethernet port (1-5)"
    original_port = device.get_ports()[port_number - 1]
    if original_port.link_up:
        pytest.skip(f"port {port_number} is link-up; refusing destructive port test")
    original_name = original_port.name
    temporary_name = "SWOS-CLI-TEST" if original_name != "SWOS-CLI-TEST" else "SWOS-CLI-TEMP"
    restorable = device.set_port_name(PortNameUpdate(number=port_number, name=original_name))
    assert not restorable.changed

    try:
        changed = device.set_port_name(PortNameUpdate(number=port_number, name=temporary_name))
        assert changed.changed
        assert changed.value.name == temporary_name
        assert device.get_ports()[port_number - 1].name == temporary_name
    finally:
        restored = device.set_port_name(PortNameUpdate(number=port_number, name=original_name))
        assert restored.value.name == original_name
        assert device.get_ports()[port_number - 1].name == original_name


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_port_flow_control_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    port_number = 5
    original = device.get_ports()[port_number - 1]
    if original.link_up:
        pytest.skip(f"port {port_number} is link-up; refusing destructive port test")

    restorable = device.set_port_configuration(
        PortConfigurationUpdate(number=port_number, flow_control=original.flow_control)
    )
    assert not restorable.changed

    try:
        changed = device.set_port_configuration(
            PortConfigurationUpdate(number=port_number, flow_control=not original.flow_control)
        )
        assert changed.changed
        assert changed.value.flow_control is not original.flow_control
        assert device.get_ports()[port_number - 1].flow_control is not original.flow_control
    finally:
        restored = device.set_port_configuration(
            PortConfigurationUpdate(number=port_number, flow_control=original.flow_control)
        )
        assert restored.value.flow_control is original.flow_control
        assert device.get_ports()[port_number - 1].flow_control is original.flow_control


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_device_name_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    original_name = device.get_system_info().name
    temporary_name = "SWOS-API-TEST" if original_name != "SWOS-API-TEST" else "SWOS-API-TEMP"
    restorable = device.set_device_name(DeviceNameUpdate(name=original_name))
    assert not restorable.changed

    try:
        changed = device.set_device_name(DeviceNameUpdate(name=temporary_name))
        assert changed.changed
        assert changed.value.name == temporary_name
        assert device.get_system_info().name == temporary_name
    finally:
        restored = device.set_device_name(DeviceNameUpdate(name=original_name))
        assert restored.value.name == original_name
        assert device.get_system_info().name == original_name


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_snmp_metadata_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    original = device.get_snmp()
    temporary_contact = "SWOS API TEST" if original.contact != "SWOS API TEST" else "SWOS API TEMP"
    restorable = device.set_snmp_metadata(
        SnmpMetadataUpdate(contact=original.contact, location=original.location)
    )
    assert not restorable.changed

    try:
        changed = device.set_snmp_metadata(SnmpMetadataUpdate(contact=temporary_contact))
        assert changed.changed
        assert changed.value.contact == temporary_contact
        assert changed.value.location == original.location
        assert changed.value.community == original.community
        assert device.get_snmp().contact == temporary_contact
    finally:
        restored = device.set_snmp_metadata(
            SnmpMetadataUpdate(contact=original.contact, location=original.location)
        )
        assert restored.value.contact == original.contact
        assert restored.value.location == original.location
        assert restored.value.community == original.community


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_static_host_write_and_restore_empty_table() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    original = tuple(host for host in device.get_hosts() if host.entry_type is HostEntryType.STATIC)
    if original:
        pytest.skip("static host table is not empty; refusing destructive replacement test")
    temporary = HostEntry(
        entry_type=HostEntryType.STATIC,
        mac_address="02:00:00:ff:ff:05",
        vlan_id=1,
        port_numbers=(5,),
    )
    changed = None

    try:
        changed = device.replace_static_hosts((temporary,), expected_current=original)
        assert changed.changed
        assert changed.value == (temporary,)
        assert tuple(
            host for host in device.get_hosts() if host.entry_type is HostEntryType.STATIC
        ) == (temporary,)
    finally:
        if changed is not None:
            restored = device.replace_static_hosts((), expected_current=changed.value)
            assert restored.value == ()
            assert not any(host.entry_type is HostEntryType.STATIC for host in device.get_hosts())


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_rstp_port_5_enable_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    port_number = 5
    if device.get_ports()[port_number - 1].link_up:
        pytest.skip("port 5 is link-up; refusing destructive RSTP test")
    original = device.get_rstp()
    original_enabled = original.ports[port_number - 1].enabled
    changed = None

    try:
        changed = device.set_rstp_port_enabled(
            RstpPortEnableUpdate(number=port_number, enabled=not original_enabled),
            expected_current=original,
        )
        assert changed.changed
        assert changed.value.ports[port_number - 1].enabled is not original_enabled
    finally:
        if changed is not None:
            restored = device.set_rstp_port_enabled(
                RstpPortEnableUpdate(number=port_number, enabled=original_enabled),
                expected_current=changed.value,
            )
            assert restored.value.ports[port_number - 1].enabled is original_enabled


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_port_5_lock_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    port_number = 5
    if device.get_ports()[port_number - 1].link_up:
        pytest.skip("port 5 is link-up; refusing destructive forwarding test")
    original = device.get_forwarding()
    original_lock = original.ports[port_number - 1].lock
    changed = None

    try:
        changed = device.set_forwarding_port_policy(
            ForwardingPortPolicyUpdate(number=port_number, lock=not original_lock),
            expected_current=original,
        )
        assert changed.changed
        assert changed.value.ports[port_number - 1].lock is not original_lock
    finally:
        if changed is not None:
            restored = device.set_forwarding_port_policy(
                ForwardingPortPolicyUpdate(number=port_number, lock=original_lock),
                expected_current=changed.value,
            )
            assert restored.value.ports[port_number - 1].lock is original_lock


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_port_5_lock_on_first_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    port_number = 5
    if device.get_ports()[port_number - 1].link_up:
        pytest.skip("port 5 is link-up; refusing destructive forwarding test")
    original = device.get_forwarding()
    original_lock_on_first = original.ports[port_number - 1].lock_on_first
    changed = None

    try:
        changed = device.set_forwarding_port_policy(
            ForwardingPortPolicyUpdate(
                number=port_number,
                lock_on_first=not original_lock_on_first,
            ),
            expected_current=original,
        )
        assert changed.changed
        assert changed.value.ports[port_number - 1].lock_on_first is not original_lock_on_first
    finally:
        if changed is not None:
            restored = device.set_forwarding_port_policy(
                ForwardingPortPolicyUpdate(
                    number=port_number,
                    lock_on_first=original_lock_on_first,
                ),
                expected_current=changed.value,
            )
            assert restored.value.ports[port_number - 1].lock_on_first is original_lock_on_first


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_port_5_egress_rate_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    port_number = 5
    if device.get_ports()[port_number - 1].link_up:
        pytest.skip("port 5 is link-up; refusing destructive forwarding test")
    original = device.get_forwarding()
    original_rate = original.ports[port_number - 1].egress_rate_limit_bps
    temporary_rate: int | Literal["unlimited"] = (
        1_000_000 if original_rate != 1_000_000 else "unlimited"
    )
    changed = None

    try:
        changed = device.set_forwarding_port_policy(
            ForwardingPortPolicyUpdate(
                number=port_number,
                egress_rate_limit_bps=temporary_rate,
            ),
            expected_current=original,
        )
        assert changed.changed
        expected_rate = None if temporary_rate == "unlimited" else temporary_rate
        assert changed.value.ports[port_number - 1].egress_rate_limit_bps == expected_rate
    finally:
        if changed is not None:
            restored = device.set_forwarding_port_policy(
                ForwardingPortPolicyUpdate(
                    number=port_number,
                    egress_rate_limit_bps=("unlimited" if original_rate is None else original_rate),
                ),
                expected_current=changed.value,
            )
            assert restored.value.ports[port_number - 1].egress_rate_limit_bps == original_rate


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.high_risk_tables
def test_rb260gs_219_acl_port_5_no_action_rule_and_restore_exact_table() -> None:
    device = _integration_device()
    if next(port for port in device.get_ports() if port.number == 5).link_up:
        pytest.skip("port 5 is link-up; refusing high-risk ACL test")
    original = device.get_acl_rules()
    if len(original) >= 32:
        pytest.skip("ACL table is full")
    if any(6 in rule.ingress_port_numbers for rule in original):
        pytest.skip("ACL table contains protected port-6 ingress and cannot be round-tripped")
    temporary_rule = AclRule(
        number=len(original) + 1,
        ingress_port_numbers=(5,),
        source_mac=None,
        source_mac_mask="00:00:00:00:00:00",
        destination_mac=None,
        destination_mac_mask="00:00:00:00:00:00",
        ether_type=0,
        vlan_tag=AclVlanTagMode.ANY,
        vlan_id_min=0,
        vlan_id_max=4095,
        source_prefix_length=0,
        source_port_min=0,
        source_port_max=0xFFFF,
        destination_prefix_length=0,
        destination_port_min=0,
        destination_port_max=0xFFFF,
        protocol_number=0,
        redirect_enabled=False,
        redirect_port_numbers=(),
        drop=False,
        mirror=False,
    )
    expected_temporary = (*original, temporary_rule)

    try:
        if next(port for port in device.get_ports() if port.number == 5).link_up:
            pytest.fail("port 5 became link-up immediately before the ACL write")
        changed = device.replace_acl_rules(expected_temporary, expected_current=original)
        assert changed.changed
        assert changed.value == expected_temporary
    finally:
        _restore_acl_table(device, original=original, expected_temporary=expected_temporary)


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.high_risk_tables
def test_rb260gs_219_vlan_4094_port_5_row_and_restore_exact_ordered_table() -> None:
    device = _integration_device()
    if next(port for port in device.get_ports() if port.number == 5).link_up:
        pytest.skip("port 5 is link-up; refusing high-risk VLAN-table test")
    original = device.get_vlans()
    if original:
        pytest.skip("VLAN table is not empty; refusing high-risk ordered-table test")
    first_vlan = VlanInfo(
        table_position=0,
        vlan_id=4094,
        independent_learning=False,
        igmp_snooping=False,
        ports=tuple(
            VlanPortMembership(
                port_number=number,
                mode=(
                    VlanMembershipMode.PRESERVE if number == 5 else VlanMembershipMode.NOT_MEMBER
                ),
            )
            for number in range(1, 7)
        ),
    )
    second_vlan = first_vlan.model_copy(update={"table_position": 1, "vlan_id": 4093})
    expected_first = (first_vlan,)
    expected_second = (second_vlan, first_vlan)
    assert _port_6_vlan_membership(original) == _port_6_vlan_membership(expected_first)
    assert _port_6_vlan_membership(original) == _port_6_vlan_membership(expected_second)

    try:
        if next(port for port in device.get_ports() if port.number == 5).link_up:
            pytest.fail("port 5 became link-up immediately before the first VLAN write")
        first = device.replace_vlans(expected_first, expected_current=original)
        assert first.changed
        assert first.value == expected_first

        if next(port for port in device.get_ports() if port.number == 5).link_up:
            pytest.fail("port 5 became link-up immediately before the second VLAN write")
        second = device.replace_vlans(expected_second, expected_current=first.value)
        assert second.changed
        assert second.value == expected_second
        assert [vlan.vlan_id for vlan in second.value] == [4093, 4094]
        assert [vlan.table_position for vlan in second.value] == [1, 0]
    finally:
        _restore_vlan_table(
            device,
            original=original,
            expected_temporaries=(expected_first, expected_second),
        )


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.high_risk_tables
def test_rb260gs_219_rstp_bridge_priority_and_restore() -> None:
    device, original = _isolated_rstp_device()
    temporary_priority = _temporary_bridge_priority(original.bridge_priority)
    _run_rstp_bridge_cycle(
        device,
        original=original,
        update=RstpBridgeUpdate(bridge_priority=temporary_priority),
        expected_temporary=original.model_copy(update={"bridge_priority": temporary_priority}),
        restore=RstpBridgeUpdate(bridge_priority=original.bridge_priority),
    )


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.high_risk_tables
def test_rb260gs_219_rstp_bridge_cost_mode_and_restore() -> None:
    device, original = _isolated_rstp_device()
    temporary_cost = (
        RstpCostMode.LONG if original.cost_mode is RstpCostMode.SHORT else RstpCostMode.SHORT
    )
    _run_rstp_bridge_cycle(
        device,
        original=original,
        update=RstpBridgeUpdate(cost_mode=temporary_cost),
        expected_temporary=original.model_copy(update={"cost_mode": temporary_cost}),
        restore=RstpBridgeUpdate(cost_mode=original.cost_mode),
    )


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.high_risk_tables
def test_rb260gs_219_rstp_bridge_reserved_multicast_and_restore() -> None:
    device, original = _isolated_rstp_device()
    temporary_forwarding = not original.forward_reserved_multicast
    _run_rstp_bridge_cycle(
        device,
        original=original,
        update=RstpBridgeUpdate(forward_reserved_multicast=temporary_forwarding),
        expected_temporary=original.model_copy(
            update={"forward_reserved_multicast": temporary_forwarding}
        ),
        restore=RstpBridgeUpdate(forward_reserved_multicast=original.forward_reserved_multicast),
    )


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.high_risk_tables
def test_rb260gs_219_forwarding_matrix_port_5_and_restore() -> None:
    device = _integration_device()
    if next(port for port in device.get_ports() if port.number == 5).link_up:
        pytest.skip("port 5 is link-up; refusing high-risk forwarding-matrix test")
    original = device.get_forwarding()
    source = next(port for port in original.ports if port.number == 5)
    removable = tuple(port for port in source.destination_port_numbers if port != 6)
    if not removable:
        pytest.skip("source port 5 has no non-port-6 forwarding destination to remove")
    temporary_destinations = tuple(
        port for port in source.destination_port_numbers if port != removable[0]
    )
    expected_temporary = original.model_copy(
        update={
            "ports": tuple(
                port.model_copy(update={"destination_port_numbers": temporary_destinations})
                if port.number == 5
                else port
                for port in original.ports
            )
        }
    )
    _assert_port_6_forwarding_unchanged(original, expected_temporary)

    try:
        _require_ethernet_ports_down(device, (5,), "forwarding matrix", skip=False)
        changed = device.set_forwarding_matrix(
            ForwardingMatrixUpdate(
                number=5,
                destination_port_numbers=temporary_destinations,
            ),
            expected_current=original,
        )
        assert changed.changed
        assert changed.value == expected_temporary
    finally:
        _restore_forwarding_matrix(
            device,
            original=original,
            expected_temporary=expected_temporary,
        )


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.high_risk_tables
@pytest.mark.parametrize("direction", ["ingress", "egress"])
def test_rb260gs_219_mirroring_port_5_to_port_4_and_restore(direction: str) -> None:
    device = _integration_device()
    ports = device.get_ports()
    port_4 = next(port for port in ports if port.number == 4)
    port_5 = next(port for port in ports if port.number == 5)
    if port_4.link_up or port_5.link_up:
        pytest.skip("ports 4 and 5 must both be link-down for high-risk mirroring test")
    original = device.get_forwarding()
    if original.mirror_target_port is not None or any(
        port.mirror_ingress or port.mirror_egress for port in original.ports
    ):
        pytest.skip("mirroring is already configured; refusing to alter active mirror policy")
    expected_temporary = original.model_copy(
        update={
            "mirror_target_port": 4,
            "ports": tuple(
                port.model_copy(update={f"mirror_{direction}": True}) if port.number == 5 else port
                for port in original.ports
            ),
        }
    )
    _assert_port_6_forwarding_unchanged(original, expected_temporary)

    try:
        _require_mirroring_links_down(device, skip=False)
        changed = device.set_forwarding_mirroring(
            ForwardingMirroringUpdate(
                source_port_number=5,
                mirror_ingress=True if direction == "ingress" else None,
                mirror_egress=True if direction == "egress" else None,
                mirror_target_port=4,
            ),
            expected_current=original,
        )
        assert changed.changed
        assert changed.value == expected_temporary
    finally:
        _restore_forwarding_mirroring(
            device,
            original=original,
            expected_temporary=expected_temporary,
        )


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_port_5_discovery_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    port_number = 5
    if device.get_ports()[port_number - 1].link_up:
        pytest.skip("port 5 is link-up; refusing destructive discovery test")
    original = device.get_system_info()
    temporary_ports = _toggle_port(original.discovery_protocol_port_numbers, port_number)
    assert (6 in temporary_ports) == (6 in original.discovery_protocol_port_numbers)
    expected_temporary = original.model_copy(
        update={"discovery_protocol_port_numbers": temporary_ports}
    )

    try:
        changed = device.set_system_configuration(
            SystemConfigurationUpdate(discovery_protocol_port_numbers=temporary_ports),
            expected_current=original,
        )
        assert changed.changed
        assert _system_configuration(changed.value) == _system_configuration(expected_temporary)
    finally:
        _restore_system_configuration(
            device,
            original=original,
            expected_temporary=expected_temporary,
            update=SystemConfigurationUpdate(
                discovery_protocol_port_numbers=original.discovery_protocol_port_numbers
            ),
        )


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_port_5_igmp_fast_leave_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    port_number = 5
    if device.get_ports()[port_number - 1].link_up:
        pytest.skip("port 5 is link-up; refusing destructive IGMP fast-leave test")
    original = device.get_system_info()
    if original.igmp is None or not original.igmp.enabled:
        pytest.skip("global IGMP snooping is disabled; fast-leave would be meaningless")
    temporary_ports = _toggle_port(original.igmp.fast_leave_port_numbers, port_number)
    assert (6 in temporary_ports) == (6 in original.igmp.fast_leave_port_numbers)
    expected_temporary = original.model_copy(
        update={
            "igmp": original.igmp.model_copy(update={"fast_leave_port_numbers": temporary_ports})
        }
    )

    try:
        changed = device.set_system_configuration(
            SystemConfigurationUpdate(igmp_fast_leave_port_numbers=temporary_ports),
            expected_current=original,
        )
        assert changed.changed
        assert _system_configuration(changed.value) == _system_configuration(expected_temporary)
    finally:
        _restore_system_configuration(
            device,
            original=original,
            expected_temporary=expected_temporary,
            update=SystemConfigurationUpdate(
                igmp_fast_leave_port_numbers=original.igmp.fast_leave_port_numbers
            ),
        )


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_port_5_management_allowed_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    port_number = 5
    if device.get_ports()[port_number - 1].link_up:
        pytest.skip("port 5 is link-up; refusing destructive management-port test")
    original = device.get_system_info()
    assert original.management is not None
    if 6 not in original.management.allowed_port_numbers:
        pytest.skip("port 6 is not a management allowed port; refusing destructive test")
    temporary_ports = _toggle_port(original.management.allowed_port_numbers, port_number)
    assert 6 in temporary_ports
    expected_temporary = original.model_copy(
        update={
            "management": original.management.model_copy(
                update={"allowed_port_numbers": temporary_ports}
            )
        }
    )

    try:
        changed = device.set_system_configuration(
            SystemConfigurationUpdate(allowed_port_numbers=temporary_ports),
            expected_current=original,
        )
        assert changed.changed
        assert _system_configuration(changed.value) == _system_configuration(expected_temporary)
        _assert_management_allowed_ports_warning(
            changed,
            before=original.management.allowed_port_numbers,
            after=temporary_ports,
        )
    finally:
        _restore_system_configuration(
            device,
            original=original,
            expected_temporary=expected_temporary,
            update=SystemConfigurationUpdate(
                allowed_port_numbers=original.management.allowed_port_numbers
            ),
            assert_management_warning=True,
        )


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.management_reconnect
def test_rb260gs_219_admin_mac_physical_value_and_restore() -> None:
    connection = _integration_connection()
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    original = device.get_system_info()
    assert original.management is not None
    if original.management.admin_mac_address is not None:
        pytest.skip("admin MAC override is already set; refusing destructive test")
    if original.mac_address is None:
        pytest.skip("physical system MAC is unavailable")
    expected_temporary = original.model_copy(
        update={
            "management": original.management.model_copy(
                update={"admin_mac_address": original.mac_address}
            )
        }
    )

    try:
        changed = device.set_system_configuration(
            SystemConfigurationUpdate(admin_mac_address=original.mac_address),
            expected_current=original,
        )
        assert changed.changed
        assert _system_configuration(changed.value) == _system_configuration(expected_temporary)
        assert changed.value.mac_address == original.mac_address
        assert any(warning.code == "management_lockout_risk" for warning in changed.warnings)
    finally:
        _restore_management_reconnect(
            registry,
            identity=identity,
            original_connection=connection,
            temporary_url=str(connection.url),
            original=original,
            expected_temporary=expected_temporary,
            update=SystemConfigurationUpdate(admin_mac_address="unset"),
        )


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.management_reconnect
def test_rb260gs_219_allow_from_connected_subnet_and_restore() -> None:
    connection = _integration_connection()
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    original = device.get_system_info()
    assert original.management is not None
    if original.management.allow_from is not None:
        pytest.skip("allow-from override is already set; refusing destructive test")
    if original.management.allow_prefix_length != 0:
        pytest.skip("allow-from prefix is not unset/0; refusing destructive test")
    if 6 not in original.management.allowed_port_numbers:
        pytest.skip("port 6 is not a management allowed port; refusing destructive test")
    allow_from = _directly_connected_allow_from(original.current_ip)
    if allow_from is None:
        pytest.skip("device and selected local route are not both in the current 192.168.88.0/24")
    expected_temporary = original.model_copy(
        update={
            "management": original.management.model_copy(
                update={"allow_from": allow_from, "allow_prefix_length": 24}
            )
        }
    )

    try:
        changed = device.set_system_configuration(
            SystemConfigurationUpdate(allow_from=allow_from, allow_prefix_length=24),
            expected_current=original,
        )
        assert changed.changed
        assert _system_configuration(changed.value) == _system_configuration(expected_temporary)
        assert changed.value.management is not None
        assert changed.value.management.allow_prefix_length == 24
        assert (
            changed.value.management.allowed_port_numbers
            == original.management.allowed_port_numbers
        )
        assert 6 in changed.value.management.allowed_port_numbers
        assert any(warning.code == "management_lockout_risk" for warning in changed.warnings)
    finally:
        _restore_management_reconnect(
            registry,
            identity=identity,
            original_connection=connection,
            temporary_url=str(connection.url),
            original=original,
            expected_temporary=expected_temporary,
            update=SystemConfigurationUpdate(allow_from="unset", allow_prefix_length=0),
        )


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.management_reconnect
def test_rb260gs_219_management_vlan_one_reconnect_and_restore() -> None:
    if os.environ.get("SWOS_INTEGRATION_MANAGEMENT_PORT") != "6":
        pytest.skip("SWOS_INTEGRATION_MANAGEMENT_PORT=6 is required")
    connection = _integration_connection()
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    original = device.get_system_info()
    assert original.management is not None
    if original.management.allowed_vlan_id is not None:
        pytest.skip("management VLAN is not unset; refusing management reconnect test")
    if 6 not in original.management.allowed_port_numbers:
        pytest.skip("port 6 is not a management allowed port; refusing destructive test")
    port6 = next(port for port in device.get_port_vlans() if port.number == 6)
    vlans = device.get_vlans()
    risk_acknowledged = _management_vlan_risk_acknowledged()
    if not _management_vlan_gate_allows(port6, vlans, risk_acknowledged=risk_acknowledged):
        if not _port6_accepts_untagged_vlan_one(port6):
            pytest.skip("port 6 does not accept untagged ingress with PVID 1")
        pytest.skip(
            "port 6 egress is not conservatively proven safe; set "
            "SWOS_INTEGRATION_MANAGEMENT_VLAN_RISK_ACKNOWLEDGED=1 to accept factory-reset risk"
        )
    expected_temporary = original.model_copy(
        update={"management": original.management.model_copy(update={"allowed_vlan_id": 1})}
    )

    try:
        changed = device.set_system_configuration(
            SystemConfigurationUpdate(allowed_vlan_id=1), expected_current=original
        )
        assert changed.changed
        assert _system_configuration(changed.value) == _system_configuration(expected_temporary)
        assert changed.value.management is not None
        assert (
            changed.value.management.allowed_port_numbers
            == original.management.allowed_port_numbers
        )
        assert 6 in changed.value.management.allowed_port_numbers
        assert any(warning.code == "management_lockout_risk" for warning in changed.warnings)
    finally:
        _restore_management_reconnect(
            registry,
            identity=identity,
            original_connection=connection,
            temporary_url=str(connection.url),
            original=original,
            expected_temporary=expected_temporary,
            update=SystemConfigurationUpdate(allowed_vlan_id="unset"),
        )


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.management_reconnect
def test_rb260gs_219_dhcp_fallback_to_same_ip_static_and_restore() -> None:
    connection = _integration_connection()
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    original = device.get_system_info()
    assert original.management is not None
    if original.management.address_mode is not AddressMode.DHCP_WITH_FALLBACK:
        pytest.skip("address mode is not DHCP with fallback")
    if original.static_ip is None or urlsplit(str(connection.url)).hostname != original.static_ip:
        pytest.skip("configured static IP is not the current integration URL host")
    expected_temporary = original.model_copy(
        update={
            "management": original.management.model_copy(
                update={"address_mode": AddressMode.STATIC}
            )
        }
    )

    try:
        changed = device.set_system_configuration(
            SystemConfigurationUpdate(address_mode="static"), expected_current=original
        )
        assert changed.changed
        assert _system_configuration(changed.value) == _system_configuration(expected_temporary)
    finally:
        _restore_management_reconnect(
            registry,
            identity=identity,
            original_connection=connection,
            temporary_url=str(connection.url),
            original=original,
            expected_temporary=expected_temporary,
            update=SystemConfigurationUpdate(address_mode="dhcp_with_fallback"),
        )


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.management_reconnect
def test_rb260gs_219_static_ip_move_and_restore() -> None:
    temporary_value = os.environ.get("SWOS_INTEGRATION_TEMPORARY_IP")
    if temporary_value is None:
        pytest.skip("SWOS_INTEGRATION_TEMPORARY_IP is not set")
    temporary_ip = str(IPv4Address(temporary_value))
    if os.environ.get("SWOS_INTEGRATION_TEMPORARY_IP_ACKNOWLEDGED") != temporary_ip:
        pytest.skip("SWOS_INTEGRATION_TEMPORARY_IP_ACKNOWLEDGED must equal the temporary IP")
    connection = _integration_connection()
    temporary_url = _url_with_host(str(connection.url), temporary_ip)
    if temporary_url == str(connection.url):
        pytest.skip("temporary IP matches the integration URL")

    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    if _tcp_endpoint_responds(temporary_url, timeout=connection.timeout):
        pytest.skip("temporary IP already accepts a TCP connection")

    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    original = device.get_system_info()
    assert original.management is not None
    expected_temporary = original.model_copy(
        update={
            "static_ip": temporary_ip,
            "management": original.management.model_copy(
                update={"address_mode": AddressMode.STATIC}
            ),
        }
    )
    restore_static_ip: str | Literal["unset"] = original.static_ip or "unset"

    try:
        changed = device.set_system_configuration(
            SystemConfigurationUpdate(address_mode="static", static_ip=temporary_ip),
            expected_current=original,
        )
        assert changed.changed
        assert _system_configuration(changed.value) == _system_configuration(expected_temporary)
        assert _system_configuration(device.get_system_info()) == _system_configuration(
            expected_temporary
        )
    finally:
        _restore_management_reconnect(
            registry,
            identity=identity,
            original_connection=connection,
            temporary_url=temporary_url,
            original=original,
            expected_temporary=expected_temporary,
            update=SystemConfigurationUpdate(
                address_mode=original.management.address_mode,
                static_ip=restore_static_ip,
            ),
        )


_CleanupState = TypeVar("_CleanupState")


def _integration_device() -> SwOSDevice:
    connection = _integration_connection()
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    return registry.connect(identity, connection, FirmwareSafetyPolicy())


def _cleanup_state(
    current: _CleanupState,
    *,
    original: _CleanupState,
    temporary: _CleanupState,
    label: str,
) -> Literal["original", "temporary"]:
    if current == original:
        return "original"
    if current == temporary:
        return "temporary"
    raise AssertionError(
        f"{label} is neither the exact original nor expected temporary state; refusing cleanup"
    )


def _staged_cleanup_state(
    current: _CleanupState,
    *,
    original: _CleanupState,
    temporaries: tuple[_CleanupState, ...],
    label: str,
) -> Literal["original", "temporary"]:
    if current == original:
        return "original"
    if current in temporaries:
        return "temporary"
    raise AssertionError(
        f"{label} is neither the exact original nor an expected temporary state; refusing cleanup"
    )


def _restore_acl_table(
    device: SwOSDevice,
    *,
    original: tuple[AclRule, ...],
    expected_temporary: tuple[AclRule, ...],
) -> None:
    current = device.get_acl_rules()
    if (
        _cleanup_state(
            current,
            original=original,
            temporary=expected_temporary,
            label="ACL table",
        )
        == "original"
    ):
        return
    _require_ethernet_ports_down(device, (5,), "ACL cleanup", skip=False)
    restored = device.replace_acl_rules(original, expected_current=current)
    assert restored.value == original
    assert device.get_acl_rules() == original


def _restore_vlan_table(
    device: SwOSDevice,
    *,
    original: tuple[VlanInfo, ...],
    expected_temporaries: tuple[tuple[VlanInfo, ...], ...],
) -> None:
    current = device.get_vlans()
    if (
        _staged_cleanup_state(
            current,
            original=original,
            temporaries=expected_temporaries,
            label="ordered VLAN table",
        )
        == "original"
    ):
        return
    _require_ethernet_ports_down(device, (5,), "VLAN cleanup", skip=False)
    restored = device.replace_vlans(original, expected_current=current)
    assert restored.value == original
    assert device.get_vlans() == original


def _rstp_writable_configuration(info: RstpInfo) -> tuple[object, ...]:
    return (
        info.bridge_priority,
        info.cost_mode,
        info.forward_reserved_multicast,
        tuple(
            (
                port.number,
                port.enabled,
                port.protocol,
                port.configured_path_cost,
                port.point_to_point,
                port.edge,
            )
            for port in info.ports
        ),
    )


def _restore_rstp_bridge(
    device: SwOSDevice,
    *,
    original: RstpInfo,
    expected_temporary: RstpInfo,
    restore: RstpBridgeUpdate,
) -> None:
    current = device.get_rstp()
    if (
        _cleanup_state(
            _rstp_writable_configuration(current),
            original=_rstp_writable_configuration(original),
            temporary=_rstp_writable_configuration(expected_temporary),
            label="RSTP writable configuration",
        )
        == "original"
    ):
        return
    _require_rstp_isolation(device, skip=False)
    restored = device.set_rstp_bridge(restore, expected_current=current)
    assert _rstp_writable_configuration(restored.value) == _rstp_writable_configuration(original)
    assert _rstp_writable_configuration(device.get_rstp()) == _rstp_writable_configuration(original)


def _restore_forwarding_matrix(
    device: SwOSDevice,
    *,
    original: ForwardingInfo,
    expected_temporary: ForwardingInfo,
) -> None:
    current = device.get_forwarding()
    if (
        _cleanup_state(
            current,
            original=original,
            temporary=expected_temporary,
            label="forwarding configuration",
        )
        == "original"
    ):
        return
    original_source = next(port for port in original.ports if port.number == 5)
    _require_ethernet_ports_down(device, (5,), "forwarding matrix cleanup", skip=False)
    restored = device.set_forwarding_matrix(
        ForwardingMatrixUpdate(
            number=5,
            destination_port_numbers=original_source.destination_port_numbers,
        ),
        expected_current=current,
    )
    assert restored.value == original
    assert device.get_forwarding() == original


def _restore_forwarding_mirroring(
    device: SwOSDevice,
    *,
    original: ForwardingInfo,
    expected_temporary: ForwardingInfo,
) -> None:
    current = device.get_forwarding()
    if (
        _cleanup_state(
            current,
            original=original,
            temporary=expected_temporary,
            label="forwarding configuration",
        )
        == "original"
    ):
        return
    original_source = next(port for port in original.ports if port.number == 5)
    _require_mirroring_links_down(device, skip=False)
    restored = device.set_forwarding_mirroring(
        ForwardingMirroringUpdate(
            source_port_number=5,
            mirror_ingress=original_source.mirror_ingress,
            mirror_egress=original_source.mirror_egress,
            mirror_target_port=original.mirror_target_port or "none",
        ),
        expected_current=current,
    )
    assert restored.value == original
    assert device.get_forwarding() == original


def _require_ethernet_ports_down(
    device: SwOSDevice,
    port_numbers: tuple[int, ...],
    label: str,
    *,
    skip: bool,
) -> None:
    ports = {port.number: port for port in device.get_ports()}
    up = tuple(number for number in port_numbers if ports[number].link_up)
    if not up:
        return
    message = f"{label} requires link-down Ethernet ports: {','.join(map(str, up))}"
    if skip:
        pytest.skip(message)
    raise AssertionError(message)


def _require_rstp_isolation(device: SwOSDevice, *, skip: bool) -> None:
    if os.environ.get("SWOS_INTEGRATION_MANAGEMENT_PORT") != "6":
        message = "RSTP bridge tests require SWOS_INTEGRATION_MANAGEMENT_PORT=6"
        if skip:
            pytest.skip(message)
        raise AssertionError(message)
    ports = {port.number: port for port in device.get_ports()}
    isolated = all(not ports[number].link_up for number in range(1, 6)) and ports[6].link_up
    if isolated:
        return
    message = "RSTP bridge tests require Ethernet ports 1-5 down and management port 6 up"
    if skip:
        pytest.skip(message)
    raise AssertionError(message)


def _isolated_rstp_device() -> tuple[SwOSDevice, RstpInfo]:
    device = _integration_device()
    system = device.get_system_info()
    if system.management is None or 6 not in system.management.allowed_port_numbers:
        pytest.skip("port 6 is not an explicitly management-allowed port")
    original = device.get_rstp()
    if (
        system.mac_address is None
        or original.root_bridge_priority != original.bridge_priority
        or original.root_bridge_mac.casefold() != system.mac_address.casefold()
    ):
        pytest.skip("device is not the directly observed RSTP root bridge")
    _require_rstp_isolation(device, skip=True)
    return device, original


def _run_rstp_bridge_cycle(
    device: SwOSDevice,
    *,
    original: RstpInfo,
    update: RstpBridgeUpdate,
    expected_temporary: RstpInfo,
    restore: RstpBridgeUpdate,
) -> None:
    try:
        _require_rstp_isolation(device, skip=False)
        changed = device.set_rstp_bridge(update, expected_current=original)
        assert changed.changed
        assert _rstp_writable_configuration(changed.value) == _rstp_writable_configuration(
            expected_temporary
        )
    finally:
        _restore_rstp_bridge(
            device,
            original=original,
            expected_temporary=expected_temporary,
            restore=restore,
        )


def _require_mirroring_links_down(device: SwOSDevice, *, skip: bool) -> None:
    _require_ethernet_ports_down(device, (4, 5), "mirroring", skip=skip)


def _port_6_vlan_membership(vlans: tuple[VlanInfo, ...]) -> dict[int, VlanMembershipMode]:
    return {
        vlan.vlan_id: vlan.ports[5].mode
        for vlan in vlans
        if vlan.ports[5].mode is not VlanMembershipMode.NOT_MEMBER
    }


def _port_6_forwarding_relationships(info: ForwardingInfo) -> tuple[object, ...]:
    port_6 = next(port for port in info.ports if port.number == 6)
    return (
        port_6,
        tuple((port.number, 6 in port.destination_port_numbers) for port in info.ports),
        info.mirror_target_port == 6,
    )


def _assert_port_6_forwarding_unchanged(
    original: ForwardingInfo, temporary: ForwardingInfo
) -> None:
    assert _port_6_forwarding_relationships(temporary) == _port_6_forwarding_relationships(original)


def _temporary_bridge_priority(priority: int) -> int:
    if priority == 0x8000:
        return 0x9000
    return priority + 0x1000 if priority < 0xF000 else priority - 0x1000


def test_high_risk_cleanup_state_accepts_only_exact_original_or_temporary() -> None:
    assert (
        _cleanup_state("before", original="before", temporary="during", label="table") == "original"
    )
    assert (
        _cleanup_state("during", original="before", temporary="during", label="table")
        == "temporary"
    )
    with pytest.raises(AssertionError, match=r"neither the exact original.*refusing cleanup"):
        _cleanup_state("other", original="before", temporary="during", label="table")

    assert (
        _staged_cleanup_state(
            "first", original="before", temporaries=("first", "second"), label="table"
        )
        == "temporary"
    )
    with pytest.raises(AssertionError, match=r"nor an expected temporary.*refusing cleanup"):
        _staged_cleanup_state(
            "other", original="before", temporaries=("first", "second"), label="table"
        )


@pytest.mark.parametrize(
    ("priority", "temporary"),
    [(0x8000, 0x9000), (0x7000, 0x8000), (0xF000, 0xE000)],
)
def test_temporary_bridge_priority_uses_one_safe_step(priority: int, temporary: int) -> None:
    assert _temporary_bridge_priority(priority) == temporary


class _LinkState:
    def __init__(self, number: int, link_up: bool) -> None:
        self.number = number
        self.link_up = link_up


class _TopologyDevice:
    def __init__(self, up_ports: tuple[int, ...]) -> None:
        self.up_ports = up_ports

    def get_ports(self) -> tuple[_LinkState, ...]:
        return tuple(_LinkState(number, number in self.up_ports) for number in range(1, 7))


def test_rstp_isolation_requires_only_explicit_management_port_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SWOS_INTEGRATION_MANAGEMENT_PORT", "6")
    isolated = _TopologyDevice((6,))

    _require_rstp_isolation(isolated, skip=False)  # type: ignore[arg-type]

    with pytest.raises(AssertionError, match="Ethernet ports 1-5 down"):
        _require_rstp_isolation(_TopologyDevice((1, 6)), skip=False)  # type: ignore[arg-type]
    with pytest.raises(AssertionError, match="management port 6 up"):
        _require_rstp_isolation(_TopologyDevice(()), skip=False)  # type: ignore[arg-type]
    monkeypatch.delenv("SWOS_INTEGRATION_MANAGEMENT_PORT")
    with pytest.raises(AssertionError, match="MANAGEMENT_PORT=6"):
        _require_rstp_isolation(isolated, skip=False)  # type: ignore[arg-type]


def test_mirroring_link_gate_requires_ports_4_and_5_down() -> None:
    _require_mirroring_links_down(_TopologyDevice((6,)), skip=False)  # type: ignore[arg-type]

    with pytest.raises(AssertionError, match="4,5"):
        _require_mirroring_links_down(_TopologyDevice((4, 5, 6)), skip=False)  # type: ignore[arg-type]


def _integration_connection() -> DeviceConnection:
    return DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )


def _directly_connected_allow_from(current_ip: str | None) -> str | None:
    try:
        device_address = IPv4Address(current_ip) if current_ip is not None else None
    except ValueError:
        return None
    required_network = IPv4Network("192.168.88.0/24")
    if device_address is None or device_address not in required_network:
        return None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_socket:
            route_socket.connect((str(device_address), 9))
            source_address = IPv4Address(route_socket.getsockname()[0])
    except (OSError, ValueError):
        return None
    source_network = IPv4Network(f"{source_address}/24", strict=False)
    if source_address not in required_network or device_address not in source_network:
        return None
    return str(source_network.network_address)


def _port6_accepts_untagged_vlan_one(port6: PortVlanInfo) -> bool:
    return (
        port6.number == 6
        and port6.default_vlan_id == 1
        and port6.receive is not VlanReceiveMode.TAGGED_ONLY
    )


def _port6_has_proven_untagged_vlan_one_egress(
    port6: PortVlanInfo,
    vlans: tuple[VlanInfo, ...],
) -> bool:
    if port6.egress is not VlanEgressMode.STRIP:
        return False
    vlan1 = next((vlan for vlan in vlans if vlan.vlan_id == 1), None)
    if vlan1 is None:
        return False
    membership = next((port for port in vlan1.ports if port.port_number == 6), None)
    return membership is not None and membership.mode is VlanMembershipMode.STRIP


def _management_vlan_gate_allows(
    port6: PortVlanInfo,
    vlans: tuple[VlanInfo, ...],
    *,
    risk_acknowledged: bool,
) -> bool:
    return _port6_accepts_untagged_vlan_one(port6) and (
        risk_acknowledged or _port6_has_proven_untagged_vlan_one_egress(port6, vlans)
    )


def _management_vlan_risk_acknowledged() -> bool:
    return os.environ.get("SWOS_INTEGRATION_MANAGEMENT_VLAN_RISK_ACKNOWLEDGED") == "1"


def test_allow_from_route_uses_connected_udp_socket(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[object, ...]] = []

    class RouteSocket:
        connected = False

        def __enter__(self) -> "RouteSocket":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def connect(self, address: tuple[str, int]) -> None:
            calls.append(("connect", address))
            self.connected = True

        def getsockname(self) -> tuple[str, int]:
            assert self.connected
            calls.append(("getsockname",))
            return ("192.168.88.42", 49152)

    def open_socket(family: int, kind: int) -> RouteSocket:
        calls.append(("socket", family, kind))
        return RouteSocket()

    monkeypatch.setattr(socket, "socket", open_socket)

    assert _directly_connected_allow_from("192.168.88.1") == "192.168.88.0"
    assert calls == [
        ("socket", socket.AF_INET, socket.SOCK_DGRAM),
        ("connect", ("192.168.88.1", 9)),
        ("getsockname",),
    ]


def test_allow_from_route_rejects_other_device_or_source_subnets(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    calls = 0

    class RouteSocket:
        def __enter__(self) -> "RouteSocket":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def connect(self, address: tuple[str, int]) -> None:
            del address

        def getsockname(self) -> tuple[str, int]:
            return ("192.168.89.42", 49152)

    def open_socket(family: int, kind: int) -> RouteSocket:
        nonlocal calls
        del family, kind
        calls += 1
        return RouteSocket()

    monkeypatch.setattr(socket, "socket", open_socket)

    assert _directly_connected_allow_from("192.168.89.1") is None
    assert calls == 0
    assert _directly_connected_allow_from("192.168.88.1") is None
    assert calls == 1


def test_management_vlan_gate_requires_ingress_and_gates_uncertain_egress() -> None:
    port6 = PortVlanInfo(
        number=6,
        mode=VlanMode.OPTIONAL,
        receive=VlanReceiveMode.ANY,
        default_vlan_id=1,
        force_vlan_id=False,
        egress=VlanEgressMode.STRIP,
    )
    vlan1 = VlanInfo(
        vlan_id=1,
        independent_learning=False,
        igmp_snooping=False,
        ports=(VlanPortMembership(port_number=6, mode=VlanMembershipMode.STRIP),),
    )

    assert _management_vlan_gate_allows(port6, (vlan1,), risk_acknowledged=False)
    uncertain_egress = port6.model_copy(update={"egress": VlanEgressMode.PRESERVE})
    assert not _management_vlan_gate_allows(uncertain_egress, (vlan1,), risk_acknowledged=False)
    assert _management_vlan_gate_allows(uncertain_egress, (vlan1,), risk_acknowledged=True)
    assert not _management_vlan_gate_allows(port6, (), risk_acknowledged=False)
    assert _management_vlan_gate_allows(port6, (), risk_acknowledged=True)
    assert not _management_vlan_gate_allows(
        port6.model_copy(update={"receive": VlanReceiveMode.TAGGED_ONLY}),
        (vlan1,),
        risk_acknowledged=True,
    )
    assert not _management_vlan_gate_allows(
        port6.model_copy(update={"default_vlan_id": 2}),
        (vlan1,),
        risk_acknowledged=True,
    )
    assert not _management_vlan_gate_allows(
        port6,
        (
            vlan1.model_copy(
                update={
                    "ports": (VlanPortMembership(port_number=6, mode=VlanMembershipMode.PRESERVE),)
                }
            ),
        ),
        risk_acknowledged=False,
    )


def test_management_vlan_risk_acknowledgement_requires_exact_one(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    variable = "SWOS_INTEGRATION_MANAGEMENT_VLAN_RISK_ACKNOWLEDGED"
    monkeypatch.delenv(variable, raising=False)
    assert not _management_vlan_risk_acknowledged()
    monkeypatch.setenv(variable, "true")
    assert not _management_vlan_risk_acknowledged()
    monkeypatch.setenv(variable, "1")
    assert _management_vlan_risk_acknowledged()


def _connection_at(connection: DeviceConnection, url: str) -> DeviceConnection:
    return DeviceConnection(
        url=url,
        username=connection.username,
        password=connection.password,
        timeout=connection.timeout,
        verify_tls=connection.verify_tls,
    )


def _url_with_host(url: str, host: str) -> str:
    parsed = urlsplit(url)
    bracketed_host = f"[{host}]" if ":" in host else host
    netloc = bracketed_host if parsed.port is None else f"{bracketed_host}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def _tcp_endpoint_responds(url: str, *, timeout: float) -> bool:
    parsed = urlsplit(url)
    if parsed.hostname is None:
        raise ValueError("temporary URL has no host")
    port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    try:
        with create_connection((parsed.hostname, port), timeout=min(timeout, 2.0)):
            return True
    except OSError:
        return False


def test_temporary_ip_occupancy_check_uses_only_tcp(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[tuple[str, int], float]] = []

    class OpenSocket:
        def __enter__(self) -> "OpenSocket":
            return self

        def __exit__(self, *args: object) -> None:
            pass

    def connect(address: tuple[str, int], timeout: float) -> OpenSocket:
        calls.append((address, timeout))
        return OpenSocket()

    monkeypatch.setattr(sys.modules[__name__], "create_connection", connect)

    assert _tcp_endpoint_responds("https://192.0.2.10/", timeout=10.0)
    assert calls == [(("192.0.2.10", 443), 2.0)]


def test_temporary_ip_occupancy_check_accepts_only_connection_refusal(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    def refuse(address: tuple[str, int], timeout: float) -> None:
        del address, timeout
        raise ConnectionRefusedError

    monkeypatch.setattr(sys.modules[__name__], "create_connection", refuse)

    assert not _tcp_endpoint_responds("http://192.0.2.10:8080/", timeout=1.0)


def _restore_management_reconnect(
    registry: PluginRegistry,
    *,
    identity: DeviceIdentity,
    original_connection: DeviceConnection,
    temporary_url: str,
    original: SystemInfo,
    expected_temporary: SystemInfo,
    update: SystemConfigurationUpdate,
) -> None:
    observations: list[tuple[str, SwOSDevice | None, SystemInfo | None]] = []
    candidate_urls = dict.fromkeys((str(original_connection.url), temporary_url))
    for url in candidate_urls:
        connection = _connection_at(original_connection, url)
        try:
            detected = registry.probe(connection)
        except (AuthenticationError, HttpStatusError, ProtocolError, DeviceDetectionError):
            observations.append(("unknown", None, None))
            continue
        except TransportError:
            observations.append(("unreachable", None, None))
            continue
        except SwOSError:
            observations.append(("unknown", None, None))
            continue
        if detected != identity:
            observations.append(("conflict", None, None))
            continue
        try:
            candidate = registry.connect(detected, connection, FirmwareSafetyPolicy())
            info = candidate.get_system_info()
        except (AuthenticationError, HttpStatusError, ProtocolError, DeviceDetectionError):
            observations.append(("unknown", None, None))
            continue
        except TransportError:
            observations.append(("unreachable", None, None))
            continue
        except SwOSError:
            observations.append(("unknown", None, None))
            continue
        if info.serial_number != original.serial_number or info.mac_address != original.mac_address:
            observations.append(("conflict", candidate, info))
            continue
        if _system_configuration(info) == _system_configuration(original):
            observations.append(("original", candidate, info))
        elif _system_configuration(info) == _system_configuration(expected_temporary):
            observations.append(("temporary", candidate, info))
        else:
            observations.append(("unknown", candidate, info))

    observed_states = {state for state, _, _ in observations if state != "unreachable"}
    if not observed_states:
        raise ManagementStateUncertainError(
            "Neither the original nor temporary management URL reaches the exact expected device; "
            "no cleanup write was attempted and a manual reset is required."
        )
    if "unknown" in observed_states:
        raise ManagementStateUncertainError(
            "A management URL returned an unknown device or configuration; no cleanup write was "
            "attempted and a manual reset is required."
        )
    if "conflict" in observed_states:
        raise AssertionError("A management URL returned a conflicting device; refusing cleanup")
    if observed_states == {"original"}:
        return
    if observed_states != {"temporary"}:
        raise AssertionError(
            "Management URLs returned conflicting original and temporary states; refusing cleanup"
        )

    _, candidate, current = next(
        observation for observation in observations if observation[0] == "temporary"
    )
    assert candidate is not None and current is not None
    restored = candidate.set_system_configuration(
        update,
        expected_current=current,
        readback_url=str(original_connection.url),
    )
    assert _system_configuration(restored.value) == _system_configuration(original)
    assert restored.value.serial_number == original.serial_number
    assert restored.value.mac_address == original.mac_address


def _toggle_port(ports: tuple[int, ...], port_number: int) -> tuple[int, ...]:
    if port_number in ports:
        return tuple(number for number in ports if number != port_number)
    return tuple(sorted((*ports, port_number)))


def _system_configuration(info: SystemInfo) -> tuple[object, ...]:
    management = info.management
    igmp = info.igmp
    return (
        info.name,
        info.static_ip,
        None if management is None else management.address_mode,
        None if management is None else management.admin_mac_address,
        None if management is None else management.allow_from,
        None if management is None else management.allow_prefix_length,
        None if management is None else management.allowed_port_numbers,
        None if management is None else management.allowed_vlan_id,
        info.independent_vlan_lookup,
        None if igmp is None else igmp.enabled,
        None if igmp is None else igmp.querier_configured,
        None if igmp is None else igmp.fast_leave_port_numbers,
        None if igmp is None else igmp.version,
        info.discovery_protocol_port_numbers,
    )


def _restore_system_configuration(
    device: SwOSDevice,
    *,
    original: SystemInfo,
    expected_temporary: SystemInfo,
    update: SystemConfigurationUpdate,
    assert_management_warning: bool = False,
) -> None:
    current = device.get_system_info()
    if _system_configuration(current) == _system_configuration(original):
        return
    if _system_configuration(current) != _system_configuration(expected_temporary):
        raise AssertionError(
            "System configuration is neither the original nor expected temporary state; "
            "refusing cleanup"
        )

    restored = device.set_system_configuration(update, expected_current=expected_temporary)
    assert _system_configuration(restored.value) == _system_configuration(original)
    assert _system_configuration(device.get_system_info()) == _system_configuration(original)
    if assert_management_warning:
        assert original.management is not None
        assert expected_temporary.management is not None
        _assert_management_allowed_ports_warning(
            restored,
            before=expected_temporary.management.allowed_port_numbers,
            after=original.management.allowed_port_numbers,
        )


def _assert_management_allowed_ports_warning(
    result: OperationResult[SystemInfo],
    *,
    before: tuple[int, ...],
    after: tuple[int, ...],
) -> None:
    warnings = tuple(
        warning for warning in result.warnings if warning.code == "management_lockout_risk"
    )
    assert len(warnings) == 1
    before_ports = ",".join(str(number) for number in before)
    after_ports = ",".join(str(number) for number in after)
    assert f"allowed ports {before_ports} -> {after_ports}" in warnings[0].message
    assert "outcome uncertain" in warnings[0].message


@pytest.mark.integration
@pytest.mark.destructive
def test_rb260gs_219_port_5_vlan_egress_write_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    port_number = 5
    if device.get_ports()[port_number - 1].link_up:
        pytest.skip("port 5 is link-up; refusing destructive VLAN policy test")
    original = device.get_port_vlans()
    original_egress = original[port_number - 1].egress
    temporary_egress = (
        VlanEgressMode.STRIP
        if original_egress is not VlanEgressMode.STRIP
        else VlanEgressMode.PRESERVE
    )
    expected_temporary = tuple(
        port.model_copy(update={"egress": temporary_egress}) if port.number == port_number else port
        for port in original
    )

    try:
        changed = device.set_port_vlan_policy(
            PortVlanPolicyUpdate(number=port_number, egress=temporary_egress),
            expected_current=original,
        )
        assert changed.changed
        assert changed.value == expected_temporary
    finally:
        _restore_port_vlan_policy(
            device,
            original=original,
            expected_temporary=expected_temporary,
            port_number=port_number,
        )


def _restore_port_vlan_policy(
    device: SwOSDevice,
    *,
    original: tuple[PortVlanInfo, ...],
    expected_temporary: tuple[PortVlanInfo, ...],
    port_number: int,
) -> None:
    current = device.get_port_vlans()
    if current == original:
        return
    if current != expected_temporary:
        raise AssertionError(
            "Port VLAN policy is neither the original nor expected temporary state; "
            "refusing cleanup"
        )

    restored = device.set_port_vlan_policy(
        PortVlanPolicyUpdate(
            number=port_number,
            egress=original[port_number - 1].egress,
        ),
        expected_current=expected_temporary,
    )
    assert restored.value == original
    assert device.get_port_vlans() == original


class _CleanupDevice:
    def __init__(
        self,
        current: tuple[PortVlanInfo, ...],
        original: tuple[PortVlanInfo, ...],
    ) -> None:
        self.current = current
        self.original = original
        self.writes: list[tuple[PortVlanPolicyUpdate, tuple[PortVlanInfo, ...]]] = []

    def get_port_vlans(self) -> tuple[PortVlanInfo, ...]:
        return self.current

    def set_port_vlan_policy(
        self,
        update: PortVlanPolicyUpdate,
        *,
        expected_current: tuple[PortVlanInfo, ...],
    ) -> OperationResult[tuple[PortVlanInfo, ...]]:
        assert self.current == expected_current
        self.writes.append((update, expected_current))
        self.current = self.original
        return OperationResult(changed=True, value=self.original)


def _cleanup_states() -> tuple[tuple[PortVlanInfo, ...], tuple[PortVlanInfo, ...]]:
    original = tuple(
        PortVlanInfo(
            number=number,
            mode="optional",
            receive="any",
            default_vlan_id=1,
            force_vlan_id=False,
            egress="preserve",
        )
        for number in range(1, 7)
    )
    temporary = tuple(
        port.model_copy(update={"egress": VlanEgressMode.STRIP}) if port.number == 5 else port
        for port in original
    )
    return original, temporary


def test_vlan_cleanup_restores_only_exact_temporary_state() -> None:
    original, temporary = _cleanup_states()
    device = _CleanupDevice(temporary, original)

    _restore_port_vlan_policy(  # type: ignore[arg-type]
        device,
        original=original,
        expected_temporary=temporary,
        port_number=5,
    )

    assert device.current == original
    assert device.writes == [
        (
            PortVlanPolicyUpdate(number=5, egress=VlanEgressMode.PRESERVE),
            temporary,
        )
    ]


def test_vlan_cleanup_accepts_already_restored_state_without_write() -> None:
    original, temporary = _cleanup_states()
    device = _CleanupDevice(original, original)

    _restore_port_vlan_policy(  # type: ignore[arg-type]
        device,
        original=original,
        expected_temporary=temporary,
        port_number=5,
    )

    assert device.writes == []


def test_vlan_cleanup_refuses_unknown_state_without_write() -> None:
    original, temporary = _cleanup_states()
    unknown = list(temporary)
    unknown[0] = unknown[0].model_copy(update={"default_vlan_id": 2})
    device = _CleanupDevice(tuple(unknown), original)

    with pytest.raises(AssertionError, match="refusing cleanup"):
        _restore_port_vlan_policy(  # type: ignore[arg-type]
            device,
            original=original,
            expected_temporary=temporary,
            port_number=5,
        )

    assert device.writes == []


class _SystemCleanupDevice:
    def __init__(self, current: SystemInfo, original: SystemInfo) -> None:
        self.current = current
        self.original = original
        self.writes: list[tuple[SystemConfigurationUpdate, SystemInfo]] = []

    def get_system_info(self) -> SystemInfo:
        return self.current

    def set_system_configuration(
        self,
        update: SystemConfigurationUpdate,
        *,
        expected_current: SystemInfo,
        readback_url: str | None = None,
    ) -> OperationResult[SystemInfo]:
        del readback_url
        assert _system_configuration(self.current) == _system_configuration(expected_current)
        self.writes.append((update, expected_current))
        self.current = self.original
        return OperationResult(changed=True, value=self.original)


def _system_cleanup_states() -> tuple[SystemInfo, SystemInfo]:
    original = SystemInfo(
        identity=DeviceIdentity(
            product_code="CSS106-5G-1S",
            firmware_family="css106",
            firmware_version="2.19",
        ),
        name="test",
        uptime_seconds=1,
        management=SystemManagementInfo(
            address_mode="dhcp_with_fallback",
            allow_prefix_length=0,
            allowed_port_numbers=(1, 6),
            watchdog_enabled=True,
        ),
        independent_vlan_lookup=False,
        igmp=IgmpInfo(
            enabled=True,
            querier_configured=False,
            querier_effective=False,
            fast_leave_port_numbers=(),
            version="v2",
        ),
        discovery_protocol_port_numbers=(1, 6),
    )
    temporary = original.model_copy(update={"discovery_protocol_port_numbers": (1, 5, 6)})
    return original, temporary


def test_system_cleanup_restores_only_exact_temporary_configuration() -> None:
    original, temporary = _system_cleanup_states()
    device = _SystemCleanupDevice(temporary, original)
    update = SystemConfigurationUpdate(
        discovery_protocol_port_numbers=original.discovery_protocol_port_numbers
    )

    _restore_system_configuration(  # type: ignore[arg-type]
        device,
        original=original,
        expected_temporary=temporary,
        update=update,
    )

    assert device.current == original
    assert device.writes == [(update, temporary)]


def test_system_cleanup_accepts_already_restored_configuration_without_write() -> None:
    original, temporary = _system_cleanup_states()
    device = _SystemCleanupDevice(original, original)

    _restore_system_configuration(  # type: ignore[arg-type]
        device,
        original=original,
        expected_temporary=temporary,
        update=SystemConfigurationUpdate(
            discovery_protocol_port_numbers=original.discovery_protocol_port_numbers
        ),
    )

    assert device.writes == []


def test_system_cleanup_refuses_unknown_configuration_without_write() -> None:
    original, temporary = _system_cleanup_states()
    unknown = temporary.model_copy(update={"independent_vlan_lookup": True})
    device = _SystemCleanupDevice(unknown, original)

    with pytest.raises(AssertionError, match="refusing cleanup"):
        _restore_system_configuration(  # type: ignore[arg-type]
            device,
            original=original,
            expected_temporary=temporary,
            update=SystemConfigurationUpdate(
                discovery_protocol_port_numbers=original.discovery_protocol_port_numbers
            ),
        )

    assert device.writes == []


class _ReconnectCleanupDevice:
    def __init__(self, current: SystemInfo, restored: SystemInfo) -> None:
        self.current = current
        self.restored = restored
        self.writes: list[tuple[SystemConfigurationUpdate, SystemInfo, str | None]] = []

    def get_system_info(self) -> SystemInfo:
        return self.current

    def set_system_configuration(
        self,
        update: SystemConfigurationUpdate,
        *,
        expected_current: SystemInfo,
        readback_url: str | None = None,
    ) -> OperationResult[SystemInfo]:
        self.writes.append((update, expected_current, readback_url))
        self.current = self.restored
        return OperationResult(changed=True, value=self.restored)


class _ReconnectCleanupRegistry:
    def __init__(
        self,
        identity: DeviceIdentity,
        devices: dict[str, _ReconnectCleanupDevice],
    ) -> None:
        self.identity = identity
        self.devices = devices

    def probe(self, connection: DeviceConnection) -> DeviceIdentity:
        if str(connection.url) not in self.devices:
            raise TransportError("unreachable")
        return self.identity

    def connect(
        self,
        identity: DeviceIdentity,
        connection: DeviceConnection,
        policy: FirmwareSafetyPolicy,
    ) -> _ReconnectCleanupDevice:
        del identity, policy
        return self.devices[str(connection.url)]


def test_management_reconnect_cleanup_restores_only_exact_temporary_state() -> None:
    original, temporary = _system_cleanup_states()
    connection = DeviceConnection(url="http://192.0.2.1")
    temporary_url = "http://192.0.2.2/"
    device = _ReconnectCleanupDevice(temporary, original)
    registry = _ReconnectCleanupRegistry(original.identity, {temporary_url: device})
    update = SystemConfigurationUpdate(
        discovery_protocol_port_numbers=original.discovery_protocol_port_numbers
    )

    _restore_management_reconnect(  # type: ignore[arg-type]
        registry,
        identity=original.identity,
        original_connection=connection,
        temporary_url=temporary_url,
        original=original,
        expected_temporary=temporary,
        update=update,
    )

    assert device.writes == [(update, temporary, "http://192.0.2.1/")]


def test_management_reconnect_cleanup_requires_reset_for_unknown_state_without_write() -> None:
    original, temporary = _system_cleanup_states()
    unknown = temporary.model_copy(update={"name": "unexpected"})
    connection = DeviceConnection(url="http://192.0.2.1")
    device = _ReconnectCleanupDevice(unknown, original)
    registry = _ReconnectCleanupRegistry(original.identity, {str(connection.url): device})

    with pytest.raises(ManagementStateUncertainError, match="manual reset is required"):
        _restore_management_reconnect(  # type: ignore[arg-type]
            registry,
            identity=original.identity,
            original_connection=connection,
            temporary_url="http://192.0.2.2/",
            original=original,
            expected_temporary=temporary,
            update=SystemConfigurationUpdate(name=original.name),
        )

    assert device.writes == []


def test_management_reconnect_cleanup_refuses_conflicting_observations_without_write() -> None:
    original, temporary = _system_cleanup_states()
    connection = DeviceConnection(url="http://192.0.2.1")
    temporary_url = "http://192.0.2.2/"
    original_device = _ReconnectCleanupDevice(original, original)
    temporary_device = _ReconnectCleanupDevice(temporary, original)
    registry = _ReconnectCleanupRegistry(
        original.identity,
        {
            str(connection.url): original_device,
            temporary_url: temporary_device,
        },
    )

    with pytest.raises(AssertionError, match=r"conflicting.*refusing cleanup"):
        _restore_management_reconnect(  # type: ignore[arg-type]
            registry,
            identity=original.identity,
            original_connection=connection,
            temporary_url=temporary_url,
            original=original,
            expected_temporary=temporary,
            update=SystemConfigurationUpdate(name=original.name),
        )

    assert original_device.writes == []
    assert temporary_device.writes == []


def test_management_reconnect_cleanup_requires_reset_when_neither_url_responds() -> None:
    original, temporary = _system_cleanup_states()
    connection = DeviceConnection(url="http://192.0.2.1")
    registry = _ReconnectCleanupRegistry(original.identity, {})

    with pytest.raises(ManagementStateUncertainError, match="manual reset is required"):
        _restore_management_reconnect(  # type: ignore[arg-type]
            registry,
            identity=original.identity,
            original_connection=connection,
            temporary_url="http://192.0.2.2/",
            original=original,
            expected_temporary=temporary,
            update=SystemConfigurationUpdate(name=original.name),
        )
