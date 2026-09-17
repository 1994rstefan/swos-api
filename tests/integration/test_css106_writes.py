import os
from typing import Literal

import pytest
from swos_core import (
    DeviceConnection,
    DeviceNameUpdate,
    ForwardingPortPolicyUpdate,
    HostEntry,
    HostEntryType,
    PluginRegistry,
    PortConfigurationUpdate,
    PortNameUpdate,
    RstpPortEnableUpdate,
    SnmpMetadataUpdate,
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
