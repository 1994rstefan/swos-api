import os

import pytest
from swos_core import (
    DeviceConnection,
    DeviceNameUpdate,
    PluginRegistry,
    PortNameUpdate,
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
    port_number = int(os.environ.get("SWOS_INTEGRATION_WRITE_PORT", "1"))
    original_name = device.get_ports()[port_number - 1].name
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
