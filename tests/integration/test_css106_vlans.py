import os

import pytest
from swos_core import DeviceConnection, PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy


@pytest.mark.integration
def test_rb260gs_219_vlan_configuration() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())

    ports = device.get_port_vlans()
    vlans = device.get_vlans()

    assert [port.number for port in ports] == [1, 2, 3, 4, 5, 6]
    assert all(1 <= port.default_vlan_id <= 4095 for port in ports)
    assert len({vlan.vlan_id for vlan in vlans}) == len(vlans)
    for vlan in vlans:
        assert [port.port_number for port in vlan.ports] == [1, 2, 3, 4, 5, 6]
