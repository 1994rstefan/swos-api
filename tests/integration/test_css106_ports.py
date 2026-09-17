import os

import pytest
from swos_core import DeviceConnection, PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy


@pytest.mark.integration
def test_rb260gs_219_port_state() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)

    ports = registry.connect(identity, connection, FirmwareSafetyPolicy()).get_ports()

    assert [port.number for port in ports] == [1, 2, 3, 4, 5, 6]
    assert all(isinstance(port.name, str) for port in ports)
    for port in ports:
        assert port.configured_speed_bps in {10_000_000, 100_000_000}
        assert port.poe_mode is None
        if port.link_up:
            assert port.speed_bps in {10_000_000, 100_000_000, 1_000_000_000}
            assert port.full_duplex is not None
        else:
            assert port.speed_bps is None
            assert port.full_duplex is None
