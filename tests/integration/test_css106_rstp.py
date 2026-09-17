import os

import pytest
from swos_core import DeviceConnection, PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy


@pytest.mark.integration
def test_rb260gs_219_rstp_state() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)

    info = registry.connect(identity, connection, FirmwareSafetyPolicy()).get_rstp()

    assert [port.number for port in info.ports] == [1, 2, 3, 4, 5, 6]
    assert len(info.root_bridge_mac.split(":")) == 6
