import os

import pytest
from swos_core import DeviceConnection, PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy


@pytest.mark.integration
def test_rb260gs_219_cumulative_port_statistics() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)

    statistics = registry.connect(
        identity,
        connection,
        FirmwareSafetyPolicy(),
    ).get_port_statistics()

    assert [port.number for port in statistics] == [1, 2, 3, 4, 5, 6]
    for port in statistics:
        assert port.rx_bytes >= 0
        assert port.tx_bytes >= 0
        assert port.rx_packets >= 0
        assert port.tx_packets >= 0
        assert port.rx_errors >= 0
        assert port.tx_errors >= 0
