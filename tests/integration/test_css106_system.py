import os
import time

import pytest
from swos_core import DeviceConnection, PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy


@pytest.mark.integration
def test_rb260gs_219_system_information() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()

    identity = registry.probe(connection)
    device = registry.connect(identity, connection, FirmwareSafetyPolicy())
    info = device.get_system_info()

    assert identity.product_code == "CSS106-5G-1S"
    assert identity.marketing_name == "RB260GS"
    assert identity.firmware_version == "2.19"
    assert identity.build_id == "0x6a181cd5"
    assert info.identity == identity
    assert info.name
    assert info.uptime_seconds > 0
    assert info.current_ip is not None
    assert info.mac_address is not None
    assert info.serial_number is not None

    time.sleep(1.1)
    later_info = device.get_system_info()
    assert 1 <= later_info.uptime_seconds - info.uptime_seconds <= 3
