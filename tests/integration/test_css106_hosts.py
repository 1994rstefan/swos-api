import os

import pytest
from swos_core import DeviceConnection, PluginRegistry
from swos_core.models import HostEntryType
from swos_core.safety import FirmwareSafetyPolicy


@pytest.mark.integration
def test_rb260gs_219_host_table() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)

    hosts = registry.connect(identity, connection, FirmwareSafetyPolicy()).get_hosts()

    assert any(host.entry_type is HostEntryType.DYNAMIC for host in hosts)
    for host in hosts:
        assert host.port_numbers == tuple(sorted(set(host.port_numbers)))
        if host.entry_type is HostEntryType.DYNAMIC:
            assert len(host.port_numbers) == 1
            assert not host.drop
            assert not host.mirror
