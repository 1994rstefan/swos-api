import os

import pytest
from swos_core import DeviceConnection, PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy


def _device():  # type: ignore[no-untyped-def]
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    registry = PluginRegistry.discover()
    identity = registry.probe(connection)
    return registry.connect(identity, connection, FirmwareSafetyPolicy())


@pytest.mark.integration
def test_rb260gs_219_sfp_diagnostics() -> None:
    info = _device().get_sfp()

    assert info.supply_voltage_volts is None or info.supply_voltage_volts >= 0
    assert info.tx_bias_ma is None or info.tx_bias_ma >= 0


@pytest.mark.integration
def test_rb260gs_219_forwarding_policy() -> None:
    info = _device().get_forwarding()

    assert [port.number for port in info.ports] == [1, 2, 3, 4, 5, 6]
    assert info.mirror_target_port is None or 1 <= info.mirror_target_port <= 6
    for port in info.ports:
        assert all(1 <= destination <= 6 for destination in port.destination_port_numbers)


@pytest.mark.integration
def test_rb260gs_219_igmp_groups_and_acl_rules() -> None:
    device = _device()

    groups = device.get_igmp_groups()
    rules = device.get_acl_rules()

    assert all(1 <= group.vlan_id <= 4095 for group in groups)
    assert all(group.port_numbers for group in groups)
    assert len(rules) <= 32
    assert [rule.number for rule in rules] == list(range(1, len(rules) + 1))
