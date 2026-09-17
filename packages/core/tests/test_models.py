import pytest
from pydantic import ValidationError
from swos_core.models import (
    DeviceCapabilities,
    DeviceConnection,
    DeviceIdentity,
    PortInfo,
    PortStatistics,
    PortVlanInfo,
    VlanInfo,
    VlanPortMembership,
)


def test_device_identity_is_immutable() -> None:
    identity = DeviceIdentity(
        firmware_family="css106",
        product_code="CSS106-5G-1S",
        firmware_version="2.19",
    )

    try:
        identity.firmware_version = "2.20"  # type: ignore[misc]
    except ValidationError:
        pass
    else:
        raise AssertionError("DeviceIdentity unexpectedly allowed mutation")


def test_connection_hides_password() -> None:
    connection = DeviceConnection(url="http://192.0.2.1", password="top-secret")

    assert "top-secret" not in repr(connection)
    assert connection.password.get_secret_value() == "top-secret"


def test_capability_lookup() -> None:
    capabilities = DeviceCapabilities(features=frozenset({"vlan", "snmp"}))

    assert capabilities.supports("vlan")
    assert not capabilities.supports("poe")


def test_port_operational_state_is_consistent() -> None:
    port = PortInfo(
        number=1,
        name="Port1",
        enabled=True,
        link_up=True,
        speed_mbps=1000,
        full_duplex=True,
        auto_negotiation=True,
        flow_control=True,
    )

    assert port.speed_mbps == 1000
    with pytest.raises(ValidationError, match="link-down"):
        PortInfo(
            number=1,
            name="Port1",
            enabled=True,
            link_up=False,
            speed_mbps=1000,
            full_duplex=True,
            auto_negotiation=True,
            flow_control=True,
        )


def test_port_statistics_reject_negative_counters() -> None:
    with pytest.raises(ValidationError):
        PortStatistics(
            number=1,
            rx_bytes=-1,
            tx_bytes=0,
            rx_packets=0,
            tx_packets=0,
            rx_errors=0,
            tx_errors=0,
        )


def test_vlan_models_validate_values_and_unique_ports() -> None:
    port = PortVlanInfo(
        number=1,
        mode="strict",
        receive="tagged_only",
        default_vlan_id=10,
        force_vlan_id=True,
        egress="preserve",
    )

    assert port.mode.value == "strict"
    with pytest.raises(ValidationError):
        PortVlanInfo(
            number=1,
            mode="strict",
            receive="tagged_only",
            default_vlan_id=4096,
            force_vlan_id=True,
            egress="preserve",
        )

    with pytest.raises(ValidationError, match="duplicate ports"):
        VlanInfo(
            vlan_id=10,
            independent_learning=True,
            igmp_snooping=False,
            ports=(
                VlanPortMembership(port_number=1, mode="strip"),
                VlanPortMembership(port_number=1, mode="not_member"),
            ),
        )
