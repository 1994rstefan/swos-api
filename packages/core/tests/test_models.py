import pytest
from pydantic import ValidationError
from swos_core.models import DeviceCapabilities, DeviceConnection, DeviceIdentity, PortInfo


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
