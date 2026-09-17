import pytest
from swos_core.errors import UnsupportedFirmwareError
from swos_core.models import DeviceConnection, DeviceIdentity
from swos_core.plugins import PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy
from swos_device_css106 import plugin


def test_placeholder_claims_no_supported_firmware() -> None:
    assert plugin.family == "css106"
    assert plugin.distribution_name == "swos-device-css106"
    assert plugin.support_records() == ()


def test_installed_entry_point_is_discoverable() -> None:
    assert "css106" in PluginRegistry.discover().known_families


def test_placeholder_cannot_create_an_adapter() -> None:
    identity = DeviceIdentity(
        firmware_family="css106",
        product_code="CSS106-5G-1S",
        firmware_version="2.19",
    )

    with pytest.raises(UnsupportedFirmwareError):
        plugin.create(
            identity=identity,
            connection=DeviceConnection(url="http://192.0.2.1"),
            policy=FirmwareSafetyPolicy(allow_untested_firmware=True),
            support=None,
        )
