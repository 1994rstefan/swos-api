import pytest
from swos_core.errors import UnsupportedFirmwareError
from swos_core.models import DeviceIdentity
from swos_core.safety import FirmwareSafetyPolicy, enforce_firmware_policy


@pytest.fixture
def identity() -> DeviceIdentity:
    return DeviceIdentity(
        firmware_family="css106",
        product_code="CSS106-5G-1S",
        firmware_version="2.20",
    )


def test_supported_firmware_needs_no_override(identity: DeviceIdentity) -> None:
    warnings = enforce_firmware_policy(
        identity,
        FirmwareSafetyPolicy(),
        supported=True,
        write=True,
    )

    assert warnings == ()


def test_untested_firmware_is_rejected_by_default(identity: DeviceIdentity) -> None:
    with pytest.raises(UnsupportedFirmwareError):
        enforce_firmware_policy(
            identity,
            FirmwareSafetyPolicy(),
            supported=False,
            write=False,
        )


def test_read_override_does_not_allow_writes(identity: DeviceIdentity) -> None:
    policy = FirmwareSafetyPolicy(allow_untested_firmware=True)

    assert enforce_firmware_policy(identity, policy, supported=False, write=False)[0].code == (
        "untested_firmware"
    )
    with pytest.raises(UnsupportedFirmwareError):
        enforce_firmware_policy(identity, policy, supported=False, write=True)


def test_write_override_implies_read_override(identity: DeviceIdentity) -> None:
    policy = FirmwareSafetyPolicy(allow_untested_firmware_writes=True)

    assert enforce_firmware_policy(identity, policy, supported=False, write=False)
    assert enforce_firmware_policy(identity, policy, supported=False, write=True)[0].code == (
        "untested_firmware_write"
    )
