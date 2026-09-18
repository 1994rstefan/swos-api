import os

import pytest
from pydantic import SecretStr
from swos_core import DeviceConnection, PasswordUpdate, PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy

TEMPORARY_ADMIN_PASSWORD = "SwOS-rotate-298"
RESET_REQUIRED = "Administrator credential state is unknown; manual device reset required"


@pytest.mark.integration
@pytest.mark.destructive
@pytest.mark.password_rotation
def test_rb260gs_219_admin_password_rotation_and_restore() -> None:
    connection = DeviceConnection(
        url=os.environ.get("SWOS_INTEGRATION_URL", "http://192.168.88.1"),
        username=os.environ.get("SWOS_INTEGRATION_USERNAME", "admin"),
        password=os.environ.get("SWOS_INTEGRATION_PASSWORD", ""),
    )
    original_password = connection.password
    original_value = original_password.get_secret_value()
    javascript_length = len(original_value.encode("utf-16-le", errors="surrogatepass")) // 2
    if javascript_length > 15:
        pytest.skip("configured password exceeds the CSS106 JavaScript length limit")
    if original_value == TEMPORARY_ADMIN_PASSWORD:
        pytest.skip("configured password must differ from the fixed temporary password")
    del original_value

    temporary_connection = connection.model_copy(
        update={"password": SecretStr(TEMPORARY_ADMIN_PASSWORD)}
    )
    registry = PluginRegistry.discover()
    policy = FirmwareSafetyPolicy()
    identity = registry.probe(connection)
    assert identity.product_code == "CSS106-5G-1S"
    assert identity.marketing_name == "RB260GS"
    assert identity.firmware_version == "2.19"
    assert identity.build_id == "0x6a181cd5"
    device = registry.connect(identity, connection, policy)
    before = device.get_system_info()

    try:
        rotated = device.set_admin_password(
            PasswordUpdate(new_password=SecretStr(TEMPORARY_ADMIN_PASSWORD))
        )
        assert rotated.changed
        assert any(
            warning.code == "administrator_credentials_changed" for warning in rotated.warnings
        )
        assert rotated.value.identity == identity
        assert rotated.value.name == before.name
        assert rotated.value.mac_address == before.mac_address
        assert rotated.value.serial_number == before.serial_number

        same_device_read = device.get_system_info()
        assert same_device_read.identity == identity
        assert same_device_read.name == before.name
        assert same_device_read.mac_address == before.mac_address
        assert same_device_read.serial_number == before.serial_number

        restored = device.set_admin_password(PasswordUpdate(new_password=original_password))
        assert restored.changed
        assert any(
            warning.code == "administrator_credentials_changed" for warning in restored.warnings
        )
        assert restored.value.identity == identity

        fresh_identity = registry.probe(connection)
        assert fresh_identity == identity
        fresh_device = registry.connect(fresh_identity, connection, policy)
        fresh_read = fresh_device.get_system_info()
        assert fresh_read.identity == identity
        assert fresh_read.name == before.name
        assert fresh_read.mac_address == before.mac_address
        assert fresh_read.serial_number == before.serial_number
    finally:
        original_works = False
        try:
            cleanup_identity = registry.probe(connection)
            original_works = cleanup_identity == identity
        except Exception:
            pass

        if not original_works:
            temporary_works = False
            try:
                cleanup_identity = registry.probe(temporary_connection)
                temporary_works = cleanup_identity == identity
            except Exception:
                pass

            if not temporary_works:
                raise RuntimeError(RESET_REQUIRED) from None

            recovery_device = registry.connect(cleanup_identity, temporary_connection, policy)
            try:
                recovery_device.set_admin_password(PasswordUpdate(new_password=original_password))
            except Exception:
                pass

            try:
                if registry.probe(connection) != identity:
                    raise RuntimeError(RESET_REQUIRED)
            except Exception:
                raise RuntimeError(RESET_REQUIRED) from None
