from __future__ import annotations

import pytest
from swos_core.api import DeviceAdapter
from swos_core.errors import (
    DeviceDetectionError,
    DuplicateDevicePluginError,
    MissingDevicePluginError,
    ProtocolError,
    UnsupportedFeatureError,
    UnsupportedFirmwareError,
)
from swos_core.models import (
    DeviceCapabilities,
    DeviceConnection,
    DeviceIdentity,
    PortInfo,
    SystemInfo,
)
from swos_core.plugins import PluginRegistry, SupportRecord
from swos_core.safety import FirmwareSafetyPolicy


class FakePlugin:
    family = "css106"
    distribution_name = "swos-device-css106"

    def support_records(self) -> tuple[SupportRecord, ...]:
        return (
            SupportRecord(
                firmware_family="css106",
                product_code="CSS106-5G-1S",
                firmware_version="2.19",
                marketing_names=("RB260GS",),
            ),
        )

    def probe(self, connection: DeviceConnection) -> DeviceIdentity | None:
        del connection
        return identity()

    def create(
        self,
        *,
        identity: DeviceIdentity,
        connection: DeviceConnection,
        policy: FirmwareSafetyPolicy,
        support: SupportRecord | None,
    ) -> DeviceAdapter:
        del connection, policy, support
        return FakeAdapter(identity)


class FakeAdapter:
    def __init__(self, device_identity: DeviceIdentity) -> None:
        self._identity = device_identity

    @property
    def identity(self) -> DeviceIdentity:
        return self._identity

    @property
    def capabilities(self) -> DeviceCapabilities:
        return DeviceCapabilities(features=frozenset({"ports", "system"}))

    def get_system_info(self) -> SystemInfo:
        return SystemInfo(identity=self.identity, name="test", uptime_seconds=1)

    def get_ports(self) -> tuple[PortInfo, ...]:
        return (
            PortInfo(
                number=1,
                name="Port1",
                enabled=True,
                link_up=True,
                speed_mbps=1000,
                full_duplex=True,
                auto_negotiation=True,
                flow_control=True,
            ),
        )


def identity(version: str = "2.19") -> DeviceIdentity:
    return DeviceIdentity(
        firmware_family="css106",
        product_code="CSS106-5G-1S",
        firmware_version=version,
        marketing_name="RB260GS",
    )


def test_registry_resolves_exact_support() -> None:
    resolution = PluginRegistry([FakePlugin()]).resolve(
        identity(),
        FirmwareSafetyPolicy(),
    )

    assert resolution.distribution_name == "swos-device-css106"
    assert resolution.support is not None
    assert resolution.warnings == ()


def test_registry_probes_and_connects_a_device() -> None:
    registry = PluginRegistry([FakePlugin()])
    connection = DeviceConnection(url="http://192.0.2.1")

    detected = registry.probe(connection)
    device = registry.connect_auto(connection, FirmwareSafetyPolicy())

    assert detected == identity()
    assert device.identity == identity()


def test_registry_rejects_unknown_firmware() -> None:
    with pytest.raises(UnsupportedFirmwareError):
        PluginRegistry([FakePlugin()]).resolve(
            identity("2.20"),
            FirmwareSafetyPolicy(),
        )


def test_registry_allows_explicit_untested_read() -> None:
    resolution = PluginRegistry([FakePlugin()]).resolve(
        identity("2.20"),
        FirmwareSafetyPolicy(allow_untested_firmware=True),
    )

    assert resolution.support is None
    assert resolution.warnings[0].code == "untested_firmware"


def test_policy_bound_device_rechecks_read_permission() -> None:
    registry = PluginRegistry([FakePlugin()])
    device = registry.connect(
        identity("2.20"),
        DeviceConnection(url="http://192.0.2.1"),
        FirmwareSafetyPolicy(allow_untested_firmware=True),
    )

    assert device.get_system_info().name == "test"
    assert device.get_ports()[0].name == "Port1"
    assert device.warnings[0].code == "untested_firmware"
    with pytest.raises(UnsupportedFirmwareError):
        device._authorize(write=True)


def test_policy_bound_device_rejects_unsupported_feature() -> None:
    class SystemOnlyAdapter(FakeAdapter):
        @property
        def capabilities(self) -> DeviceCapabilities:
            return DeviceCapabilities(features=frozenset({"system"}))

    class SystemOnlyPlugin(FakePlugin):
        def create(
            self,
            *,
            identity: DeviceIdentity,
            connection: DeviceConnection,
            policy: FirmwareSafetyPolicy,
            support: SupportRecord | None,
        ) -> DeviceAdapter:
            del connection, policy, support
            return SystemOnlyAdapter(identity)

    device = PluginRegistry([SystemOnlyPlugin()]).connect(
        identity(),
        DeviceConnection(url="http://192.0.2.1"),
        FirmwareSafetyPolicy(),
    )

    with pytest.raises(UnsupportedFeatureError, match="ports"):
        device.get_ports()


def test_registry_reports_missing_plugin() -> None:
    with pytest.raises(MissingDevicePluginError) as error:
        PluginRegistry().resolve(identity(), FirmwareSafetyPolicy())

    assert error.value.suggested_package == "swos-device-css106"


def test_registry_reports_an_unrecognized_device() -> None:
    with pytest.raises(DeviceDetectionError):
        PluginRegistry().probe(DeviceConnection(url="http://192.0.2.1"))


def test_registry_ignores_plugin_protocol_mismatches_during_probe() -> None:
    class NonMatchingPlugin(FakePlugin):
        family = "other"

        def probe(self, connection: DeviceConnection) -> DeviceIdentity | None:
            del connection
            raise ProtocolError("not this protocol")

    detected = PluginRegistry([NonMatchingPlugin(), FakePlugin()]).probe(
        DeviceConnection(url="http://192.0.2.1")
    )

    assert detected == identity()


def test_registry_rejects_duplicate_family() -> None:
    with pytest.raises(DuplicateDevicePluginError):
        PluginRegistry([FakePlugin(), FakePlugin()])


@pytest.mark.parametrize("reported_version", ["2.19.0", "v2.19", "not a version"])
def test_firmware_identifiers_are_matched_exactly(reported_version: str) -> None:
    record = FakePlugin().support_records()[0]

    assert not record.matches(identity(reported_version))


def test_build_id_is_exact_when_declared() -> None:
    record = SupportRecord(
        firmware_family="css106",
        product_code="CSS106-5G-1S",
        firmware_version="2.19",
        build_id="known-build",
    )
    reported = identity().model_copy(update={"build_id": "different-build"})

    assert not record.matches(reported)
