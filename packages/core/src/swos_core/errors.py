"""Public exception hierarchy for swos-core."""

from __future__ import annotations


class SwOSError(Exception):
    """Base class for errors raised by swos-core."""


class TransportError(SwOSError):
    """A device request failed before a valid response was received."""


class AuthenticationError(TransportError):
    """The SwOS device rejected the supplied credentials."""


class ProtocolError(SwOSError):
    """A device returned a response that could not be decoded safely."""


class UnsupportedFeatureError(SwOSError):
    """The connected device adapter does not expose a requested feature."""

    def __init__(self, feature: str) -> None:
        super().__init__(f"The connected device does not support {feature!r}")
        self.feature = feature


class DevicePluginError(SwOSError):
    """A device plugin could not be loaded or selected."""


class DeviceDetectionError(DevicePluginError):
    """No installed plugin recognized the connected device."""


class DuplicateDevicePluginError(DevicePluginError):
    """More than one plugin registered the same firmware family."""


class MissingDevicePluginError(DevicePluginError):
    """No installed plugin handles a detected firmware family."""

    def __init__(self, firmware_family: str) -> None:
        package = f"swos-device-{firmware_family.lower()}"
        super().__init__(
            f"No plugin is installed for firmware family {firmware_family!r}. Install {package!r}."
        )
        self.firmware_family = firmware_family
        self.suggested_package = package


class UnsupportedFirmwareError(DevicePluginError):
    """The model and firmware combination has not been declared supported."""

    def __init__(self, product_code: str, firmware_version: str, operation: str) -> None:
        super().__init__(
            f"{product_code} with SwOS {firmware_version} is not supported for {operation}"
        )
        self.product_code = product_code
        self.firmware_version = firmware_version
        self.operation = operation
