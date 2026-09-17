"""Public exports for the swos-core package."""

from importlib.metadata import PackageNotFoundError, version

from swos_core.api import DeviceAdapter, SwOSDevice
from swos_core.errors import DeviceDetectionError
from swos_core.models import (
    DeviceCapabilities,
    DeviceConnection,
    DeviceIdentity,
    OperationResult,
    SystemInfo,
)
from swos_core.plugins import DevicePlugin, PluginRegistry, SupportRecord
from swos_core.safety import FirmwareSafetyPolicy, SafetyWarning

try:
    __version__ = version("swos-core")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = [
    "DeviceAdapter",
    "DeviceCapabilities",
    "DeviceConnection",
    "DeviceDetectionError",
    "DeviceIdentity",
    "DevicePlugin",
    "FirmwareSafetyPolicy",
    "OperationResult",
    "PluginRegistry",
    "SafetyWarning",
    "SupportRecord",
    "SwOSDevice",
    "SystemInfo",
    "__version__",
]
