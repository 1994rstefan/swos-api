"""Public exports for the swos-core package."""

from importlib.metadata import PackageNotFoundError, version

from swos_core.api import DeviceAdapter, SwOSDevice
from swos_core.errors import DeviceDetectionError, UnsupportedFeatureError
from swos_core.models import (
    DeviceCapabilities,
    DeviceConnection,
    DeviceIdentity,
    HostEntry,
    HostEntryType,
    OperationResult,
    PortInfo,
    PortStatistics,
    PortVlanInfo,
    RstpCostMode,
    RstpInfo,
    RstpPortInfo,
    RstpPortType,
    RstpProtocol,
    RstpRole,
    RstpState,
    SnmpInfo,
    SystemInfo,
    VlanEgressMode,
    VlanInfo,
    VlanMembershipMode,
    VlanMode,
    VlanPortMembership,
    VlanReceiveMode,
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
    "HostEntry",
    "HostEntryType",
    "OperationResult",
    "PluginRegistry",
    "PortInfo",
    "PortStatistics",
    "PortVlanInfo",
    "RstpCostMode",
    "RstpInfo",
    "RstpPortInfo",
    "RstpPortType",
    "RstpProtocol",
    "RstpRole",
    "RstpState",
    "SafetyWarning",
    "SnmpInfo",
    "SupportRecord",
    "SwOSDevice",
    "SystemInfo",
    "UnsupportedFeatureError",
    "VlanEgressMode",
    "VlanInfo",
    "VlanMembershipMode",
    "VlanMode",
    "VlanPortMembership",
    "VlanReceiveMode",
    "__version__",
]
