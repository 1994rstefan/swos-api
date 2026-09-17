"""Policy-bound public device API and internal adapter contract."""

from __future__ import annotations

from typing import Protocol

from swos_core.errors import UnsupportedFeatureError
from swos_core.models import (
    DeviceCapabilities,
    DeviceIdentity,
    HostEntry,
    PortInfo,
    PortStatistics,
    PortVlanInfo,
    SystemInfo,
    VlanInfo,
)
from swos_core.safety import FirmwareSafetyPolicy, SafetyWarning, enforce_firmware_policy


class DeviceAdapter(Protocol):
    """Internal interface implemented by device support packages."""

    @property
    def identity(self) -> DeviceIdentity:
        """Return the detected device identity."""

        ...

    @property
    def capabilities(self) -> DeviceCapabilities:
        """Return capabilities for the selected model and firmware."""

        ...

    def get_system_info(self) -> SystemInfo:
        """Read normalized system information from the device."""

        ...

    def get_ports(self) -> tuple[PortInfo, ...]:
        """Read normalized port state from the device."""

        ...

    def get_port_statistics(self) -> tuple[PortStatistics, ...]:
        """Read normalized cumulative port counters from the device."""

        ...

    def get_hosts(self) -> tuple[HostEntry, ...]:
        """Read normalized static and dynamically learned host entries."""

        ...

    def get_port_vlans(self) -> tuple[PortVlanInfo, ...]:
        """Read normalized VLAN policy for every port."""

        ...

    def get_vlans(self) -> tuple[VlanInfo, ...]:
        """Read normalized configured VLAN table entries."""

        ...


class SwOSDevice:
    """Core-owned device facade that enforces firmware policy per operation."""

    def __init__(
        self,
        adapter: DeviceAdapter,
        identity: DeviceIdentity,
        policy: FirmwareSafetyPolicy,
        *,
        supported: bool,
        warnings: tuple[SafetyWarning, ...] = (),
    ) -> None:
        self._adapter = adapter
        self._identity = identity
        self._policy = policy
        self._supported = supported
        self._warnings = warnings

    @property
    def identity(self) -> DeviceIdentity:
        """Return the identity used to select this adapter."""

        return self._identity

    @property
    def capabilities(self) -> DeviceCapabilities:
        """Return capabilities exposed by the protected adapter."""

        return self._adapter.capabilities

    @property
    def warnings(self) -> tuple[SafetyWarning, ...]:
        """Return safety warnings produced while connecting this device."""

        return self._warnings

    def get_system_info(self) -> SystemInfo:
        """Read system information after enforcing read safety."""

        self._authorize(write=False)
        return self._adapter.get_system_info()

    def get_ports(self) -> tuple[PortInfo, ...]:
        """Read port state after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("ports"):
            raise UnsupportedFeatureError("ports")
        return self._adapter.get_ports()

    def get_port_statistics(self) -> tuple[PortStatistics, ...]:
        """Read cumulative counters after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("port_statistics"):
            raise UnsupportedFeatureError("port_statistics")
        return self._adapter.get_port_statistics()

    def get_hosts(self) -> tuple[HostEntry, ...]:
        """Read forwarding-database entries after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("hosts"):
            raise UnsupportedFeatureError("hosts")
        return self._adapter.get_hosts()

    def get_port_vlans(self) -> tuple[PortVlanInfo, ...]:
        """Read per-port VLAN policy after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("vlan"):
            raise UnsupportedFeatureError("vlan")
        return self._adapter.get_port_vlans()

    def get_vlans(self) -> tuple[VlanInfo, ...]:
        """Read VLAN table entries after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("vlan"):
            raise UnsupportedFeatureError("vlan")
        return self._adapter.get_vlans()

    def _authorize(self, *, write: bool) -> tuple[SafetyWarning, ...]:
        return enforce_firmware_policy(
            self._identity,
            self._policy,
            supported=self._supported,
            write=write,
        )
