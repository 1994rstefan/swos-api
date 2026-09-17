"""Policy-bound public device API and internal adapter contract."""

from __future__ import annotations

from typing import Protocol

from swos_core.models import DeviceCapabilities, DeviceIdentity, SystemInfo
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

    def _authorize(self, *, write: bool) -> tuple[SafetyWarning, ...]:
        return enforce_firmware_policy(
            self._identity,
            self._policy,
            supported=self._supported,
            write=write,
        )
