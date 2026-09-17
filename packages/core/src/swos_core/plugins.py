"""Discovery and exact matching of independently installed device plugins."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from swos_core.api import DeviceAdapter, SwOSDevice
from swos_core.errors import DuplicateDevicePluginError, MissingDevicePluginError
from swos_core.models import DeviceConnection, DeviceIdentity
from swos_core.safety import FirmwareSafetyPolicy, SafetyWarning, enforce_firmware_policy

ENTRY_POINT_GROUP = "swos.devices"


class SupportRecord(BaseModel):
    """An exact model and firmware combination tested by a device plugin."""

    model_config = ConfigDict(frozen=True)

    firmware_family: str = Field(min_length=1)
    product_code: str = Field(min_length=1)
    firmware_version: str = Field(min_length=1)
    build_id: str | None = None
    marketing_names: tuple[str, ...] = ()

    def matches(self, identity: DeviceIdentity) -> bool:
        """Return whether the reported identity exactly matches this record."""

        build_matches = self.build_id is None or self.build_id == identity.build_id
        return (
            self.firmware_family.casefold() == identity.firmware_family.casefold()
            and self.product_code.casefold() == identity.product_code.casefold()
            and self.firmware_version == identity.firmware_version
            and build_matches
        )


class DevicePlugin(Protocol):
    """Contract implemented by a separately distributed device plugin."""

    family: str
    distribution_name: str

    def support_records(self) -> tuple[SupportRecord, ...]:
        """Return all explicitly tested model and firmware combinations."""

        ...

    def create(
        self,
        *,
        identity: DeviceIdentity,
        connection: DeviceConnection,
        policy: FirmwareSafetyPolicy,
        support: SupportRecord | None,
    ) -> DeviceAdapter:
        """Create the adapter for a detected identity."""

        ...


@dataclass(frozen=True, slots=True)
class PluginResolution:
    """Selected plugin, exact support record, and any override warnings."""

    family: str
    distribution_name: str
    support: SupportRecord | None
    warnings: tuple[SafetyWarning, ...]


class PluginRegistry:
    """Registry of device plugins keyed by firmware image family."""

    def __init__(self, plugins: Iterable[DevicePlugin] = ()) -> None:
        self._plugins: dict[str, DevicePlugin] = {}
        for plugin in plugins:
            key = plugin.family.casefold()
            if key in self._plugins:
                raise DuplicateDevicePluginError(
                    f"Multiple plugins registered firmware family {plugin.family!r}"
                )
            self._plugins[key] = plugin

    @classmethod
    def discover(cls) -> PluginRegistry:
        """Load device plugins from the standard entry-point group."""

        plugins: list[DevicePlugin] = []
        for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUP):
            loaded = entry_point.load()
            plugin = loaded() if isinstance(loaded, type) else loaded
            if not hasattr(plugin, "family") or not hasattr(plugin, "support_records"):
                raise TypeError(f"Entry point {entry_point.name!r} is not a device plugin")
            plugins.append(plugin)
        return cls(plugins)

    @property
    def known_families(self) -> tuple[str, ...]:
        """Return normalized names of installed firmware families."""

        return tuple(sorted(self._plugins))

    def resolve(
        self,
        identity: DeviceIdentity,
        policy: FirmwareSafetyPolicy,
        *,
        write: bool = False,
    ) -> PluginResolution:
        """Resolve a plugin and enforce exact firmware support policy."""

        plugin, support = self._select(identity)
        warnings = enforce_firmware_policy(
            identity,
            policy,
            supported=support is not None,
            write=write,
        )
        return PluginResolution(
            family=plugin.family,
            distribution_name=plugin.distribution_name,
            support=support,
            warnings=warnings,
        )

    def connect(
        self,
        identity: DeviceIdentity,
        connection: DeviceConnection,
        policy: FirmwareSafetyPolicy,
    ) -> SwOSDevice:
        """Create a policy-bound facade without exposing the raw adapter."""

        plugin, support = self._select(identity)
        enforce_firmware_policy(
            identity,
            policy,
            supported=support is not None,
            write=False,
        )
        adapter = plugin.create(
            identity=identity,
            connection=connection,
            policy=policy,
            support=support,
        )
        return SwOSDevice(
            adapter,
            identity,
            policy,
            supported=support is not None,
        )

    def _select(self, identity: DeviceIdentity) -> tuple[DevicePlugin, SupportRecord | None]:
        plugin = self._plugins.get(identity.firmware_family.casefold())
        if plugin is None:
            raise MissingDevicePluginError(identity.firmware_family)
        support = next(
            (record for record in plugin.support_records() if record.matches(identity)),
            None,
        )
        return plugin, support
