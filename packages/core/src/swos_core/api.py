"""Policy-bound public device API and internal adapter contract."""

from __future__ import annotations

from typing import Protocol

from swos_core.errors import UnsupportedFeatureError
from swos_core.models import (
    AclRule,
    DeviceCapabilities,
    DeviceIdentity,
    DeviceNameUpdate,
    ForwardingInfo,
    ForwardingMatrixUpdate,
    ForwardingMirroringUpdate,
    ForwardingPortPolicyUpdate,
    HostEntry,
    IgmpGroup,
    OperationResult,
    PortConfigurationUpdate,
    PortInfo,
    PortNameUpdate,
    PortStatistics,
    PortVlanInfo,
    RstpBridgeUpdate,
    RstpInfo,
    RstpPortEnableUpdate,
    SafetyWarning,
    SfpInfo,
    SnmpInfo,
    SnmpMetadataUpdate,
    SystemInfo,
    VlanInfo,
)
from swos_core.safety import FirmwareSafetyPolicy, enforce_firmware_policy


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

    def get_rstp(self) -> RstpInfo:
        """Read normalized bridge and per-port RSTP state."""

        ...

    def get_snmp(self) -> SnmpInfo:
        """Read normalized SNMP service configuration."""

        ...

    def get_sfp(self) -> SfpInfo:
        """Read normalized SFP identity and diagnostics."""

        ...

    def get_forwarding(self) -> ForwardingInfo:
        """Read normalized forwarding, lock, mirror, and rate policy."""

        ...

    def get_igmp_groups(self) -> tuple[IgmpGroup, ...]:
        """Read dynamically learned IGMP groups."""

        ...

    def get_acl_rules(self) -> tuple[AclRule, ...]:
        """Read ordered access-control rules."""

        ...

    def get_port_vlans(self) -> tuple[PortVlanInfo, ...]:
        """Read normalized VLAN policy for every port."""

        ...

    def get_vlans(self) -> tuple[VlanInfo, ...]:
        """Read normalized configured VLAN table entries."""

        ...

    def set_port_name(self, update: PortNameUpdate) -> OperationResult[PortInfo]:
        """Set and verify the configured name of one port."""

        ...

    def set_port_configuration(self, update: PortConfigurationUpdate) -> OperationResult[PortInfo]:
        """Set and verify the configuration of one Ethernet port."""

        ...

    def set_device_name(self, update: DeviceNameUpdate) -> OperationResult[SystemInfo]:
        """Set and verify the configured device name."""

        ...

    def set_snmp_metadata(self, update: SnmpMetadataUpdate) -> OperationResult[SnmpInfo]:
        """Set and verify SNMP contact and location metadata."""

        ...

    def set_rstp_port_enabled(
        self,
        update: RstpPortEnableUpdate,
        *,
        expected_current: RstpInfo,
    ) -> OperationResult[RstpInfo]:
        """Set one port's RSTP state if fresh configuration matches the baseline."""

        ...

    def set_rstp_bridge(
        self,
        update: RstpBridgeUpdate,
        *,
        expected_current: RstpInfo,
    ) -> OperationResult[RstpInfo]:
        """Set bridge configuration if fresh configuration matches the baseline."""

        ...

    def set_forwarding_port_policy(
        self,
        update: ForwardingPortPolicyUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        """Set safe per-port forwarding policy against an expected baseline."""

        ...

    def set_forwarding_matrix(
        self,
        update: ForwardingMatrixUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        """Set one forwarding matrix row against an expected baseline."""

        ...

    def set_forwarding_mirroring(
        self,
        update: ForwardingMirroringUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        """Set mirroring configuration against an expected baseline."""

        ...

    def replace_static_hosts(
        self,
        hosts: tuple[HostEntry, ...],
        *,
        expected_current: tuple[HostEntry, ...],
    ) -> OperationResult[tuple[HostEntry, ...]]:
        """Replace the static host table if its fresh state matches the expected baseline."""

        ...

    def replace_acl_rules(
        self,
        rules: tuple[AclRule, ...],
        *,
        expected_current: tuple[AclRule, ...],
    ) -> OperationResult[tuple[AclRule, ...]]:
        """Replace the ACL table if its fresh state matches the expected baseline."""

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

    def get_rstp(self) -> RstpInfo:
        """Read RSTP state after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("rstp"):
            raise UnsupportedFeatureError("rstp")
        return self._adapter.get_rstp()

    def get_snmp(self) -> SnmpInfo:
        """Read SNMP configuration after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("snmp"):
            raise UnsupportedFeatureError("snmp")
        return self._adapter.get_snmp()

    def get_sfp(self) -> SfpInfo:
        """Read SFP identity and diagnostics after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("sfp"):
            raise UnsupportedFeatureError("sfp")
        return self._adapter.get_sfp()

    def get_forwarding(self) -> ForwardingInfo:
        """Read forwarding policy after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("forwarding"):
            raise UnsupportedFeatureError("forwarding")
        return self._adapter.get_forwarding()

    def get_igmp_groups(self) -> tuple[IgmpGroup, ...]:
        """Read learned multicast groups after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("igmp_groups"):
            raise UnsupportedFeatureError("igmp_groups")
        return self._adapter.get_igmp_groups()

    def get_acl_rules(self) -> tuple[AclRule, ...]:
        """Read access-control rules after enforcing read safety."""

        self._authorize(write=False)
        if not self.capabilities.supports("acl"):
            raise UnsupportedFeatureError("acl")
        return self._adapter.get_acl_rules()

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

    def set_port_name(self, update: PortNameUpdate) -> OperationResult[PortInfo]:
        """Set a port name after enforcing write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("port_name_write"):
            raise UnsupportedFeatureError("port_name_write")
        result = self._adapter.set_port_name(update)
        return OperationResult[PortInfo](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def set_port_configuration(self, update: PortConfigurationUpdate) -> OperationResult[PortInfo]:
        """Configure one port after enforcing write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("port_configuration_write"):
            raise UnsupportedFeatureError("port_configuration_write")
        result = self._adapter.set_port_configuration(update)
        return OperationResult[PortInfo](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def set_device_name(self, update: DeviceNameUpdate) -> OperationResult[SystemInfo]:
        """Set the device name after enforcing write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("device_name_write"):
            raise UnsupportedFeatureError("device_name_write")
        result = self._adapter.set_device_name(update)
        return OperationResult[SystemInfo](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def set_snmp_metadata(self, update: SnmpMetadataUpdate) -> OperationResult[SnmpInfo]:
        """Set SNMP metadata after enforcing write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("snmp_metadata_write"):
            raise UnsupportedFeatureError("snmp_metadata_write")
        result = self._adapter.set_snmp_metadata(update)
        return OperationResult[SnmpInfo](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def set_rstp_port_enabled(
        self,
        update: RstpPortEnableUpdate,
        *,
        expected_current: RstpInfo,
    ) -> OperationResult[RstpInfo]:
        """Set one port's RSTP state after write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("rstp_port_enable_write"):
            raise UnsupportedFeatureError("rstp_port_enable_write")
        result = self._adapter.set_rstp_port_enabled(update, expected_current=expected_current)
        return OperationResult[RstpInfo](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def set_rstp_bridge(
        self,
        update: RstpBridgeUpdate,
        *,
        expected_current: RstpInfo,
    ) -> OperationResult[RstpInfo]:
        """Set bridge configuration after write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("rstp_bridge_write"):
            raise UnsupportedFeatureError("rstp_bridge_write")
        result = self._adapter.set_rstp_bridge(update, expected_current=expected_current)
        return OperationResult[RstpInfo](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def set_forwarding_port_policy(
        self,
        update: ForwardingPortPolicyUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        """Set safe per-port policy after write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("forwarding_port_policy_write"):
            raise UnsupportedFeatureError("forwarding_port_policy_write")
        result = self._adapter.set_forwarding_port_policy(update, expected_current=expected_current)
        return OperationResult[ForwardingInfo](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def set_forwarding_matrix(
        self,
        update: ForwardingMatrixUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        """Set one matrix row after write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("forwarding_matrix_write"):
            raise UnsupportedFeatureError("forwarding_matrix_write")
        result = self._adapter.set_forwarding_matrix(update, expected_current=expected_current)
        return OperationResult[ForwardingInfo](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def set_forwarding_mirroring(
        self,
        update: ForwardingMirroringUpdate,
        *,
        expected_current: ForwardingInfo,
    ) -> OperationResult[ForwardingInfo]:
        """Set mirroring after write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("forwarding_mirroring_write"):
            raise UnsupportedFeatureError("forwarding_mirroring_write")
        result = self._adapter.set_forwarding_mirroring(update, expected_current=expected_current)
        return OperationResult[ForwardingInfo](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def replace_static_hosts(
        self,
        hosts: tuple[HostEntry, ...],
        *,
        expected_current: tuple[HostEntry, ...],
    ) -> OperationResult[tuple[HostEntry, ...]]:
        """Replace static hosts after enforcing write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("static_hosts_write"):
            raise UnsupportedFeatureError("static_hosts_write")
        result = self._adapter.replace_static_hosts(hosts, expected_current=expected_current)
        return OperationResult[tuple[HostEntry, ...]](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def replace_acl_rules(
        self,
        rules: tuple[AclRule, ...],
        *,
        expected_current: tuple[AclRule, ...],
    ) -> OperationResult[tuple[AclRule, ...]]:
        """Replace ACL rules after enforcing write safety and capability checks."""

        warnings = self._authorize(write=True)
        if not self.capabilities.supports("acl_write"):
            raise UnsupportedFeatureError("acl_write")
        result = self._adapter.replace_acl_rules(rules, expected_current=expected_current)
        return OperationResult[tuple[AclRule, ...]](
            changed=result.changed,
            value=result.value,
            warnings=warnings,
        )

    def _authorize(self, *, write: bool) -> tuple[SafetyWarning, ...]:
        return enforce_firmware_policy(
            self._identity,
            self._policy,
            supported=self._supported,
            write=write,
        )
