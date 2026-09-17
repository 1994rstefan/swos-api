"""Device-independent domain models."""

from __future__ import annotations

from enum import StrEnum
from typing import Generic, Self, TypeVar

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)


class DeviceIdentity(BaseModel):
    """Identity values reported by a SwOS device."""

    model_config = ConfigDict(frozen=True)

    firmware_family: str = Field(min_length=1)
    product_code: str = Field(min_length=1)
    firmware_version: str = Field(min_length=1)
    marketing_name: str | None = None
    build_id: str | None = None


class DeviceConnection(BaseModel):
    """Connection details shared by all device adapters."""

    model_config = ConfigDict(frozen=True)

    url: AnyHttpUrl
    username: str = "admin"
    password: SecretStr = SecretStr("")
    timeout: float = Field(default=10.0, gt=0)
    verify_tls: bool = True


class DeviceCapabilities(BaseModel):
    """Capabilities exposed by a concrete model and firmware combination."""

    model_config = ConfigDict(frozen=True)

    features: frozenset[str] = frozenset()

    def supports(self, feature: str) -> bool:
        """Return whether a named feature is supported."""

        return feature in self.features


class SystemInfo(BaseModel):
    """Device-independent system information."""

    model_config = ConfigDict(frozen=True)

    identity: DeviceIdentity
    name: str
    uptime_seconds: int = Field(ge=0)
    current_ip: str | None = None
    static_ip: str | None = None
    mac_address: str | None = None
    serial_number: str | None = None


class PortInfo(BaseModel):
    """Device-independent operational and basic configured port state."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1)
    name: str
    enabled: bool
    link_up: bool
    speed_mbps: int | None = Field(default=None, ge=1)
    full_duplex: bool | None = None
    auto_negotiation: bool
    flow_control: bool

    @model_validator(mode="after")
    def validate_operational_state(self) -> Self:
        if self.link_up and (self.speed_mbps is None or self.full_duplex is None):
            raise ValueError("link-up ports require speed and duplex state")
        if not self.link_up and (self.speed_mbps is not None or self.full_duplex is not None):
            raise ValueError("link-down ports cannot have operational speed or duplex state")
        return self


class PortStatistics(BaseModel):
    """Device-independent cumulative counters for one port."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1)
    rx_bytes: int = Field(ge=0)
    tx_bytes: int = Field(ge=0)
    rx_packets: int = Field(ge=0)
    tx_packets: int = Field(ge=0)
    rx_errors: int = Field(ge=0)
    tx_errors: int = Field(ge=0)


class HostEntryType(StrEnum):
    """Origin of a forwarding-database entry."""

    STATIC = "static"
    DYNAMIC = "dynamic"


class HostEntry(BaseModel):
    """Device-independent static or dynamically learned forwarding entry."""

    model_config = ConfigDict(frozen=True)

    entry_type: HostEntryType
    mac_address: str = Field(pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
    vlan_id: int | None = Field(default=None, ge=1, le=4095)
    port_numbers: tuple[int, ...]
    drop: bool = False
    mirror: bool = False

    @field_validator("mac_address")
    @classmethod
    def normalize_mac_address(cls, value: str) -> str:
        value = value.lower()
        if value == "00:00:00:00:00:00":
            raise ValueError("host entries cannot use the zero MAC address")
        return value

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        if any(port < 1 for port in self.port_numbers):
            raise ValueError("host entry port numbers must be positive")
        if len(self.port_numbers) != len(set(self.port_numbers)):
            raise ValueError("host entries cannot contain duplicate ports")
        if self.entry_type is HostEntryType.DYNAMIC:
            if len(self.port_numbers) != 1:
                raise ValueError("dynamic host entries require exactly one port")
            if self.drop or self.mirror:
                raise ValueError("dynamic host entries cannot set static actions")
        elif self.vlan_id is None:
            raise ValueError("static host entries require a VLAN ID")
        return self


class RstpProtocol(StrEnum):
    STP = "stp"
    RSTP = "rstp"


class RstpRole(StrEnum):
    DISABLED = "disabled"
    ALTERNATE = "alternate"
    ROOT = "root"
    DESIGNATED = "designated"
    BACKUP = "backup"


class RstpPortType(StrEnum):
    SHARED = "shared"
    POINT_TO_POINT = "point_to_point"
    EDGE = "edge"


class RstpState(StrEnum):
    DISCARDING = "discarding"
    LEARNING = "learning"
    FORWARDING = "forwarding"


class RstpCostMode(StrEnum):
    SHORT = "short"
    LONG = "long"


class RstpPortInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1)
    enabled: bool
    protocol: RstpProtocol
    role: RstpRole
    root_path_cost: int = Field(ge=0, le=0xFFFFFFFF)
    port_type: RstpPortType
    state: RstpState


class RstpInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    bridge_priority: int = Field(ge=0, le=0xFFFF)
    cost_mode: RstpCostMode
    forward_reserved_multicast: bool
    root_bridge_priority: int = Field(ge=0, le=0xFFFF)
    root_bridge_mac: str = Field(pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
    ports: tuple[RstpPortInfo, ...]


class SnmpInfo(BaseModel):
    """Device-independent SNMP service configuration."""

    model_config = ConfigDict(frozen=True)

    enabled: bool
    community: str = Field(max_length=64)
    contact: str = Field(max_length=64)
    location: str = Field(max_length=64)


class VlanMode(StrEnum):
    """Ingress VLAN enforcement for a switch port."""

    DISABLED = "disabled"
    OPTIONAL = "optional"
    ENABLED = "enabled"
    STRICT = "strict"


class VlanReceiveMode(StrEnum):
    """Accepted VLAN frame types for a switch port."""

    ANY = "any"
    TAGGED_ONLY = "tagged_only"
    UNTAGGED_ONLY = "untagged_only"


class VlanEgressMode(StrEnum):
    """VLAN header handling applied when a frame leaves a port."""

    PRESERVE = "preserve"
    STRIP = "strip"
    ADD_IF_MISSING = "add_if_missing"


class VlanMembershipMode(StrEnum):
    """Per-port egress behavior in a VLAN table entry."""

    PRESERVE = "preserve"
    STRIP = "strip"
    ADD_IF_MISSING = "add_if_missing"
    NOT_MEMBER = "not_member"


class PortVlanInfo(BaseModel):
    """Device-independent VLAN policy for one switch port."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1)
    mode: VlanMode
    receive: VlanReceiveMode
    default_vlan_id: int = Field(ge=1, le=4095)
    force_vlan_id: bool
    egress: VlanEgressMode


class VlanPortMembership(BaseModel):
    """Port membership and egress behavior in one VLAN table entry."""

    model_config = ConfigDict(frozen=True)

    port_number: int = Field(ge=1)
    mode: VlanMembershipMode


class VlanInfo(BaseModel):
    """Device-independent configured VLAN table entry."""

    model_config = ConfigDict(frozen=True)

    vlan_id: int = Field(ge=1, le=4095)
    independent_learning: bool
    igmp_snooping: bool
    ports: tuple[VlanPortMembership, ...]

    @model_validator(mode="after")
    def validate_unique_ports(self) -> Self:
        port_numbers = [port.port_number for port in self.ports]
        if len(port_numbers) != len(set(port_numbers)):
            raise ValueError("VLAN entries cannot contain duplicate ports")
        return self


ResultValue = TypeVar("ResultValue")


class OperationResult(BaseModel, Generic[ResultValue]):
    """Result of a read or idempotent configuration operation."""

    model_config = ConfigDict(frozen=True)

    changed: bool = False
    value: ResultValue
