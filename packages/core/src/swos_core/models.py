"""Device-independent domain models."""

from __future__ import annotations

from enum import StrEnum
from ipaddress import IPv4Address
from typing import Annotated, Generic, Self, TypeVar

from pydantic import (
    AfterValidator,
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)


def _validate_port_numbers(value: tuple[int, ...]) -> tuple[int, ...]:
    if any(number < 1 for number in value):
        raise ValueError("port numbers must be positive")
    if len(value) != len(set(value)):
        raise ValueError("port numbers must be unique")
    return value


_PortNumbers = Annotated[tuple[int, ...], AfterValidator(_validate_port_numbers)]


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


class SafetyWarning(BaseModel):
    """Machine-readable warning returned when a safety override is used."""

    model_config = ConfigDict(frozen=True)

    code: str
    message: str


class AddressMode(StrEnum):
    DHCP_WITH_FALLBACK = "dhcp_with_fallback"
    STATIC = "static"
    DHCP_ONLY = "dhcp_only"


class IgmpVersion(StrEnum):
    V2 = "v2"
    V3 = "v3"


class SystemManagementInfo(BaseModel):
    """Management-plane configuration."""

    model_config = ConfigDict(frozen=True)

    address_mode: AddressMode
    admin_mac_address: str | None = Field(
        default=None, pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"
    )
    allow_from: str | None = None
    allow_prefix_length: int = Field(ge=0, le=32)
    allowed_port_numbers: _PortNumbers
    allowed_vlan_id: int | None = Field(default=None, ge=1, le=4095)
    watchdog_enabled: bool

    @field_validator("allow_from")
    @classmethod
    def validate_allow_from(cls, value: str | None) -> str | None:
        return str(IPv4Address(value)) if value is not None else None


class IgmpInfo(BaseModel):
    """Global IGMP snooping configuration."""

    model_config = ConfigDict(frozen=True)

    enabled: bool
    querier_configured: bool
    querier_effective: bool
    fast_leave_port_numbers: _PortNumbers
    version: IgmpVersion


class SystemHealth(BaseModel):
    """Hardware health readings available for a device model."""

    model_config = ConfigDict(frozen=True)

    input_voltage_volts: float | None = Field(default=None, ge=0)
    temperature_celsius: int | None = None
    poe_in_long_cable: bool | None = None


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
    management: SystemManagementInfo | None = None
    independent_vlan_lookup: bool | None = None
    igmp: IgmpInfo | None = None
    discovery_protocol_port_numbers: _PortNumbers = ()
    health: SystemHealth | None = None


class PoeMode(StrEnum):
    OFF = "off"
    AUTO = "auto"
    ON = "on"
    CALIBRATION = "calibration"


class PoeStatus(StrEnum):
    UNSPECIFIED = "unspecified"
    DISABLED = "disabled"
    WAITING_FOR_LOAD = "waiting_for_load"
    POWERED_ON = "powered_on"
    OVERLOAD = "overload"
    SHORT_CIRCUIT = "short_circuit"
    VOLTAGE_TOO_LOW = "voltage_too_low"
    CURRENT_TOO_LOW = "current_too_low"
    POWER_CYCLE = "power_cycle"
    VOLTAGE_TOO_HIGH = "voltage_too_high"
    CONTROLLER_ERROR = "controller_error"


class PortInfo(BaseModel):
    """Device-independent operational and basic configured port state."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1)
    name: str
    enabled: bool
    link_up: bool
    speed_bps: int | None = Field(default=None, ge=1)
    full_duplex: bool | None = None
    auto_negotiation: bool
    configured_speed_bps: int = Field(ge=1)
    configured_full_duplex: bool
    flow_control: bool
    poe_mode: PoeMode | None = None
    poe_priority: int | None = Field(default=None, ge=1, le=4)
    poe_status: PoeStatus | None = None
    poe_current_ma: int | None = Field(default=None, ge=0)
    poe_power_watts: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_operational_state(self) -> Self:
        if self.link_up and (self.speed_bps is None or self.full_duplex is None):
            raise ValueError("link-up ports require speed and duplex state")
        if not self.link_up and (self.speed_bps is not None or self.full_duplex is not None):
            raise ValueError("link-down ports cannot have operational speed or duplex state")
        return self


class PortNameUpdate(BaseModel):
    """Desired name for one numbered switch port."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1)
    name: str


class PortRateStatistics(BaseModel):
    """Current traffic rates reported by the switch."""

    model_config = ConfigDict(frozen=True)

    rx_bits_per_second: float = Field(ge=0)
    tx_bits_per_second: float = Field(ge=0)
    rx_packets_per_second: float = Field(ge=0)
    tx_packets_per_second: float = Field(ge=0)


class PortTrafficStatistics(BaseModel):
    """Cumulative packet counters grouped by destination type."""

    model_config = ConfigDict(frozen=True)

    rx_unicast_packets: int = Field(ge=0)
    tx_unicast_packets: int = Field(ge=0)
    rx_broadcast_packets: int = Field(ge=0)
    tx_broadcast_packets: int = Field(ge=0)
    rx_multicast_packets: int = Field(ge=0)
    tx_multicast_packets: int = Field(ge=0)


class PacketSizeStatistics(BaseModel):
    """Cumulative frame counters grouped by wire size."""

    model_config = ConfigDict(frozen=True)

    frames_64_bytes: int = Field(ge=0)
    frames_65_to_127_bytes: int = Field(ge=0)
    frames_128_to_255_bytes: int = Field(ge=0)
    frames_256_to_511_bytes: int = Field(ge=0)
    frames_512_to_1023_bytes: int = Field(ge=0)
    frames_1024_to_1518_bytes: int = Field(ge=0)
    frames_1519_to_max_bytes: int = Field(ge=0)


class PortErrorStatistics(BaseModel):
    """Detailed receive and transmit error/event counters."""

    model_config = ConfigDict(frozen=True)

    rx_pause_frames: int = Field(ge=0)
    rx_fcs_errors: int = Field(ge=0)
    rx_alignment_errors: int = Field(ge=0)
    rx_runts: int = Field(ge=0)
    rx_fragments: int = Field(ge=0)
    rx_too_long: int = Field(ge=0)
    rx_overflows: int = Field(ge=0)
    tx_pause_frames: int = Field(ge=0)
    tx_underruns: int = Field(ge=0)
    tx_too_long: int = Field(ge=0)
    tx_collisions: int = Field(ge=0)
    tx_excessive_collisions: int = Field(ge=0)
    tx_multiple_collisions: int = Field(ge=0)
    tx_single_collisions: int = Field(ge=0)
    tx_excessive_deferred: int = Field(ge=0)
    tx_deferred: int = Field(ge=0)
    tx_late_collisions: int = Field(ge=0)


class PortStatistics(BaseModel):
    """Device-independent traffic, rate, size, and error counters for one port."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1)
    rx_bytes: int = Field(ge=0)
    tx_bytes: int = Field(ge=0)
    rx_packets: int = Field(ge=0)
    tx_packets: int = Field(ge=0)
    rx_errors: int = Field(ge=0)
    tx_errors: int = Field(ge=0)
    rates: PortRateStatistics
    traffic: PortTrafficStatistics
    rx_sizes: PacketSizeStatistics
    tx_sizes: PacketSizeStatistics
    detailed_errors: PortErrorStatistics


class SfpInfo(BaseModel):
    """Identity and diagnostics reported by an installed SFP module."""

    model_config = ConfigDict(frozen=True)

    vendor: str | None = None
    part_number: str | None = None
    revision: str | None = None
    serial_number: str | None = None
    manufacturing_date: str | None = None
    media_type: str | None = None
    temperature_celsius: int | None = None
    supply_voltage_volts: float | None = Field(default=None, ge=0)
    tx_bias_ma: int | None = Field(default=None, ge=0)
    tx_power_dbm: float | None = None
    rx_power_dbm: float | None = None


class PortForwardingInfo(BaseModel):
    """Forwarding, locking, mirroring, and egress-rate policy for one port."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1)
    destination_port_numbers: _PortNumbers
    lock: bool
    lock_on_first: bool
    mirror_ingress: bool
    mirror_egress: bool
    egress_rate_limit_bps: int | None = Field(default=None, ge=1)


class ForwardingInfo(BaseModel):
    """Switch-wide forwarding policy."""

    model_config = ConfigDict(frozen=True)

    mirror_target_port: int | None = Field(default=None, ge=1)
    ports: tuple[PortForwardingInfo, ...]

    @model_validator(mode="after")
    def validate_unique_ports(self) -> Self:
        numbers = [port.number for port in self.ports]
        if len(numbers) != len(set(numbers)):
            raise ValueError("forwarding ports must be unique")
        known_ports = set(numbers)
        if self.mirror_target_port is not None and self.mirror_target_port not in known_ports:
            raise ValueError("forwarding mirror target must reference a declared port")
        if any(
            destination not in known_ports
            for port in self.ports
            for destination in port.destination_port_numbers
        ):
            raise ValueError("forwarding destinations must reference declared ports")
        return self


class IgmpGroup(BaseModel):
    """Dynamically learned multicast group."""

    model_config = ConfigDict(frozen=True)

    address: str
    vlan_id: int = Field(ge=1, le=4095)
    port_numbers: _PortNumbers

    @field_validator("address")
    @classmethod
    def validate_multicast_address(cls, value: str) -> str:
        address = IPv4Address(value)
        if not address.is_multicast:
            raise ValueError("IGMP group address must be multicast")
        return str(address)

    @model_validator(mode="after")
    def validate_members(self) -> Self:
        if not self.port_numbers:
            raise ValueError("IGMP groups require at least one member port")
        return self


class AclVlanTagMode(StrEnum):
    ANY = "any"
    PRESENT = "present"
    NOT_PRESENT = "not_present"


class AclRule(BaseModel):
    """Normalized ordered CSS106 access-control rule."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1)
    ingress_port_numbers: _PortNumbers
    source_mac: str | None = Field(default=None, pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
    source_mac_mask: str = Field(pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
    destination_mac: str | None = Field(
        default=None, pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"
    )
    destination_mac_mask: str = Field(pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
    ether_type: int = Field(ge=0, le=0xFFFF)
    vlan_tag: AclVlanTagMode
    vlan_id_min: int = Field(ge=0, le=4095)
    vlan_id_max: int = Field(ge=0, le=4095)
    vlan_priority: int | None = Field(default=None, ge=0, le=7)
    source_ip: str | None = None
    source_prefix_length: int = Field(ge=0, le=32)
    source_port_min: int = Field(ge=0, le=0xFFFF)
    source_port_max: int = Field(ge=0, le=0xFFFF)
    destination_ip: str | None = None
    destination_prefix_length: int = Field(ge=0, le=32)
    destination_port_min: int = Field(ge=0, le=0xFFFF)
    destination_port_max: int = Field(ge=0, le=0xFFFF)
    protocol_number: int = Field(ge=0, le=0xFF)
    dscp: int | None = Field(default=None, ge=0, le=63)
    redirect_enabled: bool
    redirect_port_numbers: _PortNumbers
    drop: bool
    mirror: bool
    ingress_rate_limit_bps: int | None = Field(default=None, ge=1)
    set_vlan_id: int | None = Field(default=None, ge=1, le=4095)
    set_vlan_priority: int | None = Field(default=None, ge=0, le=7)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        return str(IPv4Address(value)) if value is not None else None

    @model_validator(mode="after")
    def validate_actions_and_ranges(self) -> Self:
        if self.drop != (self.redirect_enabled and not self.redirect_port_numbers):
            raise ValueError("ACL drop must represent an enabled redirect without destinations")
        if self.vlan_id_min > self.vlan_id_max:
            raise ValueError("ACL VLAN range is reversed")
        if self.source_port_min > self.source_port_max:
            raise ValueError("ACL source port range is reversed")
        if self.destination_port_min > self.destination_port_max:
            raise ValueError("ACL destination port range is reversed")
        return self


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
    configured_path_cost: int = Field(default=0, ge=0, le=0xFFFFFFFF)


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
    warnings: tuple[SafetyWarning, ...] = ()
