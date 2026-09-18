"""Device-independent domain models."""

from __future__ import annotations

from enum import StrEnum
from ipaddress import IPv4Address
from typing import Annotated, Generic, Literal, Self, TypeAlias, TypeVar

from pydantic import (
    AfterValidator,
    AnyHttpUrl,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
    Strict,
    field_validator,
    model_validator,
)

_StrictInt = Annotated[int, Strict()]
_StrictBool = Annotated[bool, Strict()]
_StrictStr = Annotated[str, Strict()]


def _validate_secret_string(value: object) -> object:
    raw_value = value.get_secret_value() if isinstance(value, SecretStr) else value
    if type(raw_value) is not str:
        raise ValueError("secret values must be strings")
    return value


def _validate_string_enum(value: object) -> object:
    if not isinstance(value, str):
        raise ValueError("enum values must use their documented string spelling")
    return value


_StrictSecretStr = Annotated[SecretStr, BeforeValidator(_validate_secret_string)]


def _reject_binary_values(value: object) -> None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError("binary values are not accepted by desired-state models")
    if isinstance(value, dict):
        for item in value.values():
            _reject_binary_values(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _reject_binary_values(item)


class _DesiredStateModel(BaseModel):
    """Strict boundary shared by values that can reach a device write."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def reject_binary_values(cls, value: object) -> object:
        _reject_binary_values(value)
        return value


def _validate_port_numbers(value: tuple[int, ...]) -> tuple[int, ...]:
    if any(number < 1 for number in value):
        raise ValueError("port numbers must be positive")
    if len(value) != len(set(value)):
        raise ValueError("port numbers must be unique")
    return value


_PortNumbers = Annotated[tuple[_StrictInt, ...], AfterValidator(_validate_port_numbers)]


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


class DeviceNameUpdate(_DesiredStateModel):
    """Desired device name."""

    name: _StrictStr


class PasswordUpdate(_DesiredStateModel):
    """Desired administrator password held only as a non-serializing secret."""

    new_password: _StrictSecretStr = Field(exclude=True)


class SystemConfigurationUpdate(_DesiredStateModel):
    """Desired system changes, preserving fields omitted as ``None``."""

    address_mode: Annotated[AddressMode, BeforeValidator(_validate_string_enum)] | None = None
    static_ip: _StrictStr | Literal["unset"] | None = None
    admin_mac_address: _StrictStr | Literal["unset"] | None = None
    name: _StrictStr | None = None
    allow_from: _StrictStr | Literal["unset"] | None = None
    allow_prefix_length: _StrictInt | None = Field(default=None, ge=0, le=32)
    allowed_port_numbers: _PortNumbers | None = None
    allowed_vlan_id: Annotated[_StrictInt, Field(ge=1, le=4095)] | Literal["unset"] | None = None
    independent_vlan_lookup: _StrictBool | None = None
    igmp_enabled: _StrictBool | None = None
    igmp_querier: _StrictBool | None = None
    igmp_fast_leave_port_numbers: _PortNumbers | None = None
    igmp_version: Annotated[IgmpVersion, BeforeValidator(_validate_string_enum)] | None = None
    discovery_protocol_port_numbers: _PortNumbers | None = None

    @field_validator("static_ip")
    @classmethod
    def normalize_static_ip(cls, value: str | None) -> str | None:
        if value is None or value == "unset":
            return value
        address = IPv4Address(value)
        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or address.is_reserved
            or address == IPv4Address("255.255.255.255")
        ):
            raise ValueError("static management IP must be a usable unicast IPv4 address")
        return str(address)

    @field_validator("allow_from")
    @classmethod
    def normalize_allow_from(cls, value: str | None) -> str | None:
        if value is None or value == "unset":
            return value
        return str(IPv4Address(value))

    @field_validator("admin_mac_address")
    @classmethod
    def normalize_optional_mac(cls, value: str | None) -> str | None:
        if value is None or value == "unset":
            return value
        normalized = value.lower()
        parts = normalized.split(":")
        if len(parts) != 6 or any(
            len(part) != 2 or any(character not in "0123456789abcdef" for character in part)
            for part in parts
        ):
            raise ValueError("admin MAC address must contain six hexadecimal octets")
        return normalized

    @model_validator(mode="after")
    def validate_non_empty_update(self) -> Self:
        if all(value is None for value in self.__dict__.values()):
            raise ValueError("at least one system configuration change is required")
        return self


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


class PortNameUpdate(_DesiredStateModel):
    """Desired name for one numbered switch port."""

    number: _StrictInt = Field(ge=1)
    name: _StrictStr


class ForcedPortNegotiation(_DesiredStateModel):
    """Desired forced speed and duplex for one Ethernet port."""

    speed_bps: _StrictInt = Field(ge=1)
    duplex: Literal["full", "half"]


PortNegotiation: TypeAlias = Literal["auto"] | ForcedPortNegotiation


class PortConfigurationUpdate(_DesiredStateModel):
    """Desired configuration changes for one non-management Ethernet port."""

    number: _StrictInt = Field(ge=1)
    enabled: _StrictBool | None = None
    negotiation: PortNegotiation | None = None
    flow_control: _StrictBool | None = None

    @model_validator(mode="after")
    def validate_non_empty_update(self) -> Self:
        if self.enabled is None and self.negotiation is None and self.flow_control is None:
            raise ValueError("at least one port configuration change is required")
        return self


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


class ForwardingPortPolicyUpdate(_DesiredStateModel):
    """Desired lock and egress-rate changes for one non-management port."""

    number: _StrictInt = Field(ge=1)
    lock: _StrictBool | None = None
    lock_on_first: _StrictBool | None = None
    egress_rate_limit_bps: (
        Annotated[_StrictInt, Field(ge=1, le=0xFFFFFFFF)] | Literal["unlimited"] | None
    ) = None

    @model_validator(mode="after")
    def validate_non_empty_update(self) -> Self:
        if self.lock is None and self.lock_on_first is None and self.egress_rate_limit_bps is None:
            raise ValueError("at least one forwarding port policy change is required")
        return self


class ForwardingMatrixUpdate(_DesiredStateModel):
    """Desired forwarding destinations for one source port."""

    number: _StrictInt = Field(ge=1)
    destination_port_numbers: _PortNumbers


class ForwardingMirroringUpdate(_DesiredStateModel):
    """Desired mirroring changes, preserving values omitted as ``None``."""

    source_port_number: _StrictInt = Field(ge=1)
    mirror_ingress: _StrictBool | None = None
    mirror_egress: _StrictBool | None = None
    mirror_target_port: _StrictInt | Literal["none"] | None = None

    @model_validator(mode="after")
    def validate_non_empty_update(self) -> Self:
        if (
            self.mirror_ingress is None
            and self.mirror_egress is None
            and self.mirror_target_port is None
        ):
            raise ValueError("at least one forwarding mirroring change is required")
        return self


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


class AclRule(_DesiredStateModel):
    """Normalized ordered CSS106 access-control rule."""

    number: _StrictInt = Field(ge=1)
    ingress_port_numbers: _PortNumbers
    source_mac: _StrictStr | None = Field(
        default=None, pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"
    )
    source_mac_mask: _StrictStr = Field(pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
    destination_mac: _StrictStr | None = Field(
        default=None, pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$"
    )
    destination_mac_mask: _StrictStr = Field(pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
    ether_type: _StrictInt = Field(ge=0, le=0xFFFF)
    vlan_tag: Annotated[AclVlanTagMode, BeforeValidator(_validate_string_enum)]
    vlan_id_min: _StrictInt = Field(ge=0, le=4095)
    vlan_id_max: _StrictInt = Field(ge=0, le=4095)
    vlan_priority: _StrictInt | None = Field(default=None, ge=0, le=7)
    source_ip: _StrictStr | None = None
    source_prefix_length: _StrictInt = Field(ge=0, le=32)
    source_port_min: _StrictInt = Field(ge=0, le=0xFFFF)
    source_port_max: _StrictInt = Field(ge=0, le=0xFFFF)
    destination_ip: _StrictStr | None = None
    destination_prefix_length: _StrictInt = Field(ge=0, le=32)
    destination_port_min: _StrictInt = Field(ge=0, le=0xFFFF)
    destination_port_max: _StrictInt = Field(ge=0, le=0xFFFF)
    protocol_number: _StrictInt = Field(ge=0, le=0xFF)
    dscp: _StrictInt | None = Field(default=None, ge=0, le=63)
    redirect_enabled: _StrictBool
    redirect_port_numbers: _PortNumbers
    drop: _StrictBool
    mirror: _StrictBool
    ingress_rate_limit_bps: _StrictInt | None = Field(default=None, ge=1, le=0xFFFFFFFF)
    set_vlan_id: _StrictInt | None = Field(default=None, ge=1, le=4095)
    set_vlan_priority: _StrictInt | None = Field(default=None, ge=0, le=7)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = str(IPv4Address(value))
        return None if normalized == "0.0.0.0" else normalized

    @field_validator("source_mac", "destination_mac")
    @classmethod
    def normalize_optional_mac_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.lower()
        return None if normalized == "00:00:00:00:00:00" else normalized

    @field_validator("source_mac_mask", "destination_mac_mask")
    @classmethod
    def normalize_mac_mask(cls, value: str) -> str:
        return value.lower()

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


class HostEntry(_DesiredStateModel):
    """Device-independent static or dynamically learned forwarding entry."""

    entry_type: Annotated[HostEntryType, BeforeValidator(_validate_string_enum)]
    mac_address: _StrictStr = Field(pattern=r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
    vlan_id: _StrictInt | None = Field(default=None, ge=1, le=4095)
    port_numbers: tuple[_StrictInt, ...]
    drop: _StrictBool = False
    mirror: _StrictBool = False

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
    point_to_point: bool
    edge: bool
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


class RstpPortEnableUpdate(_DesiredStateModel):
    """Desired RSTP enabled state for one non-management port."""

    number: _StrictInt = Field(ge=1)
    enabled: _StrictBool


class RstpBridgeUpdate(_DesiredStateModel):
    """Desired bridge changes, preserving values omitted as ``None``."""

    bridge_priority: _StrictInt | None = Field(default=None, ge=0, le=0xF000, multiple_of=0x1000)
    cost_mode: Annotated[RstpCostMode, BeforeValidator(_validate_string_enum)] | None = None
    forward_reserved_multicast: _StrictBool | None = None

    @model_validator(mode="after")
    def validate_non_empty_update(self) -> Self:
        if (
            self.bridge_priority is None
            and self.cost_mode is None
            and self.forward_reserved_multicast is None
        ):
            raise ValueError("at least one RSTP bridge change is required")
        return self


class SnmpInfo(BaseModel):
    """Device-independent SNMP service configuration."""

    model_config = ConfigDict(frozen=True)

    enabled: bool
    community: str = Field(max_length=64)
    contact: str = Field(max_length=64)
    location: str = Field(max_length=64)


class SnmpMetadataUpdate(_DesiredStateModel):
    """Desired SNMP metadata, preserving fields omitted as ``None``."""

    contact: _StrictStr | None = None
    location: _StrictStr | None = None


class SnmpConfigurationUpdate(_DesiredStateModel):
    """Desired SNMP service configuration, preserving fields omitted as ``None``."""

    enabled: _StrictBool | None = None
    community: _StrictSecretStr | None = Field(default=None, exclude=True)
    contact: _StrictStr | None = None
    location: _StrictStr | None = None

    @model_validator(mode="after")
    def validate_non_empty_update(self) -> Self:
        if all(value is None for value in self.__dict__.values()):
            raise ValueError("at least one SNMP configuration change is required")
        return self


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


class PortVlanPolicyUpdate(_DesiredStateModel):
    """Desired VLAN policy changes for one non-management Ethernet port."""

    number: _StrictInt = Field(ge=1)
    mode: Annotated[VlanMode, BeforeValidator(_validate_string_enum)] | None = None
    receive: Annotated[VlanReceiveMode, BeforeValidator(_validate_string_enum)] | None = None
    default_vlan_id: _StrictInt | None = Field(default=None, ge=1, le=4095)
    force_vlan_id: _StrictBool | None = None
    egress: Annotated[VlanEgressMode, BeforeValidator(_validate_string_enum)] | None = None

    @model_validator(mode="after")
    def validate_non_empty_update(self) -> Self:
        if (
            self.mode is None
            and self.receive is None
            and self.default_vlan_id is None
            and self.force_vlan_id is None
            and self.egress is None
        ):
            raise ValueError("at least one port VLAN policy change is required")
        return self


class VlanPortMembership(_DesiredStateModel):
    """Port membership and egress behavior in one VLAN table entry."""

    port_number: _StrictInt = Field(ge=1)
    mode: Annotated[VlanMembershipMode, BeforeValidator(_validate_string_enum)]


class VlanInfo(_DesiredStateModel):
    """Device-independent configured VLAN table entry."""

    table_position: _StrictInt | None = Field(default=None, ge=0, exclude=True)
    vlan_id: _StrictInt = Field(ge=1, le=4095)
    independent_learning: _StrictBool
    igmp_snooping: _StrictBool
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
