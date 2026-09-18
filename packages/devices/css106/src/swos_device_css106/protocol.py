"""Independent decoder for the compact CSS106 wire representation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from ipaddress import IPv4Address
from math import floor, log10
from string import hexdigits
from typing import Any, NoReturn, TypeAlias, TypeVar
from unicodedata import category

from pydantic import ValidationError
from swos_core.errors import InvalidOperationError, ProtocolError
from swos_core.models import (
    AclRule,
    AclVlanTagMode,
    AddressMode,
    DeviceIdentity,
    ForwardingInfo,
    ForwardingMatrixUpdate,
    ForwardingMirroringUpdate,
    ForwardingPortPolicyUpdate,
    HostEntry,
    HostEntryType,
    IgmpGroup,
    IgmpInfo,
    IgmpVersion,
    PacketSizeStatistics,
    PoeMode,
    PoeStatus,
    PortConfigurationUpdate,
    PortErrorStatistics,
    PortForwardingInfo,
    PortInfo,
    PortNameUpdate,
    PortRateStatistics,
    PortStatistics,
    PortTrafficStatistics,
    PortVlanInfo,
    PortVlanPolicyUpdate,
    RstpBridgeUpdate,
    RstpCostMode,
    RstpInfo,
    RstpPortEnableUpdate,
    RstpPortInfo,
    RstpPortType,
    RstpProtocol,
    RstpRole,
    RstpState,
    SfpInfo,
    SnmpInfo,
    SnmpMetadataUpdate,
    SystemConfigurationUpdate,
    SystemHealth,
    SystemInfo,
    SystemManagementInfo,
    VlanEgressMode,
    VlanInfo,
    VlanMembershipMode,
    VlanMode,
    VlanPortMembership,
    VlanReceiveMode,
)

SwOSValue: TypeAlias = int | str | list["SwOSValue"] | dict[str, "SwOSValue"] | None

PRODUCT_NAMES = {
    "CSS106-5G-1S": "RB260GS",
    "CSS106-1G-4P-1S": "RB260GSP",
}
PORT_COUNTS = {
    "CSS106-5G-1S": 6,
    "CSS106-1G-4P-1S": 6,
}
LINK_SPEEDS_BPS = {0: 10_000_000, 1: 100_000_000, 2: 1_000_000_000}
FORCED_LINK_SPEEDS_BPS = {0: 10_000_000, 1: 100_000_000}
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_NESTING_DEPTH = 64
MAX_NUMBER_DIGITS = 32
UPTIME_TICKS_PER_SECOND = 100
MAX_VLAN_ENTRIES = 250
MAX_ACL_RULES = 32
MAX_STATIC_HOSTS = 2048
MAX_DEVICE_NAME_BYTES = 16
MAX_PORT_NAME_BYTES = 16
MAX_SNMP_METADATA_BYTES = 64

EnumValue = TypeVar("EnumValue", bound=StrEnum)


@dataclass(frozen=True, slots=True)
class LinkWriteState:
    """Validated writable subset of a CSS106 link payload."""

    enabled_mask: int
    raw_names: tuple[str, ...]
    auto_negotiation_mask: int
    configured_speeds: tuple[int, ...]
    configured_duplex_mask: int
    flow_control_mask: int


@dataclass(frozen=True, slots=True)
class SystemConfigurationWriteState:
    """Validated complete writable CSS106 system object in UI field order."""

    address_mode: int
    static_ip: int
    admin_mac: str
    raw_name: str
    allow_from: int
    allow_prefix_length: int
    allowed_ports_mask: int
    allowed_vlan_id: int
    independent_vlan_lookup: int
    igmp_enabled: int
    igmp_querier: int
    igmp_fast_leave_mask: int
    igmp_version: int
    discovery_protocol_mask: int


@dataclass(frozen=True, slots=True)
class SnmpWriteState:
    """Validated complete writable CSS106 SNMP payload."""

    enabled: int
    raw_community: str
    raw_contact: str
    raw_location: str


@dataclass(frozen=True, slots=True)
class RstpEnableWriteState:
    """Validated complete writable CSS106 RSTP-enable group."""

    enabled_mask: int


@dataclass(frozen=True, slots=True)
class RstpBridgeWriteState:
    """Validated complete writable CSS106 bridge group."""

    bridge_priority: int
    cost_mode: int
    forward_reserved_multicast: int


@dataclass(frozen=True, slots=True)
class ForwardingWriteState:
    """Validated complete writable CSS106 forwarding group."""

    destination_masks: tuple[int, ...]
    lock_mask: int
    lock_on_first_mask: int
    mirror_ingress_mask: int
    mirror_egress_mask: int
    mirror_target_mask: int
    egress_rates: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PortVlanWriteState:
    """Validated complete writable CSS106 per-port VLAN group."""

    modes: tuple[int, ...]
    receive_modes: tuple[int, ...]
    default_vlan_ids: tuple[int, ...]
    force_vlan_id_mask: int
    egress_modes: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class VlanTableRowWriteState:
    """Validated writable values for one VLAN row in wire order."""

    vlan_id: int
    independent_learning: int
    igmp_snooping: int
    port_modes: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class VlanTableWriteState:
    """Validated complete VLAN table preserving device row order."""

    rows: tuple[VlanTableRowWriteState, ...]


def parse_payload(payload: bytes) -> dict[str, SwOSValue]:
    """Parse a CSS106 response without executing device-provided text."""

    value = _parse_value(payload)
    if not isinstance(value, dict):
        raise ProtocolError("CSS106 response must contain an object")
    return value


def parse_table_payload(payload: bytes) -> list[SwOSValue]:
    """Parse a CSS106 table response without executing device-provided text."""

    value = _parse_value(payload)
    if not isinstance(value, list):
        raise ProtocolError("CSS106 table response must contain an array")
    return value


def identity_from_system(data: dict[str, SwOSValue]) -> DeviceIdentity | None:
    """Build an identity when the system payload describes a known CSS106 product."""

    product_code = _hex_text(data, "brd")
    marketing_name = PRODUCT_NAMES.get(product_code)
    if marketing_name is None:
        return None
    build = _unsigned_32(data, "bld")
    try:
        return DeviceIdentity(
            firmware_family="css106",
            product_code=product_code,
            firmware_version=_hex_text(data, "ver"),
            marketing_name=marketing_name,
            build_id=f"0x{build:08x}",
        )
    except ValidationError as exc:
        raise ProtocolError("CSS106 identity contains invalid values") from exc


def system_info_from_payload(data: dict[str, SwOSValue], identity: DeviceIdentity) -> SystemInfo:
    """Normalize CSS106 system fields into the public core model."""

    port_count = _port_count(identity)
    address_modes = tuple(AddressMode)
    address_mode_index = _bounded_integer(data, "iptp", minimum=0, maximum=len(address_modes) - 1)
    igmp_versions = tuple(IgmpVersion)
    igmp_version_index = _bounded_integer(data, "igve", minimum=0, maximum=len(igmp_versions) - 1)
    allowed_ports = _selected_ports(data, "allp", port_count)
    fast_leave_ports = _selected_ports(data, "igfl", port_count)
    discovery_ports = _selected_ports(data, "pdsc", port_count)
    allowed_vlan = _bounded_integer(data, "avln", minimum=0, maximum=4095)
    igmp_enabled = _boolean(data, "igmp")
    querier_configured = _boolean(data, "igmq")

    health = SystemHealth()
    if identity.product_code == "CSS106-1G-4P-1S":
        health = SystemHealth(
            input_voltage_volts=_unsigned_32(data, "volt") / 10,
            temperature_celsius=_signed_low_16(data, "temp"),
            poe_in_long_cable=_boolean(data, "lcbl"),
        )

    try:
        return SystemInfo(
            identity=identity,
            name=_hex_text(data, "id"),
            uptime_seconds=_uptime_seconds(data),
            current_ip=_ip_address(data, "ip"),
            static_ip=_ip_address(data, "sip"),
            mac_address=_mac_address(data, "mac"),
            serial_number=_hex_text(data, "sid"),
            management=SystemManagementInfo(
                address_mode=address_modes[address_mode_index],
                admin_mac_address=_mac_address(data, "amac"),
                allow_from=_ip_address(data, "alla"),
                allow_prefix_length=_bounded_integer(data, "allm", minimum=0, maximum=32),
                allowed_port_numbers=allowed_ports,
                allowed_vlan_id=allowed_vlan or None,
                watchdog_enabled=_boolean(data, "wdt"),
            ),
            independent_vlan_lookup=_boolean(data, "ivl"),
            igmp=IgmpInfo(
                enabled=igmp_enabled,
                querier_configured=querier_configured,
                querier_effective=igmp_enabled and querier_configured,
                fast_leave_port_numbers=fast_leave_ports,
                version=igmp_versions[igmp_version_index],
            ),
            discovery_protocol_port_numbers=discovery_ports,
            health=health,
        )
    except ValidationError as exc:
        raise ProtocolError("CSS106 system response contains invalid values") from exc


def system_configuration_write_state_from_payload(
    data: dict[str, SwOSValue], identity: DeviceIdentity
) -> SystemConfigurationWriteState:
    """Extract and validate the complete writable CSS106 system object."""

    port_count = _port_count(identity)
    for field in ("allp", "igfl", "pdsc"):
        _bit_values(data, field, port_count)
    admin_mac = _wire_optional_mac(_mac_address(data, "amac"))
    raw_name = _string(data, "id")
    _decode_hex_text(raw_name, "id")
    igmp_enabled = int(_boolean(data, "igmp"))
    igmp_querier = int(_boolean(data, "igmq"))
    return SystemConfigurationWriteState(
        address_mode=_bounded_integer(data, "iptp", minimum=0, maximum=2),
        static_ip=_unsigned_32(data, "sip"),
        admin_mac=admin_mac,
        raw_name=raw_name.lower(),
        allow_from=_unsigned_32(data, "alla"),
        allow_prefix_length=_bounded_integer(data, "allm", minimum=0, maximum=32),
        allowed_ports_mask=_integer(data, "allp"),
        allowed_vlan_id=_bounded_integer(data, "avln", minimum=0, maximum=4095),
        independent_vlan_lookup=int(_boolean(data, "ivl")),
        igmp_enabled=igmp_enabled,
        igmp_querier=igmp_querier if igmp_enabled else 0,
        igmp_fast_leave_mask=_integer(data, "igfl"),
        igmp_version=_bounded_integer(data, "igve", minimum=0, maximum=1),
        discovery_protocol_mask=_integer(data, "pdsc"),
    )


def encode_system_configuration_update(
    data: dict[str, SwOSValue],
    identity: DeviceIdentity,
    update: SystemConfigurationUpdate,
) -> tuple[bytes, SystemConfigurationWriteState]:
    """Apply a sparse desired update to one complete preserved system object."""

    state = system_configuration_write_state_from_payload(data, identity)
    desired = state
    if update.address_mode is not None:
        desired = replace(desired, address_mode=tuple(AddressMode).index(update.address_mode))
    if update.static_ip is not None:
        desired = replace(
            desired,
            static_ip=_wire_ip(None if update.static_ip == "unset" else update.static_ip),
        )
    if update.admin_mac_address is not None:
        desired = replace(
            desired,
            admin_mac=_wire_optional_mac(
                None if update.admin_mac_address == "unset" else update.admin_mac_address
            ),
        )
    if update.name is not None:
        desired = replace(desired, raw_name=validate_device_name(update.name).hex())
    if update.allow_from is not None:
        desired = replace(
            desired,
            allow_from=_wire_ip(None if update.allow_from == "unset" else update.allow_from),
        )
    if update.allow_prefix_length is not None:
        desired = replace(desired, allow_prefix_length=update.allow_prefix_length)
    if update.allowed_port_numbers is not None:
        _validate_system_mask_ports(update.allowed_port_numbers, identity, "management allowed")
        if 6 not in update.allowed_port_numbers:
            raise InvalidOperationError("CSS106 management allowed ports must include port 6")
        desired = replace(desired, allowed_ports_mask=_port_mask(update.allowed_port_numbers))
    if update.allowed_vlan_id is not None:
        desired = replace(
            desired,
            allowed_vlan_id=0 if update.allowed_vlan_id == "unset" else update.allowed_vlan_id,
        )
    if update.independent_vlan_lookup is not None:
        desired = replace(desired, independent_vlan_lookup=int(update.independent_vlan_lookup))
    if update.igmp_enabled is not None:
        desired = replace(desired, igmp_enabled=int(update.igmp_enabled))
    if update.igmp_querier is not None:
        desired = replace(desired, igmp_querier=int(update.igmp_querier))
    if not desired.igmp_enabled:
        desired = replace(desired, igmp_querier=0)
    if update.igmp_fast_leave_port_numbers is not None:
        _validate_system_mask_ports(
            update.igmp_fast_leave_port_numbers, identity, "IGMP fast-leave"
        )
        desired = replace(
            desired,
            igmp_fast_leave_mask=_port_mask(update.igmp_fast_leave_port_numbers),
        )
    if update.igmp_version is not None:
        desired = replace(desired, igmp_version=tuple(IgmpVersion).index(update.igmp_version))
    if update.discovery_protocol_port_numbers is not None:
        _validate_system_mask_ports(
            update.discovery_protocol_port_numbers, identity, "discovery protocol"
        )
        desired = replace(
            desired,
            discovery_protocol_mask=_port_mask(update.discovery_protocol_port_numbers),
        )

    management_bit = 1 << 5
    if not desired.allowed_ports_mask & management_bit:
        raise InvalidOperationError("CSS106 management allowed ports must include port 6")
    if any(
        (before ^ after) & management_bit
        for before, after in (
            (state.allowed_ports_mask, desired.allowed_ports_mask),
            (state.igmp_fast_leave_mask, desired.igmp_fast_leave_mask),
            (state.discovery_protocol_mask, desired.discovery_protocol_mask),
        )
    ):
        raise InvalidOperationError("CSS106 system writes cannot change port 6 mask state")
    return _serialize_system_configuration_write_state(desired), desired


def validate_device_name(name: str) -> bytes:
    """Validate and encode a device name accepted by tested CSS106 firmware."""

    return _validate_printable_ascii(name, "device names", MAX_DEVICE_NAME_BYTES)


def ports_from_link_payload(
    data: dict[str, SwOSValue], identity: DeviceIdentity
) -> tuple[PortInfo, ...]:
    """Normalize CSS106 link fields into ordered public port models."""

    port_count = _port_count(identity)

    raw_names = _array(data, "nm", port_count)
    raw_speeds = _array(data, "spd", port_count)
    configured_speeds = _bounded_integer_values(
        data, "spdc", port_count, minimum=0, maximum=len(FORCED_LINK_SPEEDS_BPS) - 1
    )
    enabled = _bit_values(data, "en", port_count)
    link_up = _bit_values(data, "lnk", port_count)
    full_duplex = _bit_values(data, "dpx", port_count)
    auto_negotiation = _bit_values(data, "an", port_count)
    configured_full_duplex = _bit_values(data, "dpxc", port_count)
    flow_control = _bit_values(data, "fct", port_count)

    ports: list[PortInfo] = []
    for index in range(port_count):
        raw_name = raw_names[index]
        raw_speed = raw_speeds[index]
        if not isinstance(raw_name, str):
            raise ProtocolError(f"CSS106 field 'nm[{index}]' must be a string")
        if not isinstance(raw_speed, int):
            raise ProtocolError(f"CSS106 field 'spd[{index}]' must be an integer")
        speed_bps = None
        duplex = None
        if link_up[index]:
            try:
                speed_bps = LINK_SPEEDS_BPS[raw_speed]
            except KeyError as exc:
                raise ProtocolError(
                    f"CSS106 field 'spd[{index}]' has unknown link speed {raw_speed}"
                ) from exc
            duplex = full_duplex[index]
        try:
            ports.append(
                PortInfo(
                    number=index + 1,
                    name=_decode_hex_text(raw_name, f"nm[{index}]"),
                    enabled=enabled[index],
                    link_up=link_up[index],
                    speed_bps=speed_bps,
                    full_duplex=duplex,
                    auto_negotiation=auto_negotiation[index],
                    configured_speed_bps=FORCED_LINK_SPEEDS_BPS[configured_speeds[index]],
                    configured_full_duplex=configured_full_duplex[index],
                    flow_control=flow_control[index],
                    **_poe_port_fields(data, identity, index, port_count),
                )
            )
        except ValidationError as exc:
            raise ProtocolError(f"CSS106 port {index + 1} contains invalid values") from exc
    return tuple(ports)


def link_write_state_from_payload(
    data: dict[str, SwOSValue], identity: DeviceIdentity
) -> LinkWriteState:
    """Extract and validate exactly the writable CSS106 link fields."""

    port_count = _port_count(identity)
    raw_names = _array(data, "nm", port_count)
    names: list[str] = []
    for index, raw_name in enumerate(raw_names):
        if not isinstance(raw_name, str):
            raise ProtocolError(f"CSS106 field 'nm[{index}]' must be a string")
        _decode_hex_text(raw_name, f"nm[{index}]")
        names.append(raw_name)

    masks: dict[str, int] = {}
    for field in ("en", "an", "dpxc", "fct"):
        _bit_values(data, field, port_count)
        masks[field] = _integer(data, field)

    return LinkWriteState(
        enabled_mask=masks["en"],
        raw_names=tuple(names),
        auto_negotiation_mask=masks["an"],
        configured_speeds=_bounded_integer_values(
            data,
            "spdc",
            port_count,
            minimum=0,
            maximum=len(FORCED_LINK_SPEEDS_BPS) - 1,
        ),
        configured_duplex_mask=masks["dpxc"],
        flow_control_mask=masks["fct"],
    )


def encode_port_name_update(
    data: dict[str, SwOSValue], identity: DeviceIdentity, update: PortNameUpdate
) -> tuple[bytes, LinkWriteState]:
    """Encode a complete CSS106 link write with only one changed port name."""

    encoded_name = validate_port_name(update.name)
    state = link_write_state_from_payload(data, identity)
    _validate_writable_port(update.number, identity)

    names = list(state.raw_names)
    names[update.number - 1] = encoded_name.hex()
    desired = replace(state, raw_names=tuple(names))
    return _serialize_link_write_state(desired), desired


def encode_port_configuration_update(
    data: dict[str, SwOSValue],
    identity: DeviceIdentity,
    update: PortConfigurationUpdate,
) -> tuple[bytes, LinkWriteState]:
    """Encode a complete link write while changing only one Ethernet port."""

    state = link_write_state_from_payload(data, identity)
    _validate_writable_port(update.number, identity)
    bit = 1 << (update.number - 1)
    desired = state

    if update.enabled is not None:
        enabled_mask = state.enabled_mask | bit if update.enabled else state.enabled_mask & ~bit
        desired = replace(desired, enabled_mask=enabled_mask)

    if update.negotiation == "auto":
        desired = replace(desired, auto_negotiation_mask=state.auto_negotiation_mask | bit)
    elif update.negotiation is not None:
        try:
            speed_code = {speed: code for code, speed in FORCED_LINK_SPEEDS_BPS.items()}[
                update.negotiation.speed_bps
            ]
        except KeyError as exc:
            raise InvalidOperationError(
                "CSS106 forced speed must be 10000000 or 100000000 bps"
            ) from exc
        speeds = list(state.configured_speeds)
        speeds[update.number - 1] = speed_code
        duplex_mask = (
            state.configured_duplex_mask | bit
            if update.negotiation.duplex == "full"
            else state.configured_duplex_mask & ~bit
        )
        desired = replace(
            desired,
            auto_negotiation_mask=state.auto_negotiation_mask & ~bit,
            configured_speeds=tuple(speeds),
            configured_duplex_mask=duplex_mask,
        )

    if update.flow_control is not None:
        flow_control_mask = (
            state.flow_control_mask | bit if update.flow_control else state.flow_control_mask & ~bit
        )
        desired = replace(desired, flow_control_mask=flow_control_mask)

    return _serialize_link_write_state(desired), desired


def validate_port_name(name: str) -> bytes:
    """Validate and encode a port name accepted by tested CSS106 firmware."""

    return _validate_printable_ascii(name, "port names", MAX_PORT_NAME_BYTES)


def port_statistics_from_payload(
    data: dict[str, SwOSValue], identity: DeviceIdentity
) -> tuple[PortStatistics, ...]:
    """Normalize the complete CSS106 port statistics response."""

    port_count = _port_count(identity)

    rx_rate_raw = _uint32_values(data, "rrb", port_count)
    tx_rate_raw = _uint32_values(data, "trb", port_count)
    rx_packet_rate_raw = _uint32_values(data, "rrp", port_count)
    tx_packet_rate_raw = _uint32_values(data, "trp", port_count)
    rx_bytes = _wide_counter_values(data, "rb", "rbh", port_count)
    tx_bytes = _wide_counter_values(data, "tb", "tbh", port_count)
    rx_packets = _uint32_values(data, "rtp", port_count)
    tx_packets = _uint32_values(data, "ttp", port_count)
    rx_errors = _uint32_values(data, "rte", port_count)
    tx_errors = _uint32_values(data, "tte", port_count)
    traffic_fields = {
        name: _wide_counter_values(data, low, high, port_count)
        for name, low, high in (
            ("rx_unicast_packets", "rup", "ruph"),
            ("tx_unicast_packets", "tup", "tuph"),
            ("rx_broadcast_packets", "rbp", "rbph"),
            ("tx_broadcast_packets", "tbp", "tbph"),
            ("rx_multicast_packets", "rmp", "rmph"),
            ("tx_multicast_packets", "tmp", "tmph"),
        )
    }
    rx_sizes = _packet_size_values(data, "r", port_count)
    tx_sizes = _packet_size_values(data, "t", port_count)
    error_fields = {
        name: _uint32_values(data, field, port_count)
        for name, field in (
            ("rx_pause_frames", "rpp"),
            ("rx_fcs_errors", "rfcs"),
            ("rx_alignment_errors", "rae"),
            ("rx_runts", "rr"),
            ("rx_fragments", "fr"),
            ("rx_too_long", "rtl"),
            ("rx_overflows", "rov"),
            ("tx_pause_frames", "tpp"),
            ("tx_underruns", "tur"),
            ("tx_too_long", "ttl"),
            ("tx_collisions", "tcl"),
            ("tx_excessive_collisions", "tec"),
            ("tx_multiple_collisions", "tmc"),
            ("tx_single_collisions", "tsc"),
            ("tx_excessive_deferred", "ted"),
            ("tx_deferred", "tdf"),
            ("tx_late_collisions", "tlc"),
        )
    }
    return tuple(
        PortStatistics(
            number=index + 1,
            rx_bytes=rx_bytes[index],
            tx_bytes=tx_bytes[index],
            rx_packets=rx_packets[index],
            tx_packets=tx_packets[index],
            rx_errors=rx_errors[index],
            tx_errors=tx_errors[index],
            rates=PortRateStatistics(
                rx_bits_per_second=rx_rate_raw[index] / 0.08,
                tx_bits_per_second=tx_rate_raw[index] / 0.08,
                rx_packets_per_second=rx_packet_rate_raw[index] / 0.64,
                tx_packets_per_second=tx_packet_rate_raw[index] / 0.64,
            ),
            traffic=PortTrafficStatistics(
                **{name: values[index] for name, values in traffic_fields.items()}
            ),
            rx_sizes=PacketSizeStatistics(
                **{name: values[index] for name, values in rx_sizes.items()}
            ),
            tx_sizes=PacketSizeStatistics(
                **{name: values[index] for name, values in tx_sizes.items()}
            ),
            detailed_errors=PortErrorStatistics(
                **{name: values[index] for name, values in error_fields.items()}
            ),
        )
        for index in range(port_count)
    )


def static_hosts_from_payload(
    rows: list[SwOSValue], identity: DeviceIdentity
) -> tuple[HostEntry, ...]:
    """Normalize configured static CSS106 forwarding entries."""

    if len(rows) > MAX_STATIC_HOSTS:
        raise ProtocolError(f"CSS106 static host table exceeds {MAX_STATIC_HOSTS} entries")
    try:
        port_count = PORT_COUNTS[identity.product_code]
    except KeyError as exc:
        raise ProtocolError(f"Unknown CSS106 product {identity.product_code!r}") from exc

    hosts: list[HostEntry] = []
    seen: set[tuple[str, int]] = set()
    for row_index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ProtocolError(f"CSS106 static host row {row_index} must be an object")
        ports = _bit_values(row, "prt", port_count)
        try:
            host = HostEntry(
                entry_type=HostEntryType.STATIC,
                mac_address=_required_mac_address(row, "adr"),
                vlan_id=_bounded_integer(row, "vid", minimum=1, maximum=4095),
                port_numbers=tuple(index + 1 for index, selected in enumerate(ports) if selected),
                drop=_boolean(row, "drp"),
                mirror=_boolean(row, "mir"),
            )
        except ValidationError as exc:
            raise ProtocolError(
                f"CSS106 static host row {row_index} contains invalid values"
            ) from exc
        if host.vlan_id is None:
            raise ProtocolError(f"CSS106 static host row {row_index} requires a VLAN ID")
        key = (host.mac_address, host.vlan_id)
        if key in seen:
            raise ProtocolError(
                f"CSS106 static host table contains duplicate {host.mac_address} "
                f"VLAN {host.vlan_id}"
            )
        seen.add(key)
        hosts.append(host)
    return tuple(hosts)


def encode_static_hosts(hosts: tuple[HostEntry, ...], identity: DeviceIdentity) -> bytes:
    """Validate and encode the complete ordered CSS106 static host table."""

    _port_count(identity)
    if len(hosts) > MAX_STATIC_HOSTS:
        raise InvalidOperationError(
            f"CSS106 static host table cannot exceed {MAX_STATIC_HOSTS} entries"
        )
    seen: set[tuple[str, int]] = set()
    rows: list[str] = []
    for index, host in enumerate(hosts):
        try:
            validated = HostEntry.model_validate(host.model_dump(mode="python"))
        except ValidationError as exc:
            raise InvalidOperationError(
                f"Static host replacement row {index + 1} is invalid: {exc}"
            ) from exc
        if validated != host:
            raise InvalidOperationError(
                f"Static host replacement row {index + 1} is not normalized"
            )
        if host.entry_type is not HostEntryType.STATIC:
            raise InvalidOperationError(
                f"Static host replacement row {index + 1} cannot be dynamic"
            )
        if host.vlan_id is None:
            raise InvalidOperationError(
                f"Static host replacement row {index + 1} requires a VLAN ID"
            )
        _validate_table_ports(host.port_numbers, 5, f"Static host replacement row {index + 1}")
        key = (host.mac_address, host.vlan_id)
        if key in seen:
            raise InvalidOperationError(
                f"Static host replacement contains duplicate {host.mac_address} VLAN {host.vlan_id}"
            )
        seen.add(key)
        rows.append(
            f"{{prt:0x{_port_mask(host.port_numbers):02x},"
            f"adr:'{host.mac_address.replace(':', '')}',vid:0x{host.vlan_id:04x},"
            f"drp:0x{int(host.drop):02x},mir:0x{int(host.mirror):02x}}}"
        )
    return f"[{','.join(rows)}]".encode("ascii")


def dynamic_hosts_from_payload(
    rows: list[SwOSValue], identity: DeviceIdentity
) -> tuple[HostEntry, ...]:
    """Normalize dynamically learned CSS106 forwarding entries."""

    try:
        port_count = PORT_COUNTS[identity.product_code]
    except KeyError as exc:
        raise ProtocolError(f"Unknown CSS106 product {identity.product_code!r}") from exc

    hosts: list[HostEntry] = []
    for row_index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ProtocolError(f"CSS106 dynamic host row {row_index} must be an object")
        port_index = _bounded_integer(row, "prt", minimum=0, maximum=port_count - 1)
        vlan_id = _bounded_integer(row, "vid", minimum=0, maximum=4095)
        try:
            hosts.append(
                HostEntry(
                    entry_type=HostEntryType.DYNAMIC,
                    mac_address=_required_mac_address(row, "adr"),
                    vlan_id=vlan_id or None,
                    port_numbers=(port_index + 1,),
                )
            )
        except ValidationError as exc:
            raise ProtocolError(
                f"CSS106 dynamic host row {row_index} contains invalid values"
            ) from exc
    return tuple(hosts)


def rstp_from_payloads(
    rstp_data: dict[str, SwOSValue],
    system_data: dict[str, SwOSValue],
    identity: DeviceIdentity,
) -> RstpInfo:
    """Normalize CSS106 bridge and per-port spanning-tree state."""

    try:
        port_count = PORT_COUNTS[identity.product_code]
    except KeyError as exc:
        raise ProtocolError(f"Unknown CSS106 product {identity.product_code!r}") from exc

    enabled = _bit_values(rstp_data, "ena", port_count)
    rstp_protocol = _bit_values(rstp_data, "rstp", port_count)
    point_to_point = _bit_values(rstp_data, "p2p", port_count)
    edge = _bit_values(rstp_data, "edge", port_count)
    learning = _bit_values(rstp_data, "lrn", port_count)
    forwarding = _bit_values(rstp_data, "fwd", port_count)
    roles = _enum_values(rstp_data, "role", port_count, RstpRole)
    root_path_costs = _uint32_values(rstp_data, "rpc", port_count)
    configured_path_costs = _uint32_values(rstp_data, "cst", port_count)
    cost_modes = tuple(RstpCostMode)
    cost_mode_index = _bounded_integer(system_data, "cost", minimum=0, maximum=len(cost_modes) - 1)

    try:
        return RstpInfo(
            bridge_priority=_bounded_integer(system_data, "prio", minimum=0, maximum=0xFFFF),
            cost_mode=cost_modes[cost_mode_index],
            forward_reserved_multicast=_boolean(system_data, "frmc"),
            root_bridge_priority=_bounded_integer(system_data, "rpr", minimum=0, maximum=0xFFFF),
            root_bridge_mac=_wire_mac_address(system_data, "rmac"),
            ports=tuple(
                RstpPortInfo(
                    number=index + 1,
                    enabled=enabled[index],
                    protocol=RstpProtocol.RSTP if rstp_protocol[index] else RstpProtocol.STP,
                    role=roles[index],
                    root_path_cost=root_path_costs[index],
                    configured_path_cost=configured_path_costs[index],
                    point_to_point=point_to_point[index],
                    edge=edge[index],
                    port_type=(
                        RstpPortType.EDGE
                        if edge[index]
                        else RstpPortType.POINT_TO_POINT
                        if point_to_point[index]
                        else RstpPortType.SHARED
                    ),
                    state=(
                        RstpState.FORWARDING
                        if forwarding[index]
                        else RstpState.LEARNING
                        if learning[index]
                        else RstpState.DISCARDING
                    ),
                )
                for index in range(port_count)
            ),
        )
    except ValidationError as exc:
        raise ProtocolError("CSS106 RSTP response contains invalid values") from exc


def rstp_enable_write_state_from_payload(
    data: dict[str, SwOSValue], identity: DeviceIdentity
) -> RstpEnableWriteState:
    """Extract and validate the complete writable RSTP-enable group."""

    port_count = _port_count(identity)
    _bit_values(data, "ena", port_count)
    return RstpEnableWriteState(enabled_mask=_integer(data, "ena"))


def encode_rstp_port_enable_update(
    data: dict[str, SwOSValue],
    identity: DeviceIdentity,
    update: RstpPortEnableUpdate,
) -> tuple[bytes, RstpEnableWriteState]:
    """Encode the complete RSTP-enable group while preserving management port 6."""

    state = rstp_enable_write_state_from_payload(data, identity)
    _validate_writable_port(update.number, identity)
    bit = 1 << (update.number - 1)
    enabled_mask = state.enabled_mask | bit if update.enabled else state.enabled_mask & ~bit
    desired = replace(state, enabled_mask=enabled_mask)
    if (state.enabled_mask ^ desired.enabled_mask) & (1 << 5):
        raise InvalidOperationError("CSS106 RSTP writes cannot change management port 6")
    return _serialize_rstp_enable_write_state(desired), desired


def rstp_bridge_write_state_from_payload(data: dict[str, SwOSValue]) -> RstpBridgeWriteState:
    """Extract and validate the complete writable bridge group."""

    cost_modes = tuple(RstpCostMode)
    return RstpBridgeWriteState(
        bridge_priority=_bounded_integer(data, "prio", minimum=0, maximum=0xFFFF),
        cost_mode=_bounded_integer(data, "cost", minimum=0, maximum=len(cost_modes) - 1),
        forward_reserved_multicast=int(_boolean(data, "frmc")),
    )


def encode_rstp_bridge_update(
    data: dict[str, SwOSValue], update: RstpBridgeUpdate
) -> tuple[bytes, RstpBridgeWriteState]:
    """Encode the complete bridge group while preserving omitted settings."""

    state = rstp_bridge_write_state_from_payload(data)
    cost_modes = tuple(RstpCostMode)
    desired = replace(
        state,
        bridge_priority=(
            state.bridge_priority if update.bridge_priority is None else update.bridge_priority
        ),
        cost_mode=(
            state.cost_mode if update.cost_mode is None else cost_modes.index(update.cost_mode)
        ),
        forward_reserved_multicast=(
            state.forward_reserved_multicast
            if update.forward_reserved_multicast is None
            else int(update.forward_reserved_multicast)
        ),
    )
    return _serialize_rstp_bridge_write_state(desired), desired


def snmp_from_payload(data: dict[str, SwOSValue]) -> SnmpInfo:
    """Normalize CSS106 SNMP service fields."""

    try:
        return SnmpInfo(
            enabled=_boolean(data, "en"),
            community=_hex_text(data, "com"),
            contact=_hex_text(data, "ci"),
            location=_hex_text(data, "loc"),
        )
    except ValidationError as exc:
        raise ProtocolError("CSS106 SNMP response contains invalid values") from exc


def snmp_write_state_from_payload(data: dict[str, SwOSValue]) -> SnmpWriteState:
    """Extract and validate every writable CSS106 SNMP field."""

    snmp_from_payload(data)
    return SnmpWriteState(
        enabled=_integer(data, "en"),
        raw_community=_string(data, "com"),
        raw_contact=_string(data, "ci"),
        raw_location=_string(data, "loc"),
    )


def encode_snmp_metadata_update(
    data: dict[str, SwOSValue], update: SnmpMetadataUpdate
) -> tuple[bytes, SnmpWriteState]:
    """Encode a complete SNMP write while preserving service and community fields."""

    state = snmp_write_state_from_payload(data)
    contact = (
        state.raw_contact
        if update.contact is None
        else validate_snmp_metadata(update.contact, "contact").hex()
    )
    location = (
        state.raw_location
        if update.location is None
        else validate_snmp_metadata(update.location, "location").hex()
    )
    desired = replace(state, raw_contact=contact, raw_location=location)
    return _serialize_snmp_write_state(desired), desired


def validate_snmp_metadata(value: str, field: str) -> bytes:
    """Validate and encode writable CSS106 SNMP metadata."""

    return _validate_printable_ascii(value, f"SNMP {field}", MAX_SNMP_METADATA_BYTES)


def sfp_from_payload(data: dict[str, SwOSValue]) -> SfpInfo:
    """Normalize CSS106 SFP EEPROM identity and diagnostics."""

    text = {
        "vendor": _optional_hex_text(data, "vnd"),
        "part_number": _optional_hex_text(data, "pnr"),
        "revision": _optional_hex_text(data, "rev"),
        "serial_number": _optional_hex_text(data, "ser"),
        "manufacturing_date": _optional_hex_text(data, "dat"),
        "media_type": _optional_hex_text(data, "typ"),
    }
    if text["media_type"] is not None:
        text["media_type"] = {
            "&mmf": "multi-mode fiber",
            "&smf": "single-mode fiber",
            "&f": "fiber",
        }.get(text["media_type"], text["media_type"])
    present = any(value is not None for value in text.values())
    raw_temperature = _signed_low_16(data, "tmp")
    raw_voltage = _unsigned_32(data, "vcc")
    raw_bias = _unsigned_32(data, "tbs")
    raw_tx_power = _unsigned_32(data, "tpw")
    raw_rx_power = _unsigned_32(data, "rpw")

    try:
        return SfpInfo(
            **text,
            temperature_celsius=(
                None if not present or raw_temperature == -128 else raw_temperature
            ),
            supply_voltage_volts=raw_voltage / 1000 if present else None,
            tx_bias_ma=raw_bias if present else None,
            tx_power_dbm=_optical_power_dbm(raw_tx_power) if present else None,
            rx_power_dbm=_optical_power_dbm(raw_rx_power) if present else None,
        )
    except ValidationError as exc:
        raise ProtocolError("CSS106 SFP response contains invalid values") from exc


def forwarding_from_payload(data: dict[str, SwOSValue], identity: DeviceIdentity) -> ForwardingInfo:
    """Normalize CSS106 forwarding, lock, mirroring, and egress-rate policy."""

    port_count = _port_count(identity)
    destination_ports = tuple(
        _selected_ports(data, f"fp{index + 1}", port_count) for index in range(port_count)
    )
    locked = _bit_values(data, "lck", port_count)
    lock_on_first = _bit_values(data, "lckf", port_count)
    mirror_ingress = _bit_values(data, "imr", port_count)
    mirror_egress = _bit_values(data, "omr", port_count)
    egress_rates = _uint32_values(data, "or", port_count)
    mirror_targets = _selected_ports(data, "mrto", port_count)
    if len(mirror_targets) > 1:
        raise ProtocolError("CSS106 field 'mrto' must select at most one mirror target")

    try:
        return ForwardingInfo(
            mirror_target_port=mirror_targets[0] if mirror_targets else None,
            ports=tuple(
                PortForwardingInfo(
                    number=index + 1,
                    destination_port_numbers=destination_ports[index],
                    lock=locked[index],
                    lock_on_first=lock_on_first[index],
                    mirror_ingress=mirror_ingress[index],
                    mirror_egress=mirror_egress[index],
                    egress_rate_limit_bps=egress_rates[index] or None,
                )
                for index in range(port_count)
            ),
        )
    except ValidationError as exc:
        raise ProtocolError("CSS106 forwarding response contains invalid values") from exc


def forwarding_write_state_from_payload(
    data: dict[str, SwOSValue], identity: DeviceIdentity
) -> ForwardingWriteState:
    """Extract and validate the complete writable CSS106 forwarding group."""

    port_count = _port_count(identity)
    destination_masks: list[int] = []
    for index in range(port_count):
        field = f"fp{index + 1}"
        _bit_values(data, field, port_count)
        destination_masks.append(_integer(data, field))
    masks: dict[str, int] = {}
    for field in ("lck", "lckf", "imr", "omr", "mrto"):
        _bit_values(data, field, port_count)
        masks[field] = _integer(data, field)
    if masks["mrto"].bit_count() > 1:
        raise ProtocolError("CSS106 field 'mrto' must select at most one mirror target")
    return ForwardingWriteState(
        destination_masks=tuple(destination_masks),
        lock_mask=masks["lck"],
        lock_on_first_mask=masks["lckf"],
        mirror_ingress_mask=masks["imr"],
        mirror_egress_mask=masks["omr"],
        mirror_target_mask=masks["mrto"],
        egress_rates=_uint32_values(data, "or", port_count),
    )


def encode_forwarding_port_policy_update(
    data: dict[str, SwOSValue],
    identity: DeviceIdentity,
    update: ForwardingPortPolicyUpdate,
) -> tuple[bytes, ForwardingWriteState]:
    """Encode a complete forwarding group with only safe per-port policy changes."""

    state = forwarding_write_state_from_payload(data, identity)
    _validate_forwarding_write_safety(state)
    _validate_writable_port(update.number, identity)
    bit = 1 << (update.number - 1)
    desired = state
    if update.lock is not None:
        desired = replace(
            desired,
            lock_mask=state.lock_mask | bit if update.lock else state.lock_mask & ~bit,
        )
    if update.lock_on_first is not None:
        desired = replace(
            desired,
            lock_on_first_mask=(
                state.lock_on_first_mask | bit
                if update.lock_on_first
                else state.lock_on_first_mask & ~bit
            ),
        )
    if update.egress_rate_limit_bps is not None:
        rates = list(state.egress_rates)
        rates[update.number - 1] = (
            0 if update.egress_rate_limit_bps == "unlimited" else update.egress_rate_limit_bps
        )
        desired = replace(desired, egress_rates=tuple(rates))
    return _serialize_forwarding_write_state(desired), desired


def encode_forwarding_matrix_update(
    data: dict[str, SwOSValue],
    identity: DeviceIdentity,
    update: ForwardingMatrixUpdate,
) -> tuple[bytes, ForwardingWriteState]:
    """Encode one matrix row without changing any relationship involving port 6."""

    state = forwarding_write_state_from_payload(data, identity)
    _validate_forwarding_write_safety(state)
    _validate_writable_port(update.number, identity)
    port_count = _port_count(identity)
    _validate_table_ports(
        update.destination_port_numbers,
        port_count,
        f"Forwarding source port {update.number}",
    )
    masks = list(state.destination_masks)
    new_mask = _port_mask(update.destination_port_numbers)
    if (masks[update.number - 1] ^ new_mask) & (1 << 5):
        raise InvalidOperationError(
            "CSS106 forwarding writes cannot alter a destination relationship involving port 6"
        )
    masks[update.number - 1] = new_mask
    desired = replace(state, destination_masks=tuple(masks))
    return _serialize_forwarding_write_state(desired), desired


def encode_forwarding_mirroring_update(
    data: dict[str, SwOSValue],
    identity: DeviceIdentity,
    update: ForwardingMirroringUpdate,
) -> tuple[bytes, ForwardingWriteState]:
    """Encode complete mirroring state while excluding management port 6."""

    state = forwarding_write_state_from_payload(data, identity)
    _validate_forwarding_write_safety(state)
    _validate_writable_port(update.source_port_number, identity)
    bit = 1 << (update.source_port_number - 1)
    desired = state
    if update.mirror_ingress is not None:
        desired = replace(
            desired,
            mirror_ingress_mask=(
                state.mirror_ingress_mask | bit
                if update.mirror_ingress
                else state.mirror_ingress_mask & ~bit
            ),
        )
    if update.mirror_egress is not None:
        desired = replace(
            desired,
            mirror_egress_mask=(
                state.mirror_egress_mask | bit
                if update.mirror_egress
                else state.mirror_egress_mask & ~bit
            ),
        )
    if update.mirror_target_port is not None:
        target_mask = 0
        if update.mirror_target_port != "none":
            _validate_writable_port(update.mirror_target_port, identity)
            target_mask = 1 << (update.mirror_target_port - 1)
        desired = replace(desired, mirror_target_mask=target_mask)
    return _serialize_forwarding_write_state(desired), desired


def igmp_groups_from_payload(
    rows: list[SwOSValue], identity: DeviceIdentity
) -> tuple[IgmpGroup, ...]:
    """Normalize dynamically learned CSS106 multicast groups."""

    port_count = _port_count(identity)
    groups: list[IgmpGroup] = []
    for row_index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ProtocolError(f"CSS106 IGMP row {row_index} must be an object")
        try:
            groups.append(
                IgmpGroup(
                    address=_required_ip_address(row, "addr"),
                    vlan_id=_bounded_integer(row, "vlan", minimum=1, maximum=4095),
                    port_numbers=_selected_ports(row, "prts", port_count),
                )
            )
        except ValidationError as exc:
            raise ProtocolError(f"CSS106 IGMP row {row_index} contains invalid values") from exc
    return tuple(groups)


def acl_rules_from_payload(rows: list[SwOSValue], identity: DeviceIdentity) -> tuple[AclRule, ...]:
    """Normalize ordered CSS106 access-control rules."""

    port_count = _port_count(identity)
    if len(rows) > MAX_ACL_RULES:
        raise ProtocolError(f"CSS106 ACL table exceeds {MAX_ACL_RULES} entries")
    tag_modes = tuple(AclVlanTagMode)
    rules: list[AclRule] = []
    for row_index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ProtocolError(f"CSS106 ACL row {row_index} must be an object")
        tag_index = _bounded_integer(row, "vlan", minimum=0, maximum=len(tag_modes) - 1)
        priority = _bounded_integer(row, "prio", minimum=0, maximum=8)
        dscp = _bounded_integer(row, "dscp", minimum=0, maximum=64)
        redirect_enabled = _boolean(row, "snde")
        redirect_ports = _selected_ports(row, "snd", port_count)
        rate = _unsigned_32(row, "rate")
        set_vlan_id = _bounded_integer(row, "svid", minimum=0, maximum=4095)
        set_priority = _bounded_integer(row, "spri", minimum=0, maximum=8)
        try:
            rules.append(
                AclRule(
                    number=row_index + 1,
                    ingress_port_numbers=_selected_ports(row, "frm", port_count),
                    source_mac=_mac_address(row, "smac"),
                    source_mac_mask=_wire_mac_address(row, "smsk"),
                    destination_mac=_mac_address(row, "dmac"),
                    destination_mac_mask=_wire_mac_address(row, "dmsk"),
                    ether_type=_bounded_integer(row, "et", minimum=0, maximum=0xFFFF),
                    vlan_tag=tag_modes[tag_index],
                    vlan_id_min=_bounded_integer(row, "vidl", minimum=0, maximum=4095),
                    vlan_id_max=_bounded_integer(row, "vidh", minimum=0, maximum=4095),
                    vlan_priority=None if priority == 8 else priority,
                    source_ip=_ip_address(row, "sip"),
                    source_prefix_length=_bounded_integer(row, "sipm", minimum=0, maximum=32),
                    source_port_min=_bounded_integer(row, "sptl", minimum=0, maximum=0xFFFF),
                    source_port_max=_bounded_integer(row, "spth", minimum=0, maximum=0xFFFF),
                    destination_ip=_ip_address(row, "dip"),
                    destination_prefix_length=_bounded_integer(row, "dipm", minimum=0, maximum=32),
                    destination_port_min=_bounded_integer(row, "dptl", minimum=0, maximum=0xFFFF),
                    destination_port_max=_bounded_integer(row, "dpth", minimum=0, maximum=0xFFFF),
                    protocol_number=_bounded_integer(row, "prot", minimum=0, maximum=0xFF),
                    dscp=None if dscp == 64 else dscp,
                    redirect_enabled=redirect_enabled,
                    redirect_port_numbers=redirect_ports,
                    drop=redirect_enabled and not redirect_ports,
                    mirror=_boolean(row, "mirr"),
                    ingress_rate_limit_bps=rate or None,
                    set_vlan_id=set_vlan_id or None,
                    set_vlan_priority=None if set_priority == 8 else set_priority,
                )
            )
        except ValidationError as exc:
            raise ProtocolError(f"CSS106 ACL row {row_index} contains invalid values") from exc
    return tuple(rules)


def encode_acl_rules(rules: tuple[AclRule, ...], identity: DeviceIdentity) -> bytes:
    """Validate and encode the complete ordered CSS106 ACL table."""

    port_count = _port_count(identity)
    if len(rules) > MAX_ACL_RULES:
        raise InvalidOperationError(f"CSS106 ACL table cannot exceed {MAX_ACL_RULES} entries")
    tag_modes = tuple(AclVlanTagMode)
    rows: list[str] = []
    for index, rule in enumerate(rules):
        try:
            validated = AclRule.model_validate(rule.model_dump(mode="python"))
        except ValidationError as exc:
            raise InvalidOperationError(
                f"ACL replacement rule {index + 1} is invalid: {exc}"
            ) from exc
        if validated != rule:
            raise InvalidOperationError(f"ACL replacement rule {index + 1} is not normalized")
        expected_number = index + 1
        if rule.number != expected_number:
            raise InvalidOperationError(
                f"ACL replacement rule numbers must be consecutive from 1; expected "
                f"{expected_number}, got {rule.number}"
            )
        _validate_table_ports(
            rule.ingress_port_numbers,
            port_count,
            f"ACL replacement rule {rule.number} ingress",
        )
        if 6 in rule.ingress_port_numbers:
            raise InvalidOperationError(
                f"ACL replacement rule {rule.number} includes protected management port 6 ingress"
            )
        _validate_table_ports(
            rule.redirect_port_numbers,
            port_count,
            f"ACL replacement rule {rule.number} redirect",
        )
        vlan_tag = tag_modes.index(rule.vlan_tag)
        rate = 0 if rule.ingress_rate_limit_bps is None else rule.ingress_rate_limit_bps
        rows.append(
            f"{{frm:0x{_port_mask(rule.ingress_port_numbers):02x},"
            f"smac:'{_wire_optional_mac(rule.source_mac)}',"
            f"smsk:'{rule.source_mac_mask.replace(':', '').lower()}',"
            f"dmac:'{_wire_optional_mac(rule.destination_mac)}',"
            f"dmsk:'{rule.destination_mac_mask.replace(':', '').lower()}',"
            f"et:0x{rule.ether_type:04x},vlan:0x{vlan_tag:02x},"
            f"vidl:0x{rule.vlan_id_min:04x},vidh:0x{rule.vlan_id_max:04x},"
            f"prio:0x{8 if rule.vlan_priority is None else rule.vlan_priority:02x},"
            f"sip:0x{_wire_ip(rule.source_ip):08x},sipm:0x{rule.source_prefix_length:02x},"
            f"sptl:0x{rule.source_port_min:04x},spth:0x{rule.source_port_max:04x},"
            f"dip:0x{_wire_ip(rule.destination_ip):08x},"
            f"dipm:0x{rule.destination_prefix_length:02x},"
            f"dptl:0x{rule.destination_port_min:04x},dpth:0x{rule.destination_port_max:04x},"
            f"prot:0x{rule.protocol_number:02x},"
            f"dscp:0x{64 if rule.dscp is None else rule.dscp:02x},"
            f"snde:0x{int(rule.redirect_enabled):02x},"
            f"snd:0x{_port_mask(rule.redirect_port_numbers):02x},"
            f"mirr:0x{int(rule.mirror):02x},"
            f"rate:0x{rate:08x},"
            f"svid:0x{0 if rule.set_vlan_id is None else rule.set_vlan_id:04x},"
            f"spri:0x{8 if rule.set_vlan_priority is None else rule.set_vlan_priority:02x}}}"
        )
    return f"[{','.join(rows)}]".encode("ascii")


def port_vlans_from_forwarding_payload(
    data: dict[str, SwOSValue], identity: DeviceIdentity
) -> tuple[PortVlanInfo, ...]:
    """Normalize per-port VLAN policy from the CSS106 forwarding endpoint."""

    try:
        port_count = PORT_COUNTS[identity.product_code]
    except KeyError as exc:
        raise ProtocolError(f"Unknown CSS106 product {identity.product_code!r}") from exc

    modes = _enum_values(data, "vlan", port_count, VlanMode)
    receive_modes = _enum_values(data, "vlni", port_count, VlanReceiveMode)
    default_vlan_ids = _bounded_integer_values(data, "dvid", port_count, minimum=1, maximum=4095)
    force_vlan_ids = _bit_values(data, "fvid", port_count)
    egress_modes = _enum_values(data, "vlnh", port_count, VlanEgressMode)

    try:
        return tuple(
            PortVlanInfo(
                number=index + 1,
                mode=modes[index],
                receive=receive_modes[index],
                default_vlan_id=default_vlan_ids[index],
                force_vlan_id=force_vlan_ids[index],
                egress=egress_modes[index],
            )
            for index in range(port_count)
        )
    except ValidationError as exc:
        raise ProtocolError("CSS106 port VLAN response contains invalid values") from exc


def port_vlan_write_state_from_payload(
    data: dict[str, SwOSValue], identity: DeviceIdentity
) -> PortVlanWriteState:
    """Extract and validate the complete writable per-port VLAN group."""

    port_count = _port_count(identity)
    _bit_values(data, "fvid", port_count)
    return PortVlanWriteState(
        modes=_bounded_integer_values(
            data, "vlan", port_count, minimum=0, maximum=len(VlanMode) - 1
        ),
        receive_modes=_bounded_integer_values(
            data, "vlni", port_count, minimum=0, maximum=len(VlanReceiveMode) - 1
        ),
        default_vlan_ids=_bounded_integer_values(data, "dvid", port_count, minimum=1, maximum=4095),
        force_vlan_id_mask=_integer(data, "fvid"),
        egress_modes=_bounded_integer_values(
            data, "vlnh", port_count, minimum=0, maximum=len(VlanEgressMode) - 1
        ),
    )


def encode_port_vlan_policy_update(
    data: dict[str, SwOSValue],
    identity: DeviceIdentity,
    update: PortVlanPolicyUpdate,
) -> tuple[bytes, PortVlanWriteState]:
    """Encode a complete VLAN group while changing only one Ethernet port."""

    state = port_vlan_write_state_from_payload(data, identity)
    _validate_writable_port(update.number, identity)
    index = update.number - 1
    desired = state
    if update.mode is not None:
        values = list(state.modes)
        values[index] = tuple(VlanMode).index(update.mode)
        desired = replace(desired, modes=tuple(values))
    if update.receive is not None:
        values = list(state.receive_modes)
        values[index] = tuple(VlanReceiveMode).index(update.receive)
        desired = replace(desired, receive_modes=tuple(values))
    if update.default_vlan_id is not None:
        values = list(state.default_vlan_ids)
        values[index] = update.default_vlan_id
        desired = replace(desired, default_vlan_ids=tuple(values))
    if update.force_vlan_id is not None:
        bit = 1 << index
        mask = (
            state.force_vlan_id_mask | bit
            if update.force_vlan_id
            else state.force_vlan_id_mask & ~bit
        )
        desired = replace(desired, force_vlan_id_mask=mask)
    if update.egress is not None:
        values = list(state.egress_modes)
        values[index] = tuple(VlanEgressMode).index(update.egress)
        desired = replace(desired, egress_modes=tuple(values))
    if _port_vlan_state_at(desired, 6) != _port_vlan_state_at(state, 6):
        raise InvalidOperationError("CSS106 VLAN policy writes cannot change management port 6")
    return _serialize_port_vlan_write_state(desired), desired


def vlans_from_payload(rows: list[SwOSValue], identity: DeviceIdentity) -> tuple[VlanInfo, ...]:
    """Normalize the configured CSS106 VLAN table."""

    state = vlan_table_write_state_from_payload(rows, identity)
    membership_modes = tuple(VlanMembershipMode)
    try:
        vlans = tuple(
            VlanInfo(
                vlan_id=row.vlan_id,
                independent_learning=bool(row.independent_learning),
                igmp_snooping=bool(row.igmp_snooping),
                ports=tuple(
                    VlanPortMembership(
                        port_number=index + 1,
                        mode=membership_modes[mode],
                    )
                    for index, mode in enumerate(row.port_modes)
                ),
            )
            for row in state.rows
        )
    except ValidationError as exc:
        raise ProtocolError("CSS106 VLAN table contains invalid values") from exc
    return tuple(sorted(vlans, key=lambda vlan: vlan.vlan_id))


def vlan_table_write_state_from_payload(
    rows: list[SwOSValue], identity: DeviceIdentity
) -> VlanTableWriteState:
    """Parse complete VLAN writable state without normalizing row order."""

    port_count = _port_count(identity)
    if len(rows) > MAX_VLAN_ENTRIES:
        raise ProtocolError(f"CSS106 VLAN table exceeds {MAX_VLAN_ENTRIES} entries")

    state_rows: list[VlanTableRowWriteState] = []
    seen_vlan_ids: set[int] = set()
    for row_index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ProtocolError(f"CSS106 VLAN row {row_index} must be an object")
        vlan_id = _bounded_integer(row, "vid", minimum=1, maximum=4095)
        if vlan_id in seen_vlan_ids:
            raise ProtocolError(f"CSS106 VLAN table contains duplicate VLAN ID {vlan_id}")
        seen_vlan_ids.add(vlan_id)
        state_rows.append(
            VlanTableRowWriteState(
                vlan_id=vlan_id,
                independent_learning=int(_boolean(row, "ivl")),
                igmp_snooping=int(_boolean(row, "igmp")),
                port_modes=_bounded_integer_values(
                    row,
                    "prt",
                    port_count,
                    minimum=0,
                    maximum=len(VlanMembershipMode) - 1,
                ),
            )
        )
    return VlanTableWriteState(rows=tuple(state_rows))


def encode_vlans(
    vlans: tuple[VlanInfo, ...],
    expected_current: tuple[VlanInfo, ...],
    identity: DeviceIdentity,
) -> bytes:
    """Validate and encode the complete VLAN table without changing port 6 membership."""

    port_count = _port_count(identity)
    if len(vlans) > MAX_VLAN_ENTRIES:
        raise InvalidOperationError(f"CSS106 VLAN table cannot exceed {MAX_VLAN_ENTRIES} entries")
    _validate_vlan_table(expected_current, port_count, "expected VLAN baseline")
    _validate_vlan_table(vlans, port_count, "VLAN replacement")

    not_member = VlanMembershipMode.NOT_MEMBER
    expected_port_6 = {vlan.vlan_id: vlan.ports[5].mode for vlan in expected_current}
    desired_port_6 = {vlan.vlan_id: vlan.ports[5].mode for vlan in vlans}
    for vlan_id in expected_port_6.keys() | desired_port_6.keys():
        if expected_port_6.get(vlan_id, not_member) != desired_port_6.get(vlan_id, not_member):
            raise InvalidOperationError(
                f"CSS106 VLAN replacement cannot change management port 6 membership "
                f"for VLAN {vlan_id}"
            )

    membership_modes = tuple(VlanMembershipMode)
    rows = []
    for vlan in vlans:
        port_modes = ",".join(f"0x{membership_modes.index(port.mode):02x}" for port in vlan.ports)
        rows.append(
            f"{{vid:0x{vlan.vlan_id:04x},ivl:0x{int(vlan.independent_learning):02x},"
            f"igmp:0x{int(vlan.igmp_snooping):02x},prt:[{port_modes}]}}"
        )
    return f"[{','.join(rows)}]".encode("ascii")


def _parse_value(payload: bytes) -> SwOSValue:
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("CSS106 response exceeds the 1 MiB safety limit")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError("CSS106 response is not ASCII") from exc
    return _Parser(text).parse()


def _port_count(identity: DeviceIdentity) -> int:
    try:
        return PORT_COUNTS[identity.product_code]
    except KeyError as exc:
        raise ProtocolError(f"Unknown CSS106 product {identity.product_code!r}") from exc


def _validate_writable_port(number: int, identity: DeviceIdentity) -> None:
    port_count = _port_count(identity)
    if number == 6 and port_count >= 6:
        raise InvalidOperationError("Port 6 is the SFP management port and cannot be modified")
    if number < 1 or number > min(5, port_count):
        raise InvalidOperationError(f"Port {number} does not exist on {identity.product_code}")


def _validate_system_mask_ports(
    port_numbers: tuple[int, ...], identity: DeviceIdentity, label: str
) -> None:
    port_count = _port_count(identity)
    if any(number > port_count for number in port_numbers):
        raise InvalidOperationError(f"CSS106 {label} ports must be between 1 and {port_count}")
    if port_numbers != tuple(sorted(port_numbers)):
        raise InvalidOperationError(f"CSS106 {label} ports must be in ascending order")


def _validate_table_ports(port_numbers: tuple[int, ...], maximum: int, label: str) -> None:
    if any(number < 1 or number > maximum for number in port_numbers):
        raise InvalidOperationError(f"{label} ports must be between 1 and {maximum}")
    if port_numbers != tuple(sorted(set(port_numbers))):
        raise InvalidOperationError(f"{label} ports must be unique and in ascending order")


def _port_mask(port_numbers: tuple[int, ...]) -> int:
    return sum(1 << (number - 1) for number in port_numbers)


def _wire_optional_mac(address: str | None) -> str:
    return "000000000000" if address is None else address.replace(":", "").lower()


def _wire_ip(address: str | None) -> int:
    if address is None:
        return 0
    return int.from_bytes(IPv4Address(address).packed, byteorder="little")


def _serialize_link_write_state(state: LinkWriteState) -> bytes:
    names = ",".join(f"'{name}'" for name in state.raw_names)
    speeds = ",".join(f"0x{speed:02x}" for speed in state.configured_speeds)
    payload = (
        f"{{en:0x{state.enabled_mask:02x},nm:[{names}],"
        f"an:0x{state.auto_negotiation_mask:02x},spdc:[{speeds}],"
        f"dpxc:0x{state.configured_duplex_mask:02x},"
        f"fct:0x{state.flow_control_mask:02x}}}"
    )
    return payload.encode("ascii")


def _serialize_system_configuration_write_state(state: SystemConfigurationWriteState) -> bytes:
    return (
        f"{{iptp:{_ui_hex(state.address_mode)},sip:{_ui_hex(state.static_ip)},"
        f"amac:'{state.admin_mac}',id:'{state.raw_name}',"
        f"alla:{_ui_hex(state.allow_from)},allm:{_ui_hex(state.allow_prefix_length)},"
        f"allp:{_ui_hex(state.allowed_ports_mask)},avln:{_ui_hex(state.allowed_vlan_id)},"
        f"ivl:{_ui_hex(state.independent_vlan_lookup)},igmp:{_ui_hex(state.igmp_enabled)},"
        f"igmq:{_ui_hex(state.igmp_querier)},igfl:{_ui_hex(state.igmp_fast_leave_mask)},"
        f"igve:{_ui_hex(state.igmp_version)},pdsc:{_ui_hex(state.discovery_protocol_mask)}}}"
    ).encode("ascii")


def _ui_hex(value: int) -> str:
    encoded = f"{value:x}"
    return "0x" + ("0" if len(encoded) % 2 else "") + encoded


def _serialize_snmp_write_state(state: SnmpWriteState) -> bytes:
    payload = (
        f"{{en:0x{state.enabled:02x},com:'{state.raw_community}',"
        f"ci:'{state.raw_contact}',loc:'{state.raw_location}'}}"
    )
    return payload.encode("ascii")


def _serialize_rstp_enable_write_state(state: RstpEnableWriteState) -> bytes:
    return f"{{ena:0x{state.enabled_mask:02x}}}".encode("ascii")


def _serialize_rstp_bridge_write_state(state: RstpBridgeWriteState) -> bytes:
    return (
        f"{{prio:0x{state.bridge_priority:04x},cost:0x{state.cost_mode:02x},"
        f"frmc:0x{state.forward_reserved_multicast:02x}}}"
    ).encode("ascii")


def _serialize_forwarding_write_state(state: ForwardingWriteState) -> bytes:
    destinations = ",".join(
        f"fp{index + 1}:0x{mask:02x}" for index, mask in enumerate(state.destination_masks)
    )
    rates = ",".join(f"0x{rate:08x}" for rate in state.egress_rates)
    return (
        f"{{{destinations},lck:0x{state.lock_mask:02x},"
        f"lckf:0x{state.lock_on_first_mask:02x},imr:0x{state.mirror_ingress_mask:02x},"
        f"omr:0x{state.mirror_egress_mask:02x},mrto:0x{state.mirror_target_mask:02x},"
        f"or:[{rates}]}}"
    ).encode("ascii")


def _serialize_port_vlan_write_state(state: PortVlanWriteState) -> bytes:
    modes = ",".join(f"0x{value:02x}" for value in state.modes)
    receive = ",".join(f"0x{value:02x}" for value in state.receive_modes)
    default_ids = ",".join(f"0x{value:04x}" for value in state.default_vlan_ids)
    egress = ",".join(f"0x{value:02x}" for value in state.egress_modes)
    return (
        f"{{vlan:[{modes}],vlni:[{receive}],dvid:[{default_ids}],"
        f"fvid:0x{state.force_vlan_id_mask:02x},vlnh:[{egress}]}}"
    ).encode("ascii")


def _port_vlan_state_at(state: PortVlanWriteState, number: int) -> tuple[int, ...]:
    index = number - 1
    return (
        state.modes[index],
        state.receive_modes[index],
        state.default_vlan_ids[index],
        int(bool(state.force_vlan_id_mask & (1 << index))),
        state.egress_modes[index],
    )


def _validate_vlan_table(vlans: tuple[VlanInfo, ...], port_count: int, label: str) -> None:
    vlan_ids = tuple(vlan.vlan_id for vlan in vlans)
    if vlan_ids != tuple(sorted(set(vlan_ids))):
        raise InvalidOperationError(f"{label} VLAN IDs must be unique and in ascending order")
    expected_ports = tuple(range(1, port_count + 1))
    for index, vlan in enumerate(vlans):
        try:
            validated = VlanInfo.model_validate(vlan.model_dump(mode="python"))
        except ValidationError as exc:
            raise InvalidOperationError(f"{label} row {index + 1} is invalid: {exc}") from exc
        if validated != vlan:
            raise InvalidOperationError(f"{label} row {index + 1} is not normalized")
        if tuple(port.port_number for port in vlan.ports) != expected_ports:
            raise InvalidOperationError(
                f"{label} VLAN {vlan.vlan_id} must declare ports 1-{port_count} in order"
            )


def _validate_forwarding_write_safety(state: ForwardingWriteState) -> None:
    management_bit = 1 << 5
    if (
        state.mirror_ingress_mask & management_bit
        or state.mirror_egress_mask & management_bit
        or state.mirror_target_mask & management_bit
    ):
        raise InvalidOperationError(
            "CSS106 forwarding writes require management port 6 to be absent from mirroring"
        )


def _validate_printable_ascii(value: str, label: str, maximum_bytes: int) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise InvalidOperationError(f"CSS106 {label} must contain printable ASCII only") from exc
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise InvalidOperationError(f"CSS106 {label} must contain printable ASCII only")
    if len(encoded) > maximum_bytes:
        raise InvalidOperationError(f"CSS106 {label} cannot exceed {maximum_bytes} characters")
    return encoded


def _selected_ports(data: dict[str, SwOSValue], field: str, port_count: int) -> tuple[int, ...]:
    return tuple(
        index + 1 for index, selected in enumerate(_bit_values(data, field, port_count)) if selected
    )


def _packet_size_values(
    data: dict[str, SwOSValue], prefix: str, port_count: int
) -> dict[str, tuple[int, ...]]:
    return {
        name: _uint32_values(data, prefix + field, port_count)
        for name, field in (
            ("frames_64_bytes", "64"),
            ("frames_65_to_127_bytes", "65"),
            ("frames_128_to_255_bytes", "128"),
            ("frames_256_to_511_bytes", "256"),
            ("frames_512_to_1023_bytes", "512"),
            ("frames_1024_to_1518_bytes", "1k"),
            ("frames_1519_to_max_bytes", "max"),
        )
    }


def _poe_port_fields(
    data: dict[str, SwOSValue], identity: DeviceIdentity, index: int, port_count: int
) -> dict[str, Any]:
    if identity.product_code != "CSS106-1G-4P-1S" or index not in range(1, 5):
        return {}
    modes = _enum_values(data, "poe", port_count, PoeMode)
    priorities = _bounded_integer_values(data, "prio", port_count, minimum=0, maximum=3)
    statuses = _enum_values(data, "poes", port_count, PoeStatus)
    currents = _uint32_values(data, "curr", port_count)
    powers = _uint32_values(data, "pwr", port_count)
    return {
        "poe_mode": modes[index],
        "poe_priority": priorities[index] + 1,
        "poe_status": statuses[index],
        "poe_current_ma": currents[index],
        "poe_power_watts": powers[index] / 10,
    }


def _signed_low_16(data: dict[str, SwOSValue], field: str) -> int:
    value = _unsigned_32(data, field) & 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def _optical_power_dbm(value: int) -> float | None:
    if value == 0:
        return None
    return floor(1000 * 10 * log10(value / 10000)) / 1000


def _integer(data: dict[str, SwOSValue], field: str) -> int:
    value = data.get(field)
    if not isinstance(value, int):
        raise ProtocolError(f"CSS106 field {field!r} must be an integer")
    return value


def _string(data: dict[str, SwOSValue], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str):
        raise ProtocolError(f"CSS106 field {field!r} must be a string")
    return value


def _array(data: dict[str, SwOSValue], field: str, length: int) -> list[SwOSValue]:
    value = data.get(field)
    if not isinstance(value, list):
        raise ProtocolError(f"CSS106 field {field!r} must be an array")
    if len(value) != length:
        raise ProtocolError(f"CSS106 field {field!r} must contain {length} values")
    return value


def _bit_values(data: dict[str, SwOSValue], field: str, count: int) -> tuple[bool, ...]:
    value = _integer(data, field)
    if value < 0 or value >> count:
        raise ProtocolError(f"CSS106 field {field!r} exceeds the {count}-port bitmask")
    return tuple(bool(value & (1 << index)) for index in range(count))


def _bounded_integer(data: dict[str, SwOSValue], field: str, *, minimum: int, maximum: int) -> int:
    value = _integer(data, field)
    if not minimum <= value <= maximum:
        raise ProtocolError(f"CSS106 field {field!r} must be between {minimum} and {maximum}")
    return value


def _bounded_integer_values(
    data: dict[str, SwOSValue],
    field: str,
    count: int,
    *,
    minimum: int,
    maximum: int,
) -> tuple[int, ...]:
    raw_values = _array(data, field, count)
    values: list[int] = []
    for index, value in enumerate(raw_values):
        if not isinstance(value, int) or not minimum <= value <= maximum:
            raise ProtocolError(
                f"CSS106 field '{field}[{index}]' must be between {minimum} and {maximum}"
            )
        values.append(value)
    return tuple(values)


def _enum_values(
    data: dict[str, SwOSValue],
    field: str,
    count: int,
    enum_type: type[EnumValue],
) -> tuple[EnumValue, ...]:
    raw_values = _array(data, field, count)
    choices = tuple(enum_type)
    values: list[EnumValue] = []
    for index, value in enumerate(raw_values):
        if not isinstance(value, int) or not 0 <= value < len(choices):
            raise ProtocolError(f"CSS106 field '{field}[{index}]' has unknown value {value!r}")
        values.append(choices[value])
    return tuple(values)


def _boolean(data: dict[str, SwOSValue], field: str) -> bool:
    value = _integer(data, field)
    if value not in (0, 1):
        raise ProtocolError(f"CSS106 field {field!r} must be 0 or 1")
    return bool(value)


def _uint32_values(data: dict[str, SwOSValue], field: str, count: int) -> tuple[int, ...]:
    raw_values = _array(data, field, count)
    values: list[int] = []
    for index, value in enumerate(raw_values):
        if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
            raise ProtocolError(
                f"CSS106 field '{field}[{index}]' must be an unsigned 32-bit integer"
            )
        values.append(value)
    return tuple(values)


def _wide_counter_values(
    data: dict[str, SwOSValue], low_field: str, high_field: str, count: int
) -> tuple[int, ...]:
    low = _uint32_values(data, low_field, count)
    high = _uint32_values(data, high_field, count)
    return tuple(low[index] | (high[index] << 32) for index in range(count))


def _unsigned_32(data: dict[str, SwOSValue], field: str) -> int:
    value = _integer(data, field)
    if not 0 <= value <= 0xFFFFFFFF:
        raise ProtocolError(f"CSS106 field {field!r} is not an unsigned 32-bit integer")
    return value


def _uptime_seconds(data: dict[str, SwOSValue]) -> int:
    return _integer(data, "upt") // UPTIME_TICKS_PER_SECOND


def _hex_text(data: dict[str, SwOSValue], field: str) -> str:
    return _decode_hex_text(_string(data, field), field)


def _optional_hex_text(data: dict[str, SwOSValue], field: str) -> str | None:
    value = _hex_text(data, field).strip()
    return value or None


def _decode_hex_text(value: str, field: str) -> str:
    try:
        decoded = bytes.fromhex(value).decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError(f"CSS106 field {field!r} is not valid hex-encoded UTF-8") from exc
    decoded = decoded.partition("\0")[0]
    if any(category(character).startswith("C") for character in decoded):
        raise ProtocolError(f"CSS106 field {field!r} contains control characters")
    return decoded


def _ip_address(data: dict[str, SwOSValue], field: str) -> str | None:
    value = _integer(data, field)
    if value == 0:
        return None
    try:
        return str(IPv4Address(value.to_bytes(4, byteorder="little")))
    except OverflowError as exc:
        raise ProtocolError(f"CSS106 field {field!r} is not an IPv4 address") from exc


def _required_ip_address(data: dict[str, SwOSValue], field: str) -> str:
    value = _ip_address(data, field)
    if value is None:
        raise ProtocolError(f"CSS106 field {field!r} cannot be the zero IPv4 address")
    return value


def _mac_address(data: dict[str, SwOSValue], field: str) -> str | None:
    value = _wire_mac_address(data, field)
    if value == "00:00:00:00:00:00":
        return None
    return value


def _wire_mac_address(data: dict[str, SwOSValue], field: str) -> str:
    value = _string(data, field).lower()
    if len(value) != 12 or any(character not in hexdigits for character in value):
        raise ProtocolError(f"CSS106 field {field!r} is not a MAC address")
    return ":".join(value[index : index + 2] for index in range(0, 12, 2))


def _required_mac_address(data: dict[str, SwOSValue], field: str) -> str:
    value = _mac_address(data, field)
    if value is None:
        raise ProtocolError(f"CSS106 field {field!r} cannot be the zero MAC address")
    return value


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0

    def parse(self) -> SwOSValue:
        value = self._value(0)
        self._whitespace()
        if self.position != len(self.text):
            self._fail("unexpected trailing data")
        return value

    def _value(self, depth: int) -> SwOSValue:
        self._whitespace()
        character = self._peek()
        if character == "{":
            return self._object(depth)
        if character == "[":
            return self._array(depth)
        if character == "'":
            return self._quoted_string()
        if character == "x":
            self.position += 1
            return None
        if character == "-" or character.isdigit():
            return self._number()
        self._fail("expected a value")

    def _object(self, depth: int) -> dict[str, SwOSValue]:
        self._check_depth(depth)
        result: dict[str, SwOSValue] = {}
        self._expect("{")
        self._whitespace()
        if self._peek() == "}":
            self.position += 1
            return result
        while True:
            key = self._identifier()
            self._expect(":")
            result[key] = self._value(depth + 1)
            self._whitespace()
            separator = self._peek()
            if separator == "}":
                self.position += 1
                return result
            self._expect(",")

    def _array(self, depth: int) -> list[SwOSValue]:
        self._check_depth(depth)
        result: list[SwOSValue] = []
        self._expect("[")
        self._whitespace()
        if self._peek() == "]":
            self.position += 1
            return result
        while True:
            result.append(self._value(depth + 1))
            self._whitespace()
            separator = self._peek()
            if separator == "]":
                self.position += 1
                return result
            self._expect(",")

    def _identifier(self) -> str:
        self._whitespace()
        start = self.position
        while (character := self._peek()) and (character.isalnum() or character in "_$"):
            self.position += 1
        if self.position == start:
            self._fail("expected an object key")
        return self.text[start : self.position]

    def _quoted_string(self) -> str:
        self._expect("'")
        result: list[str] = []
        while True:
            character = self._peek()
            if not character:
                self._fail("unterminated string")
            self.position += 1
            if character == "'":
                return "".join(result)
            if character == "\\":
                escaped = self._peek()
                if not escaped:
                    self._fail("unterminated string escape")
                self.position += 1
                result.append({"n": "\n", "r": "\r", "t": "\t"}.get(escaped, escaped))
            else:
                result.append(character)

    def _number(self) -> int:
        start = self.position
        if self._peek() == "-":
            self.position += 1
        if self.text[self.position : self.position + 2].lower() == "0x":
            self.position += 2
            digits = self.position
            while (character := self._peek()) and character in hexdigits:
                self.position += 1
            if self.position == digits:
                self._fail("expected hexadecimal digits")
            return self._parsed_integer(start, 16)
        digits = self.position
        while self._peek().isdigit():
            self.position += 1
        if self.position == digits:
            self._fail("expected decimal digits")
        return self._parsed_integer(start, 10)

    def _parsed_integer(self, start: int, base: int) -> int:
        token = self.text[start : self.position]
        digits = token.removeprefix("-")
        if digits.lower().startswith("0x"):
            digits = digits[2:]
        if len(digits) > MAX_NUMBER_DIGITS:
            self._fail("number exceeds the safety limit")
        try:
            return int(token, base)
        except ValueError as exc:
            raise ProtocolError(
                f"Invalid CSS106 response at offset {start}: invalid integer"
            ) from exc

    def _check_depth(self, depth: int) -> None:
        if depth >= MAX_NESTING_DEPTH:
            self._fail("nesting exceeds the safety limit")

    def _expect(self, expected: str) -> None:
        self._whitespace()
        if self._peek() != expected:
            self._fail(f"expected {expected!r}")
        self.position += 1

    def _whitespace(self) -> None:
        while self._peek().isspace():
            self.position += 1

    def _peek(self) -> str:
        return self.text[self.position] if self.position < len(self.text) else ""

    def _fail(self, message: str) -> NoReturn:
        raise ProtocolError(f"Invalid CSS106 response at offset {self.position}: {message}")
