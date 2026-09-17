"""Independent decoder for the compact CSS106 wire representation."""

from __future__ import annotations

from enum import StrEnum
from ipaddress import IPv4Address
from string import hexdigits
from typing import NoReturn, TypeAlias, TypeVar
from unicodedata import category

from pydantic import ValidationError
from swos_core.errors import ProtocolError
from swos_core.models import (
    DeviceIdentity,
    HostEntry,
    HostEntryType,
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
    SystemInfo,
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
LINK_SPEEDS_MBPS = {0: 10, 1: 100, 2: 1000}
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_NESTING_DEPTH = 64
MAX_NUMBER_DIGITS = 32
UPTIME_TICKS_PER_SECOND = 100
MAX_VLAN_ENTRIES = 250

EnumValue = TypeVar("EnumValue", bound=StrEnum)


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

    try:
        return SystemInfo(
            identity=identity,
            name=_hex_text(data, "id"),
            uptime_seconds=_uptime_seconds(data),
            current_ip=_ip_address(data, "ip"),
            static_ip=_ip_address(data, "sip"),
            mac_address=_mac_address(data, "mac"),
            serial_number=_hex_text(data, "sid"),
        )
    except ValidationError as exc:
        raise ProtocolError("CSS106 system response contains invalid values") from exc


def ports_from_link_payload(
    data: dict[str, SwOSValue], identity: DeviceIdentity
) -> tuple[PortInfo, ...]:
    """Normalize CSS106 link fields into ordered public port models."""

    try:
        port_count = PORT_COUNTS[identity.product_code]
    except KeyError as exc:
        raise ProtocolError(f"Unknown CSS106 product {identity.product_code!r}") from exc

    raw_names = _array(data, "nm", port_count)
    raw_speeds = _array(data, "spd", port_count)
    enabled = _bit_values(data, "en", port_count)
    link_up = _bit_values(data, "lnk", port_count)
    full_duplex = _bit_values(data, "dpx", port_count)
    auto_negotiation = _bit_values(data, "an", port_count)
    flow_control = _bit_values(data, "fct", port_count)

    ports: list[PortInfo] = []
    for index in range(port_count):
        raw_name = raw_names[index]
        raw_speed = raw_speeds[index]
        if not isinstance(raw_name, str):
            raise ProtocolError(f"CSS106 field 'nm[{index}]' must be a string")
        if not isinstance(raw_speed, int):
            raise ProtocolError(f"CSS106 field 'spd[{index}]' must be an integer")
        speed_mbps = None
        duplex = None
        if link_up[index]:
            try:
                speed_mbps = LINK_SPEEDS_MBPS[raw_speed]
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
                    speed_mbps=speed_mbps,
                    full_duplex=duplex,
                    auto_negotiation=auto_negotiation[index],
                    flow_control=flow_control[index],
                )
            )
        except ValidationError as exc:
            raise ProtocolError(f"CSS106 port {index + 1} contains invalid values") from exc
    return tuple(ports)


def port_statistics_from_payload(
    data: dict[str, SwOSValue], identity: DeviceIdentity
) -> tuple[PortStatistics, ...]:
    """Normalize cumulative CSS106 counters without interpreting live-rate fields."""

    try:
        port_count = PORT_COUNTS[identity.product_code]
    except KeyError as exc:
        raise ProtocolError(f"Unknown CSS106 product {identity.product_code!r}") from exc

    rx_bytes = _wide_counter_values(data, "rb", "rbh", port_count)
    tx_bytes = _wide_counter_values(data, "tb", "tbh", port_count)
    rx_packets = _uint32_values(data, "rtp", port_count)
    tx_packets = _uint32_values(data, "ttp", port_count)
    rx_errors = _uint32_values(data, "rte", port_count)
    tx_errors = _uint32_values(data, "tte", port_count)
    return tuple(
        PortStatistics(
            number=index + 1,
            rx_bytes=rx_bytes[index],
            tx_bytes=tx_bytes[index],
            rx_packets=rx_packets[index],
            tx_packets=tx_packets[index],
            rx_errors=rx_errors[index],
            tx_errors=tx_errors[index],
        )
        for index in range(port_count)
    )


def static_hosts_from_payload(
    rows: list[SwOSValue], identity: DeviceIdentity
) -> tuple[HostEntry, ...]:
    """Normalize configured static CSS106 forwarding entries."""

    try:
        port_count = PORT_COUNTS[identity.product_code]
    except KeyError as exc:
        raise ProtocolError(f"Unknown CSS106 product {identity.product_code!r}") from exc

    hosts: list[HostEntry] = []
    for row_index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ProtocolError(f"CSS106 static host row {row_index} must be an object")
        ports = _bit_values(row, "prt", port_count)
        try:
            hosts.append(
                HostEntry(
                    entry_type=HostEntryType.STATIC,
                    mac_address=_required_mac_address(row, "adr"),
                    vlan_id=_bounded_integer(row, "vid", minimum=1, maximum=4095),
                    port_numbers=tuple(
                        index + 1 for index, selected in enumerate(ports) if selected
                    ),
                    drop=_boolean(row, "drp"),
                    mirror=_boolean(row, "mir"),
                )
            )
        except ValidationError as exc:
            raise ProtocolError(
                f"CSS106 static host row {row_index} contains invalid values"
            ) from exc
    return tuple(hosts)


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


def vlans_from_payload(rows: list[SwOSValue], identity: DeviceIdentity) -> tuple[VlanInfo, ...]:
    """Normalize the configured CSS106 VLAN table."""

    try:
        port_count = PORT_COUNTS[identity.product_code]
    except KeyError as exc:
        raise ProtocolError(f"Unknown CSS106 product {identity.product_code!r}") from exc
    if len(rows) > MAX_VLAN_ENTRIES:
        raise ProtocolError(f"CSS106 VLAN table exceeds {MAX_VLAN_ENTRIES} entries")

    vlans: list[VlanInfo] = []
    seen_vlan_ids: set[int] = set()
    for row_index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ProtocolError(f"CSS106 VLAN row {row_index} must be an object")
        vlan_id = _bounded_integer(row, "vid", minimum=1, maximum=4095)
        if vlan_id in seen_vlan_ids:
            raise ProtocolError(f"CSS106 VLAN table contains duplicate VLAN ID {vlan_id}")
        seen_vlan_ids.add(vlan_id)
        port_modes = _enum_values(row, "prt", port_count, VlanMembershipMode)
        try:
            vlans.append(
                VlanInfo(
                    vlan_id=vlan_id,
                    independent_learning=_boolean(row, "ivl"),
                    igmp_snooping=_boolean(row, "igmp"),
                    ports=tuple(
                        VlanPortMembership(port_number=index + 1, mode=port_modes[index])
                        for index in range(port_count)
                    ),
                )
            )
        except ValidationError as exc:
            raise ProtocolError(f"CSS106 VLAN row {row_index} contains invalid values") from exc
    return tuple(sorted(vlans, key=lambda vlan: vlan.vlan_id))


def _parse_value(payload: bytes) -> SwOSValue:
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("CSS106 response exceeds the 1 MiB safety limit")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError("CSS106 response is not ASCII") from exc
    return _Parser(text).parse()


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
