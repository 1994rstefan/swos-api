"""Independent decoder for the compact CSS106 wire representation."""

from __future__ import annotations

from ipaddress import IPv4Address
from string import hexdigits
from typing import NoReturn, TypeAlias
from unicodedata import category

from pydantic import ValidationError
from swos_core.errors import ProtocolError
from swos_core.models import DeviceIdentity, SystemInfo

SwOSValue: TypeAlias = int | str | list["SwOSValue"] | dict[str, "SwOSValue"] | None

PRODUCT_NAMES = {
    "CSS106-5G-1S": "RB260GS",
    "CSS106-1G-4P-1S": "RB260GSP",
}
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_NESTING_DEPTH = 64
MAX_NUMBER_DIGITS = 32
UPTIME_TICKS_PER_SECOND = 100


def parse_payload(payload: bytes) -> dict[str, SwOSValue]:
    """Parse a CSS106 response without executing device-provided text."""

    if len(payload) > MAX_PAYLOAD_BYTES:
        raise ProtocolError("CSS106 response exceeds the 1 MiB safety limit")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError("CSS106 response is not ASCII") from exc
    value = _Parser(text).parse()
    if not isinstance(value, dict):
        raise ProtocolError("CSS106 response must contain an object")
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


def _unsigned_32(data: dict[str, SwOSValue], field: str) -> int:
    value = _integer(data, field)
    if not 0 <= value <= 0xFFFFFFFF:
        raise ProtocolError(f"CSS106 field {field!r} is not an unsigned 32-bit integer")
    return value


def _uptime_seconds(data: dict[str, SwOSValue]) -> int:
    return _integer(data, "upt") // UPTIME_TICKS_PER_SECOND


def _hex_text(data: dict[str, SwOSValue], field: str) -> str:
    value = _string(data, field)
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
    value = _string(data, field).lower()
    if value == "0" * 12:
        return None
    if len(value) != 12 or any(character not in hexdigits for character in value):
        raise ProtocolError(f"CSS106 field {field!r} is not a MAC address")
    return ":".join(value[index : index + 2] for index in range(0, 12, 2))


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
