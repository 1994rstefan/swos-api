from pathlib import Path

import pytest
from swos_core.errors import ProtocolError, UnsupportedFirmwareError
from swos_core.models import DeviceConnection
from swos_core.plugins import PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy
from swos_device_css106 import CSS106Plugin, plugin
from swos_device_css106.protocol import (
    MAX_NESTING_DEPTH,
    MAX_PAYLOAD_BYTES,
    MAX_VLAN_ENTRIES,
    UPTIME_TICKS_PER_SECOND,
    identity_from_system,
    parse_payload,
    parse_table_payload,
    port_statistics_from_payload,
    port_vlans_from_forwarding_payload,
    ports_from_link_payload,
    system_info_from_payload,
    vlans_from_payload,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sys.b"
LINK_FIXTURE = Path(__file__).parent / "fixtures" / "link.b"
STATS_FIXTURE = Path(__file__).parent / "fixtures" / "stats.b"
FORWARDING_FIXTURE = Path(__file__).parent / "fixtures" / "fwd.b"
VLAN_FIXTURE = Path(__file__).parent / "fixtures" / "vlan.b"


class FakeTransport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.requests: list[tuple[str, str]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        max_response_bytes: int | None = None,
    ) -> bytes:
        self.requests.append((method, path))
        assert max_response_bytes == MAX_PAYLOAD_BYTES
        return self.response

    def __enter__(self) -> "FakeTransport":
        return self

    def __exit__(self, *args: object) -> None:
        pass


def fixture_payload() -> bytes:
    return FIXTURE.read_bytes()


def link_fixture_payload() -> bytes:
    return LINK_FIXTURE.read_bytes()


def stats_fixture_payload() -> bytes:
    return STATS_FIXTURE.read_bytes()


def forwarding_fixture_payload() -> bytes:
    return FORWARDING_FIXTURE.read_bytes()


def vlan_fixture_payload() -> bytes:
    return VLAN_FIXTURE.read_bytes()


def test_plugin_declares_exact_hardware_validated_support() -> None:
    record = plugin.support_records()[0]

    assert plugin.family == "css106"
    assert plugin.distribution_name == "swos-device-css106"
    assert record.product_code == "CSS106-5G-1S"
    assert record.firmware_version == "2.19"
    assert record.build_id == "0x6a181cd5"


def test_installed_entry_point_is_discoverable() -> None:
    assert "css106" in PluginRegistry.discover().known_families


def test_probe_and_adapter_normalize_system_data() -> None:
    transport = FakeTransport(fixture_payload())
    tested_plugin = CSS106Plugin(transport_factory=lambda connection: transport)  # type: ignore[arg-type]
    connection = DeviceConnection(url="http://192.0.2.1")

    identity = tested_plugin.probe(connection)
    assert identity is not None
    adapter = tested_plugin.create(
        identity=identity,
        connection=connection,
        policy=FirmwareSafetyPolicy(),
        support=tested_plugin.support_records()[0],
    )
    info = adapter.get_system_info()

    assert identity.product_code == "CSS106-5G-1S"
    assert identity.marketing_name == "RB260GS"
    assert identity.firmware_version == "2.19"
    assert identity.build_id == "0x6a181cd5"
    assert info.name == "Office Switch"
    assert info.uptime_seconds == 0x0012B0F5 // UPTIME_TICKS_PER_SECOND
    assert info.current_ip == "192.168.88.1"
    assert info.static_ip == "192.168.88.1"
    assert info.mac_address == "02:00:00:00:00:01"
    assert info.serial_number == "TEST1234"
    assert transport.requests == [("GET", "/sys.b"), ("GET", "/sys.b")]


def test_adapter_normalizes_port_state() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(link_fixture_payload())
    tested_plugin = CSS106Plugin(transport_factory=lambda connection: transport)  # type: ignore[arg-type]
    adapter = tested_plugin.create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=tested_plugin.support_records()[0],
    )

    ports = adapter.get_ports()

    assert len(ports) == 6
    assert ports[0].name == "Port1"
    assert ports[0].link_up
    assert ports[0].speed_mbps == 1000
    assert ports[0].full_duplex is True
    assert ports[4].name == "Port5"
    assert not ports[4].link_up
    assert ports[4].speed_mbps is None
    assert ports[4].full_duplex is None
    assert ports[5].name == "SFP"
    assert transport.requests == [("GET", "/link.b")]


def test_port_parser_rejects_inconsistent_link_fields() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    wrong_length = parse_payload(link_fixture_payload())
    wrong_length["nm"] = ["506f727431"]
    with pytest.raises(ProtocolError, match="must contain 6 values"):
        ports_from_link_payload(wrong_length, identity)

    oversized_mask = parse_payload(link_fixture_payload())
    oversized_mask["en"] = 0x7F
    with pytest.raises(ProtocolError, match="6-port bitmask"):
        ports_from_link_payload(oversized_mask, identity)

    unknown_speed = parse_payload(link_fixture_payload())
    unknown_speed["lnk"] = 0x3F
    with pytest.raises(ProtocolError, match="unknown link speed 3"):
        ports_from_link_payload(unknown_speed, identity)


def test_port_parser_handles_supported_link_variants_and_empty_names() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    data = parse_payload(link_fixture_payload())
    names = data["nm"]
    speeds = data["spd"]
    assert isinstance(names, list)
    assert isinstance(speeds, list)
    names[0] = ""
    speeds[0] = 0
    speeds[1] = 1
    data["en"] = 0x3E
    data["an"] = 0x3E
    data["fct"] = 0x3E
    data["dpx"] = 0x2D

    ports = ports_from_link_payload(data, identity)

    assert ports[0].name == ""
    assert not ports[0].enabled
    assert ports[0].speed_mbps == 10
    assert not ports[0].auto_negotiation
    assert not ports[0].flow_control
    assert ports[1].speed_mbps == 100
    assert ports[1].full_duplex is False


def test_adapter_normalizes_cumulative_port_statistics() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(stats_fixture_payload())
    tested_plugin = CSS106Plugin(transport_factory=lambda connection: transport)  # type: ignore[arg-type]
    adapter = tested_plugin.create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=tested_plugin.support_records()[0],
    )

    statistics = adapter.get_port_statistics()

    assert len(statistics) == 6
    assert statistics[0].rx_bytes == 0x10
    assert statistics[1].rx_bytes == 0x100000020
    assert statistics[2].tx_bytes == 0x100000300
    assert statistics[1].rx_errors == 1
    assert statistics[2].tx_errors == 2
    assert transport.requests == [("GET", "/!stats.b")]


def test_port_statistics_reject_invalid_counter_arrays() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    data = parse_payload(stats_fixture_payload())
    rx_packets = data["rtp"]
    assert isinstance(rx_packets, list)
    rx_packets[0] = -1

    with pytest.raises(ProtocolError, match="unsigned 32-bit"):
        port_statistics_from_payload(data, identity)


def test_adapter_normalizes_port_vlan_policy() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(forwarding_fixture_payload())
    tested_plugin = CSS106Plugin(transport_factory=lambda connection: transport)  # type: ignore[arg-type]
    adapter = tested_plugin.create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=tested_plugin.support_records()[0],
    )

    ports = adapter.get_port_vlans()

    assert len(ports) == 6
    assert ports[0].mode.value == "optional"
    assert ports[0].receive.value == "any"
    assert ports[0].default_vlan_id == 1
    assert not ports[0].force_vlan_id
    assert ports[0].egress.value == "preserve"
    assert transport.requests == [("GET", "/fwd.b")]


def test_port_vlan_parser_handles_all_supported_modes() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    data = parse_payload(forwarding_fixture_payload())
    data["vlan"] = [0, 1, 2, 3, 0, 1]
    data["vlni"] = [0, 1, 2, 0, 1, 2]
    data["vlnh"] = [0, 1, 2, 0, 1, 2]
    data["fvid"] = 0x25

    ports = port_vlans_from_forwarding_payload(data, identity)

    assert [port.mode.value for port in ports] == [
        "disabled",
        "optional",
        "enabled",
        "strict",
        "disabled",
        "optional",
    ]
    assert [port.receive.value for port in ports] == [
        "any",
        "tagged_only",
        "untagged_only",
        "any",
        "tagged_only",
        "untagged_only",
    ]
    assert [port.egress.value for port in ports] == [
        "preserve",
        "strip",
        "add_if_missing",
        "preserve",
        "strip",
        "add_if_missing",
    ]
    assert [port.force_vlan_id for port in ports] == [True, False, True, False, False, True]


def test_adapter_normalizes_vlan_table() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(vlan_fixture_payload())
    tested_plugin = CSS106Plugin(transport_factory=lambda connection: transport)  # type: ignore[arg-type]
    adapter = tested_plugin.create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=tested_plugin.support_records()[0],
    )

    vlans = adapter.get_vlans()

    assert [vlan.vlan_id for vlan in vlans] == [10, 20]
    assert vlans[0].igmp_snooping
    assert vlans[0].ports[0].mode.value == "strip"
    assert vlans[0].ports[5].mode.value == "add_if_missing"
    assert vlans[1].independent_learning
    assert {port.mode.value for port in vlans[1].ports} == {
        "preserve",
        "strip",
        "add_if_missing",
        "not_member",
    }
    assert transport.requests == [("GET", "/vlan.b")]


def test_vlan_decoders_reject_invalid_values() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    forwarding = parse_payload(forwarding_fixture_payload())
    forwarding["vlan"] = [0, 1, 2, 3, 4, 0]
    with pytest.raises(ProtocolError, match="unknown value 4"):
        port_vlans_from_forwarding_payload(forwarding, identity)

    rows = parse_table_payload(vlan_fixture_payload())
    assert isinstance(rows[0], dict)
    rows.append(rows[0].copy())
    with pytest.raises(ProtocolError, match="duplicate VLAN ID"):
        vlans_from_payload(rows, identity)

    with pytest.raises(ProtocolError, match=f"exceeds {MAX_VLAN_ENTRIES}"):
        vlans_from_payload([{}] * (MAX_VLAN_ENTRIES + 1), identity)


def test_parser_handles_nested_values_without_eval() -> None:
    parsed = parse_payload(b"{rows:[{value:0x2a,missing:x}],label:'safe'}")

    assert parsed == {"rows": [{"value": 42, "missing": None}], "label": "safe"}


def test_parser_handles_empty_containers_negative_numbers_and_escapes() -> None:
    parsed = parse_payload(b" {empty:{},items:[],decimal:-12,hex:-0x0a,label:'line\\nquoted\\''} ")

    assert parsed == {
        "empty": {},
        "items": [],
        "decimal": -12,
        "hex": -10,
        "label": "line\nquoted'",
    }


def test_table_parser_accepts_array_root_and_rejects_object_root() -> None:
    assert parse_table_payload(b"[]") == []
    with pytest.raises(ProtocolError, match="must contain an array"):
        parse_table_payload(b"{}")


@pytest.mark.parametrize(
    "payload",
    [b"__import__('os').system('false')", b"{value:0x}", b"{value:'unterminated}"],
)
def test_parser_rejects_invalid_or_executable_text(payload: bytes) -> None:
    with pytest.raises(ProtocolError):
        parse_payload(payload)


def test_parser_rejects_non_ascii_and_non_object_payloads() -> None:
    with pytest.raises(ProtocolError, match="not ASCII"):
        parse_payload(b"\xff")
    with pytest.raises(ProtocolError, match="must contain an object"):
        parse_payload(b"[]")


def test_parser_enforces_resource_limits() -> None:
    with pytest.raises(ProtocolError, match="1 MiB"):
        parse_payload(b" " * (MAX_PAYLOAD_BYTES + 1))

    nested = b"[" * (MAX_NESTING_DEPTH + 1) + b"]" * (MAX_NESTING_DEPTH + 1)
    with pytest.raises(ProtocolError, match="nesting"):
        parse_payload(nested)

    with pytest.raises(ProtocolError, match="number"):
        parse_payload(b"{value:123456789012345678901234567890123}")


def test_system_fields_reject_control_characters_and_invalid_values() -> None:
    data = parse_payload(fixture_payload())
    identity = identity_from_system(data)
    assert identity is not None

    data["id"] = "1b5b33316d"
    with pytest.raises(ProtocolError, match="control characters"):
        system_info_from_payload(data, identity)


def test_system_uptime_uses_100_ticks_per_second() -> None:
    data = parse_payload(fixture_payload())
    identity = identity_from_system(data)
    assert identity is not None

    data["upt"] = 123456

    assert system_info_from_payload(data, identity).uptime_seconds == 1234

    data["id"] = "4f6666696365"
    data["upt"] = -1
    with pytest.raises(ProtocolError, match="invalid values"):
        system_info_from_payload(data, identity)


def test_identity_fields_are_validated() -> None:
    data = parse_payload(fixture_payload())

    data["bld"] = -1
    with pytest.raises(ProtocolError, match="unsigned 32-bit"):
        identity_from_system(data)

    data["bld"] = 1
    data["ver"] = ""
    with pytest.raises(ProtocolError, match="identity contains invalid values"):
        identity_from_system(data)

    data["brd"] = "not-hex"
    with pytest.raises(ProtocolError, match="hex-encoded UTF-8"):
        identity_from_system(data)


def test_system_network_fields_are_validated() -> None:
    data = parse_payload(fixture_payload())
    identity = identity_from_system(data)
    assert identity is not None

    data["ip"] = 0
    data["sip"] = 0
    data["mac"] = "000000000000"
    info = system_info_from_payload(data, identity)
    assert info.current_ip is None
    assert info.static_ip is None
    assert info.mac_address is None

    data["ip"] = 0x100000000
    with pytest.raises(ProtocolError, match="IPv4"):
        system_info_from_payload(data, identity)

    data["ip"] = 1
    data["mac"] = "invalid"
    with pytest.raises(ProtocolError, match="MAC address"):
        system_info_from_payload(data, identity)

    data["mac"] = "020000000001"
    data["sid"] = 1
    with pytest.raises(ProtocolError, match="must be a string"):
        system_info_from_payload(data, identity)


def test_unknown_product_is_not_claimed() -> None:
    data = parse_payload(fixture_payload())
    data["brd"] = "554e4b4e4f574e"

    assert identity_from_system(data) is None


def test_untested_css106_product_is_detected_but_rejected() -> None:
    payload = fixture_payload().replace(
        b"4353533130362d35472d3153",
        b"4353533130362d31472d34502d3153",
    )
    tested_plugin = CSS106Plugin(transport_factory=lambda connection: FakeTransport(payload))  # type: ignore[arg-type]
    connection = DeviceConnection(url="http://192.0.2.1")
    identity = tested_plugin.probe(connection)

    assert identity is not None
    assert identity.marketing_name == "RB260GSP"
    with pytest.raises(UnsupportedFirmwareError):
        PluginRegistry([tested_plugin]).connect(identity, connection, FirmwareSafetyPolicy())


def test_adapter_rejects_identity_change_after_probe() -> None:
    first = fixture_payload()
    second = first.replace(b"322e3139", b"322e3230")
    responses = iter((first, second))
    tested_plugin = CSS106Plugin(
        transport_factory=lambda connection: FakeTransport(next(responses))  # type: ignore[arg-type]
    )
    connection = DeviceConnection(url="http://192.0.2.1")
    identity = tested_plugin.probe(connection)
    assert identity is not None
    adapter = tested_plugin.create(
        identity=identity,
        connection=connection,
        policy=FirmwareSafetyPolicy(),
        support=tested_plugin.support_records()[0],
    )

    with pytest.raises(ProtocolError, match="identity changed"):
        adapter.get_system_info()
