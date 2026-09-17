from pathlib import Path

import pytest
from swos_core.errors import InvalidOperationError, ProtocolError, UnsupportedFirmwareError
from swos_core.models import (
    DeviceConnection,
    DeviceNameUpdate,
    ForcedPortNegotiation,
    PortConfigurationUpdate,
    PortNameUpdate,
    SnmpMetadataUpdate,
)
from swos_core.plugins import PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy
from swos_device_css106 import CSS106Plugin, plugin
from swos_device_css106.protocol import (
    MAX_ACL_RULES,
    MAX_DEVICE_NAME_BYTES,
    MAX_NESTING_DEPTH,
    MAX_PAYLOAD_BYTES,
    MAX_PORT_NAME_BYTES,
    MAX_SNMP_METADATA_BYTES,
    MAX_VLAN_ENTRIES,
    UPTIME_TICKS_PER_SECOND,
    acl_rules_from_payload,
    dynamic_hosts_from_payload,
    encode_device_name_update,
    encode_port_configuration_update,
    encode_port_name_update,
    encode_snmp_metadata_update,
    forwarding_from_payload,
    identity_from_system,
    igmp_groups_from_payload,
    parse_payload,
    parse_table_payload,
    port_statistics_from_payload,
    port_vlans_from_forwarding_payload,
    ports_from_link_payload,
    rstp_from_payloads,
    sfp_from_payload,
    snmp_from_payload,
    static_hosts_from_payload,
    system_info_from_payload,
    vlans_from_payload,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sys.b"
LINK_FIXTURE = Path(__file__).parent / "fixtures" / "link.b"
STATS_FIXTURE = Path(__file__).parent / "fixtures" / "stats.b"
FORWARDING_FIXTURE = Path(__file__).parent / "fixtures" / "fwd.b"
VLAN_FIXTURE = Path(__file__).parent / "fixtures" / "vlan.b"
STATIC_HOST_FIXTURE = Path(__file__).parent / "fixtures" / "host.b"
DYNAMIC_HOST_FIXTURE = Path(__file__).parent / "fixtures" / "dhost.b"
RSTP_FIXTURE = Path(__file__).parent / "fixtures" / "rstp.b"
RSTP_SYSTEM_FIXTURE = Path(__file__).parent / "fixtures" / "rstp_sys.b"
SNMP_FIXTURE = Path(__file__).parent / "fixtures" / "snmp.b"
SFP_FIXTURE = Path(__file__).parent / "fixtures" / "sfp.b"
IGMP_FIXTURE = Path(__file__).parent / "fixtures" / "igmp.b"
ACL_FIXTURE = Path(__file__).parent / "fixtures" / "acl.b"


class FakeTransport:
    def __init__(self, response: bytes | tuple[bytes, ...]) -> None:
        self.responses = iter(response) if isinstance(response, tuple) else None
        self.response = response if isinstance(response, bytes) else None
        self.requests: list[tuple[str, str]] = []
        self.request_details: list[tuple[str, str, bytes | str | None, dict[str, str] | None]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        content: bytes | str | None = None,
        headers: dict[str, str] | None = None,
        max_response_bytes: int | None = None,
    ) -> bytes:
        self.requests.append((method, path))
        self.request_details.append((method, path, content, headers))
        assert max_response_bytes == MAX_PAYLOAD_BYTES
        if self.responses is not None:
            return next(self.responses)
        assert self.response is not None
        return self.response

    def __enter__(self) -> "FakeTransport":
        return self

    def __exit__(self, *args: object) -> None:
        pass


def fixture_payload() -> bytes:
    return FIXTURE.read_bytes()


def link_fixture_payload() -> bytes:
    return LINK_FIXTURE.read_bytes()


def renamed_link_payload(name: str) -> bytes:
    encoded = name.encode("ascii").hex().encode("ascii")
    return link_fixture_payload().replace(b"506f727431", encoded, 1)


def renamed_system_payload(name: str) -> bytes:
    encoded = name.encode("ascii").hex().encode("ascii")
    return fixture_payload().replace(b"4f666669636520537769746368", encoded, 1)


def updated_snmp_payload(*, contact: str = "Ops", location: str = "Office") -> bytes:
    return (
        b"{en:0x01,com:'7075626c6963',ci:'"
        + contact.encode("ascii").hex().encode("ascii")
        + b"',loc:'"
        + location.encode("ascii").hex().encode("ascii")
        + b"'}"
    )


def stats_fixture_payload() -> bytes:
    return STATS_FIXTURE.read_bytes()


def forwarding_fixture_payload() -> bytes:
    return FORWARDING_FIXTURE.read_bytes()


def vlan_fixture_payload() -> bytes:
    return VLAN_FIXTURE.read_bytes()


def static_host_fixture_payload() -> bytes:
    return STATIC_HOST_FIXTURE.read_bytes()


def dynamic_host_fixture_payload() -> bytes:
    return DYNAMIC_HOST_FIXTURE.read_bytes()


def rstp_fixture_payload() -> bytes:
    return RSTP_FIXTURE.read_bytes()


def rstp_system_fixture_payload() -> bytes:
    return RSTP_SYSTEM_FIXTURE.read_bytes()


def snmp_fixture_payload() -> bytes:
    return SNMP_FIXTURE.read_bytes()


def sfp_fixture_payload() -> bytes:
    return SFP_FIXTURE.read_bytes()


def igmp_fixture_payload() -> bytes:
    return IGMP_FIXTURE.read_bytes()


def acl_fixture_payload() -> bytes:
    return ACL_FIXTURE.read_bytes()


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
    assert info.management is not None
    assert info.management.address_mode.value == "dhcp_with_fallback"
    assert info.management.allowed_port_numbers == (1, 2, 3, 4, 5, 6)
    assert info.management.allowed_vlan_id is None
    assert info.igmp is not None
    assert info.igmp.querier_configured
    assert not info.igmp.querier_effective
    assert info.discovery_protocol_port_numbers == (1, 2, 3, 4, 5, 6)
    assert info.health is not None
    assert info.health.temperature_celsius is None
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
    assert ports[0].speed_bps == 1_000_000_000
    assert ports[0].full_duplex is True
    assert ports[0].configured_speed_bps == 100_000_000
    assert ports[0].configured_full_duplex
    assert ports[0].poe_mode is None
    assert ports[4].name == "Port5"
    assert not ports[4].link_up
    assert ports[4].speed_bps is None
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
    assert ports[0].speed_bps == 10_000_000
    assert not ports[0].auto_negotiation
    assert not ports[0].flow_control
    assert ports[1].speed_bps == 100_000_000
    assert ports[1].full_duplex is False


def test_port_name_encoder_emits_exact_complete_link_write() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    content, _ = encode_port_name_update(
        parse_payload(link_fixture_payload()),
        identity,
        PortNameUpdate(number=1, name="Uplink"),
    )

    assert content == (
        b"{en:0x3f,nm:['55706c696e6b','506f727432','506f727433','506f727434',"
        b"'506f727435','534650'],an:0x3f,spdc:[0x01,0x01,0x01,0x01,0x01,0x00],"
        b"dpxc:0x3f,fct:0x3f}"
    )


def test_port_configuration_encoder_emits_exact_complete_link_write() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    content, desired = encode_port_configuration_update(
        parse_payload(link_fixture_payload()),
        identity,
        PortConfigurationUpdate(
            number=5,
            enabled=False,
            negotiation=ForcedPortNegotiation(speed_bps=10_000_000, duplex="half"),
            flow_control=False,
        ),
    )

    assert content == (
        b"{en:0x2f,nm:['506f727431','506f727432','506f727433','506f727434',"
        b"'506f727435','534650'],an:0x2f,spdc:[0x01,0x01,0x01,0x01,0x00,0x00],"
        b"dpxc:0x2f,fct:0x2f}"
    )
    assert desired.raw_names[-1] == "534650"
    assert desired.configured_speeds[-1] == 0
    assert b"lnk" not in content
    assert b"spd:" not in content
    assert b"dpx:" not in content


def test_auto_negotiation_preserves_dormant_speed_and_duplex() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    data = parse_payload(link_fixture_payload())
    data["an"] = 0x2F
    data["dpxc"] = 0x2F
    speeds = data["spdc"]
    assert isinstance(speeds, list)
    speeds[4] = 0

    content, desired = encode_port_configuration_update(
        data,
        identity,
        PortConfigurationUpdate(number=5, negotiation="auto"),
    )

    assert desired.auto_negotiation_mask == 0x3F
    assert desired.configured_speeds[4] == 0
    assert desired.configured_duplex_mask == 0x2F
    assert b"an:0x3f" in content
    assert b"spdc:[0x01,0x01,0x01,0x01,0x00,0x00]" in content
    assert b"dpxc:0x2f" in content


def test_link_encoders_reject_management_sfp_port_even_for_constructed_models() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    data = parse_payload(link_fixture_payload())

    with pytest.raises(InvalidOperationError, match="SFP management port"):
        encode_port_name_update(
            data,
            identity,
            PortNameUpdate.model_construct(number=6, name="Management"),
        )
    with pytest.raises(InvalidOperationError, match="SFP management port"):
        encode_port_configuration_update(
            data,
            identity,
            PortConfigurationUpdate.model_construct(number=6, flow_control=False),
        )


def test_device_name_encoder_emits_exact_sparse_system_write() -> None:
    content, desired = encode_device_name_update(
        parse_payload(fixture_payload()),
        DeviceNameUpdate(name="Core Switch"),
    )

    assert content == b"{id:'436f726520537769746368'}"
    assert desired.raw_name == "436f726520537769746368"


@pytest.mark.parametrize(
    "name, message",
    [
        ("x" * (MAX_DEVICE_NAME_BYTES + 1), "cannot exceed"),
        ("Core\nSwitch", "printable ASCII"),
        ("Cöre", "printable ASCII"),
    ],
)
def test_device_name_encoder_rejects_unvalidated_values(name: str, message: str) -> None:
    with pytest.raises(InvalidOperationError, match=message):
        encode_device_name_update(
            parse_payload(fixture_payload()),
            DeviceNameUpdate(name=name),
        )


@pytest.mark.parametrize(
    "name, message",
    [
        ("x" * (MAX_PORT_NAME_BYTES + 1), "cannot exceed"),
        ("Upl\nink", "printable ASCII"),
        ("Uplänk", "printable ASCII"),
    ],
)
def test_port_name_encoder_rejects_unvalidated_values(name: str, message: str) -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    with pytest.raises(InvalidOperationError, match=message):
        encode_port_name_update(
            parse_payload(link_fixture_payload()),
            identity,
            PortNameUpdate(number=1, name=name),
        )


def test_adapter_sets_and_verifies_port_name() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(
        (fixture_payload(), link_fixture_payload(), b"", renamed_link_payload("Uplink"))
    )
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_port_name(PortNameUpdate(number=1, name="Uplink"))

    assert result.changed
    assert result.value.name == "Uplink"
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("GET", "/link.b"),
        ("POST", "/link.b"),
        ("GET", "/link.b"),
    ]
    post = transport.request_details[2]
    assert post[2] == (
        b"{en:0x3f,nm:['55706c696e6b','506f727432','506f727433','506f727434',"
        b"'506f727435','534650'],an:0x3f,spdc:[0x01,0x01,0x01,0x01,0x01,0x00],"
        b"dpxc:0x3f,fct:0x3f}"
    )
    assert post[3] == {"Content-Type": "text/plain"}


def test_adapter_sets_and_verifies_port_configuration() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    changed_link = link_fixture_payload().replace(b"fct:0x3f", b"fct:0x2f")
    transport = FakeTransport((fixture_payload(), link_fixture_payload(), b"", changed_link))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_port_configuration(PortConfigurationUpdate(number=5, flow_control=False))

    assert result.changed
    assert not result.value.flow_control
    assert result.value.number == 5
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("GET", "/link.b"),
        ("POST", "/link.b"),
        ("GET", "/link.b"),
    ]
    assert transport.request_details[2][2] == (
        b"{en:0x3f,nm:['506f727431','506f727432','506f727433','506f727434',"
        b"'506f727435','534650'],an:0x3f,spdc:[0x01,0x01,0x01,0x01,0x01,0x00],"
        b"dpxc:0x3f,fct:0x2f}"
    )


def test_adapter_skips_post_for_port_configuration_no_op() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport((fixture_payload(), link_fixture_payload()))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_port_configuration(
        PortConfigurationUpdate(number=5, enabled=True, negotiation="auto", flow_control=True)
    )

    assert not result.changed
    assert result.value.number == 5
    assert transport.requests == [("GET", "/sys.b"), ("GET", "/link.b")]


@pytest.mark.parametrize(
    "update",
    [
        PortConfigurationUpdate(number=1, enabled=False),
        PortConfigurationUpdate(
            number=1,
            negotiation=ForcedPortNegotiation(speed_bps=100_000_000, duplex="full"),
        ),
    ],
)
def test_adapter_rejects_connectivity_changes_on_active_port(
    update: PortConfigurationUpdate,
) -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport((fixture_payload(), link_fixture_payload()))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="link-up"):
        adapter.set_port_configuration(update)

    assert transport.requests == [("GET", "/sys.b"), ("GET", "/link.b")]


def test_adapter_rejects_management_sfp_port_before_post() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport((fixture_payload(), link_fixture_payload()))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="SFP management port"):
        adapter.set_port_configuration(
            PortConfigurationUpdate.model_construct(number=6, flow_control=False)
        )

    assert transport.requests == [("GET", "/sys.b"), ("GET", "/link.b")]


def test_adapter_rejects_identity_change_before_port_configuration_post() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    changed_system = fixture_payload().replace(b"322e3139", b"322e3230")
    transport = FakeTransport(changed_system)
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(ProtocolError, match="identity changed"):
        adapter.set_port_configuration(PortConfigurationUpdate(number=5, flow_control=False))

    assert transport.requests == [("GET", "/sys.b")]


def test_adapter_rejects_port_configuration_read_back_mismatch() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(
        (fixture_payload(), link_fixture_payload(), b"", link_fixture_payload())
    )
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(ProtocolError, match="read-back verification"):
        adapter.set_port_configuration(PortConfigurationUpdate(number=5, flow_control=False))


def test_adapter_skips_post_when_port_name_is_already_configured() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport((fixture_payload(), link_fixture_payload()))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_port_name(PortNameUpdate(number=1, name="Port1"))

    assert not result.changed
    assert result.value.name == "Port1"
    assert transport.requests == [("GET", "/sys.b"), ("GET", "/link.b")]


def test_adapter_rejects_management_sfp_name_even_when_it_would_be_a_no_op() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport((fixture_payload(), link_fixture_payload()))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="SFP management port"):
        adapter.set_port_name(PortNameUpdate.model_construct(number=6, name="SFP"))

    assert transport.requests == [("GET", "/sys.b"), ("GET", "/link.b")]


def test_adapter_rejects_identity_change_before_port_name_post() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    changed_system = fixture_payload().replace(b"322e3139", b"322e3230")
    transport = FakeTransport(changed_system)
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(ProtocolError, match="identity changed"):
        adapter.set_port_name(PortNameUpdate(number=1, name="Uplink"))

    assert transport.requests == [("GET", "/sys.b")]


def test_adapter_rejects_port_name_read_back_mismatch() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(
        (fixture_payload(), link_fixture_payload(), b"", link_fixture_payload())
    )
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(ProtocolError, match="read-back verification"):
        adapter.set_port_name(PortNameUpdate(number=1, name="Uplink"))


def test_adapter_sets_device_name_with_one_sparse_post_and_verifies_it() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport((fixture_payload(), b"", renamed_system_payload("Core Switch")))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_device_name(DeviceNameUpdate(name="Core Switch"))

    assert result.changed
    assert result.value.name == "Core Switch"
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("POST", "/sys.b"),
        ("GET", "/sys.b"),
    ]
    assert transport.request_details[1][2:] == (
        b"{id:'436f726520537769746368'}",
        {"Content-Type": "text/plain"},
    )


def test_adapter_skips_device_name_post_when_already_configured() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(fixture_payload())
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_device_name(DeviceNameUpdate(name="Office Switch"))

    assert not result.changed
    assert result.value.name == "Office Switch"
    assert transport.requests == [("GET", "/sys.b")]


def test_adapter_rejects_device_name_identity_or_read_back_mismatch() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    changed_identity = fixture_payload().replace(b"322e3139", b"322e3230")
    transport = FakeTransport(changed_identity)
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="identity changed"):
        adapter.set_device_name(DeviceNameUpdate(name="Core Switch"))
    assert transport.requests == [("GET", "/sys.b")]

    transport = FakeTransport((fixture_payload(), b"", fixture_payload()))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="read-back verification"):
        adapter.set_device_name(DeviceNameUpdate(name="Core Switch"))


def test_adapter_validates_device_name_before_transport() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(fixture_payload())
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="printable ASCII"):
        adapter.set_device_name(DeviceNameUpdate(name="Cöre"))
    assert transport.requests == []


def test_shared_decoder_model_gates_rb260gsp_health_and_poe_fields() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    poe_identity = identity.model_copy(
        update={"product_code": "CSS106-1G-4P-1S", "marketing_name": "RB260GSP"}
    )
    system_data = parse_payload(fixture_payload())
    system_data["volt"] = 242
    system_data["temp"] = 0xFFFFFFF6
    system_data["lcbl"] = 1
    link_data = parse_payload(link_fixture_payload())
    link_data["poe"] = [0, 1, 2, 3, 1, 0]
    link_data["prio"] = [0, 1, 2, 3, 0, 0]
    link_data["poes"] = [0, 2, 3, 4, 10, 0]
    link_data["curr"] = [0, 100, 200, 300, 400, 0]
    link_data["pwr"] = [0, 10, 20, 30, 40, 0]

    system = system_info_from_payload(system_data, poe_identity)
    ports = ports_from_link_payload(link_data, poe_identity)

    assert system.health is not None
    assert system.health.input_voltage_volts == 24.2
    assert system.health.temperature_celsius == -10
    assert system.health.poe_in_long_cable
    assert ports[0].poe_mode is None
    assert ports[1].poe_mode is not None
    assert ports[1].poe_mode.value == "auto"
    assert ports[1].poe_priority == 2
    assert ports[1].poe_status is not None
    assert ports[1].poe_status.value == "waiting_for_load"
    assert ports[1].poe_current_ma == 100
    assert ports[1].poe_power_watts == 1
    assert ports[5].poe_mode is None

    adapter = CSS106Plugin().create(
        identity=poe_identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(allow_untested_firmware_writes=True),
        support=None,
    )
    assert not adapter.capabilities.supports("port_name_write")
    assert not adapter.capabilities.supports("port_configuration_write")
    assert not adapter.capabilities.supports("device_name_write")
    assert not adapter.capabilities.supports("snmp_metadata_write")


def test_adapter_validates_port_name_before_no_op_or_transport() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport((fixture_payload(), renamed_link_payload("Port1")))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="printable ASCII"):
        adapter.set_port_name(PortNameUpdate(number=1, name="Pört1"))

    assert transport.requests == []


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
    assert statistics[0].rates.rx_bits_per_second == 100
    assert statistics[0].rates.rx_packets_per_second == 100
    assert statistics[0].traffic.rx_unicast_packets == 0x100000001
    assert statistics[1].traffic.tx_unicast_packets == 0x100000014
    assert statistics[0].rx_sizes.frames_64_bytes == 1
    assert statistics[0].tx_sizes.frames_1519_to_max_bytes == 17
    assert statistics[0].detailed_errors.rx_fcs_errors == 2
    assert statistics[0].detailed_errors.tx_late_collisions == 17
    assert transport.requests == [("GET", "/!stats.b")]


def test_adapter_normalizes_sfp_diagnostics() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(sfp_fixture_payload())
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    info = adapter.get_sfp()

    assert info.vendor == "Test Optics"
    assert info.media_type == "multi-mode fiber"
    assert info.temperature_celsius == 25
    assert info.supply_voltage_volts == 3.3
    assert info.tx_power_dbm == 0
    assert info.rx_power_dbm == -10
    assert transport.requests == [("GET", "/sfp.b")]


def test_sfp_decoder_handles_absent_module_and_signed_temperature() -> None:
    data = parse_payload(sfp_fixture_payload())
    for field in ("vnd", "pnr", "rev", "ser", "dat", "typ"):
        data[field] = ""
    data["tmp"] = 0xFFFFFF80
    data["vcc"] = 0
    data["tbs"] = 0
    data["tpw"] = 0
    data["rpw"] = 0

    info = sfp_from_payload(data)

    assert info.vendor is None
    assert info.temperature_celsius is None
    assert info.supply_voltage_volts is None
    assert info.tx_power_dbm is None


def test_adapter_normalizes_forwarding_policy() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(forwarding_fixture_payload())
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    info = adapter.get_forwarding()

    assert info.mirror_target_port == 1
    assert info.ports[0].destination_port_numbers == (2, 3, 4, 5, 6)
    assert info.ports[0].egress_rate_limit_bps is None
    assert transport.requests == [("GET", "/fwd.b")]

    data = parse_payload(forwarding_fixture_payload())
    data["mrto"] = 3
    with pytest.raises(ProtocolError, match="at most one"):
        forwarding_from_payload(data, identity)


def test_adapter_normalizes_dynamic_igmp_groups() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(igmp_fixture_payload())
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    groups = adapter.get_igmp_groups()

    assert groups[0].address == "239.1.2.3"
    assert groups[0].vlan_id == 10
    assert groups[0].port_numbers == (1, 3)
    assert groups[1].port_numbers == (6,)
    assert transport.requests == [("GET", "/!igmp.b")]

    with pytest.raises(ProtocolError, match="IGMP row 0 must be an object"):
        igmp_groups_from_payload([1], identity)

    rows = parse_table_payload(igmp_fixture_payload())
    assert isinstance(rows[0], dict)
    rows[0]["addr"] = 0x010200C0
    with pytest.raises(ProtocolError, match="invalid values"):
        igmp_groups_from_payload(rows, identity)

    rows = parse_table_payload(igmp_fixture_payload())
    assert isinstance(rows[0], dict)
    rows[0]["prts"] = 0
    with pytest.raises(ProtocolError, match="invalid values"):
        igmp_groups_from_payload(rows, identity)


def test_adapter_normalizes_acl_rules_and_drop_action() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(acl_fixture_payload())
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    rules = adapter.get_acl_rules()

    assert rules[0].source_ip == "192.0.2.0"
    assert rules[0].destination_ip == "198.51.100.1"
    assert rules[0].redirect_port_numbers == (6,)
    assert not rules[0].drop
    assert rules[0].dscp is None
    assert rules[0].set_vlan_id == 100
    assert rules[1].drop
    assert rules[1].source_mac is None
    assert transport.requests == [("GET", "/acl.b")]

    with pytest.raises(ProtocolError, match=f"exceeds {MAX_ACL_RULES}"):
        acl_rules_from_payload([{}] * (MAX_ACL_RULES + 1), identity)


def test_port_statistics_reject_invalid_counter_arrays() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    data = parse_payload(stats_fixture_payload())
    rx_packets = data["rtp"]
    assert isinstance(rx_packets, list)
    rx_packets[0] = -1

    with pytest.raises(ProtocolError, match="unsigned 32-bit"):
        port_statistics_from_payload(data, identity)


def test_adapter_normalizes_static_and_dynamic_hosts() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport((static_host_fixture_payload(), dynamic_host_fixture_payload()))
    tested_plugin = CSS106Plugin(transport_factory=lambda connection: transport)  # type: ignore[arg-type]
    adapter = tested_plugin.create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=tested_plugin.support_records()[0],
    )

    hosts = adapter.get_hosts()

    assert len(hosts) == 4
    assert hosts[0].entry_type.value == "static"
    assert hosts[0].mac_address == "02:00:00:00:00:01"
    assert hosts[0].port_numbers == (1, 2)
    assert hosts[0].vlan_id == 10
    assert hosts[0].mirror
    assert hosts[1].drop
    assert hosts[2].entry_type.value == "dynamic"
    assert hosts[2].port_numbers == (3,)
    assert hosts[2].vlan_id is None
    assert hosts[3].port_numbers == (6,)
    assert hosts[3].vlan_id == 10
    assert transport.requests == [("GET", "/host.b"), ("GET", "/!dhost.b")]


def test_host_decoders_reject_invalid_rows() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    static_rows = parse_table_payload(static_host_fixture_payload())
    assert isinstance(static_rows[0], dict)
    static_rows[0]["prt"] = 0x40
    with pytest.raises(ProtocolError, match="6-port bitmask"):
        static_hosts_from_payload(static_rows, identity)

    with pytest.raises(ProtocolError, match="static host row 0 must be an object"):
        static_hosts_from_payload([1], identity)

    invalid_action = parse_table_payload(static_host_fixture_payload())
    assert isinstance(invalid_action[0], dict)
    invalid_action[0]["drp"] = 2
    with pytest.raises(ProtocolError, match="must be 0 or 1"):
        static_hosts_from_payload(invalid_action, identity)

    dynamic_rows = parse_table_payload(dynamic_host_fixture_payload())
    assert isinstance(dynamic_rows[0], dict)
    dynamic_rows[0]["adr"] = "000000000000"
    with pytest.raises(ProtocolError, match="zero MAC"):
        dynamic_hosts_from_payload(dynamic_rows, identity)

    with pytest.raises(ProtocolError, match="dynamic host row 0 must be an object"):
        dynamic_hosts_from_payload([1], identity)

    invalid_port = parse_table_payload(dynamic_host_fixture_payload())
    assert isinstance(invalid_port[0], dict)
    invalid_port[0]["prt"] = 6
    with pytest.raises(ProtocolError, match="between 0 and 5"):
        dynamic_hosts_from_payload(invalid_port, identity)


def test_adapter_normalizes_rstp_state() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport((rstp_system_fixture_payload(), rstp_fixture_payload()))
    tested_plugin = CSS106Plugin(transport_factory=lambda connection: transport)  # type: ignore[arg-type]
    adapter = tested_plugin.create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=tested_plugin.support_records()[0],
    )

    info = adapter.get_rstp()

    assert info.bridge_priority == 0x8000
    assert info.cost_mode.value == "short"
    assert not info.forward_reserved_multicast
    assert info.root_bridge_priority == 0x8000
    assert info.root_bridge_mac == "02:00:00:00:00:01"
    assert len(info.ports) == 6
    assert info.ports[0].protocol.value == "rstp"
    assert info.ports[0].role.value == "designated"
    assert info.ports[0].configured_path_cost == 4
    assert info.ports[0].port_type.value == "edge"
    assert info.ports[0].state.value == "forwarding"
    assert info.ports[4].port_type.value == "point_to_point"
    assert info.ports[4].state.value == "discarding"
    assert transport.requests == [("GET", "/sys.b"), ("GET", "/rstp.b")]


def test_rstp_decoder_handles_all_combined_states_and_rejects_roles() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    rstp_data = parse_payload(rstp_fixture_payload())
    rstp_data["rstp"] = 0x3E
    rstp_data["ena"] = 0x2A
    rstp_data["p2p"] = 0x0A
    rstp_data["edge"] = 0x0C
    rstp_data["lrn"] = 0x0A
    rstp_data["fwd"] = 0x0C
    rstp_data["role"] = [0, 1, 2, 3, 4, 0]
    rstp_data["rpc"] = [0, 1, 2, 3, 4, 5]

    info = rstp_from_payloads(rstp_data, parse_payload(rstp_system_fixture_payload()), identity)

    assert info.ports[0].protocol.value == "stp"
    assert not info.ports[0].enabled
    assert info.ports[0].port_type.value == "shared"
    assert info.ports[0].state.value == "discarding"
    assert info.ports[1].port_type.value == "point_to_point"
    assert info.ports[1].state.value == "learning"
    assert info.ports[1].enabled
    assert info.ports[2].port_type.value == "edge"
    assert info.ports[2].state.value == "forwarding"
    assert info.ports[3].port_type.value == "edge"
    assert info.ports[3].state.value == "forwarding"
    assert info.ports[5].root_path_cost == 5
    assert info.ports[5].configured_path_cost == 4
    assert [port.role.value for port in info.ports[:5]] == [
        "disabled",
        "alternate",
        "root",
        "designated",
        "backup",
    ]

    rstp_data["role"] = [5, 0, 0, 0, 0, 0]
    with pytest.raises(ProtocolError, match="unknown value 5"):
        rstp_from_payloads(rstp_data, parse_payload(rstp_system_fixture_payload()), identity)

    system_data = parse_payload(rstp_system_fixture_payload())
    system_data["cost"] = 2
    with pytest.raises(ProtocolError, match="between 0 and 1"):
        rstp_from_payloads(parse_payload(rstp_fixture_payload()), system_data, identity)


def test_rstp_adapter_revalidates_identity_before_reading_state() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    changed_system = rstp_system_fixture_payload().replace(b"322e3139", b"322e3230")
    transport = FakeTransport(changed_system)
    tested_plugin = CSS106Plugin(transport_factory=lambda connection: transport)  # type: ignore[arg-type]
    adapter = tested_plugin.create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=tested_plugin.support_records()[0],
    )

    with pytest.raises(ProtocolError, match="identity changed"):
        adapter.get_rstp()
    assert transport.requests == [("GET", "/sys.b")]


def test_adapter_normalizes_snmp_configuration() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(snmp_fixture_payload())
    tested_plugin = CSS106Plugin(transport_factory=lambda connection: transport)  # type: ignore[arg-type]
    adapter = tested_plugin.create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=tested_plugin.support_records()[0],
    )

    info = adapter.get_snmp()

    assert info.enabled
    assert info.community == "public"
    assert info.contact == "Ops"
    assert info.location == "Office"
    assert transport.requests == [("GET", "/snmp.b")]


def test_snmp_decoder_rejects_invalid_values() -> None:
    data = parse_payload(snmp_fixture_payload())
    data["en"] = 2
    with pytest.raises(ProtocolError, match="must be 0 or 1"):
        snmp_from_payload(data)

    data = parse_payload(snmp_fixture_payload())
    data["com"] = "61" * 65
    with pytest.raises(ProtocolError, match="invalid values"):
        snmp_from_payload(data)


def test_snmp_metadata_encoder_preserves_raw_service_fields_and_exact_order() -> None:
    data = parse_payload(snmp_fixture_payload())
    data["com"] = "5055424c4943"

    content, desired = encode_snmp_metadata_update(
        data,
        SnmpMetadataUpdate(contact="Network Ops"),
    )

    assert content == (
        b"{en:0x01,com:'5055424c4943',ci:'4e6574776f726b204f7073',loc:'4f6666696365'}"
    )
    assert desired.enabled == 1
    assert desired.raw_community == "5055424c4943"
    assert desired.raw_location == "4f6666696365"


def test_snmp_metadata_encoder_preserves_omitted_and_clears_empty_values() -> None:
    content, desired = encode_snmp_metadata_update(
        parse_payload(snmp_fixture_payload()),
        SnmpMetadataUpdate(contact=None, location=""),
    )

    assert content == b"{en:0x01,com:'7075626c6963',ci:'4f7073',loc:''}"
    assert desired.raw_contact == "4f7073"
    assert desired.raw_location == ""


@pytest.mark.parametrize(
    "update, message",
    [
        (SnmpMetadataUpdate(contact="x" * (MAX_SNMP_METADATA_BYTES + 1)), "cannot exceed"),
        (SnmpMetadataUpdate(location="Rack\n1"), "printable ASCII"),
        (SnmpMetadataUpdate(contact="Tëam"), "printable ASCII"),
    ],
)
def test_snmp_metadata_encoder_rejects_unvalidated_values(
    update: SnmpMetadataUpdate, message: str
) -> None:
    with pytest.raises(InvalidOperationError, match=message):
        encode_snmp_metadata_update(parse_payload(snmp_fixture_payload()), update)


def test_adapter_sets_and_verifies_complete_snmp_metadata_state() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    after = updated_snmp_payload(contact="Network Ops", location="Rack 1")
    transport = FakeTransport((fixture_payload(), snmp_fixture_payload(), b"", after))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_snmp_metadata(SnmpMetadataUpdate(contact="Network Ops", location="Rack 1"))

    assert result.changed
    assert result.value.contact == "Network Ops"
    assert result.value.location == "Rack 1"
    assert result.value.community == "public"
    assert set(result.model_dump(mode="json")) == {"changed", "value", "warnings"}
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("GET", "/snmp.b"),
        ("POST", "/snmp.b"),
        ("GET", "/snmp.b"),
    ]
    assert transport.request_details[2][2:] == (
        b"{en:0x01,com:'7075626c6963',ci:'4e6574776f726b204f7073',loc:'5261636b2031'}",
        {"Content-Type": "text/plain"},
    )


def test_adapter_skips_snmp_metadata_post_for_omitted_or_matching_values() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport((fixture_payload(), snmp_fixture_payload()))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_snmp_metadata(SnmpMetadataUpdate(contact="Ops"))

    assert not result.changed
    assert result.value.location == "Office"
    assert transport.requests == [("GET", "/sys.b"), ("GET", "/snmp.b")]


def test_adapter_rejects_snmp_identity_change_and_full_state_mismatch() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    changed_identity = fixture_payload().replace(b"322e3139", b"322e3230")
    transport = FakeTransport(changed_identity)
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="identity changed"):
        adapter.set_snmp_metadata(SnmpMetadataUpdate(contact="NOC"))
    assert transport.requests == [("GET", "/sys.b")]

    changed_community = updated_snmp_payload(contact="NOC").replace(
        b"7075626c6963", b"70726976617465"
    )
    transport = FakeTransport((fixture_payload(), snmp_fixture_payload(), b"", changed_community))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="read-back verification"):
        adapter.set_snmp_metadata(SnmpMetadataUpdate(contact="NOC"))


def test_adapter_validates_all_snmp_metadata_before_transport() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(fixture_payload())
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="printable ASCII"):
        adapter.set_snmp_metadata(SnmpMetadataUpdate(contact="Ops", location="Räck"))
    assert transport.requests == []


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
