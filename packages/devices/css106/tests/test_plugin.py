from pathlib import Path

import pytest
from pydantic import SecretStr
from swos_core.errors import (
    AuthenticationError,
    HttpStatusError,
    InvalidOperationError,
    PasswordUpdateRejectedError,
    ProtocolError,
    UnsupportedFirmwareError,
)
from swos_core.models import (
    AddressMode,
    DeviceConnection,
    DeviceNameUpdate,
    ForcedPortNegotiation,
    ForwardingMatrixUpdate,
    ForwardingMirroringUpdate,
    ForwardingPortPolicyUpdate,
    HostEntry,
    PasswordUpdate,
    PortConfigurationUpdate,
    PortNameUpdate,
    PortVlanPolicyUpdate,
    RstpBridgeUpdate,
    RstpPortEnableUpdate,
    SnmpMetadataUpdate,
    SystemConfigurationUpdate,
    VlanInfo,
    VlanMembershipMode,
    VlanPortMembership,
)
from swos_core.plugins import PluginRegistry
from swos_core.safety import FirmwareSafetyPolicy
from swos_device_css106 import CSS106Plugin, plugin
from swos_device_css106.protocol import (
    MAX_ACL_RULES,
    MAX_ADMIN_PASSWORD_BYTES,
    MAX_DEVICE_NAME_BYTES,
    MAX_NESTING_DEPTH,
    MAX_PAYLOAD_BYTES,
    MAX_PORT_NAME_BYTES,
    MAX_SNMP_METADATA_BYTES,
    MAX_STATIC_HOSTS,
    MAX_VLAN_ENTRIES,
    UPTIME_TICKS_PER_SECOND,
    acl_rules_from_payload,
    dynamic_hosts_from_payload,
    encode_acl_rules,
    encode_forwarding_matrix_update,
    encode_forwarding_mirroring_update,
    encode_forwarding_port_policy_update,
    encode_password_update,
    encode_port_configuration_update,
    encode_port_name_update,
    encode_port_vlan_policy_update,
    encode_rstp_bridge_update,
    encode_rstp_port_enable_update,
    encode_snmp_metadata_update,
    encode_static_hosts,
    encode_system_configuration_update,
    encode_vlans,
    forwarding_from_payload,
    identity_from_system,
    igmp_groups_from_payload,
    parse_payload,
    parse_table_payload,
    port_statistics_from_payload,
    port_vlan_write_state_from_payload,
    port_vlans_from_forwarding_payload,
    ports_from_link_payload,
    rstp_from_payloads,
    sfp_from_payload,
    snmp_from_payload,
    static_hosts_from_payload,
    system_configuration_write_state_from_payload,
    system_info_from_payload,
    validate_device_name,
    validate_password_update,
    vlan_table_write_state_from_payload,
    vlans_from_payload,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sys.b"
SYSTEM_WRITE_FIXTURE = Path(__file__).parent / "fixtures" / "sys_write.b"
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


class FailingTransport(FakeTransport):
    def __init__(self, error: Exception) -> None:
        super().__init__(b"")
        self.error = error

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
        raise self.error


def fixture_payload() -> bytes:
    return FIXTURE.read_bytes()


def link_fixture_payload() -> bytes:
    return LINK_FIXTURE.read_bytes()


def renamed_link_payload(name: str) -> bytes:
    encoded = name.encode("ascii").hex().encode("ascii")
    return link_fixture_payload().replace(b"506f727431", encoded, 1)


def renamed_system_payload(name: str) -> bytes:
    encoded = name.encode("ascii").hex().encode("ascii")
    return (
        fixture_payload()
        .replace(b"4f666669636520537769746368", encoded, 1)
        .replace(b"igmq:0x01", b"igmq:0x00")
    )


def configured_system_payload() -> bytes:
    payload = fixture_payload()
    replacements = (
        (b"sip:0x0158a8c0", b"sip:0x0a0200c0"),
        (b"amac:'000000000000'", b"amac:'020000000005'"),
        (b"id:'4f666669636520537769746368'", b"id:'436f726520537769746368'"),
        (b"alla:0x00000000", b"alla:0x006433c6"),
        (b"allm:0x00", b"allm:0x18"),
        (b"allp:0x3f", b"allp:0x23"),
        (b"ivl:0x00", b"ivl:0x01"),
        (b"igmp:0x00", b"igmp:0x01"),
        (b"igmq:0x01", b"igmq:0x00"),
        (b"igfl:0x00", b"igfl:0x02"),
        (b"igve:0x00", b"igve:0x01"),
        (b"pdsc:0x3f", b"pdsc:0x21"),
    )
    for old, new in replacements:
        payload = payload.replace(old, new)
    return payload


def system_configuration_update() -> SystemConfigurationUpdate:
    return SystemConfigurationUpdate(
        static_ip="192.0.2.10",
        admin_mac_address="02:00:00:00:00:05",
        name="Core Switch",
        allow_from="198.51.100.0",
        allow_prefix_length=24,
        allowed_port_numbers=(1, 2, 6),
        independent_vlan_lookup=True,
        igmp_enabled=True,
        igmp_querier=False,
        igmp_fast_leave_port_numbers=(2,),
        igmp_version="v3",
        discovery_protocol_port_numbers=(1, 6),
    )


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


def updated_forwarding_payload(
    *,
    lock: bytes = b"00",
    lock_on_first: bytes = b"00",
    rates: bytes | None = None,
) -> bytes:
    payload = forwarding_fixture_payload()
    payload = payload.replace(b"lck:0x00", b"lck:0x" + lock)
    payload = payload.replace(b"lckf:0x00", b"lckf:0x" + lock_on_first)
    if rates is not None:
        payload = payload.replace(
            b"or:[0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000]",
            rates,
        )
    return payload


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
    assert adapter.capabilities.supports("admin_password_write")
    assert adapter.capabilities.supports("rstp_port_enable_write")
    assert adapter.capabilities.supports("forwarding_port_policy_write")
    assert not adapter.capabilities.supports("rstp_bridge_write")
    assert not adapter.capabilities.supports("forwarding_matrix_write")
    assert not adapter.capabilities.supports("forwarding_mirroring_write")
    assert adapter.capabilities.supports("static_hosts_write")
    assert adapter.capabilities.supports("system_configuration_write")
    assert not adapter.capabilities.supports("acl_write")
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


def test_system_configuration_encoder_emits_exact_full_ui_object() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    content, desired = encode_system_configuration_update(
        parse_payload(fixture_payload()),
        identity,
        system_configuration_update(),
    )

    assert content == SYSTEM_WRITE_FIXTURE.read_bytes().strip()
    assert tuple(parse_payload(content)) == (
        "iptp",
        "sip",
        "amac",
        "id",
        "alla",
        "allm",
        "allp",
        "avln",
        "ivl",
        "igmp",
        "igmq",
        "igfl",
        "igve",
        "pdsc",
    )
    assert desired.static_ip == 0x0A0200C0
    assert desired.allow_from == 0x006433C6
    assert desired.admin_mac == "020000000005"
    assert desired.igmp_version == 1
    assert desired.allowed_ports_mask & 0x20
    assert desired.discovery_protocol_mask & 0x20
    assert not desired.igmp_fast_leave_mask & 0x20


def test_system_configuration_encoder_maps_enums_and_wire_zero_values() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    content, desired = encode_system_configuration_update(
        parse_payload(fixture_payload()),
        identity,
        SystemConfigurationUpdate(
            address_mode=AddressMode.STATIC,
            static_ip="unset",
            admin_mac_address="unset",
            allow_from="unset",
            allowed_vlan_id="unset",
        ),
    )

    assert content.startswith(b"{iptp:0x01,sip:0x00,amac:'000000000000'")
    assert b"alla:0x00" in content
    assert b"avln:0x00" in content
    assert desired.address_mode == 1


def test_system_configuration_uses_ui_minimal_even_width_hex() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    content, _ = encode_system_configuration_update(
        parse_payload(fixture_payload()),
        identity,
        SystemConfigurationUpdate(
            allow_from="1.0.0.0",
            allow_prefix_length=1,
            allowed_vlan_id=256,
        ),
    )

    assert b"alla:0x01" in content
    assert b"allm:0x01" in content
    assert b"avln:0x0100" in content
    assert b"alla:0x00000001" not in content


def test_system_configuration_forces_querier_off_when_snooping_is_off() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    data = parse_payload(fixture_payload())

    state = system_configuration_write_state_from_payload(data, identity)
    assert state.igmp_enabled == 0
    assert state.igmp_querier == 0

    name_content, name_desired = encode_system_configuration_update(
        data,
        identity,
        SystemConfigurationUpdate(name="Core Switch"),
    )
    assert b"igmp:0x00,igmq:0x00" in name_content
    assert name_desired.igmp_querier == 0

    enabled_content, enabled_desired = encode_system_configuration_update(
        data,
        identity,
        SystemConfigurationUpdate(igmp_enabled=True),
    )
    assert b"igmp:0x01,igmq:0x00" in enabled_content
    assert enabled_desired.igmp_querier == 0

    querier_content, querier_desired = encode_system_configuration_update(
        data,
        identity,
        SystemConfigurationUpdate(igmp_enabled=True, igmp_querier=True),
    )
    assert b"igmp:0x01,igmq:0x01" in querier_content
    assert querier_desired.igmp_querier == 1

    disabled_content, disabled_desired = encode_system_configuration_update(
        data,
        identity,
        SystemConfigurationUpdate(igmp_enabled=False, igmp_querier=True),
    )
    assert b"igmp:0x00,igmq:0x00" in disabled_content
    assert disabled_desired.igmp_querier == 0


def test_system_configuration_encoder_rejects_port_6_mask_changes() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    data = parse_payload(fixture_payload())

    with pytest.raises(InvalidOperationError, match="must include port 6"):
        encode_system_configuration_update(
            data,
            identity,
            SystemConfigurationUpdate(allowed_port_numbers=(1, 2)),
        )
    with pytest.raises(InvalidOperationError, match="cannot change port 6"):
        encode_system_configuration_update(
            data,
            identity,
            SystemConfigurationUpdate(igmp_fast_leave_port_numbers=(6,)),
        )
    with pytest.raises(InvalidOperationError, match="cannot change port 6"):
        encode_system_configuration_update(
            data,
            identity,
            SystemConfigurationUpdate(discovery_protocol_port_numbers=(1,)),
        )


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
        validate_device_name(name)


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


@pytest.mark.parametrize(
    "new_password, current_password, expected",
    [
        ("", "", "6414bd2b64166b6271272cf3dd1464ad0f479a5109cdc8e40d14998fdcbef5df"),
        ("new", "old", "7d40892fc4eba7eda72a454d96ec084ccdd2894c51b2fbfe56ac3b1806653869"),
        ("same", "same", "fbd9792ab6d4b90f8bc521bcc8ac0b403e3183d3af15a0ae625c98d208001641"),
        (
            "123456789012345",
            "abcdefghijklmno",
            "3371053543f92285a41bff3236b175ec19dedf0c20a85316e20d130e3e2f9dfa",
        ),
        ("", "old", "7d40892faa8ed0eda72a454d96ec084ccdd2894c51b2fbfe56ac3b1806653869"),
        ("new", "", "647ad85c64166b6271272cf3dd1464ad0f479a5109cdc8e40d14998fdcbef5df"),
        ("new", "päss", "4a6c3e871a981a7d4a29102eded3832e0f396594cce68d53d072b28f22a2881f"),
        (
            "ASCII",
            "密码",
            "5bbb78c6d8a13e9e048bf12a1368f65734085a10755dec0f70bb641e73e3f3767969",
        ),
        (
            "next",
            "🔒old",
            "d8e8dd8396ce5017e6caffc482d401970acf90e6dbc31897f859c4326e2991c5b6d9",
        ),
        (
            "x",
            "😀😀😀😀😀😀😀a",
            "d8efde39d84ade18d831de2dd8bdde4fd8ddde1bd837de5ad846dee427d9fecbcc582940d2551fa3fb8a72b71558",
        ),
    ],
)
def test_password_encoder_matches_independent_ui_vectors(
    new_password: str,
    current_password: str,
    expected: str,
) -> None:
    content = encode_password_update(
        PasswordUpdate(new_password=new_password),
        SecretStr(current_password),
    )

    assert content == f"{{pwd:'{expected}'}}".encode("ascii")


@pytest.mark.parametrize(
    "new_password, current_password, message",
    [
        ("x" * (MAX_ADMIN_PASSWORD_BYTES + 1), "old", "new.*cannot exceed"),
        ("new", "x" * (MAX_ADMIN_PASSWORD_BYTES + 1), "current.*cannot exceed"),
        ("pässword", "old", "new.*must be ASCII"),
        ("new", "😀" * 8, "current.*cannot exceed.*UTF-16 code units"),
    ],
)
def test_password_encoder_rejects_invalid_new_and_connection_passwords(
    new_password: str,
    current_password: str,
    message: str,
) -> None:
    update = PasswordUpdate(new_password=new_password)

    with pytest.raises(InvalidOperationError, match=message):
        validate_password_update(update, SecretStr(current_password))
    with pytest.raises(InvalidOperationError, match=message):
        encode_password_update(update, SecretStr(current_password))


def test_adapter_rotates_password_then_verifies_with_copied_new_credentials() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    current_transport = FakeTransport(b"")
    new_transport = FakeTransport(fixture_payload())
    transports = iter((current_transport, new_transport))
    connections: list[DeviceConnection] = []

    def transport_factory(connection: DeviceConnection) -> FakeTransport:
        connections.append(connection)
        return next(transports)

    connection = DeviceConnection(
        url="https://192.0.2.1",
        username="admin",
        password="old",
        timeout=4.0,
        verify_tls=False,
    )
    adapter = CSS106Plugin(transport_factory=transport_factory).create(  # type: ignore[arg-type]
        identity=identity,
        connection=connection,
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_admin_password(PasswordUpdate(new_password="new"))

    assert result.changed
    assert result.value.identity == identity
    assert result.warnings[0].code == "administrator_credentials_changed"
    assert current_transport.requests == [("POST", "/!pwd.b")]
    assert current_transport.request_details[0][2:] == (
        b"{pwd:'7d40892fc4eba7eda72a454d96ec084ccdd2894c51b2fbfe56ac3b1806653869'}",
        {"Content-Type": "text/plain"},
    )
    assert new_transport.requests == [("GET", "/sys.b")]
    assert len(connections) == 2
    assert connections[0] is connection
    assert connections[1] is not connection
    assert connections[1].url == connection.url
    assert connections[1].username == connection.username
    assert connections[1].timeout == connection.timeout
    assert connections[1].verify_tls == connection.verify_tls
    assert connections[0].password.get_secret_value() == "old"
    assert connections[1].password.get_secret_value() == "new"
    rendered = repr(result) + str(result) + result.model_dump_json()
    assert "old" not in rendered
    assert "{pwd:" not in rendered


def test_adapter_executes_and_verifies_same_password_request() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    current_transport = FakeTransport(b"")
    verification_transport = FakeTransport(fixture_payload())
    transports = iter((current_transport, verification_transport))
    adapter = CSS106Plugin(  # type: ignore[arg-type]
        transport_factory=lambda connection: next(transports)
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1", password="same"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_admin_password(PasswordUpdate(new_password="same"))

    assert result.changed
    assert current_transport.requests == [("POST", "/!pwd.b")]
    assert verification_transport.requests == [("GET", "/sys.b")]


def test_adapter_uses_new_connection_for_subsequent_reads_and_writes() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    current_transport = FakeTransport(b"")
    verification_transport = FakeTransport(fixture_payload())
    read_transport = FakeTransport(fixture_payload())
    write_transport = FakeTransport((fixture_payload(), b"", renamed_system_payload("Rotated")))
    transports = iter((current_transport, verification_transport, read_transport, write_transport))
    connections: list[DeviceConnection] = []

    def transport_factory(connection: DeviceConnection) -> FakeTransport:
        connections.append(connection)
        return next(transports)

    adapter = CSS106Plugin(transport_factory=transport_factory).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1", password="before-rotate"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    rotation = adapter.set_admin_password(PasswordUpdate(new_password="after-rotate"))
    read = adapter.get_system_info()
    write = adapter.set_device_name(DeviceNameUpdate(name="Rotated"))

    assert rotation.changed
    assert read.identity == identity
    assert write.changed
    assert write.value.name == "Rotated"
    assert current_transport.requests == [("POST", "/!pwd.b")]
    assert verification_transport.requests == [("GET", "/sys.b")]
    assert read_transport.requests == [("GET", "/sys.b")]
    assert write_transport.requests == [
        ("GET", "/sys.b"),
        ("POST", "/sys.b"),
        ("GET", "/sys.b"),
    ]
    assert [connection.password.get_secret_value() for connection in connections] == [
        "before-rotate",
        "after-rotate",
        "after-rotate",
        "after-rotate",
    ]
    rendered = repr(rotation) + rotation.model_dump_json() + repr(read) + repr(write)
    assert "before-rotate" not in rendered
    assert "after-rotate" not in rendered


def test_adapter_normalizes_password_endpoint_405_without_leaking_secret() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FailingTransport(HttpStatusError(405))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1", password="old-secret"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(PasswordUpdateRejectedError) as error:
        adapter.set_admin_password(PasswordUpdate(new_password="new-secret"))

    assert transport.requests == [("POST", "/!pwd.b")]
    assert "old-secret" not in str(error.value)
    assert "new-secret" not in str(error.value)


def test_adapter_does_not_retry_old_credentials_after_new_authentication_failure() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    current_transport = FakeTransport(b"")
    verification_transport = FailingTransport(AuthenticationError("authentication failed"))
    transports = iter((current_transport, verification_transport))
    connections: list[DeviceConnection] = []

    def transport_factory(connection: DeviceConnection) -> FakeTransport:
        connections.append(connection)
        return next(transports)

    adapter = CSS106Plugin(transport_factory=transport_factory).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1", password="old-secret"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(AuthenticationError, match="authentication failed"):
        adapter.set_admin_password(PasswordUpdate(new_password="new-secret"))

    assert current_transport.requests == [("POST", "/!pwd.b")]
    assert verification_transport.requests == [("GET", "/sys.b")]
    assert [item.password.get_secret_value() for item in connections] == [
        "old-secret",
        "new-secret",
    ]


def test_adapter_requires_exact_identity_with_new_credentials() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    current_transport = FakeTransport(b"")
    changed_identity = fixture_payload().replace(b"322e3139", b"322e3230")
    verification_transport = FakeTransport(changed_identity)
    later_read_transport = FakeTransport(fixture_payload())
    transports = iter((current_transport, verification_transport, later_read_transport))
    connections: list[DeviceConnection] = []

    def transport_factory(connection: DeviceConnection) -> FakeTransport:
        connections.append(connection)
        return next(transports)

    adapter = CSS106Plugin(transport_factory=transport_factory).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1", password="old"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(ProtocolError, match="identity changed"):
        adapter.set_admin_password(PasswordUpdate(new_password="new"))
    adapter.get_system_info()

    assert current_transport.requests == [("POST", "/!pwd.b")]
    assert verification_transport.requests == [("GET", "/sys.b")]
    assert later_read_transport.requests == [("GET", "/sys.b")]
    assert [connection.password.get_secret_value() for connection in connections] == [
        "old",
        "new",
        "old",
    ]


def test_adapter_validates_passwords_before_opening_transport() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    factory_calls = 0

    def transport_factory(connection: DeviceConnection) -> FakeTransport:
        nonlocal factory_calls
        del connection
        factory_calls += 1
        return FakeTransport(b"")

    adapter = CSS106Plugin(transport_factory=transport_factory).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1", password="x" * 16),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match=r"current.*cannot exceed"):
        adapter.set_admin_password(PasswordUpdate(new_password="valid"))
    assert factory_calls == 0


def test_adapter_sets_device_name_with_one_complete_system_post_and_verifies_it() -> None:
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
    assert result.value.igmp is not None
    assert not result.value.igmp.querier_configured
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("POST", "/sys.b"),
        ("GET", "/sys.b"),
    ]
    assert transport.request_details[1][2:] == (
        b"{iptp:0x00,sip:0x0158a8c0,amac:'000000000000',"
        b"id:'436f726520537769746368',alla:0x00,allm:0x00,allp:0x3f,"
        b"avln:0x00,ivl:0x00,igmp:0x00,igmq:0x00,igfl:0x00,igve:0x00,pdsc:0x3f}",
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


def test_adapter_sets_system_configuration_with_baseline_and_full_readback() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    before = system_info_from_payload(parse_payload(fixture_payload()), identity)
    transport = FakeTransport((fixture_payload(), b"", configured_system_payload()))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_system_configuration(
        system_configuration_update(), expected_current=before
    )

    assert result.changed
    assert result.value.name == "Core Switch"
    assert result.value.static_ip == "192.0.2.10"
    assert result.value.management is not None
    assert result.value.management.admin_mac_address == "02:00:00:00:00:05"
    assert result.value.management.allowed_port_numbers == (1, 2, 6)
    assert result.value.igmp is not None
    assert result.value.igmp.version.value == "v3"
    assert result.value.discovery_protocol_port_numbers == (1, 6)
    assert result.warnings[0].code == "management_lockout_risk"
    assert "admin MAC unset -> 02:00:00:00:00:05" in result.warnings[0].message
    assert "allow from any -> 198.51.100.0/24" in result.warnings[0].message
    assert "allowed ports 1,2,3,4,5,6 -> 1,2,6" in result.warnings[0].message
    assert "outcome uncertain" in result.warnings[0].message
    assert transport.requests == [("GET", "/sys.b"), ("POST", "/sys.b"), ("GET", "/sys.b")]
    assert transport.request_details[1][2:] == (
        SYSTEM_WRITE_FIXTURE.read_bytes().strip(),
        {"Content-Type": "text/plain"},
    )


def test_adapter_system_configuration_stale_noop_and_readback_guards() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    before = system_info_from_payload(parse_payload(fixture_payload()), identity)

    no_op_transport = FakeTransport(fixture_payload())
    no_op_adapter = CSS106Plugin(
        transport_factory=lambda connection: no_op_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    no_op = no_op_adapter.set_system_configuration(
        SystemConfigurationUpdate(name="Office Switch"), expected_current=before
    )
    assert not no_op.changed
    assert no_op_transport.requests == [("GET", "/sys.b")]

    stale_transport = FakeTransport(fixture_payload())
    stale_adapter = CSS106Plugin(
        transport_factory=lambda connection: stale_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(InvalidOperationError, match="changed since the expected baseline"):
        stale_adapter.set_system_configuration(
            SystemConfigurationUpdate(name="Core Switch"),
            expected_current=before.model_copy(update={"name": "Stale"}),
        )
    assert stale_transport.requests == [("GET", "/sys.b")]

    mismatch_transport = FakeTransport((fixture_payload(), b"", fixture_payload()))
    mismatch_adapter = CSS106Plugin(
        transport_factory=lambda connection: mismatch_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="complete-object read-back"):
        mismatch_adapter.set_system_configuration(
            SystemConfigurationUpdate(name="Core Switch"), expected_current=before
        )


def test_adapter_rejects_unsafe_system_management_changes_without_transport() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    current = system_info_from_payload(parse_payload(fixture_payload()), identity)
    transport = FakeTransport(fixture_payload())
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="must include port 6"):
        adapter.validate_system_configuration(
            SystemConfigurationUpdate(allowed_port_numbers=(1, 2)), current=current
        )
    assert current.management is not None
    unsafe_current = current.model_copy(
        update={
            "management": current.management.model_copy(update={"allowed_port_numbers": (1, 2)})
        }
    )
    with pytest.raises(InvalidOperationError, match="must include port 6"):
        adapter.validate_system_configuration(
            SystemConfigurationUpdate(name="Core Switch"), current=unsafe_current
        )
    with pytest.raises(InvalidOperationError, match="cannot change port 6"):
        adapter.validate_system_configuration(
            SystemConfigurationUpdate(igmp_fast_leave_port_numbers=(6,)), current=current
        )
    with pytest.raises(InvalidOperationError, match="management VLAN changes are disabled"):
        adapter.validate_system_configuration(
            SystemConfigurationUpdate(allowed_vlan_id=10), current=current
        )
    with pytest.raises(InvalidOperationError, match="address-mode changes"):
        adapter.validate_system_configuration(
            SystemConfigurationUpdate(address_mode="static"), current=current
        )

    adapter.validate_system_configuration(
        SystemConfigurationUpdate(allowed_vlan_id="unset"), current=current
    )
    adapter.validate_system_configuration(
        SystemConfigurationUpdate(static_ip="192.0.2.10"), current=current
    )
    assert transport.requests == []


def test_adapter_rejects_active_static_ip_change_until_reconnect_is_supported() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    current = system_info_from_payload(parse_payload(fixture_payload()), identity)
    assert current.management is not None
    current = current.model_copy(
        update={
            "management": current.management.model_copy(update={"address_mode": AddressMode.STATIC})
        }
    )
    transport = FakeTransport(fixture_payload())
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="active static-IP changes"):
        adapter.set_system_configuration(
            SystemConfigurationUpdate(static_ip="192.0.2.10"), expected_current=current
        )

    assert transport.requests == []


def test_adapter_rejects_static_ip_staging_in_dhcp_only_mode() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    current = system_info_from_payload(parse_payload(fixture_payload()), identity)
    assert current.management is not None
    current = current.model_copy(
        update={
            "management": current.management.model_copy(
                update={"address_mode": AddressMode.DHCP_ONLY}
            )
        }
    )
    transport = FakeTransport(fixture_payload())
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="only in DHCP-with-fallback mode"):
        adapter.set_system_configuration(
            SystemConfigurationUpdate(static_ip="192.0.2.10"), expected_current=current
        )

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
    assert not adapter.capabilities.supports("rstp_port_enable_write")
    assert not adapter.capabilities.supports("forwarding_port_policy_write")
    assert not adapter.capabilities.supports("vlan_port_policy_write")
    assert not adapter.capabilities.supports("vlan_table_write")
    assert not adapter.capabilities.supports("snmp_metadata_write")
    assert not adapter.capabilities.supports("static_hosts_write")
    assert not adapter.capabilities.supports("acl_write")


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


def test_forwarding_policy_encoder_posts_complete_group_and_preserves_port_6() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    content, desired = encode_forwarding_port_policy_update(
        parse_payload(forwarding_fixture_payload()),
        identity,
        ForwardingPortPolicyUpdate(
            number=5,
            lock=True,
            lock_on_first=True,
            egress_rate_limit_bps=1_000_000,
        ),
    )

    assert content == (
        b"{fp1:0x3e,fp2:0x3d,fp3:0x3b,fp4:0x37,fp5:0x2f,fp6:0x1f,"
        b"lck:0x10,lckf:0x10,imr:0x00,omr:0x00,mrto:0x01,"
        b"or:[0x00000000,0x00000000,0x00000000,0x00000000,0x000f4240,0x00000000]}"
    )
    assert desired.destination_masks[5] == 0x1F
    assert desired.destination_masks[4] & 0x20
    assert desired.egress_rates[5] == 0


def test_forwarding_encoders_guard_every_port_6_relationship() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    data = parse_payload(forwarding_fixture_payload())

    content, desired = encode_forwarding_matrix_update(
        data,
        identity,
        ForwardingMatrixUpdate(number=5, destination_port_numbers=(2, 3, 4, 6)),
    )
    assert b"fp5:0x2e" in content
    assert b"fp6:0x1f" in content
    assert desired.destination_masks[5] == 0x1F

    with pytest.raises(InvalidOperationError, match="relationship involving port 6"):
        encode_forwarding_matrix_update(
            data,
            identity,
            ForwardingMatrixUpdate(number=5, destination_port_numbers=(1, 2, 3, 4)),
        )
    with pytest.raises(InvalidOperationError, match="management port"):
        encode_forwarding_matrix_update(
            data,
            identity,
            ForwardingMatrixUpdate.model_construct(
                number=6, destination_port_numbers=(1, 2, 3, 4, 5)
            ),
        )
    with pytest.raises(InvalidOperationError, match="management port"):
        encode_forwarding_mirroring_update(
            data,
            identity,
            ForwardingMirroringUpdate.model_construct(
                source_port_number=6,
                mirror_ingress=True,
                mirror_egress=None,
                mirror_target_port=None,
            ),
        )
    with pytest.raises(InvalidOperationError, match="management port"):
        encode_forwarding_mirroring_update(
            data,
            identity,
            ForwardingMirroringUpdate(source_port_number=5, mirror_target_port=6),
        )

    port_6_mirror = parse_payload(forwarding_fixture_payload())
    port_6_mirror["imr"] = 0x20
    with pytest.raises(InvalidOperationError, match="absent from mirroring"):
        encode_forwarding_port_policy_update(
            port_6_mirror,
            identity,
            ForwardingPortPolicyUpdate(number=5, lock=True),
        )


def test_adapter_sets_forwarding_policy_with_stale_noop_and_readback_guards() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    before = forwarding_from_payload(parse_payload(forwarding_fixture_payload()), identity)
    changed_payload = updated_forwarding_payload(lock=b"10")
    transport = FakeTransport(
        (fixture_payload(), forwarding_fixture_payload(), b"", changed_payload)
    )
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_forwarding_port_policy(
        ForwardingPortPolicyUpdate(number=5, lock=True), expected_current=before
    )

    assert result.changed
    assert result.value.ports[4].lock
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("GET", "/fwd.b"),
        ("POST", "/fwd.b"),
        ("GET", "/fwd.b"),
    ]
    assert transport.request_details[2][2] == (
        b"{fp1:0x3e,fp2:0x3d,fp3:0x3b,fp4:0x37,fp5:0x2f,fp6:0x1f,"
        b"lck:0x10,lckf:0x00,imr:0x00,omr:0x00,mrto:0x01,"
        b"or:[0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000]}"
    )

    no_op_transport = FakeTransport((fixture_payload(), forwarding_fixture_payload()))
    no_op_adapter = CSS106Plugin(
        transport_factory=lambda connection: no_op_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    no_op = no_op_adapter.set_forwarding_port_policy(
        ForwardingPortPolicyUpdate(number=5, lock=False), expected_current=before
    )
    assert not no_op.changed
    assert no_op_transport.requests == [("GET", "/sys.b"), ("GET", "/fwd.b")]

    stale_transport = FakeTransport((fixture_payload(), forwarding_fixture_payload()))
    stale_adapter = CSS106Plugin(
        transport_factory=lambda connection: stale_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(InvalidOperationError, match="changed since the expected baseline"):
        stale_adapter.set_forwarding_port_policy(
            ForwardingPortPolicyUpdate(number=5, lock=True),
            expected_current=before.model_copy(update={"mirror_target_port": None}),
        )
    assert stale_transport.requests == [("GET", "/sys.b"), ("GET", "/fwd.b")]

    mismatch_transport = FakeTransport(
        (fixture_payload(), forwarding_fixture_payload(), b"", forwarding_fixture_payload())
    )
    mismatch_adapter = CSS106Plugin(
        transport_factory=lambda connection: mismatch_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="complete-group read-back"):
        mismatch_adapter.set_forwarding_port_policy(
            ForwardingPortPolicyUpdate(number=5, lock=True), expected_current=before
        )


def test_forwarding_cleanup_rejects_concurrent_change_after_verified_mutation() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    expected_post_payload = updated_forwarding_payload(lock=b"10")
    expected_post = forwarding_from_payload(parse_payload(expected_post_payload), identity)
    concurrent_payload = updated_forwarding_payload(lock=b"10", lock_on_first=b"01")
    transport = FakeTransport((fixture_payload(), concurrent_payload))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="changed since the expected baseline"):
        adapter.set_forwarding_port_policy(
            ForwardingPortPolicyUpdate(number=5, lock=False),
            expected_current=expected_post,
        )

    assert transport.requests == [("GET", "/sys.b"), ("GET", "/fwd.b")]


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


def test_acl_encoder_emits_exact_ordered_table_and_guards_management_ingress() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    rules = acl_rules_from_payload(parse_table_payload(acl_fixture_payload()), identity)

    content = encode_acl_rules((rules[0],), identity)

    assert encode_acl_rules((), identity) == b"[]"
    first_row = acl_fixture_payload().strip()[1:].split(b"},{", 1)[0]
    assert content == b"[" + first_row + b"}]"
    zero_rule = type(rules[0]).model_validate(
        {
            **rules[0].model_dump(mode="python"),
            "source_mac": "00:00:00:00:00:00",
            "destination_mac": "00:00:00:00:00:00",
            "source_ip": "0.0.0.0",
            "destination_ip": "0.0.0.0",
        }
    )
    assert zero_rule.source_mac is None
    assert zero_rule.destination_mac is None
    assert zero_rule.source_ip is None
    assert zero_rule.destination_ip is None
    assert acl_rules_from_payload(
        parse_table_payload(encode_acl_rules((zero_rule,), identity)), identity
    ) == (zero_rule,)
    with pytest.raises(InvalidOperationError, match="management port 6 ingress"):
        encode_acl_rules(rules, identity)
    with pytest.raises(InvalidOperationError, match="consecutive"):
        encode_acl_rules((rules[0].model_copy(update={"number": 2}),), identity)
    with pytest.raises(InvalidOperationError, match=f"cannot exceed {MAX_ACL_RULES}"):
        encode_acl_rules(tuple(rules[0] for _ in range(MAX_ACL_RULES + 1)), identity)
    with pytest.raises(InvalidOperationError, match="is invalid"):
        encode_acl_rules((rules[0].model_copy(update={"ingress_rate_limit_bps": 0}),), identity)
    with pytest.raises(InvalidOperationError, match="not normalized"):
        encode_acl_rules((rules[0].model_copy(update={"source_ip": "0.0.0.0"}),), identity)


def test_adapter_replaces_and_verifies_complete_acl_table() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    rule = acl_rules_from_payload(parse_table_payload(acl_fixture_payload()), identity)[0]
    desired = (rule,)
    encoded = encode_acl_rules(desired, identity)
    transport = FakeTransport((fixture_payload(), b"[]", b"", encoded))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.replace_acl_rules(desired, expected_current=())

    assert result.changed
    assert result.value == desired
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("GET", "/acl.b"),
        ("POST", "/acl.b"),
        ("GET", "/acl.b"),
    ]
    assert transport.request_details[2][2] == encoded
    assert transport.request_details[2][3] == {"Content-Type": "text/plain"}


def test_adapter_skips_acl_post_for_no_op_and_validates_before_transport() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    rules = acl_rules_from_payload(parse_table_payload(acl_fixture_payload()), identity)
    desired = (rules[0],)
    encoded = encode_acl_rules(desired, identity)
    transport = FakeTransport((fixture_payload(), encoded))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.replace_acl_rules(desired, expected_current=desired)

    assert not result.changed
    assert transport.requests == [("GET", "/sys.b"), ("GET", "/acl.b")]
    with pytest.raises(InvalidOperationError, match="management port 6 ingress"):
        adapter.replace_acl_rules(rules, expected_current=desired)
    assert transport.requests == [("GET", "/sys.b"), ("GET", "/acl.b")]


def test_adapter_rejects_stale_acl_baseline_before_post() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    desired = (acl_rules_from_payload(parse_table_payload(acl_fixture_payload()), identity)[0],)
    encoded = encode_acl_rules(desired, identity)
    transport = FakeTransport((fixture_payload(), encoded))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="changed since the expected baseline"):
        adapter.replace_acl_rules(desired, expected_current=())

    assert transport.requests == [("GET", "/sys.b"), ("GET", "/acl.b")]


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


def test_static_host_encoder_emits_exact_ordered_table_and_validates_rows() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    hosts = static_hosts_from_payload(parse_table_payload(static_host_fixture_payload()), identity)

    assert encode_static_hosts((), identity) == b"[]"
    assert encode_static_hosts(hosts, identity) == static_host_fixture_payload().strip()
    dynamic = HostEntry(
        entry_type="dynamic",
        mac_address="02:00:00:00:00:03",
        port_numbers=(1,),
    )
    with pytest.raises(InvalidOperationError, match="cannot be dynamic"):
        encode_static_hosts((dynamic,), identity)
    with pytest.raises(InvalidOperationError, match="between 1 and 5"):
        encode_static_hosts((hosts[0].model_copy(update={"port_numbers": (6,)}),), identity)
    with pytest.raises(InvalidOperationError, match=f"cannot exceed {MAX_STATIC_HOSTS}"):
        encode_static_hosts(tuple(hosts[0] for _ in range(MAX_STATIC_HOSTS + 1)), identity)
    with pytest.raises(InvalidOperationError, match="is invalid"):
        encode_static_hosts((hosts[0].model_copy(update={"vlan_id": 4096}),), identity)
    with pytest.raises(ProtocolError, match=f"exceeds {MAX_STATIC_HOSTS}"):
        static_hosts_from_payload([{}] * (MAX_STATIC_HOSTS + 1), identity)


def test_adapter_replaces_and_verifies_complete_static_host_table() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    desired = static_hosts_from_payload(
        parse_table_payload(static_host_fixture_payload()), identity
    )
    encoded = encode_static_hosts(desired, identity)
    transport = FakeTransport((fixture_payload(), b"[]", b"", encoded))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.replace_static_hosts(desired, expected_current=())

    assert result.changed
    assert result.value == desired
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("GET", "/host.b"),
        ("POST", "/host.b"),
        ("GET", "/host.b"),
    ]
    assert transport.request_details[2][2] == static_host_fixture_payload().strip()


def test_adapter_static_host_no_op_and_read_back_mismatch() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    desired = static_hosts_from_payload(
        parse_table_payload(static_host_fixture_payload()), identity
    )
    transport = FakeTransport((fixture_payload(), static_host_fixture_payload()))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.replace_static_hosts(desired, expected_current=desired)

    assert not result.changed
    assert transport.requests == [("GET", "/sys.b"), ("GET", "/host.b")]

    mismatch_transport = FakeTransport((fixture_payload(), b"[]", b"", b"[]"))
    mismatch_adapter = CSS106Plugin(
        transport_factory=lambda connection: mismatch_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="full-table read-back"):
        mismatch_adapter.replace_static_hosts(desired, expected_current=())


def test_adapter_rejects_stale_static_host_baseline_before_post() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    current = static_hosts_from_payload(
        parse_table_payload(static_host_fixture_payload()), identity
    )
    transport = FakeTransport((fixture_payload(), static_host_fixture_payload()))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="changed since the expected baseline"):
        adapter.replace_static_hosts(current, expected_current=())

    assert transport.requests == [("GET", "/sys.b"), ("GET", "/host.b")]


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

    duplicate_rows = parse_table_payload(static_host_fixture_payload())
    duplicate_rows.append(duplicate_rows[0])
    with pytest.raises(ProtocolError, match="contains duplicate"):
        static_hosts_from_payload(duplicate_rows, identity)

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
    assert info.ports[0].point_to_point
    assert info.ports[0].edge
    assert info.ports[0].port_type.value == "edge"
    assert info.ports[0].state.value == "forwarding"
    assert info.ports[4].port_type.value == "point_to_point"
    assert info.ports[4].state.value == "discarding"
    assert transport.requests == [("GET", "/sys.b"), ("GET", "/rstp.b")]


def test_rstp_encoders_emit_complete_groups_and_preserve_port_6() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    content, desired = encode_rstp_port_enable_update(
        parse_payload(rstp_fixture_payload()),
        identity,
        RstpPortEnableUpdate(number=5, enabled=False),
    )
    assert content == b"{ena:0x2f}"
    assert desired.enabled_mask & 0x20

    bridge_content, bridge_desired = encode_rstp_bridge_update(
        parse_payload(rstp_system_fixture_payload()),
        RstpBridgeUpdate(
            bridge_priority=0x9000,
            cost_mode="long",
            forward_reserved_multicast=True,
        ),
    )
    assert bridge_content == b"{prio:0x9000,cost:0x01,frmc:0x01}"
    assert bridge_desired.bridge_priority == 0x9000

    with pytest.raises(InvalidOperationError, match="management port"):
        encode_rstp_port_enable_update(
            parse_payload(rstp_fixture_payload()),
            identity,
            RstpPortEnableUpdate.model_construct(number=6, enabled=False),
        )


def test_adapter_sets_rstp_enable_with_baseline_noop_and_readback_guards() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    before = rstp_from_payloads(
        parse_payload(rstp_fixture_payload()),
        parse_payload(rstp_system_fixture_payload()),
        identity,
    )
    changed_payload = rstp_fixture_payload().replace(b"ena:0x3f", b"ena:0x2f")
    transport = FakeTransport(
        (
            rstp_system_fixture_payload(),
            rstp_fixture_payload(),
            b"",
            rstp_system_fixture_payload(),
            changed_payload,
        )
    )
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_rstp_port_enabled(
        RstpPortEnableUpdate(number=5, enabled=False), expected_current=before
    )

    assert result.changed
    assert not result.value.ports[4].enabled
    assert result.value.ports[5].enabled
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("GET", "/rstp.b"),
        ("POST", "/rstp.b"),
        ("GET", "/sys.b"),
        ("GET", "/rstp.b"),
    ]
    assert transport.request_details[2][2] == b"{ena:0x2f}"

    no_op_transport = FakeTransport((rstp_system_fixture_payload(), rstp_fixture_payload()))
    no_op_adapter = CSS106Plugin(
        transport_factory=lambda connection: no_op_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    no_op = no_op_adapter.set_rstp_port_enabled(
        RstpPortEnableUpdate(number=5, enabled=True), expected_current=before
    )
    assert not no_op.changed
    assert no_op_transport.requests == [("GET", "/sys.b"), ("GET", "/rstp.b")]

    stale_transport = FakeTransport((rstp_system_fixture_payload(), rstp_fixture_payload()))
    stale_adapter = CSS106Plugin(
        transport_factory=lambda connection: stale_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    stale = before.model_copy(
        update={
            "ports": (
                *before.ports[:4],
                before.ports[4].model_copy(update={"enabled": False}),
                before.ports[5],
            )
        }
    )
    with pytest.raises(InvalidOperationError, match="changed since the expected baseline"):
        stale_adapter.set_rstp_port_enabled(
            RstpPortEnableUpdate(number=5, enabled=False), expected_current=stale
        )
    assert stale_transport.requests == [("GET", "/sys.b"), ("GET", "/rstp.b")]

    mismatch_transport = FakeTransport(
        (
            rstp_system_fixture_payload(),
            rstp_fixture_payload(),
            b"",
            rstp_system_fixture_payload(),
            rstp_fixture_payload(),
        )
    )
    mismatch_adapter = CSS106Plugin(
        transport_factory=lambda connection: mismatch_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="read-back verification"):
        mismatch_adapter.set_rstp_port_enabled(
            RstpPortEnableUpdate(number=5, enabled=False), expected_current=before
        )


def test_rstp_precondition_distinguishes_wire_flags_with_same_normalized_type() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    expected = rstp_from_payloads(
        parse_payload(rstp_fixture_payload()),
        parse_payload(rstp_system_fixture_payload()),
        identity,
    )
    concurrent_payload = rstp_fixture_payload().replace(b"p2p:0x3f", b"p2p:0x3e")
    concurrent = rstp_from_payloads(
        parse_payload(concurrent_payload),
        parse_payload(rstp_system_fixture_payload()),
        identity,
    )
    assert expected.ports[0].port_type == concurrent.ports[0].port_type
    assert expected.ports[0].point_to_point
    assert not concurrent.ports[0].point_to_point
    assert expected.ports[0].edge and concurrent.ports[0].edge
    transport = FakeTransport((rstp_system_fixture_payload(), concurrent_payload))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    with pytest.raises(InvalidOperationError, match="changed since the expected baseline"):
        adapter.set_rstp_port_enabled(
            RstpPortEnableUpdate(number=5, enabled=False), expected_current=expected
        )

    assert transport.requests == [("GET", "/sys.b"), ("GET", "/rstp.b")]


def test_adapter_bridge_write_is_complete_and_verified_but_not_advertised() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    before = rstp_from_payloads(
        parse_payload(rstp_fixture_payload()),
        parse_payload(rstp_system_fixture_payload()),
        identity,
    )
    changed_system = rstp_system_fixture_payload().replace(b"prio:0x8000", b"prio:0x9000")
    transport = FakeTransport(
        (
            rstp_system_fixture_payload(),
            rstp_fixture_payload(),
            b"",
            changed_system,
            rstp_fixture_payload(),
        )
    )
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_rstp_bridge(
        RstpBridgeUpdate(bridge_priority=0x9000), expected_current=before
    )

    assert result.changed
    assert result.value.bridge_priority == 0x9000
    assert transport.request_details[2][2] == b"{prio:0x9000,cost:0x00,frmc:0x00}"
    assert not adapter.capabilities.supports("rstp_bridge_write")


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
    assert info.ports[1].point_to_point
    assert not info.ports[1].edge
    assert info.ports[1].state.value == "learning"
    assert info.ports[1].enabled
    assert info.ports[2].port_type.value == "edge"
    assert not info.ports[2].point_to_point
    assert info.ports[2].edge
    assert info.ports[2].state.value == "forwarding"
    assert info.ports[3].port_type.value == "edge"
    assert info.ports[3].point_to_point
    assert info.ports[3].edge
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


def test_adapter_dry_run_validation_uses_normalized_state_without_transport() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(b"")
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    ports = ports_from_link_payload(parse_payload(link_fixture_payload()), identity)
    rstp = rstp_from_payloads(
        parse_payload(rstp_fixture_payload()),
        parse_payload(rstp_system_fixture_payload()),
        identity,
    )
    forwarding = forwarding_from_payload(parse_payload(forwarding_fixture_payload()), identity)
    port_vlans = port_vlans_from_forwarding_payload(
        parse_payload(forwarding_fixture_payload()), identity
    )
    hosts = static_hosts_from_payload(parse_table_payload(static_host_fixture_payload()), identity)

    adapter.validate_device_name(DeviceNameUpdate(name="Core Switch"))
    adapter.validate_port_name(PortNameUpdate(number=1, name="Uplink"))
    adapter.validate_port_configuration(
        PortConfigurationUpdate(number=1, flow_control=False), current=ports[0]
    )
    adapter.validate_snmp_metadata(SnmpMetadataUpdate(contact="Ops", location="Rack 1"))
    adapter.validate_rstp_port_enabled(RstpPortEnableUpdate(number=1, enabled=False), current=rstp)
    adapter.validate_forwarding_port_policy(
        ForwardingPortPolicyUpdate(number=1, lock=True), current=forwarding
    )
    adapter.validate_static_hosts(hosts)
    adapter.validate_port_vlan_policy(
        PortVlanPolicyUpdate(number=1, force_vlan_id=False), current=port_vlans
    )

    assert transport.requests == []


def test_adapter_dry_run_rejects_active_port_change_and_static_host_overflow() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    transport = FakeTransport(b"")
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    port = ports_from_link_payload(parse_payload(link_fixture_payload()), identity)[0]
    active = port.model_copy(
        update={"link_up": True, "speed_bps": 100_000_000, "full_duplex": True}
    )
    host = static_hosts_from_payload(parse_table_payload(static_host_fixture_payload()), identity)[
        0
    ]

    with pytest.raises(InvalidOperationError, match="link-up"):
        adapter.validate_port_configuration(
            PortConfigurationUpdate(number=1, enabled=False), current=active
        )
    with pytest.raises(InvalidOperationError, match=f"cannot exceed {MAX_STATIC_HOSTS}"):
        adapter.validate_static_hosts(tuple(host for _ in range(MAX_STATIC_HOSTS + 1)))

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


def test_port_vlan_encoder_posts_complete_group_and_preserves_port_6() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    before_data = parse_payload(forwarding_fixture_payload())
    before_state = port_vlan_write_state_from_payload(before_data, identity)

    content, desired = encode_port_vlan_policy_update(
        before_data,
        identity,
        PortVlanPolicyUpdate(
            number=5,
            mode="strict",
            receive="untagged_only",
            default_vlan_id=4094,
            force_vlan_id=True,
            egress="strip",
        ),
    )

    assert content == (
        b"{vlan:[0x01,0x01,0x01,0x01,0x03,0x01],"
        b"vlni:[0x00,0x00,0x00,0x00,0x02,0x00],"
        b"dvid:[0x0001,0x0001,0x0001,0x0001,0x0ffe,0x0001],"
        b"fvid:0x10,vlnh:[0x00,0x00,0x00,0x00,0x01,0x00]}"
    )
    assert desired.modes[4] == 3
    assert desired.receive_modes[4] == 2
    assert desired.default_vlan_ids[4] == 4094
    assert desired.egress_modes[4] == 1
    assert desired.force_vlan_id_mask == 0x10
    assert desired.modes[5] == before_state.modes[5]
    assert desired.receive_modes[5] == before_state.receive_modes[5]
    assert desired.default_vlan_ids[5] == before_state.default_vlan_ids[5]
    assert desired.egress_modes[5] == before_state.egress_modes[5]


def test_port_vlan_encoder_rejects_management_port_even_for_constructed_model() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None

    with pytest.raises(InvalidOperationError, match="SFP management port"):
        encode_port_vlan_policy_update(
            parse_payload(forwarding_fixture_payload()),
            identity,
            PortVlanPolicyUpdate.model_construct(number=6, force_vlan_id=True),
        )


def test_adapter_sets_port_vlan_policy_with_stale_noop_and_readback_guards() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    before_data = parse_payload(forwarding_fixture_payload())
    before = port_vlans_from_forwarding_payload(before_data, identity)
    changed_payload = forwarding_fixture_payload().replace(
        b"vlnh:[0x00,0x00,0x00,0x00,0x00,0x00]",
        b"vlnh:[0x00,0x00,0x00,0x00,0x01,0x00]",
    )
    transport = FakeTransport(
        (fixture_payload(), forwarding_fixture_payload(), b"", changed_payload)
    )
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.set_port_vlan_policy(
        PortVlanPolicyUpdate(number=5, egress="strip"), expected_current=before
    )

    assert result.changed
    assert result.value[4].egress.value == "strip"
    assert result.value[5] == before[5]
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("GET", "/fwd.b"),
        ("POST", "/fwd.b"),
        ("GET", "/fwd.b"),
    ]
    assert transport.request_details[2][2] == (
        b"{vlan:[0x01,0x01,0x01,0x01,0x01,0x01],"
        b"vlni:[0x00,0x00,0x00,0x00,0x00,0x00],"
        b"dvid:[0x0001,0x0001,0x0001,0x0001,0x0001,0x0001],"
        b"fvid:0x00,vlnh:[0x00,0x00,0x00,0x00,0x01,0x00]}"
    )

    no_op_transport = FakeTransport((fixture_payload(), forwarding_fixture_payload()))
    no_op_adapter = CSS106Plugin(
        transport_factory=lambda connection: no_op_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    no_op = no_op_adapter.set_port_vlan_policy(
        PortVlanPolicyUpdate(number=5, egress="preserve"), expected_current=before
    )
    assert not no_op.changed
    assert no_op_transport.requests == [("GET", "/sys.b"), ("GET", "/fwd.b")]

    stale_transport = FakeTransport((fixture_payload(), forwarding_fixture_payload()))
    stale_adapter = CSS106Plugin(
        transport_factory=lambda connection: stale_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    stale = list(before)
    stale[0] = stale[0].model_copy(update={"default_vlan_id": 2})
    with pytest.raises(InvalidOperationError, match="changed since the expected baseline"):
        stale_adapter.set_port_vlan_policy(
            PortVlanPolicyUpdate(number=5, egress="strip"),
            expected_current=tuple(stale),
        )
    assert stale_transport.requests == [("GET", "/sys.b"), ("GET", "/fwd.b")]

    mismatch_transport = FakeTransport(
        (fixture_payload(), forwarding_fixture_payload(), b"", forwarding_fixture_payload())
    )
    mismatch_adapter = CSS106Plugin(
        transport_factory=lambda connection: mismatch_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="complete-group read-back"):
        mismatch_adapter.set_port_vlan_policy(
            PortVlanPolicyUpdate(number=5, egress="strip"), expected_current=before
        )


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


def test_vlan_write_state_preserves_wire_order_while_public_read_stays_sorted() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    rows = parse_table_payload(vlan_fixture_payload())

    state = vlan_table_write_state_from_payload(rows, identity)
    public = vlans_from_payload(rows, identity)

    assert [row.vlan_id for row in state.rows] == [20, 10]
    assert [vlan.vlan_id for vlan in public] == [10, 20]


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


def test_vlan_table_encoder_posts_complete_rows_and_preserves_port_6() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    before = vlans_from_payload(parse_table_payload(vlan_fixture_payload()), identity)
    desired = (
        before[0].model_copy(
            update={
                "independent_learning": True,
                "ports": (
                    before[0].ports[0].model_copy(update={"mode": VlanMembershipMode.PRESERVE}),
                    *before[0].ports[1:],
                ),
            }
        ),
        before[1],
    )

    content = encode_vlans(desired, before, identity)

    assert content == (
        b"[{vid:0x000a,ivl:0x01,igmp:0x01,"
        b"prt:[0x00,0x01,0x03,0x03,0x03,0x02]},"
        b"{vid:0x0014,ivl:0x01,igmp:0x00,"
        b"prt:[0x00,0x03,0x01,0x01,0x03,0x02]}]"
    )

    changed_port_6 = list(desired[0].ports)
    changed_port_6[5] = changed_port_6[5].model_copy(update={"mode": VlanMembershipMode.NOT_MEMBER})
    unsafe = (desired[0].model_copy(update={"ports": tuple(changed_port_6)}), desired[1])
    with pytest.raises(InvalidOperationError, match="management port 6 membership"):
        encode_vlans(unsafe, before, identity)

    added = VlanInfo(
        vlan_id=30,
        independent_learning=False,
        igmp_snooping=False,
        ports=tuple(
            VlanPortMembership(
                port_number=number,
                mode="strip" if number == 6 else "not_member",
            )
            for number in range(1, 7)
        ),
    )
    with pytest.raises(InvalidOperationError, match="management port 6 membership"):
        encode_vlans((*desired, added), before, identity)
    with pytest.raises(InvalidOperationError, match="management port 6 membership"):
        encode_vlans((before[1],), before, identity)


def test_adapter_replaces_vlan_table_with_identity_stale_noop_and_readback_guards() -> None:
    identity = identity_from_system(parse_payload(fixture_payload()))
    assert identity is not None
    before = vlans_from_payload(parse_table_payload(vlan_fixture_payload()), identity)
    desired = (
        before[0].model_copy(update={"igmp_snooping": False}),
        before[1],
    )
    desired_payload = encode_vlans(desired, before, identity)
    transport = FakeTransport((fixture_payload(), vlan_fixture_payload(), b"", desired_payload))
    adapter = CSS106Plugin(transport_factory=lambda connection: transport).create(  # type: ignore[arg-type]
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )

    result = adapter.replace_vlans(desired, expected_current=before)

    assert result.changed
    assert result.value == desired
    assert transport.requests == [
        ("GET", "/sys.b"),
        ("GET", "/vlan.b"),
        ("POST", "/vlan.b"),
        ("GET", "/vlan.b"),
    ]
    assert transport.request_details[2][2] == desired_payload

    no_op_transport = FakeTransport((fixture_payload(), vlan_fixture_payload()))
    no_op_adapter = CSS106Plugin(
        transport_factory=lambda connection: no_op_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    no_op = no_op_adapter.replace_vlans(before, expected_current=before)
    assert not no_op.changed
    assert no_op_transport.requests == [("GET", "/sys.b"), ("GET", "/vlan.b")]

    stale_transport = FakeTransport((fixture_payload(), vlan_fixture_payload()))
    stale_adapter = CSS106Plugin(
        transport_factory=lambda connection: stale_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    stale = (before[0].model_copy(update={"igmp_snooping": False}), before[1])
    with pytest.raises(InvalidOperationError, match="changed since the expected baseline"):
        stale_adapter.replace_vlans(desired, expected_current=stale)
    assert stale_transport.requests == [("GET", "/sys.b"), ("GET", "/vlan.b")]

    mismatch_transport = FakeTransport(
        (fixture_payload(), vlan_fixture_payload(), b"", vlan_fixture_payload())
    )
    mismatch_adapter = CSS106Plugin(
        transport_factory=lambda connection: mismatch_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="full-table read-back"):
        mismatch_adapter.replace_vlans(desired, expected_current=before)

    first_row, second_row = desired_payload[1:-1].split(b"},{", maxsplit=1)
    reordered_payload = b"[{" + second_row + b"," + first_row + b"}]"
    reordered_transport = FakeTransport(
        (fixture_payload(), vlan_fixture_payload(), b"", reordered_payload)
    )
    reordered_adapter = CSS106Plugin(
        transport_factory=lambda connection: reordered_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    assert vlans_from_payload(parse_table_payload(reordered_payload), identity) == desired
    with pytest.raises(ProtocolError, match="full-table read-back"):
        reordered_adapter.replace_vlans(desired, expected_current=before)

    changed_identity = fixture_payload().replace(b"322e3139", b"322e3230")
    identity_transport = FakeTransport(changed_identity)
    identity_adapter = CSS106Plugin(
        transport_factory=lambda connection: identity_transport  # type: ignore[arg-type]
    ).create(
        identity=identity,
        connection=DeviceConnection(url="http://192.0.2.1"),
        policy=FirmwareSafetyPolicy(),
        support=plugin.support_records()[0],
    )
    with pytest.raises(ProtocolError, match="identity changed"):
        identity_adapter.replace_vlans(desired, expected_current=before)
    assert identity_transport.requests == [("GET", "/sys.b")]


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
