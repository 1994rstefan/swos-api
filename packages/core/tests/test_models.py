import pytest
from pydantic import ValidationError
from swos_core.models import (
    DeviceCapabilities,
    DeviceConnection,
    DeviceIdentity,
    DeviceNameUpdate,
    ForcedPortNegotiation,
    ForwardingInfo,
    ForwardingMatrixUpdate,
    ForwardingMirroringUpdate,
    ForwardingPortPolicyUpdate,
    HostEntry,
    IgmpGroup,
    OperationResult,
    PasswordUpdate,
    PortConfigurationUpdate,
    PortForwardingInfo,
    PortInfo,
    PortNameUpdate,
    PortStatistics,
    PortVlanInfo,
    PortVlanPolicyUpdate,
    RstpBridgeUpdate,
    RstpPortEnableUpdate,
    SafetyWarning,
    SnmpMetadataUpdate,
    SystemConfigurationUpdate,
    SystemManagementInfo,
    VlanInfo,
    VlanPortMembership,
)


def test_device_identity_is_immutable() -> None:
    identity = DeviceIdentity(
        firmware_family="css106",
        product_code="CSS106-5G-1S",
        firmware_version="2.19",
    )

    try:
        identity.firmware_version = "2.20"  # type: ignore[misc]
    except ValidationError:
        pass
    else:
        raise AssertionError("DeviceIdentity unexpectedly allowed mutation")


def test_connection_hides_password() -> None:
    connection = DeviceConnection(url="http://192.0.2.1", password="top-secret")

    assert "top-secret" not in repr(connection)
    assert connection.password.get_secret_value() == "top-secret"


def test_password_update_never_serializes_or_represents_plaintext() -> None:
    update = PasswordUpdate(new_password="rotation-secret")

    assert update.model_dump(mode="python") == {}
    assert update.model_dump(mode="json") == {}
    assert update.model_dump_json() == "{}"
    assert "rotation-secret" not in repr(update)
    assert "rotation-secret" not in str(update)
    assert update.new_password.get_secret_value() == "rotation-secret"


def test_capability_lookup() -> None:
    capabilities = DeviceCapabilities(features=frozenset({"vlan", "snmp"}))

    assert capabilities.supports("vlan")
    assert not capabilities.supports("poe")


def test_port_operational_state_is_consistent() -> None:
    port = PortInfo(
        number=1,
        name="Port1",
        enabled=True,
        link_up=True,
        speed_bps=1_000_000_000,
        full_duplex=True,
        auto_negotiation=True,
        configured_speed_bps=100_000_000,
        configured_full_duplex=True,
        flow_control=True,
    )

    assert port.speed_bps == 1_000_000_000
    with pytest.raises(ValidationError, match="link-down"):
        PortInfo(
            number=1,
            name="Port1",
            enabled=True,
            link_up=False,
            speed_bps=1_000_000_000,
            full_duplex=True,
            auto_negotiation=True,
            configured_speed_bps=100_000_000,
            configured_full_duplex=True,
            flow_control=True,
        )


def test_port_name_update_and_operation_result_are_typed_and_immutable() -> None:
    update = PortNameUpdate(number=1, name="Uplink")
    result = OperationResult[PortNameUpdate](
        changed=True,
        value=update,
        warnings=(SafetyWarning(code="test", message="Test warning"),),
    )

    assert result.model_dump(mode="json") == {
        "changed": True,
        "value": {"number": 1, "name": "Uplink"},
        "warnings": [{"code": "test", "message": "Test warning"}],
    }
    with pytest.raises(ValidationError):
        PortNameUpdate(number=0, name="Uplink")
    assert PortNameUpdate(number=6, name="Management").number == 6
    with pytest.raises(ValidationError):
        result.changed = False  # type: ignore[misc]


def test_port_configuration_update_is_strict_non_empty_and_uses_bps() -> None:
    update = PortConfigurationUpdate(
        number=5,
        enabled=False,
        negotiation=ForcedPortNegotiation(speed_bps=100_000_000, duplex="full"),
        flow_control=True,
    )

    assert update.model_dump(mode="json") == {
        "number": 5,
        "enabled": False,
        "negotiation": {"speed_bps": 100_000_000, "duplex": "full"},
        "flow_control": True,
    }
    assert PortConfigurationUpdate(number=1, negotiation="auto").negotiation == "auto"
    with pytest.raises(ValidationError, match="at least one"):
        PortConfigurationUpdate(number=1)
    assert PortConfigurationUpdate(number=6, flow_control=True).number == 6
    assert ForcedPortNegotiation(speed_bps=1_000_000_000, duplex="full").speed_bps == 1_000_000_000
    with pytest.raises(ValidationError):
        ForcedPortNegotiation.model_validate(
            {"speed_bps": 10_000_000, "duplex": "half", "mode": "forced"}
        )


def test_device_name_and_snmp_metadata_updates_are_typed_and_immutable() -> None:
    device_name = DeviceNameUpdate(name="Core Switch")
    metadata = SnmpMetadataUpdate(contact="", location=None)

    assert device_name.model_dump(mode="json") == {"name": "Core Switch"}
    assert metadata.model_dump(mode="json") == {"contact": "", "location": None}
    with pytest.raises(ValidationError):
        metadata.contact = "Ops"  # type: ignore[misc]


def test_system_configuration_update_is_typed_normalized_and_non_empty() -> None:
    update = SystemConfigurationUpdate(
        address_mode="dhcp_only",
        static_ip="192.0.2.10",
        admin_mac_address="AA:BB:CC:DD:EE:FF",
        allow_from="unset",
        allowed_vlan_id="unset",
        allowed_port_numbers=(1, 6),
        igmp_version="v3",
    )

    assert update.static_ip == "192.0.2.10"
    assert update.admin_mac_address == "aa:bb:cc:dd:ee:ff"
    assert update.allow_from == "unset"
    assert update.allowed_vlan_id == "unset"
    assert update.model_dump(mode="json")["address_mode"] == "dhcp_only"
    with pytest.raises(ValidationError, match="at least one"):
        SystemConfigurationUpdate()
    with pytest.raises(ValidationError):
        SystemConfigurationUpdate(static_ip="not-an-address")
    with pytest.raises(ValidationError, match="hexadecimal octets"):
        SystemConfigurationUpdate(admin_mac_address="not-a-mac")
    with pytest.raises(ValidationError, match="unique"):
        SystemConfigurationUpdate(discovery_protocol_port_numbers=(1, 1))


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
    ],
)
def test_system_configuration_rejects_unusable_static_management_ipv4(address: str) -> None:
    with pytest.raises(ValidationError, match="usable unicast IPv4"):
        SystemConfigurationUpdate(static_ip=address)


@pytest.mark.parametrize("address", ["10.0.0.1", "192.168.1.1", "169.254.1.1", "192.0.2.10"])
def test_system_configuration_accepts_private_link_local_and_normal_unicast(
    address: str,
) -> None:
    assert SystemConfigurationUpdate(static_ip=address).static_ip == address


def test_port_statistics_reject_negative_counters() -> None:
    with pytest.raises(ValidationError):
        PortStatistics(
            number=1,
            rx_bytes=-1,
            tx_bytes=0,
            rx_packets=0,
            tx_packets=0,
            rx_errors=0,
            tx_errors=0,
            rates={
                "rx_bits_per_second": 0,
                "tx_bits_per_second": 0,
                "rx_packets_per_second": 0,
                "tx_packets_per_second": 0,
            },
            traffic={
                "rx_unicast_packets": 0,
                "tx_unicast_packets": 0,
                "rx_broadcast_packets": 0,
                "tx_broadcast_packets": 0,
                "rx_multicast_packets": 0,
                "tx_multicast_packets": 0,
            },
            rx_sizes={
                "frames_64_bytes": 0,
                "frames_65_to_127_bytes": 0,
                "frames_128_to_255_bytes": 0,
                "frames_256_to_511_bytes": 0,
                "frames_512_to_1023_bytes": 0,
                "frames_1024_to_1518_bytes": 0,
                "frames_1519_to_max_bytes": 0,
            },
            tx_sizes={
                "frames_64_bytes": 0,
                "frames_65_to_127_bytes": 0,
                "frames_128_to_255_bytes": 0,
                "frames_256_to_511_bytes": 0,
                "frames_512_to_1023_bytes": 0,
                "frames_1024_to_1518_bytes": 0,
                "frames_1519_to_max_bytes": 0,
            },
            detailed_errors={
                "rx_pause_frames": 0,
                "rx_fcs_errors": 0,
                "rx_alignment_errors": 0,
                "rx_runts": 0,
                "rx_fragments": 0,
                "rx_too_long": 0,
                "rx_overflows": 0,
                "tx_pause_frames": 0,
                "tx_underruns": 0,
                "tx_too_long": 0,
                "tx_collisions": 0,
                "tx_excessive_collisions": 0,
                "tx_multiple_collisions": 0,
                "tx_single_collisions": 0,
                "tx_excessive_deferred": 0,
                "tx_deferred": 0,
                "tx_late_collisions": 0,
            },
        )


def test_new_read_models_validate_addresses_and_port_numbers() -> None:
    with pytest.raises(ValidationError, match="multicast"):
        IgmpGroup(address="192.0.2.1", vlan_id=1, port_numbers=(1,))
    with pytest.raises(ValidationError, match="member port"):
        IgmpGroup(address="239.1.2.3", vlan_id=1, port_numbers=())
    with pytest.raises(ValidationError, match="positive"):
        PortForwardingInfo(
            number=1,
            destination_port_numbers=(0,),
            lock=False,
            lock_on_first=False,
            mirror_ingress=False,
            mirror_egress=False,
        )
    with pytest.raises(ValidationError, match="declared port"):
        ForwardingInfo(
            mirror_target_port=2,
            ports=(
                PortForwardingInfo(
                    number=1,
                    destination_port_numbers=(2,),
                    lock=False,
                    lock_on_first=False,
                    mirror_ingress=False,
                    mirror_egress=False,
                ),
            ),
        )
    with pytest.raises(ValidationError, match="unique"):
        SystemManagementInfo(
            address_mode="static",
            allow_prefix_length=24,
            allowed_port_numbers=(1, 1),
            watchdog_enabled=True,
        )
    with pytest.raises(ValidationError):
        SystemManagementInfo(
            address_mode="static",
            allow_from="not-an-ip",
            allow_prefix_length=24,
            allowed_port_numbers=(1,),
            watchdog_enabled=True,
        )


def test_rstp_and_forwarding_desired_states_are_typed_and_non_empty() -> None:
    assert RstpPortEnableUpdate(number=5, enabled=False).model_dump(mode="json") == {
        "number": 5,
        "enabled": False,
    }
    assert RstpBridgeUpdate(bridge_priority=0x9000).bridge_priority == 0x9000
    assert (
        ForwardingPortPolicyUpdate(
            number=5, egress_rate_limit_bps="unlimited"
        ).egress_rate_limit_bps
        == "unlimited"
    )
    assert ForwardingMatrixUpdate(
        number=5, destination_port_numbers=(1, 2, 6)
    ).destination_port_numbers == (1, 2, 6)
    assert (
        ForwardingMirroringUpdate(
            source_port_number=5, mirror_target_port="none"
        ).mirror_target_port
        == "none"
    )

    with pytest.raises(ValidationError, match="at least one"):
        RstpBridgeUpdate()
    with pytest.raises(ValidationError, match="multiple of 4096"):
        RstpBridgeUpdate(bridge_priority=1)
    with pytest.raises(ValidationError, match="at least one"):
        ForwardingPortPolicyUpdate(number=5)
    with pytest.raises(ValidationError):
        ForwardingPortPolicyUpdate(number=5, egress_rate_limit_bps=0)
    with pytest.raises(ValidationError, match="at least one"):
        ForwardingMirroringUpdate(source_port_number=5)


def test_host_entries_validate_dynamic_and_static_invariants() -> None:
    dynamic = HostEntry(
        entry_type="dynamic",
        mac_address="02:00:00:00:00:AA",
        port_numbers=(2,),
    )

    assert dynamic.vlan_id is None
    assert dynamic.mac_address == "02:00:00:00:00:aa"
    with pytest.raises(ValidationError, match="zero MAC"):
        HostEntry(
            entry_type="dynamic",
            mac_address="00:00:00:00:00:00",
            port_numbers=(1,),
        )
    with pytest.raises(ValidationError, match="exactly one port"):
        HostEntry(
            entry_type="dynamic",
            mac_address="02:00:00:00:00:01",
            port_numbers=(1, 2),
        )
    with pytest.raises(ValidationError, match="require a VLAN ID"):
        HostEntry(
            entry_type="static",
            mac_address="02:00:00:00:00:01",
            port_numbers=(1,),
        )
    with pytest.raises(ValidationError, match="positive"):
        HostEntry(
            entry_type="static",
            mac_address="02:00:00:00:00:01",
            vlan_id=1,
            port_numbers=(0,),
        )
    with pytest.raises(ValidationError, match="duplicate ports"):
        HostEntry(
            entry_type="static",
            mac_address="02:00:00:00:00:01",
            vlan_id=1,
            port_numbers=(1, 1),
        )
    with pytest.raises(ValidationError, match="static actions"):
        HostEntry(
            entry_type="dynamic",
            mac_address="02:00:00:00:00:01",
            port_numbers=(1,),
            mirror=True,
        )


def test_vlan_models_validate_values_and_unique_ports() -> None:
    port = PortVlanInfo(
        number=1,
        mode="strict",
        receive="tagged_only",
        default_vlan_id=10,
        force_vlan_id=True,
        egress="preserve",
    )

    assert port.mode.value == "strict"
    update = PortVlanPolicyUpdate(number=5, receive="untagged_only", force_vlan_id=False)
    assert update.receive.value == "untagged_only"
    assert update.force_vlan_id is False
    vlan = VlanInfo(
        table_position=2,
        vlan_id=10,
        independent_learning=True,
        igmp_snooping=False,
        ports=(VlanPortMembership(port_number=1, mode="strip"),),
    )
    assert vlan.table_position == 2
    assert "table_position" not in vlan.model_dump(mode="json")
    with pytest.raises(ValidationError, match="at least one"):
        PortVlanPolicyUpdate(number=5)
    with pytest.raises(ValidationError):
        PortVlanInfo(
            number=1,
            mode="strict",
            receive="tagged_only",
            default_vlan_id=4096,
            force_vlan_id=True,
            egress="preserve",
        )

    with pytest.raises(ValidationError, match="duplicate ports"):
        VlanInfo(
            vlan_id=10,
            independent_learning=True,
            igmp_snooping=False,
            ports=(
                VlanPortMembership(port_number=1, mode="strip"),
                VlanPortMembership(port_number=1, mode="not_member"),
            ),
        )
