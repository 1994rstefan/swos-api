from __future__ import annotations

from typing import cast
from unittest.mock import Mock, patch

import pytest
from swos_ansible import execute
from swos_core import (
    AclRule,
    AclVlanTagMode,
    AddressMode,
    DeviceCapabilities,
    DeviceIdentity,
    ForwardingInfo,
    HostEntry,
    HostEntryType,
    IgmpInfo,
    IgmpVersion,
    InvalidOperationError,
    OperationResult,
    PortForwardingInfo,
    PortInfo,
    PortVlanInfo,
    RstpCostMode,
    RstpInfo,
    RstpPortInfo,
    RstpPortType,
    RstpProtocol,
    RstpRole,
    RstpState,
    SafetyWarning,
    SnmpInfo,
    SwOSDevice,
    SystemInfo,
    SystemManagementInfo,
    UnsupportedFeatureError,
    VlanEgressMode,
    VlanInfo,
    VlanMembershipMode,
    VlanMode,
    VlanPortMembership,
    VlanReceiveMode,
)

IDENTITY = DeviceIdentity(
    firmware_family="css106",
    product_code="CSS106-5G-1S",
    firmware_version="2.19",
    build_id="0x6a181cd5",
)


def _device() -> SwOSDevice:
    mocked = Mock(spec=SwOSDevice)
    mocked.identity = IDENTITY
    mocked.capabilities = DeviceCapabilities(
        features=frozenset(
            {
                "ports",
                "snmp",
                "device_name_write",
                "port_name_write",
                "port_configuration_write",
                "snmp_metadata_write",
                "snmp_configuration_write",
                "static_hosts_write",
                "rstp_port_enable_write",
                "forwarding_port_policy_write",
                "vlan_port_policy_write",
                "system_configuration_write",
                "admin_password_write",
                "acl_write",
                "vlan_table_write",
                "rstp_bridge_write",
                "forwarding_matrix_write",
                "forwarding_mirroring_write",
            }
        )
    )
    mocked.warnings = ()
    mocked.validate_device_name.return_value = ()
    mocked.validate_port_name.return_value = ()
    mocked.validate_port_configuration.return_value = ()
    mocked.validate_snmp_metadata.return_value = ()
    mocked.validate_snmp_configuration.return_value = ()
    mocked.validate_static_hosts.return_value = ()
    mocked.validate_rstp_port_enabled.return_value = ()
    mocked.validate_forwarding_port_policy.return_value = ()
    mocked.validate_port_vlan_policy.return_value = ()
    mocked.validate_system_configuration.return_value = ()
    mocked.validate_admin_password.return_value = ()
    mocked.validate_acl_rules.return_value = ()
    mocked.validate_vlans.return_value = ()
    mocked.validate_rstp_bridge.return_value = ()
    mocked.validate_forwarding_matrix.return_value = ()
    mocked.validate_forwarding_mirroring.return_value = ()
    return cast(SwOSDevice, mocked)


def _system(name: str = "Switch") -> SystemInfo:
    return SystemInfo(identity=IDENTITY, name=name, uptime_seconds=10)


def _configured_system() -> SystemInfo:
    return SystemInfo(
        identity=IDENTITY,
        name="Switch",
        uptime_seconds=10,
        current_ip="192.0.2.10",
        static_ip="192.0.2.10",
        mac_address="02:00:00:00:00:01",
        management=SystemManagementInfo(
            address_mode=AddressMode.STATIC,
            admin_mac_address=None,
            allow_from=None,
            allow_prefix_length=0,
            allowed_port_numbers=(1, 6),
            allowed_vlan_id=None,
            watchdog_enabled=True,
        ),
        independent_vlan_lookup=False,
        igmp=IgmpInfo(
            enabled=False,
            querier_configured=False,
            querier_effective=False,
            fast_leave_port_numbers=(),
            version=IgmpVersion.V2,
        ),
        discovery_protocol_port_numbers=(6,),
    )


def _port(
    number: int = 5,
    *,
    name: str = "Port5",
    enabled: bool = True,
    auto_negotiation: bool = True,
    configured_speed_bps: int = 100_000_000,
    configured_full_duplex: bool = True,
    flow_control: bool = False,
) -> PortInfo:
    return PortInfo(
        number=number,
        name=name,
        enabled=enabled,
        link_up=False,
        auto_negotiation=auto_negotiation,
        configured_speed_bps=configured_speed_bps,
        configured_full_duplex=configured_full_duplex,
        flow_control=flow_control,
    )


def _rstp(enabled: bool = False) -> RstpInfo:
    return RstpInfo(
        bridge_priority=0x8000,
        cost_mode=RstpCostMode.LONG,
        forward_reserved_multicast=False,
        root_bridge_priority=0x8000,
        root_bridge_mac="02:00:00:00:00:01",
        ports=(
            RstpPortInfo(
                number=5,
                enabled=enabled,
                protocol=RstpProtocol.RSTP,
                role=RstpRole.DISABLED,
                root_path_cost=0,
                point_to_point=True,
                edge=False,
                port_type=RstpPortType.POINT_TO_POINT,
                state=RstpState.DISCARDING,
            ),
        ),
    )


def _forwarding(rate: int | None = 1_000_000) -> ForwardingInfo:
    return ForwardingInfo(
        ports=(
            PortForwardingInfo(
                number=5,
                destination_port_numbers=(5,),
                lock=False,
                lock_on_first=False,
                mirror_ingress=False,
                mirror_egress=False,
                egress_rate_limit_bps=rate,
            ),
        )
    )


def _forwarding_with_management() -> ForwardingInfo:
    return ForwardingInfo(
        ports=(
            PortForwardingInfo(
                number=5,
                destination_port_numbers=(1, 5, 6),
                lock=False,
                lock_on_first=False,
                mirror_ingress=False,
                mirror_egress=False,
            ),
            *tuple(
                PortForwardingInfo(
                    number=number,
                    destination_port_numbers=(number,),
                    lock=False,
                    lock_on_first=False,
                    mirror_ingress=False,
                    mirror_egress=False,
                )
                for number in range(1, 5)
            ),
            PortForwardingInfo(
                number=6,
                destination_port_numbers=(1, 2, 3, 4, 5, 6),
                lock=False,
                lock_on_first=False,
                mirror_ingress=False,
                mirror_egress=False,
            ),
        )
    )


def _vlan_port(mode: VlanMode = VlanMode.OPTIONAL) -> PortVlanInfo:
    return PortVlanInfo(
        number=5,
        mode=mode,
        receive=VlanReceiveMode.ANY,
        default_vlan_id=1,
        force_vlan_id=False,
        egress=VlanEgressMode.PRESERVE,
    )


def _acl_rule(number: int = 1) -> AclRule:
    return AclRule(
        number=number,
        ingress_port_numbers=(5,),
        source_mac=None,
        source_mac_mask="ff:ff:ff:ff:ff:ff",
        destination_mac=None,
        destination_mac_mask="ff:ff:ff:ff:ff:ff",
        ether_type=0x0800,
        vlan_tag=AclVlanTagMode.ANY,
        vlan_id_min=0,
        vlan_id_max=0,
        vlan_priority=None,
        source_ip=None,
        source_prefix_length=0,
        source_port_min=0,
        source_port_max=0,
        destination_ip="192.0.2.1",
        destination_prefix_length=32,
        destination_port_min=0,
        destination_port_max=0,
        protocol_number=0,
        dscp=None,
        redirect_enabled=True,
        redirect_port_numbers=(),
        drop=True,
        mirror=False,
        ingress_rate_limit_bps=None,
        set_vlan_id=None,
        set_vlan_priority=None,
    )


def _vlan(vlan_id: int, position: int) -> VlanInfo:
    return VlanInfo(
        table_position=position,
        vlan_id=vlan_id,
        independent_learning=True,
        igmp_snooping=False,
        ports=tuple(
            VlanPortMembership(port_number=number, mode=VlanMembershipMode.NOT_MEMBER)
            for number in range(1, 7)
        ),
    )


def test_facts_gathers_only_requested_subsets_and_warnings() -> None:
    device = _device()
    warning = SafetyWarning(code="untested_firmware", message="Explicit override in use")
    cast(Mock, device).warnings = (warning,)
    cast(Mock, device.get_system_info).return_value = _system()
    cast(Mock, device.get_ports).return_value = (_port(),)

    result = execute("facts", {"gather_subset": ["system", "ports"]}, device=device)

    facts = result["ansible_facts"]["swos"]
    assert result["changed"] is False
    assert facts["system"]["name"] == "Switch"
    assert facts["ports"][0]["number"] == 5
    assert "snmp" not in facts
    assert result["swos_warnings"] == [warning.model_dump(mode="json")]


def test_snmp_facts_preserve_established_read_community() -> None:
    device = _device()
    cast(Mock, device.get_snmp).return_value = SnmpInfo(
        enabled=True, community="public", contact="Ops", location="Rack 1"
    )

    result = execute("facts", {"gather_subset": ["snmp"]}, device=device)

    snmp = result["ansible_facts"]["swos"]["snmp"]
    assert snmp["community"] == "public"
    assert "community_configured" not in snmp


def test_device_name_check_mode_accepts_unicode_and_projects_without_write() -> None:
    device = _device()
    cast(Mock, device.get_system_info).return_value = _system()

    result = execute("device_name", {"name": "Büro"}, check_mode=True, device=device)

    assert result == {
        "changed": True,
        "system": {**_system().model_dump(mode="json"), "name": "Büro"},
    }
    cast(Mock, device.validate_device_name).assert_called_once()
    cast(Mock, device.set_device_name).assert_not_called()


def test_unchanged_device_name_skips_write() -> None:
    device = _device()
    cast(Mock, device.get_system_info).return_value = _system("Office")

    result = execute("device_name", {"name": "Office"}, device=device)

    assert result["changed"] is False
    cast(Mock, device.set_device_name).assert_not_called()


def test_device_name_applies_core_result() -> None:
    device = _device()
    cast(Mock, device.get_system_info).return_value = _system()
    cast(Mock, device.set_device_name).return_value = OperationResult(
        changed=True, value=_system("Office")
    )

    result = execute("device_name", {"name": "Office"}, device=device)

    assert result["changed"] is True
    assert result["system"]["name"] == "Office"


def test_forced_port_configuration_check_mode_is_idempotent_and_projected() -> None:
    device = _device()
    cast(Mock, device.get_ports).return_value = (_port(),)
    params = {
        "port": 5,
        "negotiation": "forced",
        "speed_bps": 10_000_000,
        "duplex": "half",
        "flow_control": True,
    }

    result = execute("port_configuration", params, check_mode=True, device=device)

    assert result["changed"] is True
    assert result["port"]["auto_negotiation"] is False
    assert result["port"]["configured_speed_bps"] == 10_000_000
    assert result["port"]["configured_full_duplex"] is False
    assert result["port"]["flow_control"] is True
    cast(Mock, device.validate_port_configuration).assert_called_once()
    cast(Mock, device.set_port_configuration).assert_not_called()


def test_port_configuration_rejects_incomplete_forced_negotiation() -> None:
    device = _device()

    with pytest.raises(ValueError, match="requires speed_bps and duplex"):
        execute(
            "port_configuration",
            {"port": 5, "negotiation": "forced", "speed_bps": 100_000_000},
            check_mode=True,
            device=device,
        )


def test_operation_validation_happens_before_plugin_discovery() -> None:
    with patch("swos_ansible.runtime.PluginRegistry.discover") as discover:
        with pytest.raises(ValueError, match="requires speed_bps"):
            execute(
                "port_configuration",
                {"port": 5, "negotiation": "forced", "duplex": "full"},
                check_mode=True,
            )

    discover.assert_not_called()


@pytest.mark.parametrize("rate", [True, 1.5, "1000000"])
def test_forwarding_rate_rejects_bool_float_and_numeric_string_before_connect(
    rate: object,
) -> None:
    with patch("swos_ansible.runtime.PluginRegistry.discover") as discover:
        with pytest.raises(ValueError, match="integer or 'unlimited'"):
            execute(
                "forwarding_port_policy",
                {"port": 5, "egress_rate_limit_bps": rate},
                check_mode=True,
            )

    discover.assert_not_called()


@pytest.mark.parametrize(
    ("operation", "params", "message"),
    [
        ("device_name", {"name": "x" * 17}, "cannot exceed 16"),
        ("port_name", {"port": 1, "name": "Upl\nink"}, "printable Unicode"),
        ("snmp_metadata", {"contact": "x" * 65}, "cannot exceed 64"),
        ("static_hosts", {"hosts": [{}] * 2049}, "cannot exceed 2048"),
    ],
)
def test_wire_constraints_are_enforced_before_connect(
    operation: str,
    params: dict[str, object],
    message: str,
) -> None:
    with patch("swos_ansible.runtime.PluginRegistry.discover") as discover:
        with pytest.raises(ValueError, match=message):
            execute(operation, params, check_mode=True)

    discover.assert_not_called()


def test_check_mode_surfaces_adapter_validation_without_write() -> None:
    device = _device()
    cast(Mock, device.get_ports).return_value = (_port(),)
    cast(Mock, device.validate_port_configuration).side_effect = InvalidOperationError(
        "device-specific validation failed"
    )

    with pytest.raises(InvalidOperationError, match="device-specific validation failed"):
        execute(
            "port_configuration",
            {"port": 5, "enabled": False},
            check_mode=True,
            device=device,
        )

    cast(Mock, device.set_port_configuration).assert_not_called()


def test_snmp_check_mode_preserves_omitted_metadata() -> None:
    device = _device()
    cast(Mock, device.get_snmp).return_value = SnmpInfo(
        enabled=True, community="public", contact="Old", location="Rack 1"
    )

    result = execute(
        "snmp_metadata", {"contact": "New", "location": None}, check_mode=True, device=device
    )

    assert result["snmp"]["contact"] == "New"
    assert result["snmp"]["location"] == "Rack 1"
    cast(Mock, device.set_snmp_metadata).assert_not_called()


def test_snmp_configuration_check_mode_preserves_omitted_and_redacts_community() -> None:
    device = _device()
    cast(Mock, device.get_snmp).return_value = SnmpInfo(
        enabled=True, community="public", contact="Old", location="Rack 1"
    )

    result = execute(
        "snmp_configuration",
        {"enabled": False, "community": "private", "contact": "New"},
        check_mode=True,
        device=device,
    )

    assert result["changed"] is True
    assert result["snmp"] == {
        "enabled": False,
        "contact": "New",
        "location": "Rack 1",
        "community_configured": True,
    }
    assert "private" not in repr(result)
    cast(Mock, device.validate_snmp_configuration).assert_called_once()
    cast(Mock, device.set_snmp_configuration).assert_not_called()


def test_snmp_configuration_normal_mode_writes_and_redacts_community() -> None:
    device = _device()
    cast(Mock, device.get_snmp).return_value = SnmpInfo(
        enabled=True, community="public", contact="Old", location="Rack 1"
    )
    cast(Mock, device.set_snmp_configuration).return_value = OperationResult(
        changed=True,
        value=SnmpInfo(enabled=False, community="private", contact="New", location="Rack 1"),
    )

    result = execute(
        "snmp_configuration",
        {"enabled": False, "community": "private", "contact": "New"},
        device=device,
    )

    assert result["changed"] is True
    assert result["snmp"] == {
        "enabled": False,
        "contact": "New",
        "location": "Rack 1",
        "community_configured": True,
    }
    assert "private" not in repr(result)
    update = cast(Mock, device.set_snmp_configuration).call_args.args[0]
    assert update.community.get_secret_value() == "private"


@pytest.mark.parametrize("community", [1, True, ["private"]])
def test_snmp_configuration_rejects_non_string_community_before_connect(
    community: object,
) -> None:
    with patch("swos_ansible.runtime.PluginRegistry.discover") as discover:
        with pytest.raises(ValueError, match="SNMP community must be a string"):
            execute("snmp_configuration", {"community": community}, check_mode=True)
    discover.assert_not_called()


def test_static_hosts_filter_dynamic_baseline_and_sort_ports() -> None:
    device = _device()
    static = HostEntry(
        entry_type=HostEntryType.STATIC,
        mac_address="02:00:00:00:00:05",
        vlan_id=10,
        port_numbers=(2, 5),
    )
    dynamic = HostEntry(
        entry_type=HostEntryType.DYNAMIC,
        mac_address="02:00:00:00:00:06",
        port_numbers=(1,),
    )
    cast(Mock, device.get_hosts).return_value = (static, dynamic)

    result = execute(
        "static_hosts",
        {
            "hosts": [
                {
                    "mac_address": "02:00:00:00:00:05",
                    "vlan_id": 10,
                    "port_numbers": [5, 2],
                }
            ]
        },
        device=device,
    )

    assert result["changed"] is False
    cast(Mock, device.replace_static_hosts).assert_not_called()


def test_static_hosts_check_mode_never_replaces_table() -> None:
    device = _device()
    cast(Mock, device.get_hosts).return_value = ()

    result = execute(
        "static_hosts",
        {
            "hosts": [
                {
                    "mac_address": "02:00:00:00:00:05",
                    "vlan_id": 10,
                    "port_numbers": [5],
                }
            ]
        },
        check_mode=True,
        device=device,
    )

    assert result["changed"] is True
    assert result["hosts"][0]["entry_type"] == "static"
    cast(Mock, device.replace_static_hosts).assert_not_called()


def test_rstp_write_uses_fresh_read_as_expected_baseline() -> None:
    device = _device()
    current = _rstp()
    desired = _rstp(enabled=True)
    cast(Mock, device.get_rstp).return_value = current
    cast(Mock, device.set_rstp_port_enabled).return_value = OperationResult(
        changed=True, value=desired
    )

    result = execute("rstp_port", {"port": 5, "enabled": True}, device=device)

    assert result["changed"] is True
    assert result["rstp"]["ports"][0]["enabled"] is True
    assert cast(Mock, device.set_rstp_port_enabled).call_args.kwargs["expected_current"] == current


def test_forwarding_check_mode_supports_unlimited_rate() -> None:
    device = _device()
    cast(Mock, device.get_forwarding).return_value = _forwarding()

    result = execute(
        "forwarding_port_policy",
        {"port": 5, "egress_rate_limit_bps": "unlimited"},
        check_mode=True,
        device=device,
    )

    assert result["changed"] is True
    assert result["forwarding"]["ports"][0]["egress_rate_limit_bps"] is None
    cast(Mock, device.set_forwarding_port_policy).assert_not_called()


def test_vlan_check_mode_projects_only_requested_fields() -> None:
    device = _device()
    cast(Mock, device.get_port_vlans).return_value = (_vlan_port(),)

    result = execute(
        "vlan_port_policy",
        {"port": 5, "mode": "strict", "default_vlan_id": 10},
        check_mode=True,
        device=device,
    )

    assert result["ports"][0]["mode"] == "strict"
    assert result["ports"][0]["default_vlan_id"] == 10
    assert result["ports"][0]["receive"] == "any"
    cast(Mock, device.set_port_vlan_policy).assert_not_called()


def test_ports_outside_hardware_enabled_range_are_rejected() -> None:
    device = _device()

    with pytest.raises(ValueError, match="1 through 5"):
        execute("port_name", {"port": 6, "name": "SFP"}, device=device)


def test_check_mode_rejects_missing_write_capability() -> None:
    device = _device()
    cast(Mock, device).capabilities = DeviceCapabilities(features=frozenset({"ports"}))

    with pytest.raises(UnsupportedFeatureError, match="device name write"):
        execute("device_name", {"name": "Office"}, check_mode=True, device=device)

    cast(Mock, device.get_system_info).assert_not_called()


def test_connection_pre_authorizes_write_policy_in_check_mode() -> None:
    device = _device()
    cast(Mock, device.get_system_info).return_value = _system()
    registry = Mock()
    registry.probe.return_value = IDENTITY
    registry.resolve.return_value = Mock(warnings=())
    registry.connect.return_value = device

    with patch("swos_ansible.runtime.PluginRegistry.discover", return_value=registry):
        execute(
            "device_name",
            {
                "url": "http://192.0.2.10",
                "name": "Office",
                "allow_untested_firmware": False,
                "allow_untested_firmware_writes": True,
            },
            check_mode=True,
        )

    _, policy = registry.resolve.call_args.args
    assert registry.resolve.call_args.kwargs == {"write": True}
    assert policy.allow_untested_firmware is False
    assert policy.allow_untested_firmware_writes is True
    cast(Mock, device.set_device_name).assert_not_called()


def test_system_configuration_check_mode_projects_all_groups_and_passes_readback_url() -> None:
    device = _device()
    current = _configured_system()
    cast(Mock, device.get_system_info).return_value = current
    params = {
        "address_mode": "dhcp_with_fallback",
        "static_ip": "unset",
        "admin_mac_address": "02:00:00:00:00:22",
        "name": "Office",
        "allow_from": "192.0.2.0",
        "allow_prefix_length": 24,
        "allowed_port_numbers": [6, 2],
        "allowed_vlan_id": 10,
        "independent_vlan_lookup": True,
        "igmp_enabled": True,
        "igmp_querier": True,
        "igmp_fast_leave_port_numbers": [5, 1],
        "igmp_version": "v3",
        "discovery_protocol_port_numbers": [],
        "readback_url": "http://192.0.2.20",
    }

    result = execute("system_configuration", params, check_mode=True, device=device)

    assert result["changed"] is True
    assert result["system"]["name"] == "Office"
    assert result["system"]["static_ip"] is None
    assert result["system"]["management"]["allowed_port_numbers"] == [2, 6]
    assert result["system"]["management"]["allowed_vlan_id"] == 10
    assert result["system"]["igmp"]["fast_leave_port_numbers"] == [1, 5]
    assert result["system"]["discovery_protocol_port_numbers"] == []
    validate = cast(Mock, device.validate_system_configuration)
    assert validate.call_args.kwargs == {
        "current": current,
        "readback_url": "http://192.0.2.20",
    }
    cast(Mock, device.set_system_configuration).assert_not_called()


def test_system_configuration_unchanged_validates_and_skips_write() -> None:
    device = _device()
    current = _configured_system()
    cast(Mock, device.get_system_info).return_value = current

    result = execute(
        "system_configuration",
        {"name": "Switch", "allowed_port_numbers": [1, 6]},
        device=device,
    )

    assert result["changed"] is False
    cast(Mock, device.validate_system_configuration).assert_called_once()
    cast(Mock, device.set_system_configuration).assert_not_called()


def test_admin_password_check_mode_always_changes_validates_and_never_returns_secret() -> None:
    device = _device()
    cast(Mock, device.get_system_info).return_value = _system()

    result = execute(
        "admin_password",
        {"new_password": "new-secret"},
        check_mode=True,
        device=device,
    )

    assert result["changed"] is True
    assert "new-secret" not in repr(result)
    cast(Mock, device.validate_admin_password).assert_called_once()
    cast(Mock, device.set_admin_password).assert_not_called()


@pytest.mark.parametrize("new_password", ["start\x00end", "delete\x7f"])
def test_admin_password_accepts_ascii_control_and_del_code_units(new_password: str) -> None:
    device = _device()
    cast(Mock, device.get_system_info).return_value = _system()

    result = execute(
        "admin_password", {"new_password": new_password}, check_mode=True, device=device
    )

    assert result["changed"] is True
    assert new_password not in repr(result)
    update = cast(Mock, device.validate_admin_password).call_args.args[0]
    assert update.new_password.get_secret_value() == new_password


def test_admin_password_rejects_non_ascii_before_connect() -> None:
    with patch("swos_ansible.runtime.PluginRegistry.discover") as discover:
        with pytest.raises(ValueError, match=r"U\+0000\.\.U\+007F"):
            execute("admin_password", {"new_password": "pässword"}, check_mode=True)
    discover.assert_not_called()


def test_admin_password_write_returns_only_verified_system_and_warnings() -> None:
    device = _device()
    warning = SafetyWarning(code="credentials_changed", message="Credentials changed")
    cast(Mock, device.get_system_info).return_value = _system()
    cast(Mock, device.set_admin_password).return_value = OperationResult(
        changed=True,
        value=_system(),
        warnings=(warning,),
    )

    result = execute("admin_password", {"new_password": "new-secret"}, device=device)

    assert result["changed"] is True
    assert result["swos_warnings"] == [warning.model_dump(mode="json")]
    assert "new-secret" not in repr(result)


def test_acl_check_mode_derives_ordered_numbers_and_calls_public_validator() -> None:
    device = _device()
    cast(Mock, device.get_acl_rules).return_value = ()
    raw = _acl_rule().model_dump(mode="json")
    del raw["number"]

    result = execute("acl_rules", {"rules": [raw]}, check_mode=True, device=device)

    assert result["changed"] is True
    assert result["rules"][0]["number"] == 1
    validated = cast(Mock, device.validate_acl_rules).call_args.args[0]
    assert validated == (_acl_rule(),)
    cast(Mock, device.replace_acl_rules).assert_not_called()


def test_acl_check_mode_derives_ordered_number_from_explicit_null() -> None:
    device = _device()
    cast(Mock, device.get_acl_rules).return_value = ()
    raw = _acl_rule().model_dump(mode="json")
    raw["number"] = None

    result = execute("acl_rules", {"rules": [raw]}, check_mode=True, device=device)

    assert result["rules"][0]["number"] == 1
    validated = cast(Mock, device.validate_acl_rules).call_args.args[0]
    assert validated == (_acl_rule(),)
    cast(Mock, device.replace_acl_rules).assert_not_called()


def test_acl_unchanged_table_is_idempotent() -> None:
    device = _device()
    current = (_acl_rule(),)
    cast(Mock, device.get_acl_rules).return_value = current

    result = execute(
        "acl_rules",
        {"rules": [_acl_rule().model_dump(mode="json")]},
        device=device,
    )

    assert result["changed"] is False
    cast(Mock, device.validate_acl_rules).assert_called_once_with(current)
    cast(Mock, device.replace_acl_rules).assert_not_called()


def test_acl_rejects_number_that_disagrees_with_list_order_before_connect() -> None:
    raw = _acl_rule(number=2).model_dump(mode="json")
    with patch("swos_ansible.runtime.PluginRegistry.discover") as discover:
        with pytest.raises(ValueError, match="ordered position 1"):
            execute("acl_rules", {"rules": [raw]}, check_mode=True)
    discover.assert_not_called()


@pytest.mark.parametrize("allowed_vlan_id", [True, False, 10.0, "10", "UNSET"])
def test_system_allowed_vlan_rejects_coercible_values_before_connect(
    allowed_vlan_id: object,
) -> None:
    with patch("swos_ansible.runtime.PluginRegistry.discover") as discover:
        with pytest.raises(ValueError, match="integer or 'unset'"):
            execute(
                "system_configuration",
                {"allowed_vlan_id": allowed_vlan_id},
                check_mode=True,
            )
    discover.assert_not_called()


@pytest.mark.parametrize("allowed_vlan_id", [1, 4095, "unset"])
def test_system_allowed_vlan_accepts_only_exact_supported_types(
    allowed_vlan_id: int | str,
) -> None:
    device = _device()
    cast(Mock, device.get_system_info).return_value = _configured_system()

    execute(
        "system_configuration",
        {"allowed_vlan_id": allowed_vlan_id},
        check_mode=True,
        device=device,
    )

    update = cast(Mock, device.validate_system_configuration).call_args.args[0]
    assert update.allowed_vlan_id == allowed_vlan_id


def test_vlan_table_uses_list_order_as_hidden_table_positions() -> None:
    device = _device()
    current = (_vlan(10, 1), _vlan(20, 0))
    cast(Mock, device.get_vlans).return_value = current

    result = execute(
        "vlan_table",
        {
            "vlans": [
                _vlan(20, 0).model_dump(mode="json"),
                _vlan(10, 1).model_dump(mode="json"),
            ]
        },
        device=device,
    )

    assert result["changed"] is False
    desired = cast(Mock, device.validate_vlans).call_args.args[0]
    assert [vlan.vlan_id for vlan in desired] == [10, 20]
    assert [vlan.table_position for vlan in desired] == [1, 0]
    assert cast(Mock, device.validate_vlans).call_args.kwargs == {"current": current}
    cast(Mock, device.replace_vlans).assert_not_called()


def test_vlan_check_mode_requires_complete_port_membership_before_connect() -> None:
    raw = _vlan(10, 0).model_dump(mode="json")
    raw["ports"] = raw["ports"][:-1]
    with patch("swos_ansible.runtime.PluginRegistry.discover") as discover:
        with pytest.raises(ValueError, match="ports 1 through 6"):
            execute("vlan_table", {"vlans": [raw]}, check_mode=True)
    discover.assert_not_called()


def test_rstp_bridge_check_mode_projects_only_requested_fields() -> None:
    device = _device()
    current = _rstp()
    cast(Mock, device.get_rstp).return_value = current

    result = execute(
        "rstp_bridge",
        {"bridge_priority": 0x7000, "forward_reserved_multicast": True},
        check_mode=True,
        device=device,
    )

    assert result["rstp"]["bridge_priority"] == 0x7000
    assert result["rstp"]["cost_mode"] == "long"
    assert result["rstp"]["forward_reserved_multicast"] is True
    cast(Mock, device.validate_rstp_bridge).assert_called_once()
    cast(Mock, device.set_rstp_bridge).assert_not_called()


def test_forwarding_matrix_preserves_management_destination_in_check_mode() -> None:
    device = _device()
    current = _forwarding_with_management()
    cast(Mock, device.get_forwarding).return_value = current

    result = execute(
        "forwarding_matrix",
        {"port": 5, "destination_port_numbers": [5, 2]},
        check_mode=True,
        device=device,
    )

    assert result["forwarding"]["ports"][0]["destination_port_numbers"] == [2, 5, 6]
    update = cast(Mock, device.validate_forwarding_matrix).call_args.args[0]
    assert update.destination_port_numbers == (2, 5, 6)
    cast(Mock, device.set_forwarding_matrix).assert_not_called()


def test_forwarding_mirroring_check_mode_projects_source_and_global_target() -> None:
    device = _device()
    current = _forwarding_with_management()
    cast(Mock, device.get_forwarding).return_value = current

    result = execute(
        "forwarding_mirroring",
        {
            "source_port_number": 5,
            "mirror_ingress": True,
            "mirror_target_port": 1,
        },
        check_mode=True,
        device=device,
    )

    assert result["forwarding"]["mirror_target_port"] == 1
    assert result["forwarding"]["ports"][0]["mirror_ingress"] is True
    assert result["forwarding"]["ports"][0]["mirror_egress"] is False
    cast(Mock, device.validate_forwarding_mirroring).assert_called_once()
    cast(Mock, device.set_forwarding_mirroring).assert_not_called()


def test_forwarding_mirroring_none_clears_target_idempotently() -> None:
    device = _device()
    current = _forwarding_with_management()
    cast(Mock, device.get_forwarding).return_value = current

    result = execute(
        "forwarding_mirroring",
        {"source_port_number": 5, "mirror_target_port": "none"},
        device=device,
    )

    assert result["changed"] is False
    cast(Mock, device.validate_forwarding_mirroring).assert_called_once()
    cast(Mock, device.set_forwarding_mirroring).assert_not_called()


@pytest.mark.parametrize(
    ("operation", "params", "getter", "validator", "setter"),
    [
        ("acl_rules", {"rules": []}, "get_acl_rules", "validate_acl_rules", "replace_acl_rules"),
        ("vlan_table", {"vlans": []}, "get_vlans", "validate_vlans", "replace_vlans"),
    ],
)
def test_empty_complete_tables_still_validate_in_check_mode_without_writes(
    operation: str,
    params: dict[str, object],
    getter: str,
    validator: str,
    setter: str,
) -> None:
    device = _device()
    cast(Mock, getattr(device, getter)).return_value = ()

    result = execute(operation, params, check_mode=True, device=device)

    assert result["changed"] is False
    cast(Mock, getattr(device, validator)).assert_called_once()
    cast(Mock, getattr(device, setter)).assert_not_called()
