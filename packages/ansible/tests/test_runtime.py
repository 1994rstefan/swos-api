from __future__ import annotations

from typing import cast
from unittest.mock import Mock, patch

import pytest
from swos_ansible import execute
from swos_core import (
    DeviceCapabilities,
    DeviceIdentity,
    ForwardingInfo,
    HostEntry,
    HostEntryType,
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
    UnsupportedFeatureError,
    VlanEgressMode,
    VlanMode,
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
                "static_hosts_write",
                "rstp_port_enable_write",
                "forwarding_port_policy_write",
                "vlan_port_policy_write",
            }
        )
    )
    mocked.warnings = ()
    mocked.validate_device_name.return_value = ()
    mocked.validate_port_name.return_value = ()
    mocked.validate_port_configuration.return_value = ()
    mocked.validate_snmp_metadata.return_value = ()
    mocked.validate_static_hosts.return_value = ()
    mocked.validate_rstp_port_enabled.return_value = ()
    mocked.validate_forwarding_port_policy.return_value = ()
    mocked.validate_port_vlan_policy.return_value = ()
    return cast(SwOSDevice, mocked)


def _system(name: str = "Switch") -> SystemInfo:
    return SystemInfo(identity=IDENTITY, name=name, uptime_seconds=10)


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


def _vlan_port(mode: VlanMode = VlanMode.OPTIONAL) -> PortVlanInfo:
    return PortVlanInfo(
        number=5,
        mode=mode,
        receive=VlanReceiveMode.ANY,
        default_vlan_id=1,
        force_vlan_id=False,
        egress=VlanEgressMode.PRESERVE,
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


def test_device_name_check_mode_projects_change_without_write() -> None:
    device = _device()
    cast(Mock, device.get_system_info).return_value = _system()

    result = execute("device_name", {"name": "Office"}, check_mode=True, device=device)

    assert result == {
        "changed": True,
        "system": {**_system().model_dump(mode="json"), "name": "Office"},
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
        ("port_name", {"port": 1, "name": "Uplänk"}, "printable ASCII"),
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
