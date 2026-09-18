from __future__ import annotations

import importlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError
from swos_cli.app import app
from swos_core.api import SwOSDevice
from swos_core.errors import InvalidOperationError, ProtocolError
from swos_core.models import (
    AclRule,
    AclVlanTagMode,
    AddressMode,
    DeviceConnection,
    DeviceIdentity,
    DeviceNameUpdate,
    ForcedPortNegotiation,
    ForwardingMatrixUpdate,
    ForwardingMirroringUpdate,
    ForwardingPortPolicyUpdate,
    HostEntry,
    HostEntryType,
    IgmpVersion,
    PasswordUpdate,
    PortConfigurationUpdate,
    PortNameUpdate,
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
    SnmpConfigurationUpdate,
    SnmpInfo,
    SnmpMetadataUpdate,
    SystemConfigurationUpdate,
    VlanEgressMode,
    VlanInfo,
    VlanMembershipMode,
    VlanMode,
    VlanPortMembership,
    VlanReceiveMode,
)
from swos_device_css106.adapter import CSS106Adapter
from swos_device_css106.protocol import (
    LinkWriteState,
    RstpBridgeWriteState,
    RstpEnableWriteState,
    SnmpWriteState,
    SystemConfigurationWriteState,
    acl_rules_from_payload,
    encode_acl_rules,
    encode_forwarding_port_policy_update,
    encode_password_update,
    encode_port_configuration_update,
    encode_port_name_update,
    encode_port_vlan_policy_update,
    encode_rstp_bridge_update,
    encode_rstp_port_enable_update,
    encode_snmp_configuration_update,
    encode_static_hosts,
    encode_system_configuration_update,
    encode_vlans,
    parse_payload,
    parse_table_payload,
    port_statistics_from_payload,
    sfp_from_payload,
    validate_device_name,
    validate_password_update,
    validate_port_name,
    validate_snmp_metadata,
)
from typer.testing import CliRunner

ROOT = Path(__file__).parents[1]
MANIFEST_PATH = ROOT / "docs" / "css106-2.19-ui-manifest.json"
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
IDENTITY = DeviceIdentity(
    firmware_family="css106",
    product_code="CSS106-5G-1S",
    firmware_version="2.19",
    marketing_name="RB260GS",
    build_id="0x6a181cd5",
)


def _post_group(name: str) -> list[str]:
    return next(
        group["ordered_fields"] for group in MANIFEST["post_groups"] if group["name"] == name
    )


def _acl_rule(**updates: Any) -> AclRule:
    values: dict[str, Any] = {
        "number": 1,
        "ingress_port_numbers": (1,),
        "source_mac": None,
        "source_mac_mask": "ff:ff:ff:ff:ff:ff",
        "destination_mac": None,
        "destination_mac_mask": "ff:ff:ff:ff:ff:ff",
        "ether_type": 0,
        "vlan_tag": AclVlanTagMode.ANY,
        "vlan_id_min": 0,
        "vlan_id_max": 0,
        "vlan_priority": None,
        "source_ip": None,
        "source_prefix_length": 0,
        "source_port_min": 0,
        "source_port_max": 0,
        "destination_ip": None,
        "destination_prefix_length": 0,
        "destination_port_min": 0,
        "destination_port_max": 0,
        "protocol_number": 0,
        "dscp": None,
        "redirect_enabled": False,
        "redirect_port_numbers": (),
        "drop": False,
        "mirror": False,
        "ingress_rate_limit_bps": None,
        "set_vlan_id": None,
        "set_vlan_priority": None,
    }
    values.update(updates)
    return AclRule(**values)


def _rstp_info(*, forward_reserved_multicast: bool) -> RstpInfo:
    return RstpInfo(
        bridge_priority=0x8000,
        cost_mode=RstpCostMode.SHORT,
        forward_reserved_multicast=forward_reserved_multicast,
        root_bridge_priority=0x8000,
        root_bridge_mac="02:00:00:00:00:01",
        ports=tuple(
            RstpPortInfo(
                number=number,
                enabled=True,
                protocol=RstpProtocol.RSTP,
                role=RstpRole.DESIGNATED,
                root_path_cost=0,
                point_to_point=True,
                edge=False,
                port_type=RstpPortType.POINT_TO_POINT,
                state=RstpState.FORWARDING,
            )
            for number in range(1, 7)
        ),
    )


def _vlan(
    vlan_id: int,
    *,
    port_6: VlanMembershipMode = VlanMembershipMode.NOT_MEMBER,
    independent_learning: Any = False,
) -> VlanInfo:
    return VlanInfo(
        vlan_id=vlan_id,
        independent_learning=independent_learning,
        igmp_snooping=False,
        ports=tuple(
            VlanPortMembership(
                port_number=number,
                mode=port_6 if number == 6 else VlanMembershipMode.NOT_MEMBER,
            )
            for number in range(1, 7)
        ),
    )


def test_manifest_is_complete_and_self_consistent() -> None:
    """Validate the committed frozen oracle without requiring ignored live evidence."""

    surfaces = MANIFEST["surfaces"]
    profiles = MANIFEST["coverage_profiles"]
    post_groups = MANIFEST["post_groups"]

    assert MANIFEST["ui_artifact"]["decompressed_bytes"] == 37_733
    assert MANIFEST["ui_artifact"]["decompressed_sha256"] == (
        "6f631be833b4ff2d5445652422d0087448038e506ea3081fcf9a558c7aed1579"
    )
    assert len(surfaces) == 19
    assert sum(len(surface["fields"]) for surface in surfaces) == 177
    assert (
        sum(
            len(surface["fields"])
            for surface in surfaces
            if surface["access"] != "omitted_for_css106_5g_1s"
        )
        == 169
    )
    assert len(MANIFEST["actions"]) == 9
    assert len(post_groups) == 11
    assert {group["name"] for group in post_groups} == {
        "link",
        "forwarding",
        "port_vlan",
        "rstp_port",
        "rstp_bridge",
        "system",
        "snmp",
        "vlan_table_row",
        "static_host_row",
        "acl_row",
        "password",
    }
    assert sum(len(group["ordered_fields"]) for group in post_groups) == 81
    assert all(group["endpoint"].startswith("/") for group in post_groups)
    assert all(
        len(group["ordered_fields"]) == len(set(group["ordered_fields"])) for group in post_groups
    )
    assert {
        group["name"]: group.get("conditionally_omitted_fields", [])
        for group in post_groups
        if "conditionally_omitted_fields" in group
    } == {"static_host_row": ["adr"], "acl_row": ["smac", "dmac"]}
    assert all(
        set(group.get("conditionally_omitted_fields", ())) <= set(group["ordered_fields"])
        for group in post_groups
    )
    assert len({surface["name"] for surface in surfaces}) == len(surfaces)
    for surface in surfaces:
        assert len(surface["fields"]) == len(surface["labels"]) == len(surface["types"])
        assert surface["coverage"] in profiles
    assert {
        surface["name"]: surface.get("maximum_rows")
        for surface in surfaces
        if surface["name"] in {"vlan_table", "static_hosts", "acl"}
    } == {"vlan_table": 250, "static_hosts": None, "acl": 32}
    assert MANIFEST["password_transform"]["new_password_limit_utf16_units"] == 15
    assert MANIFEST["password_transform"]["new_password_allowed_code_units"] == (
        "U+0000 through U+007F"
    )


def test_manifest_classifies_every_finding_and_derives_classification_totals() -> None:
    findings = MANIFEST["known_discrepancies"]
    classifications: dict[str, int] = {}
    for finding in findings:
        classification = finding["classification"]
        classifications[classification] = classifications.get(classification, 0) + 1

    assert len(findings) == 22
    assert {finding["id"] for finding in findings} == {f"D{number:02d}" for number in range(1, 23)}
    assert classifications == MANIFEST["classification_totals"]


def test_manifest_matches_exact_public_capabilities_and_api_methods() -> None:
    adapter = CSS106Adapter(DeviceConnection(url="http://192.0.2.1"), IDENTITY)

    assert (
        sorted(adapter.capabilities.features)
        == MANIFEST["public_contract"]["required_capabilities"]
    )
    for method in MANIFEST["public_contract"]["required_api_methods"]:
        assert callable(getattr(SwOSDevice, method, None)), method


def test_core_snmp_read_serialization_preserves_configured_community() -> None:
    info = SnmpInfo(enabled=True, community="public", contact="Ops", location="Rack 1")

    assert info.model_dump(mode="json")["community"] == "public"


@pytest.mark.parametrize("command", MANIFEST["public_contract"]["required_cli_commands"])
def test_manifest_cli_commands_have_runnable_help(command: str) -> None:
    result = CliRunner().invoke(app, [*command.split(), "--help"])

    assert result.exit_code == 0, result.output
    assert "Usage:" in result.output


@pytest.mark.parametrize("name", MANIFEST["public_contract"]["required_ansible_modules"])
def test_manifest_ansible_modules_have_documented_argument_specs(name: str) -> None:
    module = importlib.import_module(f"ansible_collections.swos.api.plugins.modules.{name}")
    with patch.object(module, "run_module") as run_module:
        module.main()

    assert run_module.call_args.args[0] == name
    assert run_module.call_args.args[1]
    assert f"module: {name}" in module.DOCUMENTATION


def test_manifest_enum_wire_order_matches_public_enum_order() -> None:
    pairs = {
        "address_mode": AddressMode,
        "igmp_version": IgmpVersion,
        "rstp_cost_mode": RstpCostMode,
        "vlan_mode": VlanMode,
        "vlan_receive": VlanReceiveMode,
        "vlan_egress": VlanEgressMode,
        "vlan_membership": VlanMembershipMode,
        "acl_vlan_tag": AclVlanTagMode,
    }
    for name, enum_type in pairs.items():
        assert [item.value for item in enum_type] == MANIFEST["enums"][name]["public"]
        assert MANIFEST["enums"][name]["wire"] == list(range(len(enum_type)))


def test_manifest_post_groups_match_current_serializers() -> None:
    link_data: dict[str, Any] = {
        "en": 0,
        "nm": [""] * 6,
        "an": 0,
        "spdc": [0] * 6,
        "dpxc": 0,
        "fct": 0,
    }
    link, _ = encode_port_name_update(link_data, IDENTITY, PortNameUpdate(number=1, name="p1"))

    system_data: dict[str, Any] = {
        "iptp": 0,
        "sip": 0,
        "amac": "000000000000",
        "id": "",
        "alla": 0,
        "allm": 0,
        "allp": 1 << 5,
        "avln": 0,
        "ivl": 0,
        "igmp": 0,
        "igmq": 0,
        "igfl": 0,
        "igve": 0,
        "pdsc": 0,
    }
    system, _ = encode_system_configuration_update(
        system_data, IDENTITY, SystemConfigurationUpdate(name="switch")
    )

    forwarding_data: dict[str, Any] = {
        **{f"fp{number}": 0 for number in range(1, 7)},
        "lck": 0,
        "lckf": 0,
        "imr": 0,
        "omr": 0,
        "mrto": 0,
        "or": [0] * 6,
    }
    forwarding, _ = encode_forwarding_port_policy_update(
        forwarding_data, IDENTITY, ForwardingPortPolicyUpdate(number=1, lock=True)
    )
    port_vlan_data: dict[str, Any] = {
        "vlan": [0] * 6,
        "vlni": [0] * 6,
        "dvid": [1] * 6,
        "fvid": 0,
        "vlnh": [0] * 6,
    }
    port_vlan, _ = encode_port_vlan_policy_update(
        port_vlan_data, IDENTITY, PortVlanPolicyUpdate(number=1, force_vlan_id=True)
    )
    rstp_port, _ = encode_rstp_port_enable_update(
        {"ena": 0}, IDENTITY, RstpPortEnableUpdate(number=1, enabled=True)
    )
    rstp_bridge, _ = encode_rstp_bridge_update(
        {"prio": 0x8000, "cost": 0, "frmc": 0}, RstpBridgeUpdate(cost_mode=RstpCostMode.LONG)
    )
    snmp, snmp_state = encode_snmp_configuration_update(
        {"en": 0, "com": "", "ci": "", "loc": ""},
        SnmpConfigurationUpdate(
            enabled=True,
            community=SecretStr("private"),
            contact="x",
        ),
    )
    assert snmp == b"{en:0x01,com:'70726976617465',ci:'78',loc:''}"
    assert snmp_state.raw_community == "70726976617465"
    password = encode_password_update(PasswordUpdate(new_password=SecretStr("")), SecretStr(""))

    object_payloads = {
        "link": link,
        "forwarding": forwarding,
        "port_vlan": port_vlan,
        "rstp_port": rstp_port,
        "rstp_bridge": rstp_bridge,
        "system": system,
        "snmp": snmp,
        "password": password,
    }
    for name, payload in object_payloads.items():
        assert list(parse_payload(payload)) == _post_group(name)

    host = HostEntry(
        entry_type=HostEntryType.STATIC,
        mac_address="02:00:00:00:00:01",
        vlan_id=1,
        port_numbers=(1,),
    )
    table_payloads = {
        "static_host_row": encode_static_hosts((host,), IDENTITY),
        "vlan_table_row": encode_vlans((_vlan(1),), (), IDENTITY),
        "acl_row": encode_acl_rules((_acl_rule(),), IDENTITY),
    }
    for name, payload in table_payloads.items():
        row = parse_table_payload(payload)[0]
        assert isinstance(row, dict)
        assert list(row) == [field for field in _post_group(name) if field in row]
        if name == "acl_row":
            assert "smac" not in row
            assert "dmac" not in row


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SystemConfigurationUpdate(igmp_enabled=1),
        lambda: PortConfigurationUpdate(number=1, flow_control=1),
        lambda: ForwardingPortPolicyUpdate(number=1, lock=1),
        lambda: ForwardingMirroringUpdate(source_port_number=1, mirror_ingress=1),
        lambda: RstpPortEnableUpdate(number=1, enabled=1),
        lambda: RstpBridgeUpdate(forward_reserved_multicast=1),
        lambda: PortVlanPolicyUpdate(number=1, force_vlan_id=1),
        lambda: _vlan(1, independent_learning=1),
        lambda: HostEntry(
            entry_type=HostEntryType.STATIC,
            mac_address="02:00:00:00:00:01",
            vlan_id=1,
            port_numbers=(1,),
            drop=1,
        ),
        lambda: _acl_rule(mirror=1),
        lambda: SnmpConfigurationUpdate(enabled=1),
        lambda: SystemConfigurationUpdate(igmp_enabled="true"),
        lambda: RstpPortEnableUpdate(number=1, enabled="false"),
    ],
)
def test_public_boolean_inputs_reject_integer_spellings(factory: Callable[[], object]) -> None:
    with pytest.raises(ValidationError):
        factory()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: PortVlanPolicyUpdate(number=1, default_vlan_id=True),
        lambda: ForwardingPortPolicyUpdate(number=1, egress_rate_limit_bps=True),
        lambda: SystemConfigurationUpdate(allow_prefix_length=True),
        lambda: SystemConfigurationUpdate(discovery_protocol_port_numbers=(True,)),
        lambda: _acl_rule(ether_type=True),
        lambda: SystemConfigurationUpdate(allow_prefix_length="24"),
        lambda: PortConfigurationUpdate(number="1", flow_control=True),
        lambda: ForwardingMirroringUpdate(source_port_number="1", mirror_ingress=True),
        lambda: RstpBridgeUpdate(bridge_priority="32768"),
        lambda: HostEntry(
            entry_type=HostEntryType.STATIC,
            mac_address="02:00:00:00:00:01",
            vlan_id="1",
            port_numbers=(1,),
        ),
        lambda: _acl_rule(source_prefix_length="24"),
        lambda: VlanInfo(
            vlan_id="1",
            independent_learning=False,
            igmp_snooping=False,
            ports=(),
        ),
    ],
)
def test_public_integer_inputs_reject_bool_and_numeric_strings(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ValidationError):
        factory()


def test_wire_boolean_parser_rejects_non_boolean_integers() -> None:
    with pytest.raises(ProtocolError, match="must be 0 or 1"):
        acl_rules_from_payload(
            [
                {
                    **parse_table_payload(encode_acl_rules((_acl_rule(),), IDENTITY))[0],
                    "mirr": 2,
                }
            ],
            IDENTITY,
        )


@pytest.mark.parametrize(
    ("model", "field", "bad_value"),
    [
        (PortVlanPolicyUpdate, "mode", "Disabled"),
        (PortVlanPolicyUpdate, "receive", "only tagged"),
        (PortVlanPolicyUpdate, "egress", "leave as is"),
        (SystemConfigurationUpdate, "address_mode", "DHCP only"),
        (SystemConfigurationUpdate, "igmp_version", "V3"),
    ],
)
def test_public_enums_reject_ui_labels_and_wrong_case(
    model: type[Any], field: str, bad_value: str
) -> None:
    values: dict[str, Any] = {field: bad_value}
    if model is PortVlanPolicyUpdate:
        values["number"] = 1
    with pytest.raises(ValidationError):
        model(**values)


def test_every_public_write_model_forbids_unknown_fields() -> None:
    write_models = (
        DeviceNameUpdate,
        PasswordUpdate,
        SystemConfigurationUpdate,
        PortNameUpdate,
        ForcedPortNegotiation,
        PortConfigurationUpdate,
        ForwardingPortPolicyUpdate,
        ForwardingMatrixUpdate,
        ForwardingMirroringUpdate,
        AclRule,
        HostEntry,
        RstpPortEnableUpdate,
        RstpBridgeUpdate,
        SnmpMetadataUpdate,
        SnmpConfigurationUpdate,
        PortVlanPolicyUpdate,
        VlanPortMembership,
        VlanInfo,
    )

    assert all(model.model_config.get("extra") == "forbid" for model in write_models)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: DeviceNameUpdate.model_validate({"name": "switch", "naem": "typo"}),
        lambda: PasswordUpdate.model_validate(
            {"new_password": SecretStr("secret"), "new_passwrod": "typo"}
        ),
        lambda: SystemConfigurationUpdate.model_validate(
            {"address_mode": "static", "address_mod": "static"}
        ),
        lambda: PortNameUpdate.model_validate({"number": 1, "name": "uplink", "naem": "typo"}),
        lambda: ForcedPortNegotiation.model_validate(
            {"speed_bps": 100_000_000, "duplex": "full", "duplx": "half"}
        ),
        lambda: PortConfigurationUpdate.model_validate(
            {"number": 1, "flow_control": True, "flow_contorl": False}
        ),
        lambda: ForwardingPortPolicyUpdate.model_validate(
            {"number": 1, "lock": True, "lokc": False}
        ),
        lambda: ForwardingMatrixUpdate.model_validate(
            {"number": 1, "destination_port_numbers": (2,), "destinations": (3,)}
        ),
        lambda: ForwardingMirroringUpdate.model_validate(
            {"source_port_number": 1, "mirror_ingress": True, "mirror_ingres": False}
        ),
        lambda: AclRule.model_validate({**_acl_rule().model_dump(mode="python"), "miror": True}),
        lambda: HostEntry.model_validate(
            {
                "entry_type": "static",
                "mac_address": "02:00:00:00:00:01",
                "vlan_id": 1,
                "port_numbers": (1,),
                "miror": True,
            }
        ),
        lambda: RstpPortEnableUpdate.model_validate(
            {"number": 1, "enabled": True, "enable": False}
        ),
        lambda: RstpBridgeUpdate.model_validate({"cost_mode": "long", "cost_mod": "short"}),
        lambda: SnmpMetadataUpdate.model_validate({"contat": "Ops"}),
        lambda: SnmpConfigurationUpdate.model_validate({"enabled": True, "enable": False}),
        lambda: PortVlanPolicyUpdate.model_validate(
            {"number": 1, "mode": "strict", "recieve": "any"}
        ),
        lambda: VlanPortMembership.model_validate(
            {"port_number": 1, "mode": "not_member", "mod": "strip"}
        ),
        lambda: VlanInfo.model_validate(
            {
                **_vlan(1).model_dump(mode="python"),
                "igmp_snopping": True,
            }
        ),
    ],
)
def test_write_model_typos_are_rejected_instead_of_becoming_no_ops(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        factory()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: DeviceNameUpdate(name=b"switch"),
        lambda: DeviceNameUpdate(name=1),
        lambda: SystemConfigurationUpdate(address_mode=b"static"),
        lambda: PasswordUpdate(new_password=b"secret"),
        lambda: PasswordUpdate(new_password=SecretStr(b"secret")),
        lambda: SnmpMetadataUpdate(contact=b"Ops"),
        lambda: SnmpConfigurationUpdate(community=b"private"),
        lambda: RstpBridgeUpdate(cost_mode=b"long"),
        lambda: PortVlanPolicyUpdate(number=1, mode=b"strict"),
        lambda: HostEntry(
            entry_type=b"static",
            mac_address="02:00:00:00:00:01",
            vlan_id=1,
            port_numbers=(1,),
        ),
        lambda: _acl_rule(vlan_tag=b"any"),
        lambda: ForwardingPortPolicyUpdate(number=1, egress_rate_limit_bps=b"unlimited"),
    ],
)
def test_write_model_text_secret_and_enum_inputs_reject_coercions(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ValidationError):
        factory()


def test_documented_string_enum_spellings_remain_supported() -> None:
    assert SystemConfigurationUpdate(address_mode="static").address_mode is AddressMode.STATIC
    assert RstpBridgeUpdate(cost_mode="long").cost_mode is RstpCostMode.LONG
    assert PortVlanPolicyUpdate(number=1, mode="strict").mode is VlanMode.STRICT


def test_every_port_scoped_encoder_enforces_documented_port_6_safety() -> None:
    link_data: dict[str, Any] = {
        "en": 0,
        "nm": [""] * 6,
        "an": 0,
        "spdc": [0] * 6,
        "dpxc": 0,
        "fct": 0,
    }
    with pytest.raises(InvalidOperationError, match="Port 6"):
        encode_port_name_update(link_data, IDENTITY, PortNameUpdate(number=6, name="sfp"))
    with pytest.raises(InvalidOperationError, match="Port 6"):
        encode_port_configuration_update(
            link_data, IDENTITY, PortConfigurationUpdate(number=6, flow_control=True)
        )
    with pytest.raises(InvalidOperationError, match="Port 6"):
        encode_rstp_port_enable_update(
            {"ena": 0}, IDENTITY, RstpPortEnableUpdate(number=6, enabled=True)
        )

    forwarding_data: dict[str, Any] = {
        **{f"fp{number}": 0 for number in range(1, 7)},
        "lck": 0,
        "lckf": 0,
        "imr": 0,
        "omr": 0,
        "mrto": 0,
        "or": [0] * 6,
    }
    with pytest.raises(InvalidOperationError, match="Port 6"):
        encode_forwarding_port_policy_update(
            forwarding_data, IDENTITY, ForwardingPortPolicyUpdate(number=6, lock=True)
        )
    with pytest.raises(InvalidOperationError, match="between 1 and 5"):
        encode_static_hosts(
            (
                HostEntry(
                    entry_type=HostEntryType.STATIC,
                    mac_address="02:00:00:00:00:06",
                    vlan_id=1,
                    port_numbers=(6,),
                ),
            ),
            IDENTITY,
        )
    with pytest.raises(InvalidOperationError, match="port 6 ingress"):
        encode_acl_rules((_acl_rule(ingress_port_numbers=(6,)),), IDENTITY)


def test_port_6_mask_and_vlan_membership_invariants() -> None:
    system_data: dict[str, Any] = {
        "iptp": 0,
        "sip": 0,
        "amac": "000000000000",
        "id": "",
        "alla": 0,
        "allm": 0,
        "allp": 1 << 5,
        "avln": 0,
        "ivl": 0,
        "igmp": 0,
        "igmq": 0,
        "igfl": 0,
        "igve": 0,
        "pdsc": 0,
    }
    with pytest.raises(InvalidOperationError, match="must include port 6"):
        encode_system_configuration_update(
            system_data,
            IDENTITY,
            SystemConfigurationUpdate(allowed_port_numbers=(1,)),
        )
    with pytest.raises(InvalidOperationError, match="port 6 mask state"):
        encode_system_configuration_update(
            system_data,
            IDENTITY,
            SystemConfigurationUpdate(igmp_fast_leave_port_numbers=(6,)),
        )
    with pytest.raises(InvalidOperationError, match="port 6 membership"):
        encode_vlans((_vlan(1, port_6=VlanMembershipMode.PRESERVE),), (), IDENTITY)


@pytest.mark.parametrize("vlan_id", [0, 4096])
def test_vlan_id_boundaries_reject_out_of_range_values(vlan_id: int) -> None:
    with pytest.raises(ValidationError):
        PortVlanPolicyUpdate(number=1, default_vlan_id=vlan_id)
    with pytest.raises(ValidationError):
        _vlan(vlan_id)
    with pytest.raises(ValidationError):
        HostEntry(
            entry_type=HostEntryType.STATIC,
            mac_address="02:00:00:00:00:01",
            vlan_id=vlan_id,
            port_numbers=(1,),
        )


@pytest.mark.parametrize("vlan_id", [1, 4095])
def test_vlan_id_boundaries_accept_ui_endpoints(vlan_id: int) -> None:
    assert PortVlanPolicyUpdate(number=1, default_vlan_id=vlan_id).default_vlan_id == vlan_id
    assert _vlan(vlan_id).vlan_id == vlan_id


@pytest.mark.parametrize("priority", [-1, 8])
def test_acl_priority_boundaries_reject_non_sentinel_public_values(priority: int) -> None:
    with pytest.raises(ValidationError):
        _acl_rule(vlan_priority=priority)
    with pytest.raises(ValidationError):
        _acl_rule(set_vlan_priority=priority)


@pytest.mark.parametrize("priority", [1, 0x1001, 0x10000])
def test_rstp_priority_enforces_public_device_boundary(priority: int) -> None:
    with pytest.raises(ValidationError):
        RstpBridgeUpdate(bridge_priority=priority)


def test_port_masks_reject_duplicates_out_of_range_and_wire_high_bits() -> None:
    with pytest.raises(ValidationError):
        SystemConfigurationUpdate(discovery_protocol_port_numbers=(1, 1))

    system_data: dict[str, Any] = {
        "iptp": 0,
        "sip": 0,
        "amac": "000000000000",
        "id": "",
        "alla": 0,
        "allm": 0,
        "allp": 1 << 5,
        "avln": 0,
        "ivl": 0,
        "igmp": 0,
        "igmq": 0,
        "igfl": 0,
        "igve": 0,
        "pdsc": 0,
    }
    with pytest.raises(InvalidOperationError, match="between 1 and 6"):
        encode_system_configuration_update(
            system_data,
            IDENTITY,
            SystemConfigurationUpdate(discovery_protocol_port_numbers=(7,)),
        )

    with pytest.raises(ProtocolError, match="bitmask"):
        encode_port_name_update(
            {"en": 0x40, "nm": [""] * 6, "an": 0, "spdc": [0] * 6, "dpxc": 0, "fct": 0},
            IDENTITY,
            PortNameUpdate(number=1, name="x"),
        )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ForwardingPortPolicyUpdate(number=1, egress_rate_limit_bps=0),
        lambda: ForwardingPortPolicyUpdate(number=1, egress_rate_limit_bps=0x1_0000_0000),
        lambda: _acl_rule(ingress_rate_limit_bps=0),
        lambda: _acl_rule(ingress_rate_limit_bps=0x1_0000_0000),
    ],
)
def test_rate_boundaries_reject_zero_and_values_above_uint32(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ValidationError):
        factory()


def test_rate_and_statistics_scaling_match_manifest() -> None:
    forwarding_data: dict[str, Any] = {
        **{f"fp{number}": 0 for number in range(1, 7)},
        "lck": 0,
        "lckf": 0,
        "imr": 0,
        "omr": 0,
        "mrto": 0,
        "or": [0] * 6,
    }
    payload, _ = encode_forwarding_port_policy_update(
        forwarding_data,
        IDENTITY,
        ForwardingPortPolicyUpdate(number=1, egress_rate_limit_bps=1000),
    )
    assert parse_payload(payload)["or"] == [1000, 0, 0, 0, 0, 0]

    fields = {
        name
        for surface in MANIFEST["surfaces"]
        if surface["coverage"] == "statistics"
        for name in surface["fields"]
    }
    stats: dict[str, Any] = {field: [0] * 6 for field in fields}
    stats["rrb"][0] = 8
    stats["trb"][0] = 16
    stats["rrp"][0] = 64
    stats["trp"][0] = 128
    parsed = port_statistics_from_payload(stats, IDENTITY)[0]
    assert parsed.rates.rx_bits_per_second == 100
    assert parsed.rates.tx_bits_per_second == 200
    assert parsed.rates.rx_packets_per_second == 100
    assert parsed.rates.tx_packets_per_second == 200


@pytest.mark.parametrize(
    ("validator", "maximum"),
    [(validate_device_name, 16), (validate_port_name, 16)],
)
def test_name_safe_unicode_boundaries(validator: Callable[[str], bytes], maximum: int) -> None:
    assert validator("x" * maximum) == b"x" * maximum
    assert validator("😀" * (maximum // 2)) == bytes.fromhex("eda0bdedb880") * (maximum // 2)
    with pytest.raises(InvalidOperationError, match="cannot exceed"):
        validator("x" * (maximum + 1))
    with pytest.raises(InvalidOperationError, match="printable Unicode"):
        validator("line\nbreak")


def test_snmp_safe_unicode_boundaries() -> None:
    assert validate_snmp_metadata("x" * 64, "contact") == b"x" * 64
    assert validate_snmp_metadata("Tëam", "contact") == "Tëam".encode()
    with pytest.raises(InvalidOperationError, match="cannot exceed"):
        validate_snmp_metadata("x" * 65, "contact")


def test_ui_compatible_writable_text_accepts_bmp_unicode() -> None:
    assert validate_device_name("MikroTik-ä") == "MikroTik-ä".encode()


def test_ui_compatible_reader_accepts_cesu8_surrogate_pairs() -> None:
    data = {
        "en": 0,
        "nm": ["eda0bdedb898", "", "", "", "", ""],
        "lnk": 0,
        "an": 0,
        "spd": [0] * 6,
        "spdc": [0] * 6,
        "dpx": 0,
        "dpxc": 0,
        "fct": 0,
    }
    state = encode_port_name_update(data, IDENTITY, PortNameUpdate(number=2, name="x"))[1]
    assert state.raw_names[0] == "eda0bdedb898"
    from swos_device_css106.protocol import ports_from_link_payload

    assert ports_from_link_payload(data, IDENTITY)[0].name == "😘"


def test_intentional_sfp_normalization_is_stable() -> None:
    info = sfp_from_payload(
        {
            "vnd": "205820",
            "pnr": "",
            "rev": "",
            "ser": "",
            "dat": "",
            "typ": "",
            "tmp": 0,
            "vcc": 0,
            "tbs": 0,
            "tpw": 0,
            "rpw": 0,
        }
    )
    assert info.vendor == "X"
    assert info.supply_voltage_volts == 0.0
    assert info.tx_bias_ma == 0


def test_acl_encoder_omits_ui_blank_optional_mac_fields() -> None:
    row = parse_table_payload(encode_acl_rules((_acl_rule(),), IDENTITY))[0]
    assert isinstance(row, dict)
    assert "smac" not in row
    assert "dmac" not in row


def test_static_host_model_rejects_ui_blank_required_value_hole() -> None:
    with pytest.raises(ValidationError):
        HostEntry(
            entry_type=HostEntryType.STATIC,
            mac_address="",
            vlan_id=0,
            port_numbers=(1,),
        )


def test_vlan_encoder_rejects_ui_textual_duplicate_hole() -> None:
    with pytest.raises(InvalidOperationError, match="unique"):
        encode_vlans((_vlan(1), _vlan(1)), (), IDENTITY)


def test_static_host_encoder_rejects_ui_duplicate_key_hole() -> None:
    host = HostEntry(
        entry_type=HostEntryType.STATIC,
        mac_address="02:00:00:00:00:01",
        vlan_id=1,
        port_numbers=(1,),
    )
    with pytest.raises(InvalidOperationError, match="duplicate"):
        encode_static_hosts((host, host), IDENTITY)


def test_vlan_encoder_enforces_canonical_desired_order() -> None:
    with pytest.raises(InvalidOperationError, match="ascending order"):
        encode_vlans((_vlan(2), _vlan(1)), (), IDENTITY)


def test_public_mac_and_ip_boundaries() -> None:
    update = SystemConfigurationUpdate(
        admin_mac_address="02:00:00:00:00:01",
        allow_from="192.0.2.1",
    )
    assert update.admin_mac_address == "02:00:00:00:00:01"
    assert update.allow_from == "192.0.2.1"
    with pytest.raises(ValidationError):
        SystemConfigurationUpdate(admin_mac_address="gg:00:00:00:00:01")
    with pytest.raises(ValidationError):
        SystemConfigurationUpdate(allow_from="192.0.2.256")


@pytest.mark.parametrize(
    "values",
    [
        {"admin_mac_address": "2:0:0:0:0:1"},
        {"allow_from": "192.2"},
    ],
)
def test_public_address_syntax_rejects_noncanonical_ui_spellings(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SystemConfigurationUpdate(**values)


@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"])
def test_static_management_ip_rejects_unsafe_ui_values(address: str) -> None:
    with pytest.raises(ValidationError):
        SystemConfigurationUpdate(static_ip=address)


@pytest.mark.parametrize(
    "updates",
    [
        {"vlan_id_min": 2, "vlan_id_max": 1},
        {"source_port_min": 2, "source_port_max": 1},
        {"destination_port_min": 2, "destination_port_max": 1},
    ],
)
def test_acl_rejects_semantically_reversed_ui_range_holes(updates: dict[str, int]) -> None:
    with pytest.raises(ValidationError, match="reversed"):
        _acl_rule(**updates)


def test_password_utf16_ascii_and_length_boundaries() -> None:
    validate_password_update(PasswordUpdate(new_password=SecretStr("x" * 15)), SecretStr(""))
    validate_password_update(
        PasswordUpdate(new_password=SecretStr("\x00\x1f\x7f")),
        SecretStr("😀" * 7),
    )
    with pytest.raises(InvalidOperationError, match="new administrator password"):
        validate_password_update(PasswordUpdate(new_password=SecretStr("x" * 16)), SecretStr(""))
    with pytest.raises(InvalidOperationError, match=r"U\+0000\.\.U\+007F"):
        validate_password_update(PasswordUpdate(new_password=SecretStr("ä")), SecretStr(""))
    with pytest.raises(InvalidOperationError, match="current administrator password"):
        validate_password_update(PasswordUpdate(new_password=SecretStr("")), SecretStr("😀" * 8))


def test_rstp_validator_enforces_ui_disabled_dependency() -> None:
    adapter = CSS106Adapter(DeviceConnection(url="http://192.0.2.1"), IDENTITY)
    current = _rstp_info(forward_reserved_multicast=True)
    with pytest.raises(InvalidOperationError):
        adapter.validate_rstp_port_enabled(
            RstpPortEnableUpdate(number=1, enabled=False), current=current
        )
    with pytest.raises(InvalidOperationError):
        adapter.validate_rstp_bridge(RstpBridgeUpdate(cost_mode=RstpCostMode.LONG), current=current)
    adapter.validate_rstp_port_enabled(
        RstpPortEnableUpdate(number=1, enabled=True), current=current
    )
    adapter.validate_rstp_bridge(
        RstpBridgeUpdate(
            bridge_priority=current.bridge_priority,
            cost_mode=current.cost_mode,
            forward_reserved_multicast=True,
        ),
        current=current,
    )
    adapter.validate_rstp_bridge(
        RstpBridgeUpdate(
            cost_mode=RstpCostMode.LONG,
            forward_reserved_multicast=False,
        ),
        current=current,
    )


def test_missing_ui_write_surfaces_remain_explicit_in_manifest() -> None:
    snmp = next(surface for surface in MANIFEST["surfaces"] if surface["name"] == "snmp")
    assert snmp["fields"] == ["en", "com", "ci", "loc"]
    assert set(SnmpConfigurationUpdate.model_fields) == {
        "enabled",
        "community",
        "contact",
        "location",
    }
    assert all(action["coverage"] == "missing" for action in MANIFEST["actions"][1:])


def test_serializer_state_field_order_types_remain_explicit() -> None:
    assert list(LinkWriteState.__dataclass_fields__) == [
        "enabled_mask",
        "raw_names",
        "auto_negotiation_mask",
        "configured_speeds",
        "configured_duplex_mask",
        "flow_control_mask",
    ]
    assert list(SystemConfigurationWriteState.__dataclass_fields__) == [
        "address_mode",
        "static_ip",
        "admin_mac",
        "raw_name",
        "allow_from",
        "allow_prefix_length",
        "allowed_ports_mask",
        "allowed_vlan_id",
        "independent_vlan_lookup",
        "igmp_enabled",
        "igmp_querier",
        "igmp_fast_leave_mask",
        "igmp_version",
        "discovery_protocol_mask",
    ]
    assert list(SnmpWriteState.__dataclass_fields__) == [
        "enabled",
        "raw_community",
        "raw_contact",
        "raw_location",
    ]
    assert list(RstpEnableWriteState.__dataclass_fields__) == ["enabled_mask"]
    assert list(RstpBridgeWriteState.__dataclass_fields__) == [
        "bridge_priority",
        "cost_mode",
        "forward_reserved_multicast",
    ]
