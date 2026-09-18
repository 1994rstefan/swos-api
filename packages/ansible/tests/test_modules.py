from __future__ import annotations

from importlib import import_module
from typing import Any, cast
from unittest.mock import Mock, patch

import pytest
from ansible_collections.swos.api.plugins.module_utils.swos import CONNECTION_ARGUMENTS
from swos_core import AclRule, SystemConfigurationUpdate, VlanInfo, VlanPortMembership

MODULE_PACKAGE = "ansible_collections.swos.api.plugins.modules"
NEW_MODULES = {
    "system_configuration": "system_configuration",
    "admin_password": "admin_password",
    "acl_rules": "acl_rules",
    "vlan_table": "vlan_table",
    "rstp_bridge": "rstp_bridge",
    "forwarding_matrix": "forwarding_matrix",
    "forwarding_mirroring": "forwarding_mirroring",
    "snmp_configuration": "snmp_configuration",
}


def _module(name: str) -> Any:
    return import_module(f"{MODULE_PACKAGE}.{name}")


@pytest.mark.parametrize(("name", "operation"), NEW_MODULES.items())
def test_new_module_main_delegates_to_runtime(name: str, operation: str) -> None:
    module = _module(name)
    with patch.object(module, "run_module") as run_module:
        module.main()

    assert cast(Mock, run_module).call_args.args[0] == operation
    assert cast(Mock, run_module).call_args.args[1]


def test_system_configuration_schema_matches_public_update_model() -> None:
    module = _module("system_configuration")
    with patch.object(module, "run_module") as run_module:
        module.main()

    schema = cast(Mock, run_module).call_args.args[1]
    assert set(schema) == {*SystemConfigurationUpdate.model_fields, "readback_url"}
    assert schema["allowed_vlan_id"]["type"] == "raw"
    required_one_of = cast(Mock, run_module).call_args.kwargs["required_one_of"]
    assert set(required_one_of[0]) == set(SystemConfigurationUpdate.model_fields)


def test_acl_nested_schema_matches_public_rule_model() -> None:
    module = _module("acl_rules")
    with patch.object(module, "run_module") as run_module:
        module.main()

    schema = cast(Mock, run_module).call_args.args[1]["rules"]["options"]
    assert set(schema) == set(AclRule.model_fields)
    assert schema["ingress_port_numbers"]["choices"] == [1, 2, 3, 4, 5]
    assert schema["redirect_port_numbers"]["choices"] == [1, 2, 3, 4, 5, 6]


def test_vlan_nested_schema_matches_public_models_except_internal_position() -> None:
    module = _module("vlan_table")
    with patch.object(module, "run_module") as run_module:
        module.main()

    schema = cast(Mock, run_module).call_args.args[1]["vlans"]["options"]
    assert set(schema) == set(VlanInfo.model_fields) - {"table_position"}
    assert set(schema["ports"]["options"]) == set(VlanPortMembership.model_fields)
    assert schema["ports"]["options"]["port_number"]["choices"] == [1, 2, 3, 4, 5, 6]


def test_both_password_inputs_are_no_log() -> None:
    module = _module("admin_password")
    with patch.object(module, "run_module") as run_module:
        module.main()

    assert CONNECTION_ARGUMENTS["password"]["no_log"] is True
    assert cast(Mock, run_module).call_args.args[1]["new_password"]["no_log"] is True


def test_snmp_community_is_no_log() -> None:
    module = _module("snmp_configuration")
    with patch.object(module, "run_module") as run_module:
        module.main()

    assert cast(Mock, run_module).call_args.args[1]["community"]["no_log"] is True


@pytest.mark.parametrize("name", NEW_MODULES)
def test_new_module_documentation_and_examples_declare_version(name: str) -> None:
    module = _module(name)
    expected = "0.3.0" if name == "snmp_configuration" else "0.2.0"
    assert f'version_added: "{expected}"' in module.DOCUMENTATION
    assert f"swos.api.{name}:" in module.EXAMPLES


def test_management_reconnect_risk_is_documented() -> None:
    documentation = _module("system_configuration").DOCUMENTATION
    assert "move the controller" in documentation
    assert "state is uncertain" in documentation
    assert "manually resetting" in documentation
