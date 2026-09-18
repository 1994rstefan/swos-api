#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: system_configuration
short_description: Manage SwOS system and management configuration
description:
  - Manages all fields exposed by C(SystemConfigurationUpdate) while preserving omitted fields.
  - Management address changes can move the controller to another endpoint; provide O(readback_url)
    when the desired endpoint differs from O(url).
  - A reconnect failure after a management write can mean the state is uncertain. Do not blindly
    retry; recovery can require reaching another management address or manually resetting the
    switch.
version_added: "0.2.0"
extends_documentation_fragment: [swos.api.connection]
options:
  address_mode:
    description: Management address mode.
    type: str
    choices: [dhcp_with_fallback, static, dhcp_only]
  static_ip:
    description: Static management IPv4 address, or C(unset) to clear it.
    type: str
  admin_mac_address:
    description: Administrator MAC restriction, or C(unset) to clear it.
    type: str
  name:
    description: Device name of at most 16 printable ASCII characters.
    type: str
  allow_from:
    description: Management source IPv4 address, or C(unset) to clear it.
    type: str
  allow_prefix_length:
    description: Management source prefix length.
    type: int
  allowed_port_numbers:
    description: Complete ascending set of management-allowed ports; port 6 must remain present.
    type: list
    elements: int
    choices: [1, 2, 3, 4, 5, 6]
  allowed_vlan_id:
    description: Integer management VLAN ID, or exactly C(unset) to clear it.
    type: raw
  independent_vlan_lookup:
    description: Enable independent VLAN lookup.
    type: bool
  igmp_enabled:
    description: Enable IGMP snooping.
    type: bool
  igmp_querier:
    description: Configure the IGMP querier.
    type: bool
  igmp_fast_leave_port_numbers:
    description: Complete ascending IGMP fast-leave port set. An empty list clears the set.
    type: list
    elements: int
    choices: [1, 2, 3, 4, 5, 6]
  igmp_version:
    description: IGMP protocol version.
    type: str
    choices: [v2, v3]
  discovery_protocol_port_numbers:
    description: Complete ascending discovery-protocol port set. An empty list clears the set.
    type: list
    elements: int
    choices: [1, 2, 3, 4, 5, 6]
  readback_url:
    description: URL used to reconnect and verify a management endpoint change.
    type: str
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Configure IGMP and discovery ports
  swos.api.system_configuration:
    url: http://192.0.2.10
    password: "{{ vault_swos_password }}"
    igmp_enabled: true
    igmp_version: v3
    discovery_protocol_port_numbers: [1, 6]
  delegate_to: localhost

- name: Move the management endpoint and verify it there
  swos.api.system_configuration:
    url: http://192.0.2.10
    password: "{{ vault_swos_password }}"
    address_mode: static
    static_ip: 192.0.2.20
    readback_url: http://192.0.2.20
  delegate_to: localhost
"""

RETURN = r"""
system:
  description: Normalized system state after, or projected for, the operation.
  returned: always
  type: dict
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    options = {
        "address_mode": {
            "type": "str",
            "choices": ["dhcp_with_fallback", "static", "dhcp_only"],
        },
        "static_ip": {"type": "str"},
        "admin_mac_address": {"type": "str"},
        "name": {"type": "str"},
        "allow_from": {"type": "str"},
        "allow_prefix_length": {"type": "int"},
        "allowed_port_numbers": {
            "type": "list",
            "elements": "int",
            "choices": [1, 2, 3, 4, 5, 6],
        },
        "allowed_vlan_id": {"type": "raw"},
        "independent_vlan_lookup": {"type": "bool"},
        "igmp_enabled": {"type": "bool"},
        "igmp_querier": {"type": "bool"},
        "igmp_fast_leave_port_numbers": {
            "type": "list",
            "elements": "int",
            "choices": [1, 2, 3, 4, 5, 6],
        },
        "igmp_version": {"type": "str", "choices": ["v2", "v3"]},
        "discovery_protocol_port_numbers": {
            "type": "list",
            "elements": "int",
            "choices": [1, 2, 3, 4, 5, 6],
        },
        "readback_url": {"type": "str"},
    }
    run_module(
        "system_configuration",
        options,
        required_one_of=[
            [
                "address_mode",
                "static_ip",
                "admin_mac_address",
                "name",
                "allow_from",
                "allow_prefix_length",
                "allowed_port_numbers",
                "allowed_vlan_id",
                "independent_vlan_lookup",
                "igmp_enabled",
                "igmp_querier",
                "igmp_fast_leave_port_numbers",
                "igmp_version",
                "discovery_protocol_port_numbers",
            ]
        ],
    )


if __name__ == "__main__":
    main()
