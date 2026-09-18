#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: vlan_port_policy
short_description: Manage per-port SwOS VLAN policy
description:
  - Manages ingress and egress VLAN policy on Ethernet ports 1 through 5.
version_added: "0.1.0"
extends_documentation_fragment: [swos.api.connection]
options:
  port:
    description: Ethernet port number.
    type: int
    required: true
    choices: [1, 2, 3, 4, 5]
  mode:
    description: Ingress VLAN enforcement mode.
    type: str
    choices: [disabled, optional, enabled, strict]
  receive:
    description: Accepted frame tag state.
    type: str
    choices: [any, tagged_only, untagged_only]
  default_vlan_id:
    description: Port default VLAN ID.
    type: int
  force_vlan_id:
    description: Whether to force the default VLAN ID.
    type: bool
  egress:
    description: Egress VLAN header policy.
    type: str
    choices: [preserve, strip, add_if_missing]
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Configure port 5 as an access port
  swos.api.vlan_port_policy:
    url: http://192.0.2.10
    port: 5
    mode: strict
    receive: untagged_only
    default_vlan_id: 10
    force_vlan_id: true
    egress: strip
  delegate_to: localhost
"""

RETURN = r"""
ports:
  description: Complete normalized port VLAN state after, or projected for, the operation.
  returned: always
  type: list
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "vlan_port_policy",
        {
            "port": {"type": "int", "required": True, "choices": [1, 2, 3, 4, 5]},
            "mode": {
                "type": "str",
                "choices": ["disabled", "optional", "enabled", "strict"],
            },
            "receive": {
                "type": "str",
                "choices": ["any", "tagged_only", "untagged_only"],
            },
            "default_vlan_id": {"type": "int"},
            "force_vlan_id": {"type": "bool"},
            "egress": {
                "type": "str",
                "choices": ["preserve", "strip", "add_if_missing"],
            },
        },
        required_one_of=[["mode", "receive", "default_vlan_id", "force_vlan_id", "egress"]],
    )


if __name__ == "__main__":
    main()
