#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: vlan_table
short_description: Manage the complete ordered SwOS VLAN table
description:
  - Declares the complete VLAN table; list order declares device table order.
  - Every row must declare ports 1 through 6 exactly once.
  - Protected management-port membership must match current state. An empty list removes all rows
    only when doing so does not change management-port membership.
version_added: "0.2.0"
extends_documentation_fragment: [swos.api.connection]
options:
  vlans:
    description: Desired complete ordered VLAN table.
    type: list
    elements: dict
    required: true
    suboptions:
      vlan_id:
        description: VLAN ID.
        type: int
        required: true
      independent_learning:
        description: Use independent VLAN learning for this row.
        type: bool
        required: true
      igmp_snooping:
        description: Enable IGMP snooping for this row.
        type: bool
        required: true
      ports:
        description: Complete port membership list containing ports 1 through 6 exactly once.
        type: list
        elements: dict
        required: true
        suboptions:
          port_number:
            description: Port number.
            type: int
            required: true
            choices: [1, 2, 3, 4, 5, 6]
          mode:
            description: Membership and egress mode.
            type: str
            required: true
            choices: [preserve, strip, add_if_missing, not_member]
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Declare the complete VLAN table
  swos.api.vlan_table:
    url: http://192.0.2.10
    vlans:
      - vlan_id: 10
        independent_learning: true
        igmp_snooping: true
        ports:
          - {port_number: 1, mode: strip}
          - {port_number: 2, mode: not_member}
          - {port_number: 3, mode: not_member}
          - {port_number: 4, mode: not_member}
          - {port_number: 5, mode: preserve}
          - {port_number: 6, mode: not_member}
  delegate_to: localhost
"""

RETURN = r"""
vlans:
  description: Normalized VLAN table after, or projected for, the operation.
  returned: always
  type: list
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "vlan_table",
        {
            "vlans": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "options": {
                    "vlan_id": {"type": "int", "required": True},
                    "independent_learning": {"type": "bool", "required": True},
                    "igmp_snooping": {"type": "bool", "required": True},
                    "ports": {
                        "type": "list",
                        "elements": "dict",
                        "required": True,
                        "options": {
                            "port_number": {
                                "type": "int",
                                "required": True,
                                "choices": [1, 2, 3, 4, 5, 6],
                            },
                            "mode": {
                                "type": "str",
                                "required": True,
                                "choices": [
                                    "preserve",
                                    "strip",
                                    "add_if_missing",
                                    "not_member",
                                ],
                            },
                        },
                    },
                },
            }
        },
    )


if __name__ == "__main__":
    main()
