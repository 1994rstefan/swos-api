#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: static_hosts
short_description: Manage the complete SwOS static host table
description:
  - Declares the complete ordered static host table with a maximum of 2048 entries.
version_added: "0.1.0"
extends_documentation_fragment: [swos.api.connection]
options:
  hosts:
    description: Desired complete ordered static host table. An empty list removes all static hosts.
    type: list
    elements: dict
    required: true
    suboptions:
      mac_address:
        description: Host MAC address.
        type: str
        required: true
      vlan_id:
        description: Host VLAN ID.
        type: int
        required: true
      port_numbers:
        description: Destination Ethernet ports. May be empty for a drop entry.
        type: list
        elements: int
        default: []
        choices: [1, 2, 3, 4, 5]
      drop:
        description: Drop matching traffic.
        type: bool
        default: false
      mirror:
        description: Mirror matching traffic.
        type: bool
        default: false
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Declare the static host table
  swos.api.static_hosts:
    url: http://192.0.2.10
    hosts:
      - mac_address: 02:00:00:00:00:05
        vlan_id: 10
        port_numbers: [5]
  delegate_to: localhost
"""

RETURN = r"""
hosts:
  description: Normalized static host table after, or projected for, the operation.
  returned: always
  type: list
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "static_hosts",
        {
            "hosts": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "options": {
                    "mac_address": {"type": "str", "required": True},
                    "vlan_id": {"type": "int", "required": True},
                    "port_numbers": {
                        "type": "list",
                        "elements": "int",
                        "default": [],
                        "choices": [1, 2, 3, 4, 5],
                    },
                    "drop": {"type": "bool", "default": False},
                    "mirror": {"type": "bool", "default": False},
                },
            }
        },
    )


if __name__ == "__main__":
    main()
