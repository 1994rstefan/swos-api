#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: acl_rules
short_description: Manage the complete ordered SwOS ACL table
description:
  - Declares the complete ordered ACL table. An empty list removes every rule.
  - Rule numbers may be omitted or null and are derived from list order; supplied numbers must
    match it.
version_added: "0.2.0"
extends_documentation_fragment: [swos.api.connection]
options:
  rules:
    description: Desired complete ordered ACL table.
    type: list
    elements: dict
    required: true
    suboptions:
      number:
        description:
          - One-based rule number matching this row's list position.
          - Omitted or null values are derived from list order.
        type: int
      ingress_port_numbers:
        description: Ingress Ethernet ports.
        type: list
        elements: int
        required: true
        choices: [1, 2, 3, 4, 5]
      source_mac:
        description: Source MAC match, or null for any.
        type: str
      source_mac_mask:
        description: Source MAC mask.
        type: str
        default: ff:ff:ff:ff:ff:ff
      destination_mac:
        description: Destination MAC match, or null for any.
        type: str
      destination_mac_mask:
        description: Destination MAC mask.
        type: str
        default: ff:ff:ff:ff:ff:ff
      ether_type:
        description: Ethernet type match; zero means any.
        type: int
        default: 0
      vlan_tag:
        description: VLAN tag-presence match.
        type: str
        choices: [any, present, not_present]
        default: any
      vlan_id_min:
        description: Minimum VLAN ID match; zero means any.
        type: int
        default: 0
      vlan_id_max:
        description: Maximum VLAN ID match; zero means any.
        type: int
        default: 0
      vlan_priority:
        description: VLAN priority match, or null for any.
        type: int
      source_ip:
        description: Source IPv4 match, or null for any.
        type: str
      source_prefix_length:
        description: Source IPv4 prefix length.
        type: int
        default: 0
      source_port_min:
        description: Minimum transport source port.
        type: int
        default: 0
      source_port_max:
        description: Maximum transport source port.
        type: int
        default: 0
      destination_ip:
        description: Destination IPv4 match, or null for any.
        type: str
      destination_prefix_length:
        description: Destination IPv4 prefix length.
        type: int
        default: 0
      destination_port_min:
        description: Minimum transport destination port.
        type: int
        default: 0
      destination_port_max:
        description: Maximum transport destination port.
        type: int
        default: 0
      protocol_number:
        description: IP protocol number; zero means any.
        type: int
        default: 0
      dscp:
        description: DSCP match, or null for any.
        type: int
      redirect_enabled:
        description: Enable redirect or drop action processing.
        type: bool
        default: false
      redirect_port_numbers:
        description: Redirect destination ports. Empty with redirect enabled represents drop.
        type: list
        elements: int
        default: []
        choices: [1, 2, 3, 4, 5, 6]
      drop:
        description: Whether the normalized action is drop.
        type: bool
        default: false
      mirror:
        description: Mirror matching traffic.
        type: bool
        default: false
      ingress_rate_limit_bps:
        description: Ingress rate limit in bits per second, or null for unlimited.
        type: int
      set_vlan_id:
        description: VLAN ID to assign, or null to preserve it.
        type: int
      set_vlan_priority:
        description: VLAN priority to assign, or null to preserve it.
        type: int
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Declare one ACL rule
  swos.api.acl_rules:
    url: http://192.0.2.10
    rules:
      - ingress_port_numbers: [5]
        ether_type: 2048
        destination_ip: 192.0.2.1
        destination_prefix_length: 32
        redirect_enabled: true
        drop: true
  delegate_to: localhost
"""

RETURN = r"""
rules:
  description: Normalized ordered ACL table after, or projected for, the operation.
  returned: always
  type: list
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "acl_rules",
        {
            "rules": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "options": {
                    "number": {"type": "int"},
                    "ingress_port_numbers": {
                        "type": "list",
                        "elements": "int",
                        "required": True,
                        "choices": [1, 2, 3, 4, 5],
                    },
                    "source_mac": {"type": "str"},
                    "source_mac_mask": {"type": "str", "default": "ff:ff:ff:ff:ff:ff"},
                    "destination_mac": {"type": "str"},
                    "destination_mac_mask": {
                        "type": "str",
                        "default": "ff:ff:ff:ff:ff:ff",
                    },
                    "ether_type": {"type": "int", "default": 0},
                    "vlan_tag": {
                        "type": "str",
                        "choices": ["any", "present", "not_present"],
                        "default": "any",
                    },
                    "vlan_id_min": {"type": "int", "default": 0},
                    "vlan_id_max": {"type": "int", "default": 0},
                    "vlan_priority": {"type": "int"},
                    "source_ip": {"type": "str"},
                    "source_prefix_length": {"type": "int", "default": 0},
                    "source_port_min": {"type": "int", "default": 0},
                    "source_port_max": {"type": "int", "default": 0},
                    "destination_ip": {"type": "str"},
                    "destination_prefix_length": {"type": "int", "default": 0},
                    "destination_port_min": {"type": "int", "default": 0},
                    "destination_port_max": {"type": "int", "default": 0},
                    "protocol_number": {"type": "int", "default": 0},
                    "dscp": {"type": "int"},
                    "redirect_enabled": {"type": "bool", "default": False},
                    "redirect_port_numbers": {
                        "type": "list",
                        "elements": "int",
                        "default": [],
                        "choices": [1, 2, 3, 4, 5, 6],
                    },
                    "drop": {"type": "bool", "default": False},
                    "mirror": {"type": "bool", "default": False},
                    "ingress_rate_limit_bps": {"type": "int"},
                    "set_vlan_id": {"type": "int"},
                    "set_vlan_priority": {"type": "int"},
                },
            }
        },
    )


if __name__ == "__main__":
    main()
