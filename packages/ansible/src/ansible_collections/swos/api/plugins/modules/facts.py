#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: facts
short_description: Gather normalized SwOS device facts
description:
  - Gathers selected normalized device data through the public C(swos-core) API.
version_added: "0.1.0"
extends_documentation_fragment:
  - swos.api.connection
options:
  gather_subset:
    description: Normalized data groups to gather. Use C(all) for every group.
    type: list
    elements: str
    default: [all]
    choices: [all, system, ports, port_statistics, hosts, rstp, snmp, sfp, forwarding,
              igmp_groups, acl_rules, port_vlans, vlans]
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Gather system and port facts
  swos.api.facts:
    url: http://192.0.2.10
    password: "{{ vault_swos_password }}"
    gather_subset: [system, ports]
  delegate_to: localhost
"""

RETURN = r"""
ansible_facts:
  description: Facts under the C(swos) key.
  returned: always
  type: dict
swos_warnings:
  description: Structured exact-firmware policy warnings.
  returned: when a policy override is used
  type: list
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "facts",
        {
            "gather_subset": {
                "type": "list",
                "elements": "str",
                "default": ["all"],
                "choices": [
                    "all",
                    "system",
                    "ports",
                    "port_statistics",
                    "hosts",
                    "rstp",
                    "snmp",
                    "sfp",
                    "forwarding",
                    "igmp_groups",
                    "acl_rules",
                    "port_vlans",
                    "vlans",
                ],
            }
        },
    )


if __name__ == "__main__":
    main()
