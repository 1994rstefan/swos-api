#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: snmp_configuration
short_description: Manage complete SwOS SNMP service configuration
description:
  - Manages SNMP enabled state, community, contact, and location as one complete group.
  - Community input is marked no_log and is never returned by the module.
version_added: "0.3.0"
extends_documentation_fragment: [swos.api.connection]
options:
  enabled:
    description: Whether the SNMP service is enabled.
    type: bool
  community:
    description: Desired printable Unicode community of at most 64 UTF-16 code units.
    type: str
  contact:
    description: Desired printable Unicode contact of at most 64 UTF-16 code units.
    type: str
  location:
    description: Desired printable Unicode location of at most 64 UTF-16 code units.
    type: str
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Enable SNMP and set its community
  swos.api.snmp_configuration:
    url: http://192.0.2.10
    enabled: true
    community: "{{ vault_snmp_community }}"
    contact: Network Operations
  delegate_to: localhost
"""

RETURN = r"""
snmp:
  description: Normalized write result with community replaced by community_configured.
  returned: always
  type: dict
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "snmp_configuration",
        {
            "enabled": {"type": "bool"},
            "community": {"type": "str", "no_log": True},
            "contact": {"type": "str"},
            "location": {"type": "str"},
        },
        required_one_of=[["enabled", "community", "contact", "location"]],
    )


if __name__ == "__main__":
    main()
