#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: snmp_metadata
short_description: Manage SwOS SNMP contact and location metadata
description:
  - Manages printable Unicode SNMP contact and location values while preserving service settings.
version_added: "0.1.0"
extends_documentation_fragment: [swos.api.connection]
options:
  contact:
    description:
      - Desired printable Unicode SNMP contact, at most 64 UTF-16 code units.
      - Empty clears it.
    type: str
  location:
    description:
      - Desired printable Unicode SNMP location, at most 64 UTF-16 code units.
      - Empty clears it.
    type: str
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Set SNMP metadata
  swos.api.snmp_metadata:
    url: http://192.0.2.10
    contact: Network Operations
    location: Floor 2
  delegate_to: localhost
"""

RETURN = r"""
snmp:
  description: Normalized SNMP state after, or projected for, the operation.
  returned: always
  type: dict
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "snmp_metadata",
        {"contact": {"type": "str"}, "location": {"type": "str"}},
        required_one_of=[["contact", "location"]],
    )


if __name__ == "__main__":
    main()
