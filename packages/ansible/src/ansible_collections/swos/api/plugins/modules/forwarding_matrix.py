#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: forwarding_matrix
short_description: Manage one complete SwOS forwarding matrix row
description:
  - Declares all Ethernet destinations for one Ethernet source port.
  - The protected management-port destination relationship is preserved automatically.
version_added: "0.2.0"
extends_documentation_fragment: [swos.api.connection]
options:
  port:
    description: Ethernet source port number.
    type: int
    required: true
    choices: [1, 2, 3, 4, 5]
  destination_port_numbers:
    description: Complete Ethernet destination set. An empty list clears Ethernet destinations.
    type: list
    elements: int
    required: true
    choices: [1, 2, 3, 4, 5]
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Limit port 5 forwarding destinations
  swos.api.forwarding_matrix:
    url: http://192.0.2.10
    port: 5
    destination_port_numbers: [1, 5]
  delegate_to: localhost
"""

RETURN = r"""
forwarding:
  description: Normalized forwarding state after, or projected for, the operation.
  returned: always
  type: dict
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "forwarding_matrix",
        {
            "port": {"type": "int", "required": True, "choices": [1, 2, 3, 4, 5]},
            "destination_port_numbers": {
                "type": "list",
                "elements": "int",
                "required": True,
                "choices": [1, 2, 3, 4, 5],
            },
        },
    )


if __name__ == "__main__":
    main()
