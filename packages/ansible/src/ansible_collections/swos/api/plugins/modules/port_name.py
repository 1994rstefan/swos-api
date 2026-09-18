#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: port_name
short_description: Manage a SwOS Ethernet port name
description:
  - Sets or clears the name of Ethernet ports 1 through 5.
version_added: "0.1.0"
extends_documentation_fragment: [swos.api.connection]
options:
  port:
    description: Ethernet port number.
    type: int
    required: true
    choices: [1, 2, 3, 4, 5]
  name:
    description:
      - Desired printable ASCII port name, at most 16 characters. An empty string clears it.
    type: str
    required: true
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Label port 1
  swos.api.port_name:
    url: http://192.0.2.10
    port: 1
    name: Uplink
  delegate_to: localhost
"""

RETURN = r"""
port:
  description: Normalized port state after, or projected for, the operation.
  returned: always
  type: dict
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "port_name",
        {
            "port": {"type": "int", "required": True, "choices": [1, 2, 3, 4, 5]},
            "name": {"type": "str", "required": True},
        },
    )


if __name__ == "__main__":
    main()
