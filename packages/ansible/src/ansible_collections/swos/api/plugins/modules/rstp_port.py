#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: rstp_port
short_description: Manage per-port SwOS RSTP enable state
description:
  - Enables or disables RSTP on Ethernet ports 1 through 5.
version_added: "0.1.0"
extends_documentation_fragment: [swos.api.connection]
options:
  port:
    description: Ethernet port number.
    type: int
    required: true
    choices: [1, 2, 3, 4, 5]
  enabled:
    description: Whether RSTP is enabled on the port.
    type: bool
    required: true
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Enable RSTP on port 5
  swos.api.rstp_port:
    url: http://192.0.2.10
    port: 5
    enabled: true
  delegate_to: localhost
"""

RETURN = r"""
rstp:
  description: Normalized RSTP state after, or projected for, the operation.
  returned: always
  type: dict
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "rstp_port",
        {
            "port": {"type": "int", "required": True, "choices": [1, 2, 3, 4, 5]},
            "enabled": {"type": "bool", "required": True},
        },
    )


if __name__ == "__main__":
    main()
