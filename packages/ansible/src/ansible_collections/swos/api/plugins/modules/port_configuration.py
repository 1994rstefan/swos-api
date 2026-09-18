#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: port_configuration
short_description: Manage safe SwOS Ethernet port configuration
description:
  - Manages enabled state, negotiation, speed, duplex, and flow control on ports 1 through 5.
version_added: "0.1.0"
extends_documentation_fragment: [swos.api.connection]
options:
  port:
    description: Ethernet port number.
    type: int
    required: true
    choices: [1, 2, 3, 4, 5]
  enabled:
    description: Whether the port is enabled.
    type: bool
  negotiation:
    description: Automatic or forced Ethernet negotiation.
    type: str
    choices: [auto, forced]
  speed_bps:
    description: Forced speed; required with C(negotiation=forced).
    type: int
    choices: [10000000, 100000000]
  duplex:
    description: Forced duplex; required with C(negotiation=forced).
    type: str
    choices: [full, half]
  flow_control:
    description: Whether flow control is enabled.
    type: bool
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Enable automatic negotiation and flow control
  swos.api.port_configuration:
    url: http://192.0.2.10
    port: 5
    enabled: true
    negotiation: auto
    flow_control: true
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
        "port_configuration",
        {
            "port": {"type": "int", "required": True, "choices": [1, 2, 3, 4, 5]},
            "enabled": {"type": "bool"},
            "negotiation": {"type": "str", "choices": ["auto", "forced"]},
            "speed_bps": {"type": "int", "choices": [10_000_000, 100_000_000]},
            "duplex": {"type": "str", "choices": ["full", "half"]},
            "flow_control": {"type": "bool"},
        },
        required_one_of=[["enabled", "negotiation", "flow_control"]],
        required_if=[["negotiation", "forced", ["speed_bps", "duplex"]]],
    )


if __name__ == "__main__":
    main()
