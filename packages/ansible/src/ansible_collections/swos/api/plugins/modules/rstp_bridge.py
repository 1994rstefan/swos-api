#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: rstp_bridge
short_description: Manage bridge-global SwOS RSTP configuration
description:
  - Manages bridge priority, path-cost mode, and reserved multicast forwarding.
version_added: "0.2.0"
extends_documentation_fragment: [swos.api.connection]
options:
  bridge_priority:
    description: Bridge priority from 0 through 61440 in increments of 4096.
    type: int
  cost_mode:
    description: RSTP path-cost mode.
    type: str
    choices: [short, long]
  forward_reserved_multicast:
    description: Forward reserved multicast traffic.
    type: bool
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Configure bridge RSTP
  swos.api.rstp_bridge:
    url: http://192.0.2.10
    bridge_priority: 28672
    cost_mode: long
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
        "rstp_bridge",
        {
            "bridge_priority": {"type": "int"},
            "cost_mode": {"type": "str", "choices": ["short", "long"]},
            "forward_reserved_multicast": {"type": "bool"},
        },
        required_one_of=[["bridge_priority", "cost_mode", "forward_reserved_multicast"]],
    )


if __name__ == "__main__":
    main()
