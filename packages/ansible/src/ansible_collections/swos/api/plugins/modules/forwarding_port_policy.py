#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: forwarding_port_policy
short_description: Manage per-port SwOS forwarding lock and egress policy
description:
  - Manages lock, lock-on-first, and egress rate policy on Ethernet ports 1 through 5.
version_added: "0.1.0"
extends_documentation_fragment: [swos.api.connection]
options:
  port:
    description: Ethernet port number.
    type: int
    required: true
    choices: [1, 2, 3, 4, 5]
  lock:
    description: Whether forwarding database locking is enabled.
    type: bool
  lock_on_first:
    description: Whether the first learned source locks the port.
    type: bool
  egress_rate_limit_bps:
    description: Egress limit in bits per second, or C(unlimited) to remove the limit.
    type: raw
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Lock port 5 and remove its egress limit
  swos.api.forwarding_port_policy:
    url: http://192.0.2.10
    port: 5
    lock: true
    egress_rate_limit_bps: unlimited
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
        "forwarding_port_policy",
        {
            "port": {"type": "int", "required": True, "choices": [1, 2, 3, 4, 5]},
            "lock": {"type": "bool"},
            "lock_on_first": {"type": "bool"},
            "egress_rate_limit_bps": {"type": "raw"},
        },
        required_one_of=[["lock", "lock_on_first", "egress_rate_limit_bps"]],
    )


if __name__ == "__main__":
    main()
