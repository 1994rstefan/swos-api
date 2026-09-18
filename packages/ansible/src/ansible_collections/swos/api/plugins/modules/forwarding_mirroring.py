#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: forwarding_mirroring
short_description: Manage SwOS port mirroring
description:
  - Manages ingress and egress mirroring for one source and the switch-wide mirror target.
version_added: "0.2.0"
extends_documentation_fragment: [swos.api.connection]
options:
  source_port_number:
    description: Ethernet mirror source port.
    type: int
    required: true
    choices: [1, 2, 3, 4, 5]
  mirror_ingress:
    description: Enable ingress mirroring for the source.
    type: bool
  mirror_egress:
    description: Enable egress mirroring for the source.
    type: bool
  mirror_target_port:
    description: Ethernet mirror target, or C(none) to clear the target.
    type: raw
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Mirror ingress and egress from port 5 to port 1
  swos.api.forwarding_mirroring:
    url: http://192.0.2.10
    source_port_number: 5
    mirror_ingress: true
    mirror_egress: true
    mirror_target_port: 1
  delegate_to: localhost

- name: Clear the mirror target
  swos.api.forwarding_mirroring:
    url: http://192.0.2.10
    source_port_number: 5
    mirror_target_port: none
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
        "forwarding_mirroring",
        {
            "source_port_number": {
                "type": "int",
                "required": True,
                "choices": [1, 2, 3, 4, 5],
            },
            "mirror_ingress": {"type": "bool"},
            "mirror_egress": {"type": "bool"},
            "mirror_target_port": {"type": "raw"},
        },
        required_one_of=[["mirror_ingress", "mirror_egress", "mirror_target_port"]],
    )


if __name__ == "__main__":
    main()
