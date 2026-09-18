#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_name
short_description: Manage the SwOS device name
description:
  - Sets or clears the device name through the public C(swos-core) API.
version_added: "0.1.0"
extends_documentation_fragment: [swos.api.connection]
options:
  name:
    description:
      - Desired printable Unicode device name, at most 16 UTF-16 code units.
      - An empty string clears it.
    type: str
    required: true
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Name the office switch
  swos.api.device_name:
    url: http://192.0.2.10
    name: Office Switch
  delegate_to: localhost
"""

RETURN = r"""
system:
  description: Normalized system state after, or projected for, the operation.
  returned: always
  type: dict
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module("device_name", {"name": {"type": "str", "required": True}})


if __name__ == "__main__":
    main()
