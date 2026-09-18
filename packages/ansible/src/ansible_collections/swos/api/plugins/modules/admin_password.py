#!/usr/bin/python
# Copyright: (c) 2026, 1994rstefan
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: admin_password
short_description: Rotate the SwOS administrator password
description:
  - Rotates and verifies the administrator password.
  - The connection O(password) is the current password and O(new_password) is the replacement.
  - Check mode validates the replacement and always reports changed because password equality cannot
    be read.
  - Neither password is returned or logged.
version_added: "0.2.0"
extends_documentation_fragment: [swos.api.connection]
options:
  new_password:
    description: New administrator password.
    type: str
    required: true
author:
  - 1994rstefan (@1994rstefan)
"""

EXAMPLES = r"""
- name: Rotate the administrator password
  swos.api.admin_password:
    url: http://192.0.2.10
    password: "{{ vault_swos_old_password }}"
    new_password: "{{ vault_swos_new_password }}"
  no_log: true
  delegate_to: localhost
"""

RETURN = r"""
system:
  description: Normalized system state verified after, or read during check mode for, the operation.
  returned: always
  type: dict
"""

from ansible_collections.swos.api.plugins.module_utils.swos import run_module


def main() -> None:
    run_module(
        "admin_password",
        {"new_password": {"type": "str", "required": True, "no_log": True}},
    )


if __name__ == "__main__":
    main()
