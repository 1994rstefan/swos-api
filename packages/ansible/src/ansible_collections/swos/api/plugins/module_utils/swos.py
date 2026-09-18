"""Thin Ansible adapter for the independently testable execution layer."""

from __future__ import annotations

from typing import Any

from ansible.module_utils.basic import AnsibleModule

CONNECTION_ARGUMENTS: dict[str, dict[str, Any]] = {
    "url": {"type": "str", "required": True},
    "username": {"type": "str", "default": "admin"},
    "password": {"type": "str", "default": "", "no_log": True},
    "timeout": {"type": "float", "default": 10.0},
    "validate_certs": {"type": "bool", "default": True},
    "allow_untested_firmware": {"type": "bool", "default": False},
    "allow_untested_firmware_writes": {"type": "bool", "default": False},
}


def run_module(
    operation: str,
    argument_spec: dict[str, dict[str, Any]],
    *,
    required_one_of: list[list[str]] | None = None,
    required_if: list[list[Any]] | None = None,
) -> None:
    """Execute one operation and map failures to stable Ansible result data."""

    module = AnsibleModule(
        argument_spec=CONNECTION_ARGUMENTS | argument_spec,
        supports_check_mode=True,
        required_one_of=required_one_of,
        required_if=required_if,
    )
    try:
        from swos_ansible import execute

        result = execute(operation, module.params, check_mode=module.check_mode)
    except Exception as exc:
        module.fail_json(
            msg=str(exc),
            error={"type": type(exc).__name__, "message": str(exc)},
        )
    module.exit_json(**result)
