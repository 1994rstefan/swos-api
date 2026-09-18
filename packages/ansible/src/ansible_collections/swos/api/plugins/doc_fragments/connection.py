"""Shared documentation for swos.api connection options."""


class ModuleDocFragment:
    DOCUMENTATION = r"""
options:
  url:
    description: Base URL of the SwOS device.
    type: str
    required: true
  username:
    description: Device login username.
    type: str
    default: admin
  password:
    description: Device login password.
    type: str
    default: ""
  timeout:
    description: Request timeout in seconds.
    type: float
    default: 10.0
  validate_certs:
    description: Validate the device TLS certificate.
    type: bool
    default: true
  allow_untested_firmware:
    description:
      - Explicitly permit reads from firmware without an exact support record.
      - This does not permit writes.
    type: bool
    default: false
  allow_untested_firmware_writes:
    description:
      - Explicitly permit writes to firmware without an exact support record.
      - This also permits prerequisite reads and is enforced in check mode.
    type: bool
    default: false
"""
