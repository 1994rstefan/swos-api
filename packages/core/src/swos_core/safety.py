"""Safety policy for explicitly unsupported firmware versions."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from swos_core.errors import UnsupportedFirmwareError
from swos_core.models import DeviceIdentity, SafetyWarning


class FirmwareSafetyPolicy(BaseModel):
    """Explicit overrides for operations against untested firmware."""

    model_config = ConfigDict(frozen=True)

    allow_untested_firmware: bool = False
    allow_untested_firmware_writes: bool = False

    @property
    def permits_untested_reads(self) -> bool:
        """Write permission implies read permission for the same invocation."""

        return self.allow_untested_firmware or self.allow_untested_firmware_writes


def enforce_firmware_policy(
    identity: DeviceIdentity,
    policy: FirmwareSafetyPolicy,
    *,
    supported: bool,
    write: bool,
) -> tuple[SafetyWarning, ...]:
    """Enforce exact firmware support and return override warnings."""

    if supported:
        return ()

    operation = "write operations" if write else "read operations"
    allowed = policy.allow_untested_firmware_writes if write else policy.permits_untested_reads
    if not allowed:
        raise UnsupportedFirmwareError(
            identity.product_code,
            identity.firmware_version,
            operation,
        )

    return (
        SafetyWarning(
            code="untested_firmware_write" if write else "untested_firmware",
            message=(
                f"Proceeding with {operation} on untested device "
                f"{identity.product_code} running SwOS {identity.firmware_version}"
            ),
        ),
    )
