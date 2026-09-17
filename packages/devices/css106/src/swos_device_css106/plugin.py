"""CSS106 plugin registration without prematurely claiming device support."""

from __future__ import annotations

from swos_core.api import DeviceAdapter
from swos_core.errors import UnsupportedFirmwareError
from swos_core.models import DeviceConnection, DeviceIdentity
from swos_core.plugins import SupportRecord
from swos_core.safety import FirmwareSafetyPolicy


class CSS106Plugin:
    """Plugin metadata for the CSS106 firmware family."""

    family = "css106"
    distribution_name = "swos-device-css106"

    def support_records(self) -> tuple[SupportRecord, ...]:
        """Return no records until the independent adapter is implemented."""

        return ()

    def create(
        self,
        *,
        identity: DeviceIdentity,
        connection: DeviceConnection,
        policy: FirmwareSafetyPolicy,
        support: SupportRecord | None,
    ) -> DeviceAdapter:
        """Reject adapter creation until CSS106 support is implemented."""

        del connection, policy, support
        raise UnsupportedFirmwareError(
            identity.product_code,
            identity.firmware_version,
            "adapter creation",
        )


plugin = CSS106Plugin()
