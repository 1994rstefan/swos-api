"""CSS106 device probing and adapter registration."""

from __future__ import annotations

from collections.abc import Callable

from swos_core.api import DeviceAdapter
from swos_core.models import DeviceConnection, DeviceIdentity
from swos_core.plugins import SupportRecord
from swos_core.safety import FirmwareSafetyPolicy
from swos_core.transport import HttpTransport

from swos_device_css106.adapter import CSS106Adapter
from swos_device_css106.protocol import MAX_PAYLOAD_BYTES, identity_from_system, parse_payload


class CSS106Plugin:
    """Plugin metadata for the CSS106 firmware family."""

    family = "css106"
    distribution_name = "swos-device-css106"

    def __init__(
        self,
        transport_factory: Callable[[DeviceConnection], HttpTransport] = HttpTransport,
    ) -> None:
        self._transport_factory = transport_factory

    def support_records(self) -> tuple[SupportRecord, ...]:
        """Return exact model, firmware, and build combinations tested on hardware."""

        return (
            SupportRecord(
                firmware_family=self.family,
                product_code="CSS106-5G-1S",
                firmware_version="2.19",
                build_id="0x6a181cd5",
                marketing_names=("RB260GS",),
            ),
        )

    def probe(self, connection: DeviceConnection) -> DeviceIdentity | None:
        """Identify known CSS106 products through the read-only system endpoint."""

        with self._transport_factory(connection) as transport:
            payload = transport.request(
                "GET",
                "/sys.b",
                max_response_bytes=MAX_PAYLOAD_BYTES,
            )
        return identity_from_system(parse_payload(payload))

    def create(
        self,
        *,
        identity: DeviceIdentity,
        connection: DeviceConnection,
        policy: FirmwareSafetyPolicy,
        support: SupportRecord | None,
    ) -> DeviceAdapter:
        """Create the guarded adapter for a recognized CSS106 identity."""

        del policy, support
        return CSS106Adapter(
            connection,
            identity,
            transport_factory=self._transport_factory,
        )


plugin = CSS106Plugin()
